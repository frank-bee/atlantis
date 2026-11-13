// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/runatlantis/atlantis/server/events"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/jobs"
	"github.com/runatlantis/atlantis/server/logging"
)

const (
	// DefaultWaitSeconds is how long a tool call waits for a command to finish
	// when the caller does not say.
	DefaultWaitSeconds = 30
	// MaxWaitSeconds bounds a single tool call. It stays below the 60 second
	// idle timeout that many load balancers apply to a silent connection.
	MaxWaitSeconds = 50
	// DefaultTailLines and MaxTailLines bound the job output a call returns.
	DefaultTailLines = 200
	MaxTailLines     = 2000
	maxOutputBytes   = 64 * 1024

	finishedRunRetention = time.Hour
)

var ansiEscape = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// CommandRunner runs a parsed command the same way a pull request comment
// would: with the team allowlist, command requirements, locks, hooks and the
// result comment on the pull request.
type CommandRunner interface {
	RunCommentCommand(baseRepo models.Repo, maybeHeadRepo *models.Repo, maybePull *models.PullRequest, user models.User, pullNum int, cmd *events.CommentCommand)
}

// CommentParser turns command text into a command, enforcing --allow-commands
// and the flag validation that applies to pull request comments.
type CommentParser interface {
	Parse(comment string, vcsHost models.VCSHostType) events.CommentParseResult
}

// RepoResolver builds the repo model for a full repository name.
type RepoResolver interface {
	ResolveRepo(fullName string) (models.Repo, error)
}

// PullFetcher fetches the current state of a pull request from the VCS host.
type PullFetcher interface {
	FetchPull(repo models.Repo, num int) (models.PullRequest, error)
}

// PermissionChecker reports the permission a user has on a repository:
// "admin", "write", "read" or "none".
type PermissionChecker interface {
	GetUserRepoPermission(logger logging.SimpleLogging, repo models.Repo, username string) (string, error)
}

// Commenter comments on pull requests.
type Commenter interface {
	CreateComment(logger logging.SimpleLogging, repo models.Repo, pullNum int, comment string, command string) error
}

// RepoAllowlist reports whether Atlantis may operate on a repository.
type RepoAllowlist interface {
	IsAllowlisted(repoFullName string, vcsHostname string) bool
}

// StatusStore reads pull request status and locks.
type StatusStore interface {
	GetPullStatus(pull models.PullRequest) (*models.PullStatus, error)
	List() ([]models.ProjectLock, error)
}

// JobOutputReader reads the buffered terminal output of jobs.
type JobOutputReader interface {
	GetPullToJobMapping() []jobs.PullInfoWithJobIDs
	GetProjectOutputBuffer(jobID string) jobs.OutputBuffer
}

// Service implements the operations behind the MCP tools. It knows nothing
// about the MCP protocol.
type Service struct {
	Logger         logging.SimpleLogging
	CommandRunner  CommandRunner
	CommentParser  CommentParser
	RepoResolver   RepoResolver
	PullFetcher    PullFetcher
	Permissions    PermissionChecker
	Commenter      Commenter
	RepoAllowlist  RepoAllowlist
	StatusStore    StatusStore
	Jobs           JobOutputReader // nil when log streaming is disabled
	VCSHostType    models.VCSHostType
	ExecutableName string
	// ReadOnly disables every operation that runs a command.
	ReadOnly bool

	mu      sync.Mutex
	runs    map[string]*run
	closing chan struct{}
	once    sync.Once
}

type run struct {
	Command  string
	User     string
	Started  time.Time
	Finished time.Time
	done     chan struct{}
}

func (s *Service) init() {
	s.once.Do(func() {
		s.runs = map[string]*run{}
		s.closing = make(chan struct{})
	})
}

// Shutdown makes every waiting call return immediately so that open requests
// do not hold up a graceful server shutdown. Commands that are already running
// are unaffected; the drainer waits for those.
func (s *Service) Shutdown() {
	s.init()
	s.mu.Lock()
	defer s.mu.Unlock()
	select {
	case <-s.closing:
	default:
		close(s.closing)
	}
}

// PullRef names a pull request.
type PullRef struct {
	Repo string `json:"repo" jsonschema:"full repository name, for example owner/name"`
	Pull int    `json:"pull" jsonschema:"pull request number"`
}

// ProjectSelector narrows a command to one project. Leave it empty to run the
// command for every project of the pull request.
type ProjectSelector struct {
	Project   string `json:"project,omitempty" jsonschema:"project name from the repo config; cannot be combined with dir or workspace"`
	Dir       string `json:"dir,omitempty" jsonschema:"directory relative to the repository root"`
	Workspace string `json:"workspace,omitempty" jsonschema:"Terraform workspace"`
}

// PlanInput is the input of the plan operation.
type PlanInput struct {
	PullRef
	ProjectSelector
	ExtraArgs   []string `json:"extra_args,omitempty" jsonschema:"extra arguments passed to terraform plan, for example -target=aws_s3_bucket.logs"`
	WaitSeconds *int     `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for the command to finish, 0 to 50, default 30"`
}

// ApplyInput is the input of the apply operation.
type ApplyInput struct {
	PullRef
	ProjectSelector
	ExpectedHeadSHA string `json:"expected_head_sha" jsonschema:"full commit SHA of the pull request head whose plan was reviewed; the apply is refused when the pull request has moved"`
	WaitSeconds     *int   `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for the command to finish, 0 to 50, default 30"`
}

// UnlockInput is the input of the unlock operation.
type UnlockInput struct {
	PullRef
	WaitSeconds *int `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for the command to finish, 0 to 50, default 30"`
}

// PullStatusInput is the input of the pull status operation.
type PullStatusInput struct {
	PullRef
	WaitSeconds *int `json:"wait_seconds,omitempty" jsonschema:"seconds to wait for a running command to finish, 0 to 50, default 0"`
	TailLines   *int `json:"tail_lines,omitempty" jsonschema:"lines of output to include per job of the latest command, default 200"`
}

// JobOutputInput is the input of the job output operation.
type JobOutputInput struct {
	JobID     string `json:"job_id" jsonschema:"job id from a pull status result"`
	TailLines *int   `json:"tail_lines,omitempty" jsonschema:"lines to return from the end of the output, default 200"`
}

// ListLocksInput is the input of the list locks operation.
type ListLocksInput struct {
	Repo string `json:"repo" jsonschema:"full repository name, for example owner/name"`
}

// RunInfo describes a command started through MCP.
type RunInfo struct {
	Command    string `json:"command"`
	User       string `json:"user"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at,omitempty"`
	Running    bool   `json:"running"`
}

// ProjectInfo is the stored status of one project of a pull request.
type ProjectInfo struct {
	Project   string `json:"project,omitempty"`
	Dir       string `json:"dir"`
	Workspace string `json:"workspace"`
	Status    string `json:"status"`
}

// PlanStats are the resource counts of a plan.
type PlanStats struct {
	Import  int `json:"import"`
	Add     int `json:"add"`
	Change  int `json:"change"`
	Destroy int `json:"destroy"`
	Forget  int `json:"forget"`
}

// JobInfo describes one job of a pull request.
type JobInfo struct {
	JobID     string     `json:"job_id"`
	Project   string     `json:"project,omitempty"`
	Dir       string     `json:"dir"`
	Workspace string     `json:"workspace"`
	Step      string     `json:"step,omitempty"`
	StartedAt string     `json:"started_at"`
	Complete  bool       `json:"complete"`
	PlanStats *PlanStats `json:"plan_stats,omitempty"`
	// Output is set only for jobs of the latest MCP command.
	Output    string `json:"output,omitempty"`
	Truncated bool   `json:"output_truncated,omitempty"`
}

// LockInfo describes a project lock.
type LockInfo struct {
	Repo      string `json:"repo"`
	Dir       string `json:"dir"`
	Workspace string `json:"workspace"`
	Project   string `json:"project,omitempty"`
	Pull      int    `json:"pull"`
	LockedBy  string `json:"locked_by"`
	LockedAt  string `json:"locked_at"`
}

// PullStatusOutput is the state of a pull request as Atlantis sees it.
type PullStatusOutput struct {
	Repo     string        `json:"repo"`
	Pull     int           `json:"pull"`
	HeadSHA  string        `json:"head_sha"`
	Open     bool          `json:"open"`
	Command  *RunInfo      `json:"command,omitempty"`
	Projects []ProjectInfo `json:"projects"`
	Jobs     []JobInfo     `json:"jobs"`
	Locks    []LockInfo    `json:"locks"`
	Note     string        `json:"note,omitempty"`
}

// JobOutputOutput is the buffered output of one job.
type JobOutputOutput struct {
	JobID     string     `json:"job_id"`
	Complete  bool       `json:"complete"`
	Output    string     `json:"output"`
	Truncated bool       `json:"output_truncated,omitempty"`
	PlanStats *PlanStats `json:"plan_stats,omitempty"`
}

// ListLocksOutput lists the locks of one repository.
type ListLocksOutput struct {
	Locks []LockInfo `json:"locks"`
}

// WhoamiOutput describes the caller.
type WhoamiOutput struct {
	Username       string `json:"username"`
	TokenExpiresAt string `json:"token_expires_at"`
	ReadOnly       bool   `json:"read_only"`
}

// Whoami returns the identity behind the token.
func (s *Service) Whoami(claims Claims) WhoamiOutput {
	return WhoamiOutput{
		Username:       claims.Username,
		TokenExpiresAt: claims.Expiry().UTC().Format(time.RFC3339),
		ReadOnly:       s.ReadOnly,
	}
}

// Plan runs "atlantis plan" on the pull request as the calling user.
func (s *Service) Plan(ctx context.Context, claims Claims, in PlanInput) (*PullStatusOutput, error) {
	text, err := s.commandText(command.Plan, in.ProjectSelector, in.ExtraArgs)
	if err != nil {
		return nil, err
	}
	return s.runCommand(ctx, claims, in.PullRef, text, "", in.WaitSeconds)
}

// Apply runs "atlantis apply" on the pull request as the calling user.
func (s *Service) Apply(ctx context.Context, claims Claims, in ApplyInput) (*PullStatusOutput, error) {
	if len(in.ExpectedHeadSHA) != 40 {
		return nil, errors.New("expected_head_sha must be the full 40 character commit SHA of the reviewed pull request head")
	}
	text, err := s.commandText(command.Apply, in.ProjectSelector, nil)
	if err != nil {
		return nil, err
	}
	return s.runCommand(ctx, claims, in.PullRef, text, in.ExpectedHeadSHA, in.WaitSeconds)
}

// Unlock runs "atlantis unlock", which discards all plans and locks of the
// pull request.
func (s *Service) Unlock(ctx context.Context, claims Claims, in UnlockInput) (*PullStatusOutput, error) {
	text, err := s.commandText(command.Unlock, ProjectSelector{}, nil)
	if err != nil {
		return nil, err
	}
	return s.runCommand(ctx, claims, in.PullRef, text, "", in.WaitSeconds)
}

// PullStatus returns the state of a pull request, optionally waiting for a
// running MCP command to finish first.
func (s *Service) PullStatus(ctx context.Context, claims Claims, in PullStatusInput) (*PullStatusOutput, error) {
	s.init()
	repo, err := s.authorize(claims, in.Repo, false)
	if err != nil {
		return nil, err
	}
	if in.Pull <= 0 {
		return nil, errors.New("pull must be a positive pull request number")
	}
	wait, err := waitDuration(in.WaitSeconds, 0)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	r := s.runs[runKey(repo, in.Pull)]
	s.mu.Unlock()
	if r != nil {
		s.wait(ctx, r, wait)
	}
	return s.snapshot(repo, in.Pull, tailLines(in.TailLines))
}

// JobOutput returns the buffered output of a job.
func (s *Service) JobOutput(claims Claims, in JobOutputInput) (*JobOutputOutput, error) {
	if s.Jobs == nil {
		return nil, errors.New("job output is unavailable because terraform log streaming is disabled on this server")
	}
	// The job id alone does not say which repository it belongs to, so find it
	// first and authorize against that repository.
	var repoName string
	for _, p := range s.Jobs.GetPullToJobMapping() {
		for _, j := range p.JobIDInfos {
			if j.JobID == in.JobID {
				repoName = p.Pull.RepoFullName
			}
		}
	}
	if repoName == "" {
		return nil, fmt.Errorf("job %q not found; job output is kept in memory only until the pull request is closed or Atlantis restarts", in.JobID)
	}
	if _, err := s.authorize(claims, repoName, false); err != nil {
		return nil, err
	}
	buf := s.Jobs.GetProjectOutputBuffer(in.JobID)
	out, truncated := tail(buf.Buffer, tailLines(in.TailLines))
	return &JobOutputOutput{
		JobID:     in.JobID,
		Complete:  buf.OperationComplete,
		Output:    out,
		Truncated: truncated,
		PlanStats: planStats(buf),
	}, nil
}

// ListLocks returns the project locks held in one repository.
func (s *Service) ListLocks(claims Claims, in ListLocksInput) (*ListLocksOutput, error) {
	repo, err := s.authorize(claims, in.Repo, false)
	if err != nil {
		return nil, err
	}
	locks, err := s.locks(repo)
	if err != nil {
		return nil, err
	}
	return &ListLocksOutput{Locks: locks}, nil
}

// authorize resolves the repository and checks that Atlantis manages it and
// that the user may read it, or write to it when write is true.
//
// A pull request comment proves that its author can at least comment on the
// repository. A personal token proves only who the caller is, so the
// repository permission is checked here on every call. The team allowlist and
// command requirements are enforced later by the command runner, exactly as
// they are for comments.
func (s *Service) authorize(claims Claims, repoName string, write bool) (models.Repo, error) {
	if !models.IsValidAPIRepositoryForType(repoName, s.VCSHostType.String()) {
		return models.Repo{}, fmt.Errorf("invalid repository %q, expected owner/name", repoName)
	}
	repo, err := s.RepoResolver.ResolveRepo(repoName)
	if err != nil {
		s.Logger.Warn("MCP: resolving repo %q for user %q: %s", repoName, claims.Username, err)
		return models.Repo{}, fmt.Errorf("repository %q not found or not accessible to Atlantis", repoName)
	}
	if !s.RepoAllowlist.IsAllowlisted(repo.FullName, repo.VCSHost.Hostname) {
		return models.Repo{}, fmt.Errorf("repository %q is not in the Atlantis repo allowlist", repo.FullName)
	}
	level, err := s.Permissions.GetUserRepoPermission(s.Logger, repo, claims.Username)
	if err != nil {
		s.Logger.Warn("MCP: checking permission of user %q on %q: %s", claims.Username, repo.FullName, err)
		return models.Repo{}, fmt.Errorf("could not verify the permission of user %q on %q", claims.Username, repo.FullName)
	}
	switch {
	case level == "admin" || level == "write":
	case level == "read" && !write:
	default:
		need := "read"
		if write {
			need = "write"
		}
		return models.Repo{}, fmt.Errorf("user %q needs %s permission on %q", claims.Username, need, repo.FullName)
	}
	return repo, nil
}

func (s *Service) runCommand(ctx context.Context, claims Claims, ref PullRef, text string, expectedHeadSHA string, waitSeconds *int) (*PullStatusOutput, error) {
	s.init()
	if s.ReadOnly {
		return nil, errors.New("this server is read-only; commands are disabled")
	}
	wait, err := waitDuration(waitSeconds, DefaultWaitSeconds)
	if err != nil {
		return nil, err
	}
	if ref.Pull <= 0 {
		return nil, errors.New("pull must be a positive pull request number")
	}
	repo, err := s.authorize(claims, ref.Repo, true)
	if err != nil {
		return nil, err
	}
	parsed := s.CommentParser.Parse(text, s.VCSHostType)
	if parsed.Command == nil {
		reason := strings.TrimSpace(strings.Trim(strings.TrimSpace(parsed.CommentResponse), "`"))
		if reason == "" {
			reason = "command not recognized"
		}
		return nil, fmt.Errorf("command rejected: %s", reason)
	}
	pull, err := s.PullFetcher.FetchPull(repo, ref.Pull)
	if err != nil {
		s.Logger.Warn("MCP: fetching pull %s#%d: %s", repo.FullName, ref.Pull, err)
		return nil, fmt.Errorf("could not fetch pull request %s#%d", repo.FullName, ref.Pull)
	}
	if expectedHeadSHA != "" && !strings.EqualFold(expectedHeadSHA, pull.HeadCommit) {
		return nil, fmt.Errorf("pull request head is %s, not the expected %s; review the plan for the new head before applying", pull.HeadCommit, expectedHeadSHA)
	}

	key := runKey(repo, ref.Pull)
	r := &run{Command: text, User: claims.Username, Started: time.Now(), done: make(chan struct{})}
	s.mu.Lock()
	select {
	case <-s.closing:
		s.mu.Unlock()
		return nil, errors.New("atlantis is shutting down")
	default:
	}
	if prev := s.runs[key]; prev != nil && prev.Finished.IsZero() {
		s.mu.Unlock()
		return nil, fmt.Errorf("%q started by %s is still running on this pull request; wait for it with the pull status tool", prev.Command, prev.User)
	}
	for k, old := range s.runs {
		if !old.Finished.IsZero() && time.Since(old.Finished) > finishedRunRetention {
			delete(s.runs, k)
		}
	}
	s.runs[key] = r
	s.mu.Unlock()

	// The pull request is the audit trail and what a reviewer reads, so the
	// command is announced there before it runs. Without the announcement the
	// command does not run.
	// The text must not start with the executable name or a mention, or the
	// comment webhook would run it as a command a second time.
	audit := fmt.Sprintf("Via the MCP server, @%s ran: `%s`", claims.Username, text)
	if err := s.Commenter.CreateComment(s.Logger, repo, ref.Pull, audit, ""); err != nil {
		s.finish(r)
		s.Logger.Err("MCP: announcing %q on %s#%d: %s", text, repo.FullName, ref.Pull, err)
		return nil, errors.New("could not comment on the pull request, so the command was not run")
	}
	s.Logger.Info("MCP: user %q (token %q) runs %q on %s#%d", claims.Username, claims.ID, text, repo.FullName, ref.Pull)

	go func() {
		defer s.finish(r)
		s.CommandRunner.RunCommentCommand(repo, nil, nil, models.User{Username: claims.Username}, ref.Pull, parsed.Command)
	}()

	s.wait(ctx, r, wait)
	return s.snapshot(repo, ref.Pull, DefaultTailLines)
}

func (s *Service) finish(r *run) {
	s.mu.Lock()
	r.Finished = time.Now()
	s.mu.Unlock()
	close(r.done)
}

func (s *Service) wait(ctx context.Context, r *run, d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-r.done:
	case <-t.C:
	case <-ctx.Done():
	case <-s.closing:
	}
}

func (s *Service) snapshot(repo models.Repo, pullNum int, lines int) (*PullStatusOutput, error) {
	pull, err := s.PullFetcher.FetchPull(repo, pullNum)
	if err != nil {
		s.Logger.Warn("MCP: fetching pull %s#%d: %s", repo.FullName, pullNum, err)
		return nil, fmt.Errorf("could not fetch pull request %s#%d", repo.FullName, pullNum)
	}
	out := &PullStatusOutput{
		Repo:     repo.FullName,
		Pull:     pullNum,
		HeadSHA:  pull.HeadCommit,
		Open:     pull.State == models.OpenPullState,
		Projects: []ProjectInfo{},
		Jobs:     []JobInfo{},
	}

	s.mu.Lock()
	var since time.Time
	if r := s.runs[runKey(repo, pullNum)]; r != nil {
		since = r.Started
		out.Command = &RunInfo{
			Command:   r.Command,
			User:      r.User,
			StartedAt: r.Started.UTC().Format(time.RFC3339),
			Running:   r.Finished.IsZero(),
		}
		if !r.Finished.IsZero() {
			out.Command.FinishedAt = r.Finished.UTC().Format(time.RFC3339)
		}
	}
	s.mu.Unlock()

	status, err := s.StatusStore.GetPullStatus(pull)
	if err != nil {
		return nil, fmt.Errorf("reading pull status: %w", err)
	}
	if status != nil {
		for _, p := range status.Projects {
			out.Projects = append(out.Projects, ProjectInfo{
				Project:   p.ProjectName,
				Dir:       p.RepoRelDir,
				Workspace: p.Workspace,
				Status:    p.Status.String(),
			})
		}
	}

	jobsOfCommand := 0
	if s.Jobs != nil {
		for _, p := range s.Jobs.GetPullToJobMapping() {
			if p.Pull.RepoFullName != repo.FullName || p.Pull.PullNum != pullNum {
				continue
			}
			for _, j := range p.JobIDInfos {
				buf := s.Jobs.GetProjectOutputBuffer(j.JobID)
				info := JobInfo{
					JobID:     j.JobID,
					Project:   p.Pull.ProjectName,
					Dir:       p.Pull.Path,
					Workspace: p.Pull.Workspace,
					Step:      j.JobStep,
					StartedAt: j.Time.UTC().Format(time.RFC3339),
					Complete:  buf.OperationComplete,
					PlanStats: planStats(buf),
				}
				// Job times have second precision in some paths, so compare
				// against the start truncated to the second.
				if !since.IsZero() && !j.Time.Before(since.Truncate(time.Second)) {
					jobsOfCommand++
					info.Output, info.Truncated = tail(buf.Buffer, lines)
				}
				out.Jobs = append(out.Jobs, info)
			}
		}
		sort.Slice(out.Jobs, func(i, k int) bool { return out.Jobs[i].StartedAt < out.Jobs[k].StartedAt })
	}

	// All locks of the repository are listed, not only this pull request's:
	// a lock held by another pull request is what blocks a plan here.
	out.Locks, err = s.locks(repo)
	if err != nil {
		return nil, err
	}

	switch {
	case out.Command != nil && out.Command.Running:
		out.Note = "The command is still running. Call the pull status tool with wait_seconds to wait for it."
	case out.Command != nil && s.Jobs != nil && jobsOfCommand == 0 && !strings.Contains(out.Command.Command, command.Unlock.String()):
		out.Note = "The command finished without starting a job. Atlantis explains why in a pull request comment, for example a missing team permission, an unmet apply requirement, a lock held by another pull request, or no matching project."
	}
	return out, nil
}

func (s *Service) locks(repo models.Repo) ([]LockInfo, error) {
	all, err := s.StatusStore.List()
	if err != nil {
		return nil, fmt.Errorf("listing locks: %w", err)
	}
	locks := []LockInfo{}
	for _, l := range all {
		if l.Project.RepoFullName != repo.FullName {
			continue
		}
		locks = append(locks, LockInfo{
			Repo:      l.Project.RepoFullName,
			Dir:       l.Project.Path,
			Workspace: l.Workspace,
			Project:   l.Project.ProjectName,
			Pull:      l.Pull.Num,
			LockedBy:  l.User.Username,
			LockedAt:  l.Time.UTC().Format(time.RFC3339),
		})
	}
	return locks, nil
}

// commandText builds the comment text for a command. Every value is validated
// and quoted here; the comment parser validates the result again.
func (s *Service) commandText(name command.Name, sel ProjectSelector, extraArgs []string) (string, error) {
	parts := []string{s.ExecutableName, name.String()}
	for _, f := range []struct{ flag, value string }{
		{"-p", sel.Project},
		{"-d", sel.Dir},
		{"-w", sel.Workspace},
	} {
		if f.value == "" {
			continue
		}
		if err := validateArg(f.value); err != nil {
			return "", fmt.Errorf("invalid value %q: %w", f.value, err)
		}
		if strings.HasPrefix(f.value, "-") {
			return "", fmt.Errorf("invalid value %q: must not start with a dash", f.value)
		}
		parts = append(parts, f.flag, "'"+f.value+"'")
	}
	if len(extraArgs) > 0 {
		parts = append(parts, "--")
		for _, a := range extraArgs {
			if a == "" {
				return "", errors.New("extra_args must not contain empty values")
			}
			if err := validateArg(a); err != nil {
				return "", fmt.Errorf("invalid extra argument %q: %w", a, err)
			}
			parts = append(parts, "'"+a+"'")
		}
	}
	return strings.Join(parts, " "), nil
}

// validateArg rejects values that cannot be single-quoted safely.
func validateArg(v string) error {
	for _, r := range v {
		if r == '\'' || r == '\\' || unicode.IsControl(r) {
			return errors.New("single quotes, backslashes and control characters are not allowed")
		}
	}
	return nil
}

func runKey(repo models.Repo, pull int) string {
	return fmt.Sprintf("%s/%s#%d", repo.VCSHost.Hostname, repo.FullName, pull)
}

func waitDuration(v *int, def int) (time.Duration, error) {
	n := def
	if v != nil {
		n = *v
	}
	if n < 0 || n > MaxWaitSeconds {
		return 0, fmt.Errorf("wait_seconds must be between 0 and %d", MaxWaitSeconds)
	}
	return time.Duration(n) * time.Second, nil
}

func tailLines(v *int) int {
	if v == nil || *v <= 0 {
		return DefaultTailLines
	}
	return min(*v, MaxTailLines)
}

// tail returns the last n lines, also bounded in bytes, and whether anything
// was cut off.
func tail(lines []string, n int) (string, bool) {
	truncated := false
	if len(lines) > n {
		lines = lines[len(lines)-n:]
		truncated = true
	}
	// Terraform colors its output for the web terminal; the escape codes are
	// noise to an MCP client.
	out := ansiEscape.ReplaceAllString(strings.Join(lines, "\n"), "")
	if len(out) > maxOutputBytes {
		out = out[len(out)-maxOutputBytes:]
		truncated = true
	}
	return out, truncated
}

func planStats(buf jobs.OutputBuffer) *PlanStats {
	if !buf.OperationComplete {
		return nil
	}
	st := models.NewPlanSuccessStats(ansiEscape.ReplaceAllString(strings.Join(buf.Buffer, "\n"), ""))
	if !st.Changes {
		return nil
	}
	return &PlanStats{Import: st.Import, Add: st.Add, Change: st.Change, Destroy: st.Destroy, Forget: st.Forget}
}
