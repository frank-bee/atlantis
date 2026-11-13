// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/runatlantis/atlantis/server/events"
	"github.com/runatlantis/atlantis/server/events/command"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/jobs"
	"github.com/runatlantis/atlantis/server/logging"
	. "github.com/runatlantis/atlantis/testing"
)

const headSHA = "1111111111111111111111111111111111111111"

type ranCommand struct {
	repo string
	pull int
	user models.User
	cmd  *events.CommentCommand
}

// fakes implements every dependency of Service.
type fakes struct {
	mu          sync.Mutex
	ran         []ranCommand
	comments    []string
	permission  string
	permErr     error
	commentErr  error
	allowlisted bool
	pull        models.PullRequest
	status      *models.PullStatus
	locks       []models.ProjectLock
	jobMapping  []jobs.PullInfoWithJobIDs
	buffers     map[string]jobs.OutputBuffer
	// block, when set, is closed by the test to let a running command finish.
	block chan struct{}
	// onRun runs inside the command, before it returns.
	onRun func()
}

func (f *fakes) RunCommentCommand(baseRepo models.Repo, _ *models.Repo, _ *models.PullRequest, user models.User, pullNum int, cmd *events.CommentCommand) {
	f.mu.Lock()
	f.ran = append(f.ran, ranCommand{repo: baseRepo.FullName, pull: pullNum, user: user, cmd: cmd})
	block, onRun := f.block, f.onRun
	f.mu.Unlock()
	if onRun != nil {
		onRun()
	}
	if block != nil {
		<-block
	}
}

func (f *fakes) ResolveRepo(fullName string) (models.Repo, error) {
	return models.NewRepo(models.Github, fullName, "https://github.com/"+fullName+".git", "bot", "token", "github.com")
}

func (f *fakes) FetchPull(repo models.Repo, num int) (models.PullRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := f.pull
	p.BaseRepo = repo
	p.Num = num
	return p, nil
}

func (f *fakes) GetUserRepoPermission(logging.SimpleLogging, models.Repo, string) (string, error) {
	return f.permission, f.permErr
}

func (f *fakes) CreateComment(_ logging.SimpleLogging, _ models.Repo, _ int, comment string, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.commentErr != nil {
		return f.commentErr
	}
	f.comments = append(f.comments, comment)
	return nil
}

func (f *fakes) IsAllowlisted(string, string) bool { return f.allowlisted }

func (f *fakes) GetPullStatus(models.PullRequest) (*models.PullStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, nil
}

func (f *fakes) List() ([]models.ProjectLock, error) { return f.locks, nil }

func (f *fakes) GetPullToJobMapping() []jobs.PullInfoWithJobIDs {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jobMapping
}

func (f *fakes) GetProjectOutputBuffer(jobID string) jobs.OutputBuffer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.buffers[jobID]
}

func (f *fakes) commands() []ranCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ranCommand(nil), f.ran...)
}

func newTestService(t *testing.T, allow ...command.Name) (*Service, *fakes) {
	t.Helper()
	if allow == nil {
		allow = []command.Name{command.Plan, command.Apply, command.Unlock}
	}
	f := &fakes{
		permission:  "write",
		allowlisted: true,
		pull:        models.PullRequest{HeadCommit: headSHA, State: models.OpenPullState},
		buffers:     map[string]jobs.OutputBuffer{},
	}
	svc := &Service{
		Logger:         logging.NewNoopLogger(t),
		CommandRunner:  f,
		CommentParser:  events.NewCommentParser("bot", "", "", "", "", "atlantis", allow, nil),
		RepoResolver:   f,
		PullFetcher:    f,
		Permissions:    f,
		Commenter:      f,
		RepoAllowlist:  f,
		StatusStore:    f,
		Jobs:           f,
		VCSHostType:    models.Github,
		ExecutableName: "atlantis",
	}
	return svc, f
}

var (
	testClaims = Claims{Username: "octocat", UserID: 42, ID: "t1", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	testRef    = PullRef{Repo: "owner/repo", Pull: 7}
	noWait     = new(int)
)

func TestPlan_RunsAsUserThroughCommentPath(t *testing.T) {
	svc, f := newTestService(t)
	out, err := svc.Plan(context.Background(), testClaims, PlanInput{
		PullRef:         testRef,
		ProjectSelector: ProjectSelector{Project: "network"},
		ExtraArgs:       []string{`-target=module.a.aws_s3_bucket.b["logs"]`},
	})
	Ok(t, err)

	ran := f.commands()
	Equals(t, 1, len(ran))
	Equals(t, "owner/repo", ran[0].repo)
	Equals(t, 7, ran[0].pull)
	// The command runs as the token's user so that the team allowlist and
	// requirements are evaluated for that user.
	Equals(t, "octocat", ran[0].user.Username)
	Equals(t, command.Plan, ran[0].cmd.Name)
	Equals(t, "network", ran[0].cmd.ProjectName)
	Assert(t, strings.Contains(strings.Join(ran[0].cmd.Flags, " "), `module.a.aws_s3_bucket.b`), "extra arg lost: %v", ran[0].cmd.Flags)

	// The pull request carries the audit trail.
	Equals(t, 1, len(f.comments))
	Assert(t, strings.Contains(f.comments[0], "@octocat"), "comment must name the user: %s", f.comments[0])
	Assert(t, strings.Contains(f.comments[0], "atlantis plan -p 'network'"), "comment must show the command: %s", f.comments[0])
	// It must not itself parse as a command, or Atlantis would run it again
	// when the comment webhook arrives.
	Assert(t, svc.CommentParser.Parse(f.comments[0], models.Github).Ignore, "audit comment must not be a command")

	Equals(t, headSHA, out.HeadSHA)
	Equals(t, false, out.Command.Running)
}

func TestRunCommand_Refusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*Service, *fakes)
		ref   PullRef
		want  string
	}{
		{"read-only server", func(s *Service, _ *fakes) { s.ReadOnly = true }, testRef, "read-only"},
		{"repo not allowlisted", func(_ *Service, f *fakes) { f.allowlisted = false }, testRef, "allowlist"},
		{"read permission only", func(_ *Service, f *fakes) { f.permission = "read" }, testRef, "needs write permission"},
		{"no permission", func(_ *Service, f *fakes) { f.permission = "none" }, testRef, "needs write permission"},
		{"permission lookup fails", func(_ *Service, f *fakes) { f.permErr = errors.New("boom") }, testRef, "could not verify"},
		{"audit comment fails", func(_ *Service, f *fakes) { f.commentErr = errors.New("boom") }, testRef, "was not run"},
		{"invalid repo", func(*Service, *fakes) {}, PullRef{Repo: "../etc", Pull: 7}, "invalid repository"},
		{"invalid pull", func(*Service, *fakes) {}, PullRef{Repo: "owner/repo"}, "positive pull request number"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, f := newTestService(t)
			tc.setup(svc, f)
			_, err := svc.Plan(context.Background(), testClaims, PlanInput{PullRef: tc.ref})
			ErrContains(t, tc.want, err)
			Equals(t, 0, len(f.commands()))
		})
	}
}

func TestRunCommand_HonorsAllowCommands(t *testing.T) {
	svc, f := newTestService(t, command.Plan)
	_, err := svc.Apply(context.Background(), testClaims, ApplyInput{PullRef: testRef, ExpectedHeadSHA: headSHA})
	ErrContains(t, "command rejected", err)
	Equals(t, 0, len(f.commands()))
	Equals(t, 0, len(f.comments))
}

func TestApply_RequiresReviewedHead(t *testing.T) {
	svc, f := newTestService(t)

	_, err := svc.Apply(context.Background(), testClaims, ApplyInput{PullRef: testRef, ExpectedHeadSHA: "1111111"})
	ErrContains(t, "full 40 character", err)

	_, err = svc.Apply(context.Background(), testClaims, ApplyInput{PullRef: testRef, ExpectedHeadSHA: strings.Repeat("2", 40)})
	ErrContains(t, "pull request head is "+headSHA, err)
	Equals(t, 0, len(f.commands()))

	_, err = svc.Apply(context.Background(), testClaims, ApplyInput{PullRef: testRef, ExpectedHeadSHA: headSHA})
	Ok(t, err)
	ran := f.commands()
	Equals(t, 1, len(ran))
	Equals(t, command.Apply, ran[0].cmd.Name)
}

func TestCommandText_RejectsUnsafeValues(t *testing.T) {
	svc, f := newTestService(t)
	for _, in := range []PlanInput{
		{PullRef: testRef, ProjectSelector: ProjectSelector{Project: "a' -- -destroy '"}},
		{PullRef: testRef, ProjectSelector: ProjectSelector{Project: "-d"}},
		{PullRef: testRef, ProjectSelector: ProjectSelector{Dir: "a\nb"}},
		{PullRef: testRef, ExtraArgs: []string{"-var=x='y'"}},
		{PullRef: testRef, ExtraArgs: []string{""}},
		{PullRef: testRef, ExtraArgs: []string{`a\b`}},
	} {
		_, err := svc.Plan(context.Background(), testClaims, in)
		Assert(t, err != nil, "expected %+v to be rejected", in)
	}
	Equals(t, 0, len(f.commands()))
}

func TestCommandText_QuotedValuesCannotAddFlags(t *testing.T) {
	svc, f := newTestService(t)
	// A value with spaces must stay one argument rather than become flags.
	_, err := svc.Plan(context.Background(), testClaims, PlanInput{PullRef: testRef, ExtraArgs: []string{"-target=a.b -destroy"}})
	Ok(t, err)
	ran := f.commands()
	Equals(t, 1, len(ran))
	for _, flag := range ran[0].cmd.Flags {
		Assert(t, strings.TrimSpace(flag) != "-destroy", "value was split into a separate flag: %v", ran[0].cmd.Flags)
	}
}

func TestRunCommand_OneAtATimePerPull_AndWaiting(t *testing.T) {
	svc, f := newTestService(t)
	f.block = make(chan struct{})

	out, err := svc.Plan(context.Background(), testClaims, PlanInput{PullRef: testRef, WaitSeconds: noWait})
	Ok(t, err)
	Equals(t, true, out.Command.Running)
	Assert(t, out.Note != "", "a running command must be explained")

	_, err = svc.Plan(context.Background(), testClaims, PlanInput{PullRef: testRef, WaitSeconds: noWait})
	ErrContains(t, "still running", err)

	// Another pull request is independent.
	_, err = svc.Plan(context.Background(), testClaims, PlanInput{PullRef: PullRef{Repo: "owner/repo", Pull: 8}, WaitSeconds: noWait})
	Ok(t, err)

	// A waiting status call returns as soon as the command finishes.
	done := make(chan *PullStatusOutput, 1)
	go func() {
		wait := 20
		st, err := svc.PullStatus(context.Background(), testClaims, PullStatusInput{PullRef: testRef, WaitSeconds: &wait})
		Ok(t, err)
		done <- st
	}()
	close(f.block)
	select {
	case st := <-done:
		Equals(t, false, st.Command.Running)
	case <-time.After(5 * time.Second):
		t.Fatal("status call did not return after the command finished")
	}
}

func TestShutdown_ReleasesWaitingCalls(t *testing.T) {
	svc, f := newTestService(t)
	f.block = make(chan struct{})
	defer close(f.block)

	started := make(chan struct{})
	f.onRun = func() { close(started) }
	done := make(chan error, 1)
	go func() {
		wait := 50
		_, err := svc.Plan(context.Background(), testClaims, PlanInput{PullRef: testRef, WaitSeconds: &wait})
		done <- err
	}()
	<-started
	svc.Shutdown()
	select {
	case err := <-done:
		Ok(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("waiting call was not released by Shutdown")
	}

	_, err := svc.Plan(context.Background(), testClaims, PlanInput{PullRef: PullRef{Repo: "owner/repo", Pull: 9}})
	ErrContains(t, "shutting down", err)
}

func TestPullStatus_ReportsProjectsJobsAndLocks(t *testing.T) {
	svc, f := newTestService(t)
	f.permission = "read"
	f.status = &models.PullStatus{Projects: []models.ProjectStatus{
		{ProjectName: "network", RepoRelDir: "network", Workspace: "default", Status: models.PlannedPlanStatus},
	}}
	f.locks = []models.ProjectLock{
		{Project: models.Project{RepoFullName: "owner/repo", Path: "network"}, Workspace: "default", Pull: models.PullRequest{Num: 3}, User: models.User{Username: "hubot"}},
		{Project: models.Project{RepoFullName: "other/repo", Path: "x"}, Workspace: "default", Pull: models.PullRequest{Num: 1}},
	}
	f.jobMapping = []jobs.PullInfoWithJobIDs{
		{Pull: jobs.PullInfo{PullNum: 7, RepoFullName: "owner/repo", ProjectName: "network", Path: "network", Workspace: "default"},
			JobIDInfos: []jobs.JobIDInfo{{JobID: "job-1", JobStep: "plan", Time: time.Now().Add(-time.Hour)}}},
		{Pull: jobs.PullInfo{PullNum: 7, RepoFullName: "other/repo"}, JobIDInfos: []jobs.JobIDInfo{{JobID: "job-x"}}},
	}
	// Terraform colors the summary line; the codes must not hide the counts.
	f.buffers["job-1"] = jobs.OutputBuffer{OperationComplete: true, Buffer: []string{"...", "\x1b[1mPlan:\x1b[0m \x1b[0m2 to add, 1 to change, 3 to destroy."}}

	out, err := svc.PullStatus(context.Background(), testClaims, PullStatusInput{PullRef: testRef})
	Ok(t, err)
	Equals(t, []ProjectInfo{{Project: "network", Dir: "network", Workspace: "default", Status: "planned"}}, out.Projects)
	Equals(t, 1, len(out.Jobs))
	Equals(t, "job-1", out.Jobs[0].JobID)
	Equals(t, &PlanStats{Add: 2, Change: 1, Destroy: 3}, out.Jobs[0].PlanStats)
	// Output is attached only for jobs of the latest MCP command.
	Equals(t, "", out.Jobs[0].Output)
	// Locks of the same repository are listed, including other pull requests'.
	Equals(t, 1, len(out.Locks))
	Equals(t, 3, out.Locks[0].Pull)
	Assert(t, out.Command == nil, "no MCP command ran")
}

func TestPlan_AttachesOutputOfItsJobs(t *testing.T) {
	svc, f := newTestService(t)
	f.onRun = func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.jobMapping = []jobs.PullInfoWithJobIDs{{
			Pull:       jobs.PullInfo{PullNum: 7, RepoFullName: "owner/repo", Path: "."},
			JobIDInfos: []jobs.JobIDInfo{{JobID: "job-2", JobStep: "plan", Time: time.Now()}},
		}}
		f.buffers["job-2"] = jobs.OutputBuffer{OperationComplete: true, Buffer: []string{"\x1b[1mPlan:\x1b[0m \x1b[0m1 to add, 0 to change, 0 to destroy."}}
	}
	out, err := svc.Plan(context.Background(), testClaims, PlanInput{PullRef: testRef})
	Ok(t, err)
	Equals(t, 1, len(out.Jobs))
	Equals(t, "Plan: 1 to add, 0 to change, 0 to destroy.", out.Jobs[0].Output)
	Equals(t, "", out.Note)
}

func TestPlan_ExplainsCommandWithoutJobs(t *testing.T) {
	svc, _ := newTestService(t)
	out, err := svc.Plan(context.Background(), testClaims, PlanInput{PullRef: testRef})
	Ok(t, err)
	Assert(t, strings.Contains(out.Note, "without starting a job"), "note: %q", out.Note)
}

func TestJobOutput_AuthorizesAgainstTheJobsRepo(t *testing.T) {
	svc, f := newTestService(t)
	f.jobMapping = []jobs.PullInfoWithJobIDs{{
		Pull:       jobs.PullInfo{PullNum: 7, RepoFullName: "owner/repo"},
		JobIDInfos: []jobs.JobIDInfo{{JobID: "job-1"}},
	}}
	f.buffers["job-1"] = jobs.OutputBuffer{OperationComplete: true, Buffer: []string{"a", "b", "c"}}

	two := 2
	out, err := svc.JobOutput(testClaims, JobOutputInput{JobID: "job-1", TailLines: &two})
	Ok(t, err)
	Equals(t, "b\nc", out.Output)
	Equals(t, true, out.Truncated)

	_, err = svc.JobOutput(testClaims, JobOutputInput{JobID: "unknown"})
	ErrContains(t, "not found", err)

	f.permission = "none"
	_, err = svc.JobOutput(testClaims, JobOutputInput{JobID: "job-1"})
	ErrContains(t, "needs read permission", err)
}

func TestListLocks_RequiresReadPermission(t *testing.T) {
	svc, f := newTestService(t)
	f.permission = "none"
	_, err := svc.ListLocks(testClaims, ListLocksInput{Repo: "owner/repo"})
	ErrContains(t, "needs read permission", err)
}
