// Copyright 2026 The Atlantis Authors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"github.com/google/go-github/v88/github"
	"github.com/runatlantis/atlantis/server/events/models"
	"github.com/runatlantis/atlantis/server/logging"
)

// CloneURLGetter returns the clone URL of a repository.
type CloneURLGetter interface {
	GetCloneURL(logger logging.SimpleLogging, VCSHostType models.VCSHostType, repo string) (string, error)
}

// APIRepoParser builds a repo model from a repository name and clone URL.
type APIRepoParser interface {
	ParseAPIPlanRequest(vcsHostType models.VCSHostType, repoFullName string, cloneURL string) (models.Repo, error)
}

// GithubPullGetter fetches a pull request from GitHub.
type GithubPullGetter interface {
	GetPullRequest(logger logging.SimpleLogging, repo models.Repo, pullNum int) (*github.PullRequest, error)
}

// GithubPullParser converts a GitHub pull request into the Atlantis model.
type GithubPullParser interface {
	ParseGithubPull(logger logging.SimpleLogging, ghPull *github.PullRequest) (models.PullRequest, models.Repo, models.Repo, error)
}

// GithubRepoResolver implements RepoResolver for GitHub.
type GithubRepoResolver struct {
	Logger    logging.SimpleLogging
	VCSClient CloneURLGetter
	Parser    APIRepoParser
}

// ResolveRepo implements RepoResolver.
func (r *GithubRepoResolver) ResolveRepo(fullName string) (models.Repo, error) {
	cloneURL, err := r.VCSClient.GetCloneURL(r.Logger, models.Github, fullName)
	if err != nil {
		return models.Repo{}, err
	}
	return r.Parser.ParseAPIPlanRequest(models.Github, fullName, cloneURL)
}

// GithubPullFetcher implements PullFetcher for GitHub.
type GithubPullFetcher struct {
	Logger logging.SimpleLogging
	Getter GithubPullGetter
	Parser GithubPullParser
}

// FetchPull implements PullFetcher.
func (f *GithubPullFetcher) FetchPull(repo models.Repo, num int) (models.PullRequest, error) {
	ghPull, err := f.Getter.GetPullRequest(f.Logger, repo, num)
	if err != nil {
		return models.PullRequest{}, err
	}
	pull, _, _, err := f.Parser.ParseGithubPull(f.Logger, ghPull)
	return pull, err
}
