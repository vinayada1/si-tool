package scanner

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"strings"

	"github.com/google/go-github/v57/github"
	"golang.org/x/oauth2"
)

// GitHubData contains information gathered from GitHub API
type GitHubData struct {
	// Basic repo info
	ProjectURL    string
	RepoName      string
	Description   string
	Homepage      string
	DefaultBranch string
	Owner         string
	Repo          string
	IsOrg         bool
	OrgURL        string

	// Status
	IsArchived bool
	IsFork     bool

	// Security settings (requires admin access)
	MFAEnforced             bool
	BranchProtectionEnabled bool
	CodeReviewRequired      bool

	// License
	License    string
	LicenseURL string

	// Community files
	HasSecurityPolicy             bool
	SecurityPolicyURL             string
	HasCodeOfConduct              bool
	CodeOfConductURL              string
	HasContributing               bool
	ContributingURL               string
	HasFunding                    bool
	FundingURL                    string
	HasGovernance                 bool
	GovernanceURL                 string
	HasChangelog                  bool
	ChangelogURL                  string
	HasRoadmap                    bool
	RoadmapURL                    string
	HasReviewPolicy               bool
	ReviewPolicyURL               string
	HasDependencyManagementPolicy bool
	DependencyManagementPolicyURL string

	// Vulnerability reporting
	BugBountyURL string
	ContactEmail string

	// Release info
	HasReleases          bool
	LatestReleaseURL     string
	HasAutomatedReleases bool

	// Contributors/maintainers
	TopContributors []Contributor

	// Topics (can indicate security tools)
	Topics []string
}

// Contributor represents a repository contributor
type Contributor struct {
	Login         string
	Name          string
	Email         string
	Contributions int
}

// GitHubScanner fetches repository data from GitHub API
type GitHubScanner struct {
	client  *github.Client
	owner   string
	repo    string
	verbose bool
}

// NewGitHubScanner creates a new GitHubScanner instance
func NewGitHubScanner(token, repoURL string, verbose bool) (*GitHubScanner, error) {
	owner, repo, err := parseRepoURL(repoURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse repo URL: %w", err)
	}

	ctx := context.Background()
	var client *github.Client

	if token != "" {
		ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
		tc := oauth2.NewClient(ctx, ts)
		client = github.NewClient(tc)
	} else {
		client = github.NewClient(nil)
	}

	return &GitHubScanner{
		client:  client,
		owner:   owner,
		repo:    repo,
		verbose: verbose,
	}, nil
}

// Scan fetches repository data from GitHub
func (s *GitHubScanner) Scan(ctx context.Context) (GitHubData, error) {
	data := GitHubData{
		Owner: s.owner,
		Repo:  s.repo,
	}

	// Get basic repository info
	repo, _, err := s.client.Repositories.Get(ctx, s.owner, s.repo)
	if err != nil {
		return data, fmt.Errorf("failed to get repository: %w", err)
	}

	data.ProjectURL = repo.GetHTMLURL()
	data.RepoName = repo.GetName()
	data.Description = repo.GetDescription()
	data.Homepage = repo.GetHomepage()
	data.DefaultBranch = repo.GetDefaultBranch()
	data.IsArchived = repo.GetArchived()
	data.IsFork = repo.GetFork()
	data.Topics = repo.Topics

	if repo.License != nil {
		data.License = repo.License.GetSPDXID()
		data.LicenseURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/LICENSE", s.owner, s.repo, data.DefaultBranch)
	}

	// Check if owner is an org
	if org, _, err := s.client.Organizations.Get(ctx, s.owner); err == nil {
		data.IsOrg = true
		data.OrgURL = org.GetHTMLURL()
		data.MFAEnforced = org.GetTwoFactorRequirementEnabled()
	}

	// Get community health metrics
	s.scanCommunityHealth(ctx, &data)

	// Check for additional files
	s.scanRepositoryFiles(ctx, &data)

	// Check branch protection (requires admin)
	s.scanBranchProtection(ctx, &data)

	// Get release info
	s.scanReleases(ctx, &data)

	// Get top contributors
	s.scanContributors(ctx, &data)

	// Detect bug bounty program
	data.BugBountyURL = s.detectBugBounty()

	return data, nil
}

// scanCommunityHealth fetches community health metrics
func (s *GitHubScanner) scanCommunityHealth(ctx context.Context, data *GitHubData) {
	community, _, err := s.client.Repositories.GetCommunityHealthMetrics(ctx, s.owner, s.repo)
	if err != nil {
		return
	}

	if community.Files != nil {
		if community.Files.CodeOfConduct != nil {
			data.HasCodeOfConduct = true
			data.CodeOfConductURL = community.Files.CodeOfConduct.GetURL()
		}
		if community.Files.Contributing != nil {
			data.HasContributing = true
			data.ContributingURL = community.Files.Contributing.GetHTMLURL()
		}
	}
}

// scanRepositoryFiles checks for specific files in the repository
func (s *GitHubScanner) scanRepositoryFiles(ctx context.Context, data *GitHubData) {
	// Security policy
	securityPaths := []string{"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"}
	for _, path := range securityPaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil); err == nil {
			data.HasSecurityPolicy = true
			data.SecurityPolicyURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path)
			break
		}
	}

	// Funding
	fundingPaths := []string{".github/FUNDING.yml", "FUNDING.yml"}
	for _, path := range fundingPaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil); err == nil {
			data.HasFunding = true
			data.FundingURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path)
			break
		}
	}

	// Governance
	governancePaths := []string{"GOVERNANCE.md", ".github/GOVERNANCE.md", "docs/GOVERNANCE.md", "docs/governance.md"}
	for _, path := range governancePaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil); err == nil {
			data.HasGovernance = true
			data.GovernanceURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path)
			break
		}
	}

	// Changelog
	changelogPaths := []string{"CHANGELOG.md", "CHANGELOG", "HISTORY.md", "CHANGES.md", "docs/CHANGELOG.md"}
	for _, path := range changelogPaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil); err == nil {
			data.HasChangelog = true
			data.ChangelogURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path)
			break
		}
	}

	// Roadmap
	roadmapPaths := []string{"ROADMAP.md", "docs/ROADMAP.md", "docs/roadmap.md"}
	for _, path := range roadmapPaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil); err == nil {
			data.HasRoadmap = true
			data.RoadmapURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path)
			break
		}
	}

	// Review policy
	reviewPolicyPaths := []string{"REVIEW_POLICY.md", ".github/REVIEW_POLICY.md", "docs/REVIEW_POLICY.md", "docs/review-policy.md", ".github/PULL_REQUEST_TEMPLATE.md"}
	for _, path := range reviewPolicyPaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil); err == nil {
			data.HasReviewPolicy = true
			data.ReviewPolicyURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path)
			break
		}
	}

	// Dependency management policy
	dependencyPolicyPaths := []string{"DEPENDENCY_POLICY.md", ".github/DEPENDENCY_POLICY.md", "docs/DEPENDENCY_POLICY.md", "docs/dependency-management.md", "docs/dependencies.md"}
	for _, path := range dependencyPolicyPaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil); err == nil {
			data.HasDependencyManagementPolicy = true
			data.DependencyManagementPolicyURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path)
			break
		}
	}
}

// scanBranchProtection checks branch protection settings
func (s *GitHubScanner) scanBranchProtection(ctx context.Context, data *GitHubData) {
	protection, _, err := s.client.Repositories.GetBranchProtection(ctx, s.owner, s.repo, data.DefaultBranch)
	if err == nil {
		data.BranchProtectionEnabled = true
		if protection.RequiredPullRequestReviews != nil {
			data.CodeReviewRequired = protection.RequiredPullRequestReviews.RequiredApprovingReviewCount > 0
		}
	}
}

// scanReleases checks for releases and release automation
func (s *GitHubScanner) scanReleases(ctx context.Context, data *GitHubData) {
	releases, _, err := s.client.Repositories.ListReleases(ctx, s.owner, s.repo, &github.ListOptions{PerPage: 1})
	if err == nil && len(releases) > 0 {
		data.HasReleases = true
		data.LatestReleaseURL = releases[0].GetHTMLURL()
	}

	// Check for release workflows
	workflows, _, err := s.client.Actions.ListWorkflows(ctx, s.owner, s.repo, &github.ListOptions{PerPage: 100})
	if err == nil {
		for _, wf := range workflows.Workflows {
			name := strings.ToLower(wf.GetName())
			path := strings.ToLower(wf.GetPath())
			if strings.Contains(name, "release") || strings.Contains(path, "release") {
				data.HasAutomatedReleases = true
				break
			}
		}
	}
}

// scanContributors gets top contributors
func (s *GitHubScanner) scanContributors(ctx context.Context, data *GitHubData) {
	contributors, _, err := s.client.Repositories.ListContributors(ctx, s.owner, s.repo, &github.ListContributorsOptions{
		ListOptions: github.ListOptions{PerPage: 10},
	})
	if err != nil {
		return
	}

	for _, c := range contributors {
		contrib := Contributor{
			Login:         c.GetLogin(),
			Contributions: c.GetContributions(),
		}

		// Try to get user details
		if user, _, err := s.client.Users.Get(ctx, c.GetLogin()); err == nil {
			contrib.Name = user.GetName()
			contrib.Email = user.GetEmail()
		}

		data.TopContributors = append(data.TopContributors, contrib)
	}
}

// GetRepoURL returns the full repository URL
func (s *GitHubScanner) GetRepoURL() string {
	return fmt.Sprintf("https://github.com/%s/%s", s.owner, s.repo)
}

func parseRepoURL(repoURL string) (string, string, error) {
	if repoURL == "" {
		return detectFromGitRemote()
	}

	if strings.HasPrefix(repoURL, "git@github.com:") {
		parts := strings.TrimPrefix(repoURL, "git@github.com:")
		parts = strings.TrimSuffix(parts, ".git")
		split := strings.Split(parts, "/")
		if len(split) == 2 {
			return split[0], split[1], nil
		}
	}

	u, err := url.Parse(repoURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid URL: %w", err)
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid GitHub URL format")
	}

	repo := strings.TrimSuffix(parts[1], ".git")
	return parts[0], repo, nil
}

func detectFromGitRemote() (string, string, error) {
	cmd := exec.Command("git", "remote", "get-url", "origin")
	output, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to get git remote: %w", err)
	}

	remoteURL := strings.TrimSpace(string(output))
	if remoteURL == "" {
		return "", "", fmt.Errorf("no git remote found")
	}

	return parseRepoURL(remoteURL)
}

func (s *GitHubScanner) detectBugBounty() string {
	knownBugBounties := map[string]string{
		"google":    "https://bughunters.google.com/",
		"microsoft": "https://msrc.microsoft.com/bounty",
		"facebook":  "https://www.facebook.com/whitehat",
		"meta":      "https://www.facebook.com/whitehat",
		"github":    "https://bounty.github.com/",
	}

	lowerOwner := strings.ToLower(s.owner)
	if url, ok := knownBugBounties[lowerOwner]; ok {
		return url
	}

	return ""
}

// ScanWithoutAuth creates a scanner for public repository data only
func ScanWithoutAuth(repoURL string, verbose bool) (*GitHubScanner, error) {
	return NewGitHubScanner("", repoURL, verbose)
}
