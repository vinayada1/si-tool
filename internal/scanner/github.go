package scanner

import (
	"context"
	"fmt"
	"net/url"
	"os/exec"
	"regexp"
	"strings"

	"github.com/google/go-github/v57/github"
	"golang.org/x/oauth2"
)

// GitHubData contains information gathered from GitHub API
type GitHubData struct {
	// Basic repo info
	ProjectURL    string
	RepoName      string
	Homepage      string
	DefaultBranch string
	Owner         string
	Repo          string
	IsOrg         bool
	OrgURL        string

	// Status
	IsArchived bool

	// License
	License    string
	LicenseURL string

	// Community files
	HasSecurityPolicy             bool
	SecurityPolicyURL             string
	CodeOfConductURL              string
	ContributingURL               string
	HasFunding                    bool
	FundingURL                    string
	GovernanceURL                 string
	ChangelogURL                  string
	HasRoadmap                    bool
	RoadmapURL                    string
	ReviewPolicyURL               string
	DependencyManagementPolicyURL string
	SupportPolicyURL              string

	// Vulnerability reporting
	BugBountyURL string

	// Release info
	HasReleases          bool
	HasAutomatedReleases bool

	// Contributors/maintainers
	TopContributors []Contributor
	Maintainers     []MaintainerInfo

	// Security tools detected from workflow files
	CodeScanningTools []SecurityToolInfo
	DependencyTools   []string
	Attestations      []AttestationInfo

	// Organization sibling repositories
	OrgRepos []OrgRepoInfo

	// Security contacts/champions from SECURITY.md
	SecurityChampions []MaintainerInfo

	// Security assessments (threat models, audits)
	SelfAssessment   *AssessmentInfo
	ThirdPartyAudits []AssessmentInfo

	// Findings from sibling org repos (community, design-notes, etc.)
	SiblingGovernanceURL     string
	SiblingCodeOfConductURL  string
	SiblingReleaseProcessURL string
	SiblingThreatModelURL    string
	SiblingThreatModelFiles  []string // individual threat model file URLs

	// Package manifest data (distribution points, dependency detection)
	DistributionPoints []DistributionPointInfo
	HasDependencies    bool
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
	data.Homepage = repo.GetHomepage()
	data.DefaultBranch = repo.GetDefaultBranch()
	data.IsArchived = repo.GetArchived()

	if repo.License != nil {
		data.License = repo.License.GetSPDXID()
		data.LicenseURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/LICENSE", s.owner, s.repo, data.DefaultBranch)
	}

	// Check if owner is an org
	if org, _, err := s.client.Organizations.Get(ctx, s.owner); err == nil {
		data.IsOrg = true
		data.OrgURL = org.GetHTMLURL()

		// List sibling repos in the org
		s.scanOrgRepos(ctx, &data)

		// Scan interesting sibling repos for security-relevant files
		s.scanSiblingRepos(ctx, &data)
	}

	// Get community health metrics
	s.scanCommunityHealth(ctx, &data)

	// Check for additional files
	s.scanRepositoryFiles(ctx, &data)

	// Get release info
	s.scanReleases(ctx, &data)

	// Scan workflow file contents for security tools
	s.scanWorkflowContents(ctx, &data)

	// Get top contributors
	s.scanContributors(ctx, &data)

	// Scan for maintainer/admin files
	s.scanMaintainers(ctx, &data)

	// Scan SECURITY.md for security contacts
	s.scanSecurityContacts(ctx, &data)

	// Scan for security assessments (threat models, audits)
	s.scanSecurityAssessments(ctx, &data)

	// Detect bug bounty program
	data.BugBountyURL = s.detectBugBounty()

	// Scan package manifests for distribution points and dependency detection
	s.scanPackageManifests(ctx, &data)

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
			data.CodeOfConductURL = community.Files.CodeOfConduct.GetHTMLURL()
		}
		if community.Files.Contributing != nil {
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
			data.GovernanceURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path)
			break
		}
	}

	// Changelog
	changelogPaths := []string{"CHANGELOG.md", "CHANGELOG", "HISTORY.md", "CHANGES.md", "docs/CHANGELOG.md"}
	for _, path := range changelogPaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil); err == nil {
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
			data.ReviewPolicyURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path)
			break
		}
	}

	// Dependency management policy
	dependencyPolicyPaths := []string{"DEPENDENCY_POLICY.md", ".github/DEPENDENCY_POLICY.md", "docs/DEPENDENCY_POLICY.md", "docs/dependency-management.md", "docs/dependencies.md", "THIRD-PARTY-NOTICES.txt", "THIRD-PARTY-NOTICES.md", "NOTICE", "NOTICE.txt", "NOTICE.md"}
	for _, path := range dependencyPolicyPaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil); err == nil {
			data.DependencyManagementPolicyURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path)
			break
		}
	}

	// Support policy
	supportPaths := []string{"SUPPORT.md", ".github/SUPPORT.md", "docs/SUPPORT.md"}
	for _, path := range supportPaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil); err == nil {
			data.SupportPolicyURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path)
			break
		}
	}
}

// scanOrgRepos lists public repositories in the organization.
func (s *GitHubScanner) scanOrgRepos(ctx context.Context, data *GitHubData) {
	repos, _, err := s.client.Repositories.ListByOrg(ctx, s.owner, &github.RepositoryListByOrgOptions{
		Type:        "public",
		ListOptions: github.ListOptions{PerPage: 100},
	})
	if err != nil {
		return
	}

	for _, r := range repos {
		if r.GetArchived() || r.GetFork() {
			continue
		}
		name := r.GetName()
		// Skip the .github meta-repo
		if name == ".github" {
			continue
		}
		data.OrgRepos = append(data.OrgRepos, OrgRepoInfo{
			Name:        r.GetName(),
			URL:         r.GetHTMLURL(),
			Description: r.GetDescription(),
		})
	}
}

// scanSiblingRepos scans interesting sibling repos in the org for security-relevant files
// (threat models, governance, release process, code of conduct).
func (s *GitHubScanner) scanSiblingRepos(ctx context.Context, data *GitHubData) {
	// Patterns that indicate repos worth scanning
	interestingPatterns := map[string][]string{
		"community":    {"governance", "community"},
		"design":       {"architecture", "design", "threat"},
		"security":     {"security", "threat"},
		"architecture": {"architecture", "design", "threat"},
	}

	for _, orgRepo := range data.OrgRepos {
		if orgRepo.Name == s.repo {
			continue // skip the main repo
		}
		nameLower := strings.ToLower(orgRepo.Name)
		descLower := strings.ToLower(orgRepo.Description)

		isInteresting := false
		for keyword := range interestingPatterns {
			if strings.Contains(nameLower, keyword) || strings.Contains(descLower, keyword) {
				isInteresting = true
				break
			}
		}
		if !isInteresting {
			continue
		}

		if s.verbose {
			fmt.Printf("🔍 Scanning sibling repo %s/%s for security-relevant files\n", s.owner, orgRepo.Name)
		}

		// Get default branch for this repo
		siblingRepo, _, err := s.client.Repositories.Get(ctx, s.owner, orgRepo.Name)
		if err != nil {
			continue
		}
		defaultBranch := siblingRepo.GetDefaultBranch()

		// Scan for governance files
		if data.SiblingGovernanceURL == "" {
			govPaths := []string{"GOVERNANCE.md", "community-membership.md", "governance.md"}
			for _, p := range govPaths {
				if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, orgRepo.Name, p, nil); err == nil {
					data.SiblingGovernanceURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, orgRepo.Name, defaultBranch, p)
					break
				}
			}
		}

		// Scan for code of conduct
		if data.SiblingCodeOfConductURL == "" {
			cocPaths := []string{"CODE_OF_CONDUCT.md", "CODE-OF-CONDUCT.md", "code-of-conduct.md"}
			for _, p := range cocPaths {
				if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, orgRepo.Name, p, nil); err == nil {
					data.SiblingCodeOfConductURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, orgRepo.Name, defaultBranch, p)
					break
				}
			}
		}

		// Scan for release process docs — only in governance/community repos to avoid false positives
		if data.SiblingReleaseProcessURL == "" {
			if strings.Contains(nameLower, "community") || strings.Contains(nameLower, "governance") || strings.Contains(nameLower, "project") {
				relPaths := []string{"RELEASE.md", "RELEASE_PROCESS.md", "release-process.md", "docs/release-process.md", "releases.md"}
				for _, p := range relPaths {
					if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, orgRepo.Name, p, nil); err == nil {
						data.SiblingReleaseProcessURL = fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, orgRepo.Name, defaultBranch, p)
						break
					}
				}
			}
		}

		// Scan for threat models / architecture docs
		if data.SiblingThreatModelURL == "" {
			threatDirs := []string{"architecture", "threat-models", "security", "docs/threat-models", "docs/security"}
			for _, dir := range threatDirs {
				_, dirContents, _, err := s.client.Repositories.GetContents(ctx, s.owner, orgRepo.Name, dir, nil)
				if err != nil || len(dirContents) == 0 {
					continue
				}
				var threatFiles []string
				for _, entry := range dirContents {
					if entry.GetType() != "file" {
						continue
					}
					entryLower := strings.ToLower(entry.GetName())
					if strings.Contains(entryLower, "threat") && strings.Contains(entryLower, "model") {
						threatFiles = append(threatFiles, fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s/%s", s.owner, orgRepo.Name, defaultBranch, dir, entry.GetName()))
					}
				}
				if len(threatFiles) > 0 {
					data.SiblingThreatModelURL = fmt.Sprintf("https://github.com/%s/%s/tree/%s/%s", s.owner, orgRepo.Name, defaultBranch, dir)
					data.SiblingThreatModelFiles = threatFiles
					break
				}
			}
		}
	}
}

// scanReleases checks for releases and release automation
func (s *GitHubScanner) scanReleases(ctx context.Context, data *GitHubData) {
	releases, _, err := s.client.Repositories.ListReleases(ctx, s.owner, s.repo, &github.ListOptions{PerPage: 1})
	if err == nil && len(releases) > 0 {
		data.HasReleases = true
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
			Login: c.GetLogin(),
		}

		// Try to get user details
		if user, _, err := s.client.Users.Get(ctx, c.GetLogin()); err == nil {
			contrib.Name = user.GetName()
			contrib.Email = user.GetEmail()
		}

		data.TopContributors = append(data.TopContributors, contrib)
	}
}

// scanMaintainers checks for CODEOWNERS and MAINTAINERS files in the remote repo
// and parses them to extract maintainer information.
func (s *GitHubScanner) scanMaintainers(ctx context.Context, data *GitHubData) {
	// Try CODEOWNERS
	codeownersPaths := []string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"}
	for _, path := range codeownersPaths {
		fileContent, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil)
		if err != nil || fileContent == nil {
			continue
		}
		text, err := fileContent.GetContent()
		if err != nil {
			continue
		}
		users, teams := parseCodeownersContent(text)
		data.Maintainers = append(data.Maintainers, users...)
		// Resolve team members via API (requires read:org scope, fails gracefully)
		if len(teams) > 0 && data.IsOrg {
			data.Maintainers = append(data.Maintainers, s.resolveTeamMembers(ctx, teams)...)
		}
		break
	}

	// Try MAINTAINERS file
	maintainersPaths := []string{"MAINTAINERS.md", "MAINTAINERS", ".github/MAINTAINERS.md", "OWNERS.md"}
	for _, path := range maintainersPaths {
		fileContent, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil)
		if err != nil || fileContent == nil {
			continue
		}
		text, err := fileContent.GetContent()
		if err != nil {
			continue
		}
		data.Maintainers = append(data.Maintainers, parseMaintainersContent(text)...)
		break
	}

	// Deduplicate and filter out entries where GitHub username is the org name
	seen := make(map[string]bool)
	filtered := make([]MaintainerInfo, 0, len(data.Maintainers))
	for _, m := range data.Maintainers {
		if m.GitHub != "" && strings.EqualFold(m.GitHub, s.owner) {
			continue
		}
		key := strings.ToLower(m.GitHub)
		if key == "" {
			key = strings.ToLower(m.Name + "|" + m.Email)
		}
		if !seen[key] {
			seen[key] = true
			filtered = append(filtered, m)
		}
	}
	data.Maintainers = filtered
}

// IsBotAccount returns true if the username looks like a bot or CI account.
func IsBotAccount(username string) bool {
	lower := strings.ToLower(username)
	botPatterns := []string{
		"[bot]", "dependabot", "renovate", "github-actions",
		"ci-robot", "ci-bot", "prow", "mergify", "codecov",
		"stale", "greenkeeper", "snyk-bot", "allstar",
	}
	for _, p := range botPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// Common CI bot exact matches
	botExact := map[string]bool{
		"k8s-ci-robot": true, "openshift-ci-robot": true,
		"openshift-merge-robot": true, "istio-testing": true,
	}
	return botExact[lower]
}

// parseCodeownersContent parses CODEOWNERS file content for GitHub usernames and team references.
// Only processes global ownership lines (starting with *) to avoid noisy per-directory entries.
// Returns individual users and team slugs (org/team-name pairs) separately.
func parseCodeownersContent(content string) (users []MaintainerInfo, teams []string) {
	seenUsers := make(map[string]bool)
	seenTeams := make(map[string]bool)
	githubRefRegex := regexp.MustCompile(`@([\w-]+)(?:/([\w-]+))?`)

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Only process global ownership lines ("* @user") to avoid per-directory noise
		if !strings.HasPrefix(line, "*") {
			continue
		}
		matches := githubRefRegex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 2 && match[2] != "" {
				// Team reference: @org/team-slug
				slug := match[2]
				if !seenTeams[slug] {
					seenTeams[slug] = true
					teams = append(teams, slug)
				}
			} else {
				// Individual user
				username := match[1]
				if strings.EqualFold(username, "UNOWNED") || IsBotAccount(username) {
					continue
				}
				if !seenUsers[username] {
					seenUsers[username] = true
					users = append(users, MaintainerInfo{GitHub: username})
				}
			}
		}
	}
	return users, teams
}

// resolveTeamMembers queries the GitHub API to list members of org teams.
// Requires a token with read:org scope. Fails gracefully on permission errors.
// Only resolves the first team that returns results to keep the list focused (e.g. maintainers over on-call).
func (s *GitHubScanner) resolveTeamMembers(ctx context.Context, teamSlugs []string) []MaintainerInfo {
	var members []MaintainerInfo
	seen := make(map[string]bool)

	for _, slug := range teamSlugs {
		teamMembers, _, err := s.client.Teams.ListTeamMembersBySlug(ctx, s.owner, slug, nil)
		if err != nil {
			if s.verbose {
				fmt.Printf("  Could not resolve team %s/%s (may need read:org scope): %v\n", s.owner, slug, err)
			}
			continue
		}
		for _, m := range teamMembers {
			login := m.GetLogin()
			if login == "" || IsBotAccount(login) {
				continue
			}
			if !seen[strings.ToLower(login)] {
				seen[strings.ToLower(login)] = true
				name := m.GetName()
				if name == "" {
					name = login
				}
				members = append(members, MaintainerInfo{
					Name:   name,
					GitHub: login,
				})
			}
		}
		// If we got members from this team, use them and stop
		if len(members) > 0 {
			if s.verbose {
				fmt.Printf("  Resolved %d members from team %s/%s\n", len(members), s.owner, slug)
			}
			break
		}
	}
	return members
}

// parseMaintainersContent parses MAINTAINERS file content for names, emails, and GitHub usernames.
func parseMaintainersContent(content string) []MaintainerInfo {
	var maintainers []MaintainerInfo
	seen := make(map[string]bool)
	emailRegex := regexp.MustCompile(`[\w.+-]+@[\w.-]+\.\w+`)
	// Only match github.com/username URLs, not bare @username (which collides with emails)
	githubRegex := regexp.MustCompile(`github\.com/([\w-]+[\w])`)
	// Non-user GitHub URL paths to skip
	githubNonUserPaths := map[string]bool{
		"orgs": true, "apps": true, "issues": true, "pull": true,
		"blob": true, "tree": true, "settings": true, "search": true,
	}
	// Detect markdown table separator lines
	tableSepRegex := regexp.MustCompile(`^[\s|:-]+$`)

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Skip markdown table separators (|---|---|)
		if tableSepRegex.MatchString(line) {
			continue
		}
		// Skip lines that look like prose descriptions
		if strings.HasPrefix(line, "You can contact") || strings.HasPrefix(line, "Note ") {
			continue
		}

		var m MaintainerInfo

		// Extract GitHub username first (most reliable identifier)
		if gh := githubRegex.FindStringSubmatch(line); len(gh) > 1 {
			if !githubNonUserPaths[gh[1]] {
				m.GitHub = gh[1]
			}
		}

		if email := emailRegex.FindString(line); email != "" {
			m.Email = email
			idx := strings.Index(line, email)
			if idx > 0 {
				name := strings.TrimSpace(strings.TrimRight(line[:idx], "<("))
				name = cleanMaintainerName(name)
				if name != "" {
					m.Name = name
				}
			}
		}

		if m.GitHub == "" && m.Email == "" {
			continue
		}

		// Dedup by GitHub username or email
		key := m.GitHub
		if key == "" {
			key = m.Email
		}
		if seen[key] {
			continue
		}
		// Skip bot accounts
		if m.GitHub != "" && IsBotAccount(m.GitHub) {
			continue
		}
		seen[key] = true

		maintainers = append(maintainers, m)
	}
	return maintainers
}

// cleanMaintainerName removes markdown artifacts from a name string.
func cleanMaintainerName(name string) string {
	// Strip leading/trailing pipe characters (markdown tables)
	name = strings.Trim(name, "|")
	name = strings.TrimSpace(name)
	// Strip leading bullet markers
	name = strings.TrimLeft(name, "*-• ")
	name = strings.TrimSpace(name)
	// Strip backtick-wrapped prefixes like "`module`:" or "`tsdb`:"
	backtickPrefix := regexp.MustCompile("^`[^`]+`:\\s*")
	name = backtickPrefix.ReplaceAllString(name, "")
	// Remove markdown links: [text](url) -> text
	mdLink := regexp.MustCompile(`\[([^\]]+)\]\([^)]+\)`)
	name = mdLink.ReplaceAllString(name, "$1")
	// Remove parenthetical GitHub handles like "(mattklein123)" or "(@username)"
	parenHandle := regexp.MustCompile(`\s*\([@]?[\w-]+\)\s*`)
	name = parenHandle.ReplaceAllString(name, "")
	// Remove remaining markdown formatting
	name = strings.ReplaceAll(name, "**", "")
	name = strings.ReplaceAll(name, "__", "")
	name = strings.Trim(name, "|")
	name = strings.TrimSpace(name)
	// If the name still has pipe chars in it, it's probably a table row — discard
	if strings.Contains(name, "|") {
		return ""
	}
	return name
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

// scanSecurityContacts extracts security contact emails from SECURITY.md
func (s *GitHubScanner) scanSecurityContacts(ctx context.Context, data *GitHubData) {
	securityPaths := []string{"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"}
	emailRegex := regexp.MustCompile(`([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})`)

	for _, path := range securityPaths {
		fileContent, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil)
		if err != nil || fileContent == nil {
			continue
		}
		text, err := fileContent.GetContent()
		if err != nil {
			continue
		}

		seenEmails := make(map[string]bool)
		for _, line := range strings.Split(text, "\n") {
			lineLower := strings.ToLower(line)
			if strings.Contains(lineLower, "security") || strings.Contains(lineLower, "contact") ||
				strings.Contains(lineLower, "report") || strings.Contains(lineLower, "email") ||
				strings.Contains(lineLower, "disclose") {
				emails := emailRegex.FindAllString(line, -1)
				for _, email := range emails {
					if strings.Contains(email, "noreply") || strings.Contains(email, "bot@") ||
						strings.Contains(email, "github.com") || strings.Contains(email, "example.com") {
						continue
					}
					if !seenEmails[email] {
						data.SecurityChampions = append(data.SecurityChampions, MaintainerInfo{
							Email: email,
						})
						seenEmails[email] = true
					}
				}
			}
		}

		if len(data.SecurityChampions) > 0 {
			break
		}
	}
}

// scanSecurityAssessments looks for threat models and audit files in the remote repo.
func (s *GitHubScanner) scanSecurityAssessments(ctx context.Context, data *GitHubData) {
	// Look for self-assessment / threat model files
	selfAssessmentPaths := []string{
		"SECURITY_ASSESSMENT.md", "security-assessment.md", "docs/security-assessment.md",
		"SELF_ASSESSMENT.md", "self-assessment.md", "docs/self-assessment.md",
	}
	for _, path := range selfAssessmentPaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, path, nil); err == nil {
			data.SelfAssessment = &AssessmentInfo{
				Evidence: fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, path),
				Comment:  "Self-assessment document",
			}
			break
		}
	}

	// Look for threat model files in common directories
	if data.SelfAssessment == nil {
		threatModelDirs := []string{"docs/threat-models", "docs/threat-model", "security", "docs/security", "architecture"}
		for _, dir := range threatModelDirs {
			_, dirContents, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, dir, nil)
			if err != nil || len(dirContents) == 0 {
				continue
			}
			// Check if any file in this dir looks like a threat model
			for _, entry := range dirContents {
				nameLower := strings.ToLower(entry.GetName())
				if strings.Contains(nameLower, "threat") && strings.Contains(nameLower, "model") {
					data.SelfAssessment = &AssessmentInfo{
						Evidence: fmt.Sprintf("https://github.com/%s/%s/tree/%s/%s", s.owner, s.repo, data.DefaultBranch, dir),
						Comment:  "Threat model documentation",
					}
					break
				}
			}
			if data.SelfAssessment != nil {
				break
			}
		}
	}

	// Look for third-party audit files
	auditDirs := []string{"audits", "security/audits", "docs/audits", "audit-reports"}
	for _, dir := range auditDirs {
		_, dirContents, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, dir, nil)
		if err != nil || len(dirContents) == 0 {
			continue
		}
		for _, entry := range dirContents {
			name := entry.GetName()
			if strings.HasSuffix(name, ".pdf") || strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".html") {
				data.ThirdPartyAudits = append(data.ThirdPartyAudits, AssessmentInfo{
					Evidence: fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s/%s", s.owner, s.repo, data.DefaultBranch, dir, name),
					Comment:  "Third-party security audit",
				})
			}
		}
	}

	// Check for root-level audit files
	rootAuditFiles := []string{"AUDIT.md", "SECURITY_AUDIT.md", "audit.md"}
	for _, f := range rootAuditFiles {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, f, nil); err == nil {
			data.ThirdPartyAudits = append(data.ThirdPartyAudits, AssessmentInfo{
				Evidence: fmt.Sprintf("https://github.com/%s/%s/blob/%s/%s", s.owner, s.repo, data.DefaultBranch, f),
				Comment:  "Security audit report",
			})
			break
		}
	}
}

// scanPackageManifests fetches package manifest files via GitHub API to detect
// distribution points (purl URLs) and whether the project has third-party dependencies.
func (s *GitHubScanner) scanPackageManifests(ctx context.Context, data *GitHubData) {
	// package.json → npm
	if fileContent, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, "package.json", nil); err == nil && fileContent != nil {
		data.HasDependencies = true
		if text, err := fileContent.GetContent(); err == nil {
			nameRegex := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)
			if match := nameRegex.FindStringSubmatch(text); len(match) > 1 {
				data.DistributionPoints = append(data.DistributionPoints, DistributionPointInfo{
					Type: "npm",
					URL:  "pkg:npm/" + match[1],
				})
			}
		}
	}

	// go.mod → golang
	if fileContent, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, "go.mod", nil); err == nil && fileContent != nil {
		data.HasDependencies = true
		if text, err := fileContent.GetContent(); err == nil {
			for _, line := range strings.Split(text, "\n") {
				if strings.HasPrefix(line, "module ") {
					modName := strings.TrimSpace(strings.TrimPrefix(line, "module "))
					data.DistributionPoints = append(data.DistributionPoints, DistributionPointInfo{
						Type: "go",
						URL:  "pkg:golang/" + modName,
					})
					break
				}
			}
		}
	}

	// Cargo.toml → cargo
	if fileContent, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, "Cargo.toml", nil); err == nil && fileContent != nil {
		data.HasDependencies = true
		if text, err := fileContent.GetContent(); err == nil {
			nameRegex := regexp.MustCompile(`name\s*=\s*"([^"]+)"`)
			if match := nameRegex.FindStringSubmatch(text); len(match) > 1 {
				data.DistributionPoints = append(data.DistributionPoints, DistributionPointInfo{
					Type: "cargo",
					URL:  "pkg:cargo/" + match[1],
				})
			}
		}
	}

	// pyproject.toml → pypi
	if fileContent, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, "pyproject.toml", nil); err == nil && fileContent != nil {
		data.HasDependencies = true
		if text, err := fileContent.GetContent(); err == nil {
			nameRegex := regexp.MustCompile(`name\s*=\s*"([^"]+)"`)
			if match := nameRegex.FindStringSubmatch(text); len(match) > 1 {
				data.DistributionPoints = append(data.DistributionPoints, DistributionPointInfo{
					Type: "pypi",
					URL:  "pkg:pypi/" + match[1],
				})
			}
		}
	}

	// Check additional dependency indicators if not already found
	if !data.HasDependencies {
		depFiles := []string{"requirements.txt", "Pipfile", "Gemfile", "pom.xml", "build.gradle", "composer.json"}
		for _, f := range depFiles {
			if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, f, nil); err == nil {
				data.HasDependencies = true
				break
			}
		}
	}
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

// scanWorkflowContents fetches workflow file contents via GitHub API and detects
// security tools, dependency tools, and release workflows.
func (s *GitHubScanner) scanWorkflowContents(ctx context.Context, data *GitHubData) {
	// List .github/workflows directory
	_, dirContents, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, ".github/workflows", nil)
	if err != nil {
		if s.verbose {
			fmt.Printf("⚠️  Could not list workflows: %v\n", err)
		}
		return
	}

	toolPatterns := map[string]struct {
		name     string
		toolType string
	}{
		"codeql":            {"CodeQL", "SAST"},
		"snyk":              {"Snyk", "SCA"},
		"sonarcloud":        {"SonarCloud", "SAST"},
		"sonarqube":         {"SonarQube", "SAST"},
		"semgrep":           {"Semgrep", "SAST"},
		"trivy":             {"Trivy", "SCA"},
		"grype":             {"Grype", "SCA"},
		"gosec":             {"GoSec", "SAST"},
		"bandit":            {"Bandit", "SAST"},
		"safety":            {"Safety", "SCA"},
		"npm audit":         {"npm-audit", "SCA"},
		"yarn audit":        {"yarn-audit", "SCA"},
		"scorecard":         {"OpenSSF Scorecard", "other"},
		"checkov":           {"Checkov", "SAST"},
		"tfsec":             {"tfsec", "SAST"},
		"dependency-review": {"Dependency Review", "SCA"},
		"fuzz":              {"Fuzzing", "fuzzing"},
		"oss-fuzz":          {"OSS-Fuzz", "fuzzing"},
		"slsa":              {"SLSA", "other"},
		"sigstore":          {"Sigstore", "other"},
		"cosign":            {"Cosign", "other"},
	}

	versionPatterns := map[string]*regexp.Regexp{
		"CodeQL":            regexp.MustCompile(`codeql.*?#\s*v(\d+(?:\.\d+)*)|codeql.*?@v(\d+(?:\.\d+)*)`),
		"Trivy":             regexp.MustCompile(`trivy.*?#\s*v(\d+(?:\.\d+)*)|trivy.*?@v(\d+(?:\.\d+)*)`),
		"Snyk":              regexp.MustCompile(`snyk.*?#\s*v(\d+(?:\.\d+)*)|snyk.*?@v(\d+(?:\.\d+)*)`),
		"Semgrep":           regexp.MustCompile(`semgrep.*?#\s*v(\d+(?:\.\d+)*)|semgrep.*?@v(\d+(?:\.\d+)*)`),
		"GoSec":             regexp.MustCompile(`gosec.*?#\s*v(\d+(?:\.\d+)*)|gosec.*?@v(\d+(?:\.\d+)*)`),
		"OpenSSF Scorecard": regexp.MustCompile(`scorecard.*?#\s*v(\d+(?:\.\d+)*)|scorecard.*?@v(\d+(?:\.\d+)*)`),
	}

	seenTools := make(map[string]bool)

	attestationPatterns := map[string]struct {
		name         string
		predicateURI string
		comment      string
	}{
		"slsa-github-generator":                {"SLSA Provenance", "https://slsa.dev/provenance/v1", "SLSA provenance attestation"},
		"slsa-framework/slsa-github-generator": {"SLSA Provenance", "https://slsa.dev/provenance/v1", "SLSA provenance attestation"},
		"actions/attest-build-provenance":      {"Build Provenance", "https://slsa.dev/provenance/v1", "GitHub build provenance attestation"},
		"actions/attest-sbom":                  {"SBOM", "https://spdx.dev/Document", "Software Bill of Materials"},
		"anchore/sbom-action":                  {"SBOM", "https://spdx.dev/Document", "Anchore SBOM generation"},
		"aquasecurity/trivy-action":            {"SBOM", "https://cyclonedx.org/bom", "Trivy SBOM generation"},
		"sigstore/cosign-installer":            {"Sigstore", "https://cosign.sigstore.dev", "Sigstore signing"},
		"cosign sign":                          {"Sigstore Signature", "https://cosign.sigstore.dev", "Container image signing"},
		"syft":                                 {"SBOM", "https://spdx.dev/Document", "Syft SBOM generation"},
		"goreleaser":                           {"GoReleaser", "https://goreleaser.com", "GoReleaser with optional signing/SBOM"},
	}
	seenAttestations := make(map[string]bool)

	for _, entry := range dirContents {
		name := entry.GetName()
		if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
			continue
		}

		// Fetch file content
		fileContent, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, ".github/workflows/"+name, nil)
		if err != nil || fileContent == nil {
			continue
		}

		text, err := fileContent.GetContent()
		if err != nil {
			continue
		}

		textLower := strings.ToLower(text)
		fileNameLower := strings.ToLower(name)

		// Detect workflow trigger types
		isCI := strings.Contains(textLower, "pull_request") || strings.Contains(textLower, "push")
		isRelease := strings.Contains(fileNameLower, "release") || strings.Contains(textLower, "release:")
		isAdHoc := strings.Contains(textLower, "schedule") || strings.Contains(textLower, "cron") || strings.Contains(textLower, "workflow_dispatch")

		for pattern, info := range toolPatterns {
			if strings.Contains(textLower, pattern) && !seenTools[info.name] {
				tool := SecurityToolInfo{
					Name:      info.name,
					Type:      info.toolType,
					InAdHoc:   isAdHoc,
					InCI:      isCI,
					InRelease: isRelease,
				}

				// Try to extract version
				if vp, ok := versionPatterns[info.name]; ok {
					if match := vp.FindStringSubmatch(textLower); len(match) > 1 {
						for _, m := range match[1:] {
							if m != "" {
								tool.Version = m
								break
							}
						}
					}
				}

				// Detect rulesets for certain tools
				if info.name == "CodeQL" {
					if strings.Contains(textLower, "security-extended") {
						tool.Rulesets = append(tool.Rulesets, "security-extended")
					} else if strings.Contains(textLower, "security-and-quality") {
						tool.Rulesets = append(tool.Rulesets, "security-and-quality")
					} else {
						tool.Rulesets = append(tool.Rulesets, "default")
					}
				}
				if info.name == "Semgrep" {
					if strings.Contains(textLower, "p/default") || strings.Contains(textLower, "auto") {
						tool.Rulesets = append(tool.Rulesets, "default")
					}
					if strings.Contains(textLower, "p/security-audit") {
						tool.Rulesets = append(tool.Rulesets, "security-audit")
					}
					if strings.Contains(textLower, "p/owasp") {
						tool.Rulesets = append(tool.Rulesets, "owasp")
					}
				}

				data.CodeScanningTools = append(data.CodeScanningTools, tool)
				seenTools[info.name] = true
			}
		}

		// Detect attestations — only in release/build/publish/deploy workflows
		nameLower := strings.ToLower(name)
		isReleaseWorkflow := strings.Contains(nameLower, "release") || strings.Contains(nameLower, "publish") ||
			strings.Contains(nameLower, "build") || strings.Contains(nameLower, "deploy") ||
			strings.Contains(nameLower, "ci") || strings.Contains(nameLower, "cd")
		if isReleaseWorkflow {
			for pattern, info := range attestationPatterns {
				if strings.Contains(textLower, strings.ToLower(pattern)) && !seenAttestations[info.name] {
					data.Attestations = append(data.Attestations, AttestationInfo{
						Name:         info.name,
						PredicateURI: info.predicateURI,
						Location:     ".github/workflows/" + name,
						Comment:      info.comment,
					})
					seenAttestations[info.name] = true
				}
			}
		}
	}

	// Detect dependency management tools (Dependabot, Renovate)
	dependabotPaths := []string{".github/dependabot.yml", ".github/dependabot.yaml"}
	for _, p := range dependabotPaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, p, nil); err == nil {
			data.DependencyTools = append(data.DependencyTools, "Dependabot")
			break
		}
	}

	renovatePaths := []string{"renovate.json", "renovate.json5", ".renovaterc", ".renovaterc.json", ".github/renovate.json"}
	for _, p := range renovatePaths {
		if _, _, _, err := s.client.Repositories.GetContents(ctx, s.owner, s.repo, p, nil); err == nil {
			data.DependencyTools = append(data.DependencyTools, "Renovate")
			break
		}
	}
}
