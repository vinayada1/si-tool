// Package generator provides functionality to build and write security insights
package generator

import (
	"fmt"
	"strings"
	"time"

	"github.com/vinayada1/si-tool/internal/scanner"
	"github.com/vinayada1/si-tool/pkg/model"
)

// Builder constructs SecurityInsights from scanned data
type Builder struct {
	verbose bool
}

// NewBuilder creates a new Builder instance
func NewBuilder(verbose bool) *Builder {
	return &Builder{verbose: verbose}
}

// BuildInsights creates a full SecurityInsights struct from GitHub API data
func (b *Builder) BuildInsights(remote scanner.GitHubData) model.SecurityInsights {
	now := time.Now().Format("2006-01-02")

	insights := model.SecurityInsights{
		Header: model.Header{
			SchemaVersion: "2.0.0",
			LastUpdated:   now,
			LastReviewed:  now,
			URL:           b.buildSIFileURL(remote),
		},
		Project:    b.buildProject(remote),
		Repository: b.buildRepository(remote),
	}

	return insights
}

func (b *Builder) buildSIFileURL(remote scanner.GitHubData) string {
	if remote.ProjectURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/blob/%s/security-insights.yml", remote.ProjectURL, remote.DefaultBranch)
}

func (b *Builder) buildProject(remote scanner.GitHubData) *model.Project {
	project := &model.Project{
		Name:     remote.RepoName,
		Homepage: remote.Homepage,
	}

	// Funding
	if remote.HasFunding {
		project.Funding = remote.FundingURL
	}

	// Roadmap
	if remote.HasRoadmap {
		project.Roadmap = remote.RoadmapURL
	}

	// Steward (if org)
	if remote.IsOrg && remote.OrgURL != "" {
		project.Steward = &model.Steward{
			URI:     remote.OrgURL,
			Comment: fmt.Sprintf("Organization: %s", remote.Owner),
		}
	}

	// Administrators from maintainers
	if len(remote.Maintainers) > 0 {
		for i, m := range remote.Maintainers {
			person := model.Person{
				Name:    m.Name,
				Email:   m.Email,
				Primary: i == 0,
			}
			if m.GitHub != "" {
				person.Social = fmt.Sprintf("https://github.com/%s", m.GitHub)
			}
			project.Administrators = append(project.Administrators, person)
		}
	}

	// Documentation
	project.Documentation = b.buildProjectDocumentation(remote)

	// Repositories from org (cap at 10 to keep output manageable)
	const maxRepos = 10
	if len(remote.OrgRepos) > 0 {
		for i, r := range remote.OrgRepos {
			if i >= maxRepos {
				break
			}
			project.Repositories = append(project.Repositories, model.RepositoryRef{
				Name:    r.Name,
				URL:     r.URL,
				Comment: r.Description,
			})
		}
	}

	// Vulnerability reporting
	project.VulnerabilityReporting = b.buildVulnerabilityReporting(remote)

	return project
}

func (b *Builder) buildProjectDocumentation(remote scanner.GitHubData) *model.ProjectDocumentation {
	docs := &model.ProjectDocumentation{}
	hasContent := false

	// Detailed guide from homepage
	if remote.Homepage != "" {
		docs.DetailedGuide = remote.Homepage
		hasContent = true
	}

	// Code of conduct (main repo > sibling repo)
	if remote.CodeOfConductURL != "" {
		docs.CodeOfConduct = remote.CodeOfConductURL
		hasContent = true
	} else if remote.SiblingCodeOfConductURL != "" {
		docs.CodeOfConduct = remote.SiblingCodeOfConductURL
		hasContent = true
	}

	// Release process (from sibling repos like community)
	if remote.SiblingReleaseProcessURL != "" {
		docs.ReleaseProcess = remote.SiblingReleaseProcessURL
		hasContent = true
	}

	// Support policy
	if remote.SupportPolicyURL != "" {
		docs.SupportPolicy = remote.SupportPolicyURL
		hasContent = true
	}

	if !hasContent {
		return nil
	}

	return docs
}

func (b *Builder) buildVulnerabilityReporting(remote scanner.GitHubData) *model.VulnerabilityReporting {
	vr := &model.VulnerabilityReporting{
		ReportsAccepted: remote.HasSecurityPolicy,
	}

	// Bug bounty
	if remote.BugBountyURL != "" {
		vr.BugBountyAvailable = true
		vr.BugBountyProgram = remote.BugBountyURL
	}

	// Policy URL
	if remote.SecurityPolicyURL != "" {
		vr.Policy = remote.SecurityPolicyURL
	}

	// Only return if we have meaningful data
	if !vr.ReportsAccepted && !vr.BugBountyAvailable && vr.Policy == "" {
		return nil
	}

	return vr
}

func (b *Builder) buildRepository(remote scanner.GitHubData) *model.Repository {
	repo := &model.Repository{
		URL:                           remote.ProjectURL,
		Status:                        b.determineStatus(remote),
		AcceptsChangeRequest:          !remote.IsArchived,
		AcceptsAutomatedChangeRequest: false,
		NoThirdPartyPackages:          !remote.HasDependencies,
	}

	// Core team: prefer maintainers, fall back to top contributors
	// Cap at 5 to avoid noisy output from large CODEOWNERS files
	const maxCoreTeam = 5
	if len(remote.Maintainers) > 0 {
		for i, m := range remote.Maintainers {
			if i >= maxCoreTeam {
				break
			}
			person := model.Person{
				Name:    m.Name,
				Email:   m.Email,
				Primary: i == 0,
			}
			if m.GitHub != "" {
				person.Social = fmt.Sprintf("https://github.com/%s", m.GitHub)
			}
			repo.CoreTeam = append(repo.CoreTeam, person)
		}
	} else if len(remote.TopContributors) > 0 {
		// Use top contributors as fallback, skip bots
		count := 0
		for _, c := range remote.TopContributors {
			if count >= maxCoreTeam {
				break
			}
			if strings.Contains(c.Login, "[bot]") || scanner.IsBotAccount(c.Login) {
				continue
			}
			person := model.Person{
				Name:    c.Name,
				Email:   c.Email,
				Primary: count == 0,
			}
			if c.Login != "" {
				person.Social = fmt.Sprintf("https://github.com/%s", c.Login)
			}
			repo.CoreTeam = append(repo.CoreTeam, person)
			count++
		}
	}

	// Documentation
	repo.Documentation = b.buildRepositoryDocumentation(remote)

	// License
	repo.License = b.buildLicense(remote)

	// Release
	repo.Release = b.buildRelease(remote)

	// Security
	repo.Security = b.buildSecurity(remote)

	return repo
}

func (b *Builder) determineStatus(remote scanner.GitHubData) string {
	if remote.IsArchived {
		return "inactive"
	}
	return "active"
}

func (b *Builder) buildRepositoryDocumentation(remote scanner.GitHubData) *model.RepositoryDocumentation {
	docs := &model.RepositoryDocumentation{}
	hasContent := false

	// Contributing guide
	if remote.ContributingURL != "" {
		docs.ContributingGuide = remote.ContributingURL
		hasContent = true
	}

	// Security policy
	if remote.SecurityPolicyURL != "" {
		docs.SecurityPolicy = remote.SecurityPolicyURL
		hasContent = true
	}

	// Governance (main repo > sibling repo)
	if remote.GovernanceURL != "" {
		docs.Governance = remote.GovernanceURL
		hasContent = true
	} else if remote.SiblingGovernanceURL != "" {
		docs.Governance = remote.SiblingGovernanceURL
		hasContent = true
	}

	// Review policy
	if remote.ReviewPolicyURL != "" {
		docs.ReviewPolicy = remote.ReviewPolicyURL
		hasContent = true
	}

	// Dependency management policy
	if remote.DependencyManagementPolicyURL != "" {
		docs.DependencyManagementPolicy = remote.DependencyManagementPolicyURL
		hasContent = true
	}

	if !hasContent {
		return nil
	}

	return docs
}

func (b *Builder) buildLicense(remote scanner.GitHubData) *model.License {
	if remote.License == "" {
		return nil
	}

	return &model.License{
		Expression: remote.License,
		URL:        remote.LicenseURL,
	}
}

func (b *Builder) buildRelease(remote scanner.GitHubData) *model.Release {
	release := &model.Release{}
	hasContent := false

	// Changelog
	if remote.ChangelogURL != "" {
		release.Changelog = remote.ChangelogURL
		hasContent = true
	}

	// Automated pipeline
	if remote.HasAutomatedReleases {
		release.AutomatedPipeline = true
		hasContent = true
	}

	// Attestations
	for _, att := range remote.Attestations {
		release.Attestations = append(release.Attestations, model.Attestation{
			Name:         att.Name,
			PredicateURI: att.PredicateURI,
			Location:     att.Location,
			Comment:      att.Comment,
		})
		hasContent = true
	}

	// Distribution points from package manifests
	for _, dp := range remote.DistributionPoints {
		release.DistributionPoints = append(release.DistributionPoints, model.DistributionPoint{
			URI:     dp.URL,
			Comment: fmt.Sprintf("%s package", dp.Type),
		})
		hasContent = true
	}

	// GitHub releases as distribution point
	if remote.HasReleases {
		release.DistributionPoints = append(release.DistributionPoints, model.DistributionPoint{
			URI:     fmt.Sprintf("%s/releases", remote.ProjectURL),
			Comment: "GitHub Releases",
		})
		hasContent = true
	}

	if !hasContent {
		return nil
	}

	return release
}

func (b *Builder) buildSecurity(remote scanner.GitHubData) *model.Security {
	security := &model.Security{}
	hasContent := false

	// Assessments: prefer remote, fall back to sibling repo
	selfAssessment := remote.SelfAssessment
	if selfAssessment == nil && remote.SiblingThreatModelURL != "" {
		comment := "Threat model documentation"
		if len(remote.SiblingThreatModelFiles) > 0 {
			comment = strings.Join(remote.SiblingThreatModelFiles, "\n")
		}
		selfAssessment = &scanner.AssessmentInfo{
			Evidence: remote.SiblingThreatModelURL,
			Comment:  comment,
		}
	}
	thirdPartyAudits := remote.ThirdPartyAudits

	// Always populate assessments section if we have self-assessment
	if selfAssessment != nil {
		security.Assessments = &model.Assessments{}
		comment := selfAssessment.Comment
		if comment == "" {
			comment = "Self assessment has not yet been completed."
		}
		security.Assessments.Self = &model.Assessment{
			Evidence: selfAssessment.Evidence,
			Date:     selfAssessment.Date,
			Comment:  comment,
		}

		if len(thirdPartyAudits) > 0 {
			for _, audit := range thirdPartyAudits {
				security.Assessments.ThirdParty = append(security.Assessments.ThirdParty, model.Assessment{
					Evidence: audit.Evidence,
					Date:     audit.Date,
					Comment:  audit.Comment,
				})
			}
		} else {
			// Default entry when no third-party assessments found
			security.Assessments.ThirdParty = append(security.Assessments.ThirdParty, model.Assessment{
				Comment: "No third-party assessment performed",
			})
		}
		hasContent = true
	} else if len(thirdPartyAudits) > 0 {
		security.Assessments = &model.Assessments{
			Self: &model.Assessment{
				Comment: "Self assessment has not yet been completed.",
			},
		}
		for _, audit := range thirdPartyAudits {
			security.Assessments.ThirdParty = append(security.Assessments.ThirdParty, model.Assessment{
				Evidence: audit.Evidence,
				Date:     audit.Date,
				Comment:  audit.Comment,
			})
		}
		hasContent = true
	} else {
		// Always provide assessments section with default self-assessment
		security.Assessments = &model.Assessments{
			Self: &model.Assessment{
				Comment: "Self assessment has not yet been completed.",
			},
		}
		hasContent = true
	}

	// Security tools
	for _, tool := range remote.CodeScanningTools {
		secTool := model.SecurityTool{
			Name:    tool.Name,
			Type:    tool.Type,
			Version: tool.Version,
			Comment: tool.Comment,
			Results: &model.ToolResults{},
			Integration: &model.ToolIntegration{
				AdHoc:   tool.InAdHoc,
				CI:      tool.InCI,
				Release: tool.InRelease,
			},
		}
		if len(tool.Rulesets) > 0 {
			secTool.Rulesets = tool.Rulesets
		} else {
			secTool.Rulesets = []string{"default"}
		}
		security.Tools = append(security.Tools, secTool)
		hasContent = true
	}

	// Dependency tools
	for _, tool := range remote.DependencyTools {
		security.Tools = append(security.Tools, model.SecurityTool{
			Name:     tool,
			Type:     "SCA",
			Rulesets: []string{"default"},
			Results:  &model.ToolResults{},
			Integration: &model.ToolIntegration{
				CI: true,
			},
		})
		hasContent = true
	}

	// Security champions
	for i, champion := range remote.SecurityChampions {
		person := model.Person{
			Name:    champion.Name,
			Email:   champion.Email,
			Primary: i == 0,
		}
		if champion.GitHub != "" {
			person.Social = fmt.Sprintf("https://github.com/%s", champion.GitHub)
		}
		security.Champions = append(security.Champions, person)
		hasContent = true
	}

	if !hasContent {
		return nil
	}

	return security
}
