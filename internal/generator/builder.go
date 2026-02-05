// Package generator provides functionality to build and write security insights
package generator

import (
	"fmt"
	"time"

	"github.com/si-generator/internal/scanner"
	"github.com/si-generator/pkg/model"
)

// Builder constructs SecurityInsights from scanned data
type Builder struct {
	verbose bool
}

// NewBuilder creates a new Builder instance
func NewBuilder(verbose bool) *Builder {
	return &Builder{verbose: verbose}
}

// BuildInsights creates a full SecurityInsights struct from local and GitHub data
func (b *Builder) BuildInsights(local scanner.LocalData, remote scanner.GitHubData) model.SecurityInsights {
	now := time.Now().Format("2006-01-02")

	insights := model.SecurityInsights{
		Header: model.Header{
			SchemaVersion: "2.0.0",
			LastUpdated:   now,
			LastReviewed:  now,
			URL:           b.buildSIFileURL(remote),
		},
		Project:    b.buildProject(local, remote),
		Repository: b.buildRepository(local, remote),
	}

	return insights
}

// BuildFromLocalOnly creates SecurityInsights from local data only
func (b *Builder) BuildFromLocalOnly(local scanner.LocalData, projectURL string) model.SecurityInsights {
	now := time.Now().Format("2006-01-02")

	// Build the SI file URL if we have a project URL
	var siFileURL string
	if projectURL != "" {
		// Default to main branch if we don't know the actual default branch
		siFileURL = fmt.Sprintf("%s/blob/main/security-insights.yml", projectURL)
	}

	insights := model.SecurityInsights{
		Header: model.Header{
			SchemaVersion: "2.0.0",
			LastUpdated:   now,
			LastReviewed:  now,
			URL:           siFileURL,
		},
		Repository: b.buildRepositoryFromLocal(local, projectURL),
	}

	return insights
}

func (b *Builder) buildSIFileURL(remote scanner.GitHubData) string {
	if remote.ProjectURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/blob/%s/security-insights.yml", remote.ProjectURL, remote.DefaultBranch)
}

func (b *Builder) buildProject(local scanner.LocalData, remote scanner.GitHubData) *model.Project {
	project := &model.Project{
		Name:     remote.RepoName,
		Homepage: remote.Homepage,
	}

	// Funding
	if remote.HasFunding || local.FundingPath != "" {
		if remote.FundingURL != "" {
			project.Funding = remote.FundingURL
		} else if local.FundingPath != "" {
			project.Funding = local.FundingPath
		}
	}

	// Roadmap
	if remote.HasRoadmap || local.RoadmapPath != "" {
		if remote.RoadmapURL != "" {
			project.Roadmap = remote.RoadmapURL
		} else if local.RoadmapPath != "" {
			project.Roadmap = local.RoadmapPath
		}
	}

	// Steward (if org)
	if remote.IsOrg && remote.OrgURL != "" {
		project.Steward = &model.Steward{
			URI: remote.OrgURL,
		}
	}

	// Administrators from maintainers
	if len(local.Maintainers) > 0 {
		for i, m := range local.Maintainers {
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
	project.Documentation = b.buildProjectDocumentation(local, remote)

	// Vulnerability reporting
	project.VulnerabilityReporting = b.buildVulnerabilityReporting(local, remote)

	return project
}

func (b *Builder) buildProjectDocumentation(local scanner.LocalData, remote scanner.GitHubData) *model.ProjectDocumentation {
	docs := &model.ProjectDocumentation{}
	hasContent := false

	// Code of conduct
	if remote.CodeOfConductURL != "" {
		docs.CodeOfConduct = remote.CodeOfConductURL
		hasContent = true
	} else if local.CodeOfConductPath != "" {
		docs.CodeOfConduct = local.CodeOfConductPath
		hasContent = true
	}

	if !hasContent {
		return nil
	}

	return docs
}

func (b *Builder) buildVulnerabilityReporting(local scanner.LocalData, remote scanner.GitHubData) *model.VulnerabilityReporting {
	vr := &model.VulnerabilityReporting{
		ReportsAccepted: remote.HasSecurityPolicy || local.SecurityPolicyPath != "",
	}

	// Bug bounty
	if remote.BugBountyURL != "" {
		vr.BugBountyAvailable = true
		vr.BugBountyProgram = remote.BugBountyURL
	}

	// Policy URL
	if remote.SecurityPolicyURL != "" {
		vr.Policy = remote.SecurityPolicyURL
	} else if local.SecurityPolicyPath != "" {
		vr.Policy = local.SecurityPolicyPath
	}

	// Contact
	if remote.ContactEmail != "" {
		vr.Contact = &model.Contact{
			Email:   remote.ContactEmail,
			Primary: true,
		}
	}

	// Only return if we have meaningful data
	if !vr.ReportsAccepted && !vr.BugBountyAvailable && vr.Policy == "" {
		return nil
	}

	return vr
}

func (b *Builder) buildRepository(local scanner.LocalData, remote scanner.GitHubData) *model.Repository {
	repo := &model.Repository{
		URL:                           remote.ProjectURL,
		Status:                        b.determineStatus(remote),
		AcceptsChangeRequest:          !remote.IsArchived,
		AcceptsAutomatedChangeRequest: len(local.DependencyTools) > 0,
		NoThirdPartyPackages:          !local.HasDependencies,
	}

	// Core team from maintainers
	if len(local.Maintainers) > 0 {
		for i, m := range local.Maintainers {
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
		// Use top contributors as fallback
		for i, c := range remote.TopContributors {
			if i >= 5 { // Limit to top 5
				break
			}
			person := model.Person{
				Name:    c.Name,
				Email:   c.Email,
				Primary: i == 0,
			}
			if c.Login != "" {
				person.Social = fmt.Sprintf("https://github.com/%s", c.Login)
			}
			repo.CoreTeam = append(repo.CoreTeam, person)
		}
	}

	// Documentation
	repo.Documentation = b.buildRepositoryDocumentation(local, remote)

	// License
	repo.License = b.buildLicense(local, remote)

	// Release
	repo.Release = b.buildRelease(local, remote)

	// Security
	repo.Security = b.buildSecurity(local, remote)

	return repo
}

func (b *Builder) buildRepositoryFromLocal(local scanner.LocalData, projectURL string) *model.Repository {
	repo := &model.Repository{
		URL:                           projectURL,
		Status:                        "active",
		AcceptsChangeRequest:          true,
		AcceptsAutomatedChangeRequest: len(local.DependencyTools) > 0,
		NoThirdPartyPackages:          !local.HasDependencies,
	}

	// Core team from maintainers
	if len(local.Maintainers) > 0 {
		for i, m := range local.Maintainers {
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
	}

	// Documentation
	repo.Documentation = &model.RepositoryDocumentation{
		ContributingGuide: local.ContributingPath,
		SecurityPolicy:    local.SecurityPolicyPath,
		Governance:        local.GovernancePath,
	}

	// License
	if local.LicenseType != "" {
		repo.License = &model.License{
			URL:        local.LicensePath,
			Expression: local.LicenseType,
		}
	}

	// Release
	if local.ChangelogPath != "" || local.HasReleaseWorkflow {
		repo.Release = &model.Release{
			Changelog:         local.ChangelogPath,
			AutomatedPipeline: local.HasReleaseWorkflow,
		}
	}

	// Security
	repo.Security = b.buildSecurityFromLocal(local)

	// Distribution points and attestations
	if repo.Release == nil && (len(local.DistributionPoints) > 0 || len(local.Attestations) > 0) {
		repo.Release = &model.Release{}
	}
	if repo.Release != nil {
		for _, dp := range local.DistributionPoints {
			repo.Release.DistributionPoints = append(repo.Release.DistributionPoints, model.DistributionPoint{
				URI:     dp.URL,
				Comment: fmt.Sprintf("%s package", dp.Type),
			})
		}
		// Attestations
		for _, att := range local.Attestations {
			repo.Release.Attestations = append(repo.Release.Attestations, model.Attestation{
				Name:         att.Name,
				PredicateURI: att.PredicateURI,
				Location:     att.Location,
				Comment:      att.Comment,
			})
		}
	}

	return repo
}

func (b *Builder) determineStatus(remote scanner.GitHubData) string {
	if remote.IsArchived {
		return "inactive"
	}
	return "active"
}

func (b *Builder) buildRepositoryDocumentation(local scanner.LocalData, remote scanner.GitHubData) *model.RepositoryDocumentation {
	docs := &model.RepositoryDocumentation{}
	hasContent := false

	// Contributing guide
	if remote.ContributingURL != "" {
		docs.ContributingGuide = remote.ContributingURL
		hasContent = true
	} else if local.ContributingPath != "" {
		docs.ContributingGuide = local.ContributingPath
		hasContent = true
	}

	// Security policy
	if remote.SecurityPolicyURL != "" {
		docs.SecurityPolicy = remote.SecurityPolicyURL
		hasContent = true
	} else if local.SecurityPolicyPath != "" {
		docs.SecurityPolicy = local.SecurityPolicyPath
		hasContent = true
	}

	// Governance
	if remote.GovernanceURL != "" {
		docs.Governance = remote.GovernanceURL
		hasContent = true
	} else if local.GovernancePath != "" {
		docs.Governance = local.GovernancePath
		hasContent = true
	}

	// Review policy
	if remote.ReviewPolicyURL != "" {
		docs.ReviewPolicy = remote.ReviewPolicyURL
		hasContent = true
	} else if local.ReviewPolicyPath != "" {
		docs.ReviewPolicy = local.ReviewPolicyPath
		hasContent = true
	}

	// Dependency management policy
	if remote.DependencyManagementPolicyURL != "" {
		docs.DependencyManagementPolicy = remote.DependencyManagementPolicyURL
		hasContent = true
	} else if local.DependencyManagementPolicyPath != "" {
		docs.DependencyManagementPolicy = local.DependencyManagementPolicyPath
		hasContent = true
	}

	if !hasContent {
		return nil
	}

	return docs
}

func (b *Builder) buildLicense(local scanner.LocalData, remote scanner.GitHubData) *model.License {
	if remote.License == "" && local.LicenseType == "" {
		return nil
	}

	license := &model.License{}

	if remote.License != "" {
		license.Expression = remote.License
		license.URL = remote.LicenseURL
	} else {
		license.Expression = local.LicenseType
		license.URL = local.LicensePath
	}

	return license
}

func (b *Builder) buildRelease(local scanner.LocalData, remote scanner.GitHubData) *model.Release {
	release := &model.Release{}
	hasContent := false

	// Changelog
	if remote.ChangelogURL != "" {
		release.Changelog = remote.ChangelogURL
		hasContent = true
	} else if local.ChangelogPath != "" {
		release.Changelog = local.ChangelogPath
		hasContent = true
	}

	// Automated pipeline
	if remote.HasAutomatedReleases || local.HasReleaseWorkflow {
		release.AutomatedPipeline = true
		hasContent = true
	}

	// Attestations (SLSA, SBOM, Sigstore, etc.)
	for _, att := range local.Attestations {
		release.Attestations = append(release.Attestations, model.Attestation{
			Name:         att.Name,
			PredicateURI: att.PredicateURI,
			Location:     att.Location,
			Comment:      att.Comment,
		})
		hasContent = true
	}

	// Note: When scanning a remote repo via API, we skip local.DistributionPoints
	// because they would be from the wrong (local) repository.
	// Distribution points detection for remote repos would require API access
	// to their package.json, go.mod, etc.

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

func (b *Builder) buildSecurity(local scanner.LocalData, remote scanner.GitHubData) *model.Security {
	security := &model.Security{}
	hasContent := false

	// Security practices from GitHub API
	if remote.MFAEnforced || remote.BranchProtectionEnabled || remote.CodeReviewRequired {
		security.Practices = &model.SecurityPractices{
			MFAEnforced:        remote.MFAEnforced,
			BranchProtection:   remote.BranchProtectionEnabled,
			CodeReviewRequired: remote.CodeReviewRequired,
		}
		hasContent = true
	}

	// Assessments from local scan (these are from the cloned/local repo)
	if local.SelfAssessment != nil || len(local.ThirdPartyAudits) > 0 {
		security.Assessments = &model.Assessments{}

		if local.SelfAssessment != nil {
			security.Assessments.Self = &model.Assessment{
				Evidence: local.SelfAssessment.Evidence,
				Date:     local.SelfAssessment.Date,
				Comment:  local.SelfAssessment.Comment,
			}
		}

		for _, audit := range local.ThirdPartyAudits {
			security.Assessments.ThirdParty = append(security.Assessments.ThirdParty, model.Assessment{
				Evidence: audit.Evidence,
				Date:     audit.Date,
				Comment:  audit.Comment,
			})
		}
		hasContent = true
	}

	// Security tools from local scan
	for _, tool := range local.CodeScanningTools {
		secTool := model.SecurityTool{
			Name:     tool.Name,
			Type:     tool.Type,
			Version:  tool.Version,
			Rulesets: tool.Rulesets,
			Comment:  tool.Comment,
		}
		if tool.InAdHoc || tool.InCI || tool.InRelease {
			secTool.Integration = &model.ToolIntegration{
				AdHoc:   tool.InAdHoc,
				CI:      tool.InCI,
				Release: tool.InRelease,
			}
		}
		security.Tools = append(security.Tools, secTool)
		hasContent = true
	}

	// Security champions from local scan
	for i, champion := range local.SecurityChampions {
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

func (b *Builder) buildSecurityFromLocal(local scanner.LocalData) *model.Security {
	security := &model.Security{}
	hasContent := false

	// Assessments
	if local.SelfAssessment != nil || len(local.ThirdPartyAudits) > 0 {
		security.Assessments = &model.Assessments{}

		if local.SelfAssessment != nil {
			security.Assessments.Self = &model.Assessment{
				Evidence: local.SelfAssessment.Evidence,
				Date:     local.SelfAssessment.Date,
				Comment:  local.SelfAssessment.Comment,
			}
		}

		for _, audit := range local.ThirdPartyAudits {
			security.Assessments.ThirdParty = append(security.Assessments.ThirdParty, model.Assessment{
				Evidence: audit.Evidence,
				Date:     audit.Date,
				Comment:  audit.Comment,
			})
		}
		hasContent = true
	} else if local.AuditHistory != "" {
		// Fallback to old simple detection
		security.Assessments = &model.Assessments{
			Self: &model.Assessment{
				Evidence: local.AuditHistory,
			},
		}
		hasContent = true
	}

	// Security tools
	for _, tool := range local.CodeScanningTools {
		secTool := model.SecurityTool{
			Name:     tool.Name,
			Type:     tool.Type,
			Version:  tool.Version,
			Rulesets: tool.Rulesets,
			Comment:  tool.Comment,
		}

		if tool.InAdHoc || tool.InCI || tool.InRelease {
			secTool.Integration = &model.ToolIntegration{
				AdHoc:   tool.InAdHoc,
				CI:      tool.InCI,
				Release: tool.InRelease,
			}
		}

		security.Tools = append(security.Tools, secTool)
		hasContent = true
	}

	// Dependency tools
	for _, tool := range local.DependencyTools {
		security.Tools = append(security.Tools, model.SecurityTool{
			Name: tool,
			Type: "SCA",
			Integration: &model.ToolIntegration{
				CI: true,
			},
		})
		hasContent = true
	}

	// Fuzzing
	if local.FuzzingEnabled {
		security.Tools = append(security.Tools, model.SecurityTool{
			Name: "Fuzzing",
			Type: "Fuzzing",
		})
		hasContent = true
	}

	// Security champions
	for i, champion := range local.SecurityChampions {
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
