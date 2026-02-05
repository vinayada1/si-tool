// Package model defines the data structures for security-insights.yml
package model

// SecurityInsights represents the full Security Insights Spec 2.0.0 structure
type SecurityInsights struct {
	Header     Header      `yaml:"header"`
	Project    *Project    `yaml:"project,omitempty"`
	Repository *Repository `yaml:"repository,omitempty"`
}

// Header contains metadata about the security insights file
type Header struct {
	SchemaVersion   string `yaml:"schema-version"`
	LastUpdated     string `yaml:"last-updated"`
	LastReviewed    string `yaml:"last-reviewed"`
	URL             string `yaml:"url,omitempty"`
	ProjectSISource string `yaml:"project-si-source,omitempty"` // URL to inherit project section from
	Comment         string `yaml:"comment"`
}

// Project contains project-level security information
type Project struct {
	Name                   string                  `yaml:"name"`
	Homepage               string                  `yaml:"homepage,omitempty"`
	Funding                string                  `yaml:"funding,omitempty"`
	Roadmap                string                  `yaml:"roadmap,omitempty"`
	Steward                *Steward                `yaml:"steward,omitempty"`
	Administrators         []Person                `yaml:"administrators,omitempty"`
	Documentation          *ProjectDocumentation   `yaml:"documentation,omitempty"`
	Repositories           []RepositoryRef         `yaml:"repositories,omitempty"`
	VulnerabilityReporting *VulnerabilityReporting `yaml:"vulnerability-reporting,omitempty"`
}

// Steward represents the organization or entity that maintains the project
type Steward struct {
	URI     string `yaml:"uri"`
	Comment string `yaml:"comment,omitempty"`
}

// Person represents an individual (administrator, champion, core team member)
type Person struct {
	Name        string `yaml:"name"`
	Affiliation string `yaml:"affiliation,omitempty"`
	Email       string `yaml:"email,omitempty"`
	Social      string `yaml:"social,omitempty"`
	Primary     bool   `yaml:"primary,omitempty"`
}

// ProjectDocumentation contains project-level documentation links
type ProjectDocumentation struct {
	QuickstartGuide       string `yaml:"quickstart-guide,omitempty"`
	DetailedGuide         string `yaml:"detailed-guide,omitempty"`
	CodeOfConduct         string `yaml:"code-of-conduct,omitempty"`
	ReleaseProcess        string `yaml:"release-process,omitempty"`
	SupportPolicy         string `yaml:"support-policy,omitempty"`
	SignatureVerification string `yaml:"signature-verification,omitempty"`
}

// RepositoryRef is a reference to a repository within the project
type RepositoryRef struct {
	Name    string `yaml:"name"`
	URL     string `yaml:"url"`
	Comment string `yaml:"comment,omitempty"`
}

// VulnerabilityReporting contains information about how to report vulnerabilities
type VulnerabilityReporting struct {
	ReportsAccepted    bool     `yaml:"reports-accepted"`
	BugBountyAvailable bool     `yaml:"bug-bounty-available,omitempty"`
	BugBountyProgram   string   `yaml:"bug-bounty-program,omitempty"`
	Contact            *Contact `yaml:"contact,omitempty"`
	Policy             string   `yaml:"policy,omitempty"`
	InScope            []string `yaml:"in-scope,omitempty"`
	OutOfScope         []string `yaml:"out-of-scope,omitempty"`
	PGPKey             string   `yaml:"pgp-key,omitempty"`
	Comment            string   `yaml:"comment,omitempty"`
}

// Contact represents security contact information
type Contact struct {
	Name    string `yaml:"name,omitempty"`
	Email   string `yaml:"email,omitempty"`
	Primary bool   `yaml:"primary,omitempty"`
}

// Repository contains repository-specific security information
type Repository struct {
	URL                           string                   `yaml:"url"`
	Status                        string                   `yaml:"status"` // active, inactive, deprecated
	BugFixesOnly                  bool                     `yaml:"bug-fixes-only"`
	AcceptsChangeRequest          bool                     `yaml:"accepts-change-request"`
	AcceptsAutomatedChangeRequest bool                     `yaml:"accepts-automated-change-request"`
	NoThirdPartyPackages          bool                     `yaml:"no-third-party-packages"`
	CoreTeam                      []Person                 `yaml:"core-team,omitempty"`
	Documentation                 *RepositoryDocumentation `yaml:"documentation,omitempty"`
	License                       *License                 `yaml:"license,omitempty"`
	Release                       *Release                 `yaml:"release,omitempty"`
	Security                      *Security                `yaml:"security,omitempty"`
}

// RepositoryDocumentation contains repository-level documentation links
type RepositoryDocumentation struct {
	ContributingGuide          string `yaml:"contributing-guide,omitempty"`
	ReviewPolicy               string `yaml:"review-policy,omitempty"`
	SecurityPolicy             string `yaml:"security-policy,omitempty"`
	Governance                 string `yaml:"governance,omitempty"`
	DependencyManagementPolicy string `yaml:"dependency-management-policy,omitempty"`
}

// License contains license information
type License struct {
	URL        string `yaml:"url,omitempty"`
	Expression string `yaml:"expression,omitempty"` // SPDX expression
}

// Release contains release and distribution information
type Release struct {
	Changelog          string              `yaml:"changelog,omitempty"`
	AutomatedPipeline  bool                `yaml:"automated-pipeline,omitempty"`
	Attestations       []Attestation       `yaml:"attestations,omitempty"`
	DistributionPoints []DistributionPoint `yaml:"distribution-points,omitempty"`
	License            *License            `yaml:"license,omitempty"`
}

// Attestation represents a release attestation (SLSA, SBOM, etc.)
type Attestation struct {
	Name         string `yaml:"name"`
	PredicateURI string `yaml:"predicate-uri,omitempty"`
	Location     string `yaml:"location"`
	Comment      string `yaml:"comment,omitempty"`
}

// DistributionPoint represents where releases are distributed
type DistributionPoint struct {
	URI     string `yaml:"uri"`
	Comment string `yaml:"comment,omitempty"`
}

// Security contains security-specific information
type Security struct {
	Practices   *SecurityPractices `yaml:"practices,omitempty"`
	Assessments *Assessments       `yaml:"assessments,omitempty"`
	Champions   []Person           `yaml:"champions,omitempty"`
	Tools       []SecurityTool     `yaml:"tools,omitempty"`
}

// SecurityPractices contains security practice settings (custom extension)
type SecurityPractices struct {
	MFAEnforced        bool `yaml:"mfa-enforced,omitempty"`
	BranchProtection   bool `yaml:"branch-protection,omitempty"`
	CodeReviewRequired bool `yaml:"code-review-required,omitempty"`
	SignedCommits      bool `yaml:"signed-commits,omitempty"`
}

// Assessments contains security assessment information
type Assessments struct {
	Self       *Assessment  `yaml:"self,omitempty"`
	ThirdParty []Assessment `yaml:"third-party,omitempty"`
}

// Assessment represents a security assessment
type Assessment struct {
	Evidence string `yaml:"evidence,omitempty"`
	Date     string `yaml:"date,omitempty"`
	Comment  string `yaml:"comment,omitempty"`
}

// SecurityTool represents a security tool used in the repository
type SecurityTool struct {
	Name        string           `yaml:"name"`
	Type        string           `yaml:"type"` // SCA, SAST, DAST, Fuzzing, etc.
	Version     string           `yaml:"version,omitempty"`
	Rulesets    []string         `yaml:"rulesets,omitempty"`
	Results     *ToolResults     `yaml:"results,omitempty"`
	Integration *ToolIntegration `yaml:"integration,omitempty"`
	Comment     string           `yaml:"comment,omitempty"`
}

// ToolResults contains links to tool results
type ToolResults struct {
	AdHoc   *Attestation `yaml:"adhoc,omitempty"`
	CI      *Attestation `yaml:"ci,omitempty"`
	Release *Attestation `yaml:"release,omitempty"`
}

// ToolIntegration indicates where the tool is integrated
type ToolIntegration struct {
	AdHoc   bool `yaml:"adhoc,omitempty"`
	CI      bool `yaml:"ci,omitempty"`
	Release bool `yaml:"release,omitempty"`
}

// DefaultSecurityInsights returns a SecurityInsights with default values
func DefaultSecurityInsights() SecurityInsights {
	return SecurityInsights{
		Header: Header{
			SchemaVersion: "2.0.0",
		},
	}
}
