// Package model defines the data structures for security-insights.yml
package model

// SecurityInsights represents the full Security Insights Spec 2.0.0 structure
type SecurityInsights struct {
	Header     Header      `yaml:"header" json:"header"`
	Project    *Project    `yaml:"project,omitempty" json:"project,omitempty"`
	Repository *Repository `yaml:"repository,omitempty" json:"repository,omitempty"`
}

// Header contains metadata about the security insights file
type Header struct {
	SchemaVersion   string `yaml:"schema-version" json:"schema-version"`
	LastUpdated     string `yaml:"last-updated" json:"last-updated"`
	LastReviewed    string `yaml:"last-reviewed" json:"last-reviewed"`
	URL             string `yaml:"url,omitempty" json:"url,omitempty"`
	ProjectSISource string `yaml:"project-si-source,omitempty" json:"project-si-source,omitempty"` // URL to inherit project section from
	Comment         string `yaml:"comment" json:"comment"`
}

// Project contains project-level security information
type Project struct {
	Name                   string                  `yaml:"name" json:"name"`
	Homepage               string                  `yaml:"homepage,omitempty" json:"homepage,omitempty"`
	Funding                string                  `yaml:"funding,omitempty" json:"funding,omitempty"`
	Roadmap                string                  `yaml:"roadmap,omitempty" json:"roadmap,omitempty"`
	Steward                *Steward                `yaml:"steward,omitempty" json:"steward,omitempty"`
	Administrators         []Person                `yaml:"administrators,omitempty" json:"administrators,omitempty"`
	Documentation          *ProjectDocumentation   `yaml:"documentation,omitempty" json:"documentation,omitempty"`
	Repositories           []RepositoryRef         `yaml:"repositories,omitempty" json:"repositories,omitempty"`
	VulnerabilityReporting *VulnerabilityReporting `yaml:"vulnerability-reporting,omitempty" json:"vulnerability-reporting,omitempty"`
}

// Steward represents the organization or entity that maintains the project
type Steward struct {
	URI     string `yaml:"uri" json:"uri"`
	Comment string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// Person represents an individual (administrator, champion, core team member)
type Person struct {
	Name        string `yaml:"name" json:"name"`
	Affiliation string `yaml:"affiliation,omitempty" json:"affiliation,omitempty"`
	Email       string `yaml:"email,omitempty" json:"email,omitempty"`
	Social      string `yaml:"social,omitempty" json:"social,omitempty"`
	Primary     bool   `yaml:"primary" json:"primary"`
}

// ProjectDocumentation contains project-level documentation links
type ProjectDocumentation struct {
	QuickstartGuide       string `yaml:"quickstart-guide,omitempty" json:"quickstart-guide,omitempty"`
	DetailedGuide         string `yaml:"detailed-guide,omitempty" json:"detailed-guide,omitempty"`
	CodeOfConduct         string `yaml:"code-of-conduct,omitempty" json:"code-of-conduct,omitempty"`
	ReleaseProcess        string `yaml:"release-process,omitempty" json:"release-process,omitempty"`
	SupportPolicy         string `yaml:"support-policy,omitempty" json:"support-policy,omitempty"`
	SignatureVerification string `yaml:"signature-verification,omitempty" json:"signature-verification,omitempty"`
}

// RepositoryRef is a reference to a repository within the project
type RepositoryRef struct {
	Name    string `yaml:"name" json:"name"`
	URL     string `yaml:"url" json:"url"`
	Comment string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// VulnerabilityReporting contains information about how to report vulnerabilities
type VulnerabilityReporting struct {
	ReportsAccepted    bool     `yaml:"reports-accepted" json:"reports-accepted"`
	BugBountyAvailable bool     `yaml:"bug-bounty-available" json:"bug-bounty-available"`
	BugBountyProgram   string   `yaml:"bug-bounty-program,omitempty" json:"bug-bounty-program,omitempty"`
	Contact            *Contact `yaml:"contact,omitempty" json:"contact,omitempty"`
	Policy             string   `yaml:"policy,omitempty" json:"policy,omitempty"`
	InScope            []string `yaml:"in-scope,omitempty" json:"in-scope,omitempty"`
	OutOfScope         []string `yaml:"out-of-scope,omitempty" json:"out-of-scope,omitempty"`
	PGPKey             string   `yaml:"pgp-key,omitempty" json:"pgp-key,omitempty"`
	Comment            string   `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// Contact represents security contact information
type Contact struct {
	Name    string `yaml:"name,omitempty" json:"name,omitempty"`
	Email   string `yaml:"email,omitempty" json:"email,omitempty"`
	Primary bool   `yaml:"primary" json:"primary"`
}

// Repository contains repository-specific security information
type Repository struct {
	URL                           string                   `yaml:"url" json:"url"`
	Status                        string                   `yaml:"status" json:"status"` // active, inactive, abandoned, concept, moved, suspended, unsupported, WIP
	BugFixesOnly                  bool                     `yaml:"bug-fixes-only" json:"bug-fixes-only"`
	AcceptsChangeRequest          bool                     `yaml:"accepts-change-request" json:"accepts-change-request"`
	AcceptsAutomatedChangeRequest bool                     `yaml:"accepts-automated-change-request" json:"accepts-automated-change-request"`
	NoThirdPartyPackages          bool                     `yaml:"no-third-party-packages" json:"no-third-party-packages"`
	CoreTeam                      []Person                 `yaml:"core-team,omitempty" json:"core-team,omitempty"`
	Documentation                 *RepositoryDocumentation `yaml:"documentation,omitempty" json:"documentation,omitempty"`
	License                       *License                 `yaml:"license,omitempty" json:"license,omitempty"`
	Release                       *Release                 `yaml:"release,omitempty" json:"release,omitempty"`
	Security                      *Security                `yaml:"security,omitempty" json:"security,omitempty"`
}

// RepositoryDocumentation contains repository-level documentation links
type RepositoryDocumentation struct {
	ContributingGuide          string `yaml:"contributing-guide,omitempty" json:"contributing-guide,omitempty"`
	ReviewPolicy               string `yaml:"review-policy,omitempty" json:"review-policy,omitempty"`
	SecurityPolicy             string `yaml:"security-policy,omitempty" json:"security-policy,omitempty"`
	Governance                 string `yaml:"governance,omitempty" json:"governance,omitempty"`
	DependencyManagementPolicy string `yaml:"dependency-management-policy,omitempty" json:"dependency-management-policy,omitempty"`
}

// License contains license information
type License struct {
	URL        string `yaml:"url,omitempty" json:"url,omitempty"`
	Expression string `yaml:"expression,omitempty" json:"expression,omitempty"` // SPDX expression
}

// Release contains release and distribution information
type Release struct {
	Changelog          string              `yaml:"changelog,omitempty" json:"changelog,omitempty"`
	AutomatedPipeline  bool                `yaml:"automated-pipeline,omitempty" json:"automated-pipeline,omitempty"`
	Attestations       []Attestation       `yaml:"attestations,omitempty" json:"attestations,omitempty"`
	DistributionPoints []DistributionPoint `yaml:"distribution-points,omitempty" json:"distribution-points,omitempty"`
	License            *License            `yaml:"license,omitempty" json:"license,omitempty"`
}

// Attestation represents a release attestation (SLSA, SBOM, etc.)
type Attestation struct {
	Name         string `yaml:"name" json:"name"`
	PredicateURI string `yaml:"predicate-uri,omitempty" json:"predicate-uri,omitempty"`
	Location     string `yaml:"location" json:"location"`
	Comment      string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// DistributionPoint represents where releases are distributed
type DistributionPoint struct {
	URI     string `yaml:"uri" json:"uri"`
	Comment string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// Security contains security-specific information
type Security struct {
	Assessments *Assessments   `yaml:"assessments,omitempty" json:"assessments,omitempty"`
	Champions   []Person       `yaml:"champions,omitempty" json:"champions,omitempty"`
	Tools       []SecurityTool `yaml:"tools,omitempty" json:"tools,omitempty"`
}

// Assessments contains security assessment information
type Assessments struct {
	Self       *Assessment  `yaml:"self,omitempty" json:"self,omitempty"`
	ThirdParty []Assessment `yaml:"third-party,omitempty" json:"third-party,omitempty"`
}

// Assessment represents a security assessment
type Assessment struct {
	Evidence string `yaml:"evidence,omitempty" json:"evidence,omitempty"`
	Date     string `yaml:"date,omitempty" json:"date,omitempty"`
	Comment  string `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// SecurityTool represents a security tool used in the repository
type SecurityTool struct {
	Name        string           `yaml:"name" json:"name"`
	Type        string           `yaml:"type" json:"type"` // SCA, SAST, DAST, Fuzzing, etc.
	Version     string           `yaml:"version,omitempty" json:"version,omitempty"`
	Rulesets    []string         `yaml:"rulesets" json:"rulesets"`
	Results     *ToolResults     `yaml:"results" json:"results"`
	Integration *ToolIntegration `yaml:"integration" json:"integration"`
	Comment     string           `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// ToolResults contains links to tool results
type ToolResults struct {
	AdHoc   *Attestation `yaml:"adhoc,omitempty" json:"adhoc,omitempty"`
	CI      *Attestation `yaml:"ci,omitempty" json:"ci,omitempty"`
	Release *Attestation `yaml:"release,omitempty" json:"release,omitempty"`
}

// ToolIntegration indicates where the tool is integrated
type ToolIntegration struct {
	AdHoc   bool `yaml:"adhoc" json:"adhoc"`
	CI      bool `yaml:"ci" json:"ci"`
	Release bool `yaml:"release" json:"release"`
}
