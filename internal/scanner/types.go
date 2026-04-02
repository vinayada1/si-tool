// Package scanner provides functionality to scan GitHub repositories
package scanner

// AttestationInfo contains info about a release attestation
type AttestationInfo struct {
	Name         string
	PredicateURI string
	Location     string
	Comment      string
}

// AssessmentInfo contains info about a security assessment or audit
type AssessmentInfo struct {
	Evidence string
	Date     string
	Comment  string
}

// SecurityToolInfo contains detailed info about a security tool
type SecurityToolInfo struct {
	Name      string
	Type      string   // SCA, SAST, DAST, Fuzzing, Other
	Version   string   // Version if detected from workflow
	Rulesets  []string // Rulesets if detected
	InAdHoc   bool     // scheduled/cron runs
	InCI      bool     // PR/push triggered
	InRelease bool     // release triggered
	Comment   string   // Additional info
}

// MaintainerInfo represents a maintainer parsed from files
type MaintainerInfo struct {
	Name   string
	Email  string
	GitHub string
}

// DistributionPointInfo represents a package distribution point
type DistributionPointInfo struct {
	Type string // npm, pypi, go, cargo, etc.
	URL  string
}

// OrgRepoInfo contains basic info about an org repository
type OrgRepoInfo struct {
	Name        string
	URL         string
	Description string
}

// Contributor represents a repository contributor
type Contributor struct {
	Login string
	Name  string
	Email string
}
