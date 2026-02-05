// Package scanner provides functionality to scan local repositories and GitHub APIs
package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// LocalData contains information gathered from scanning a local repository
type LocalData struct {
	RepoRoot string

	// Documentation files
	SecurityPolicyPath             string
	CodeOfConductPath              string
	ContributingPath               string
	GovernancePath                 string
	ChangelogPath                  string
	RoadmapPath                    string
	MaintainersPath                string
	CodeownersPath                 string
	ReviewPolicyPath               string
	DependencyManagementPolicyPath string

	// Funding
	FundingPath string

	// License
	LicenseType string
	LicensePath string

	// Vulnerability
	VulnDisclosureURL string

	// Security tools and practices
	CodeScanningTools []SecurityToolInfo
	DependencyTools   []string
	FuzzingEnabled    bool
	AuditHistory      string

	// Security assessments
	SelfAssessment   *AssessmentInfo
	ThirdPartyAudits []AssessmentInfo

	// Security champions
	SecurityChampions []MaintainerInfo

	// Dependencies
	HasDependencies bool
	DependencyFiles []string
	PackageManager  string

	// Maintainers/Contributors parsed from files
	Maintainers []MaintainerInfo

	// Release info
	HasReleaseWorkflow bool
	Attestations       []AttestationInfo

	// Distribution points detected from package files
	DistributionPoints []DistributionPointInfo
}

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
	Workflow  string   // which workflow file it was found in
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
	Role   string
}

// DistributionPointInfo represents a package distribution point
type DistributionPointInfo struct {
	Type string // npm, pypi, go, cargo, etc.
	Name string // package name
	URL  string
}

// LocalScanner scans local repository files
type LocalScanner struct {
	repoPath string
	verbose  bool
}

// NewLocalScanner creates a new LocalScanner instance
func NewLocalScanner(repoPath string, verbose bool) *LocalScanner {
	return &LocalScanner{
		repoPath: repoPath,
		verbose:  verbose,
	}
}

// Scan performs a full scan of the local repository
func (s *LocalScanner) Scan() (LocalData, error) {
	data := LocalData{
		RepoRoot: s.repoPath,
	}

	// Documentation files
	data.SecurityPolicyPath = s.findFile([]string{".github/SECURITY.md", "SECURITY.md", "docs/SECURITY.md"})
	data.CodeOfConductPath = s.findFile([]string{".github/CODE_OF_CONDUCT.md", "CODE_OF_CONDUCT.md", "docs/CODE_OF_CONDUCT.md"})
	data.ContributingPath = s.findFile([]string{".github/CONTRIBUTING.md", "CONTRIBUTING.md", "docs/CONTRIBUTING.md"})
	data.GovernancePath = s.findFile([]string{"GOVERNANCE.md", ".github/GOVERNANCE.md", "docs/GOVERNANCE.md", "docs/governance.md"})
	data.ChangelogPath = s.findFile([]string{"CHANGELOG.md", "CHANGELOG", "HISTORY.md", "CHANGES.md", "docs/CHANGELOG.md"})
	data.RoadmapPath = s.findFile([]string{"ROADMAP.md", "docs/ROADMAP.md", "docs/roadmap.md"})
	data.MaintainersPath = s.findFile([]string{"MAINTAINERS.md", "MAINTAINERS", ".github/MAINTAINERS.md", "docs/MAINTAINERS.md"})
	data.CodeownersPath = s.findFile([]string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"})
	data.FundingPath = s.findFile([]string{".github/FUNDING.yml", "FUNDING.yml"})
	data.ReviewPolicyPath = s.findFile([]string{"REVIEW_POLICY.md", ".github/REVIEW_POLICY.md", "docs/REVIEW_POLICY.md", "docs/review-policy.md", "PULL_REQUEST_TEMPLATE.md"})
	data.DependencyManagementPolicyPath = s.findFile([]string{"DEPENDENCY_POLICY.md", ".github/DEPENDENCY_POLICY.md", "docs/DEPENDENCY_POLICY.md", "docs/dependency-management.md", "docs/dependencies.md"})

	// License
	data.LicenseType, data.LicensePath = s.detectLicense()

	// Security tools
	data.CodeScanningTools, data.HasReleaseWorkflow = s.detectCodeScanningTools()
	data.DependencyTools = s.detectDependencyTools()
	data.FuzzingEnabled = s.detectFuzzing()
	data.AuditHistory = s.findFile([]string{"AUDIT.md", "audit.md", "audits/README.md", "docs/audits/README.md", "security/audits/README.md"})

	// Security assessments
	data.SelfAssessment, data.ThirdPartyAudits = s.detectSecurityAssessments()

	// Security champions
	data.SecurityChampions = s.detectSecurityChampions()

	// Dependencies
	data.HasDependencies, data.DependencyFiles, data.PackageManager = s.detectDependencies()

	// Parse maintainers from CODEOWNERS or MAINTAINERS
	data.Maintainers = s.parseMaintainers()

	// Vulnerability disclosure
	data.VulnDisclosureURL = s.findVulnerabilityDisclosure()

	// Distribution points
	data.DistributionPoints = s.detectDistributionPoints()

	// Attestations (SLSA, SBOM, etc.)
	data.Attestations = s.detectAttestations()

	return data, nil
}

// findFile looks for a file in multiple paths and returns the first found
func (s *LocalScanner) findFile(paths []string) string {
	for _, p := range paths {
		fullPath := filepath.Join(s.repoPath, p)
		if _, err := os.Stat(fullPath); err == nil {
			return p
		}
	}
	return ""
}

func (s *LocalScanner) detectLicense() (string, string) {
	licenseFiles := []string{"LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"}

	for _, lf := range licenseFiles {
		fullPath := filepath.Join(s.repoPath, lf)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		text := strings.ToLower(string(content))

		var licenseType string
		switch {
		case strings.Contains(text, "apache license") && strings.Contains(text, "2.0"):
			licenseType = "Apache-2.0"
		case strings.Contains(text, "mit license"):
			licenseType = "MIT"
		case strings.Contains(text, "gnu general public license") && strings.Contains(text, "version 3"):
			licenseType = "GPL-3.0"
		case strings.Contains(text, "gnu general public license") && strings.Contains(text, "version 2"):
			licenseType = "GPL-2.0"
		case strings.Contains(text, "bsd 3-clause"):
			licenseType = "BSD-3-Clause"
		case strings.Contains(text, "bsd 2-clause"):
			licenseType = "BSD-2-Clause"
		case strings.Contains(text, "mozilla public license"):
			licenseType = "MPL-2.0"
		case strings.Contains(text, "isc license"):
			licenseType = "ISC"
		default:
			licenseType = "Unknown"
		}
		return licenseType, lf
	}
	return "", ""
}

func (s *LocalScanner) detectCodeScanningTools() ([]SecurityToolInfo, bool) {
	var tools []SecurityToolInfo
	hasReleaseWorkflow := false
	workflowPath := filepath.Join(s.repoPath, ".github", "workflows")

	files, err := os.ReadDir(workflowPath)
	if err != nil {
		return tools, hasReleaseWorkflow
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
		"scorecard":         {"OpenSSF Scorecard", "Other"},
		"checkov":           {"Checkov", "SAST"},
		"tfsec":             {"tfsec", "SAST"},
		"dependency-review": {"Dependency Review", "SCA"},
		"fuzz":              {"Fuzzing", "Fuzzing"},
		"oss-fuzz":          {"OSS-Fuzz", "Fuzzing"},
		"slsa":              {"SLSA", "Supply Chain"},
		"sigstore":          {"Sigstore", "Supply Chain"},
		"cosign":            {"Cosign", "Supply Chain"},
	}

	// Version patterns to extract tool versions
	versionPatterns := map[string]*regexp.Regexp{
		"CodeQL":            regexp.MustCompile(`codeql.*?@v?(\d+(?:\.\d+)*)`),
		"Trivy":             regexp.MustCompile(`trivy.*?@v?(\d+(?:\.\d+)*)`),
		"Snyk":              regexp.MustCompile(`snyk.*?@v?(\d+(?:\.\d+)*)`),
		"Semgrep":           regexp.MustCompile(`semgrep.*?@v?(\d+(?:\.\d+)*)`),
		"GoSec":             regexp.MustCompile(`gosec.*?@v?(\d+(?:\.\d+)*)`),
		"OpenSSF Scorecard": regexp.MustCompile(`scorecard.*?@v?(\d+(?:\.\d+)*)`),
	}

	seenTools := make(map[string]bool)

	for _, f := range files {
		if f.IsDir() || (!strings.HasSuffix(f.Name(), ".yml") && !strings.HasSuffix(f.Name(), ".yaml")) {
			continue
		}

		content, err := os.ReadFile(filepath.Join(workflowPath, f.Name()))
		if err != nil {
			continue
		}

		text := string(content)
		textLower := strings.ToLower(text)
		fileName := strings.ToLower(f.Name())

		// Check for release workflow
		if strings.Contains(fileName, "release") || strings.Contains(textLower, "release") {
			hasReleaseWorkflow = true
		}

		// Detect workflow trigger types
		isCI := strings.Contains(textLower, "pull_request") || strings.Contains(textLower, "push")
		isRelease := strings.Contains(fileName, "release") || strings.Contains(textLower, "release:")
		isAdHoc := strings.Contains(textLower, "schedule") || strings.Contains(textLower, "cron") || strings.Contains(textLower, "workflow_dispatch")

		for pattern, info := range toolPatterns {
			if strings.Contains(textLower, pattern) && !seenTools[info.name] {
				tool := SecurityToolInfo{
					Name:      info.name,
					Type:      info.toolType,
					Workflow:  f.Name(),
					InAdHoc:   isAdHoc,
					InCI:      isCI,
					InRelease: isRelease,
				}

				// Try to extract version
				if vp, ok := versionPatterns[info.name]; ok {
					if match := vp.FindStringSubmatch(textLower); len(match) > 1 {
						tool.Version = match[1]
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

				tools = append(tools, tool)
				seenTools[info.name] = true
			}
		}
	}

	return tools, hasReleaseWorkflow
}

func (s *LocalScanner) detectDependencyTools() []string {
	var tools []string

	dependabotPaths := []string{".github/dependabot.yml", ".github/dependabot.yaml"}
	for _, p := range dependabotPaths {
		if _, err := os.Stat(filepath.Join(s.repoPath, p)); err == nil {
			tools = append(tools, "Dependabot")
			break
		}
	}

	renovatePaths := []string{
		"renovate.json",
		"renovate.json5",
		".renovaterc",
		".renovaterc.json",
		".github/renovate.json",
	}
	for _, p := range renovatePaths {
		if _, err := os.Stat(filepath.Join(s.repoPath, p)); err == nil {
			tools = append(tools, "Renovate")
			break
		}
	}

	return tools
}

func (s *LocalScanner) detectFuzzing() bool {
	found := false
	filepath.Walk(s.repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || found {
			return nil
		}
		if info.IsDir() {
			if info.Name() == "vendor" || info.Name() == "node_modules" || info.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, "_test.go") {
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			if strings.Contains(string(content), "func Fuzz") {
				found = true
				return filepath.SkipAll
			}
		}
		return nil
	})

	if found {
		return true
	}

	// Check for OSS-Fuzz or ClusterFuzzLite
	fuzzPaths := []string{".clusterfuzzlite", "fuzz", ".cifuzz.yaml", "fuzz.go"}
	for _, p := range fuzzPaths {
		if _, err := os.Stat(filepath.Join(s.repoPath, p)); err == nil {
			return true
		}
	}

	return false
}

func (s *LocalScanner) detectDependencies() (bool, []string, string) {
	depFiles := map[string]string{
		"package.json":      "npm",
		"package-lock.json": "npm",
		"yarn.lock":         "yarn",
		"pnpm-lock.yaml":    "pnpm",
		"requirements.txt":  "pip",
		"Pipfile":           "pipenv",
		"poetry.lock":       "poetry",
		"pyproject.toml":    "python",
		"go.mod":            "go",
		"Gemfile":           "bundler",
		"Cargo.toml":        "cargo",
		"pom.xml":           "maven",
		"build.gradle":      "gradle",
		"composer.json":     "composer",
	}

	var foundFiles []string
	var packageManager string

	for file, pm := range depFiles {
		if _, err := os.Stat(filepath.Join(s.repoPath, file)); err == nil {
			foundFiles = append(foundFiles, file)
			if packageManager == "" {
				packageManager = pm
			}
		}
	}

	return len(foundFiles) > 0, foundFiles, packageManager
}

func (s *LocalScanner) parseMaintainers() []MaintainerInfo {
	var maintainers []MaintainerInfo

	// Try CODEOWNERS first
	codeownersPath := s.findFile([]string{".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"})
	if codeownersPath != "" {
		maintainers = append(maintainers, s.parseCodeowners(filepath.Join(s.repoPath, codeownersPath))...)
	}

	// Try MAINTAINERS file
	maintainersPath := s.findFile([]string{"MAINTAINERS.md", "MAINTAINERS", ".github/MAINTAINERS.md"})
	if maintainersPath != "" {
		maintainers = append(maintainers, s.parseMaintainersFile(filepath.Join(s.repoPath, maintainersPath))...)
	}

	return maintainers
}

func (s *LocalScanner) parseCodeowners(path string) []MaintainerInfo {
	var maintainers []MaintainerInfo
	seen := make(map[string]bool)

	file, err := os.Open(path)
	if err != nil {
		return maintainers
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	githubUserRegex := regexp.MustCompile(`@([\w-]+)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := githubUserRegex.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if len(match) > 1 && !seen[match[1]] {
				maintainers = append(maintainers, MaintainerInfo{
					GitHub: match[1],
					Role:   "codeowner",
				})
				seen[match[1]] = true
			}
		}
	}

	return maintainers
}

func (s *LocalScanner) parseMaintainersFile(path string) []MaintainerInfo {
	var maintainers []MaintainerInfo

	content, err := os.ReadFile(path)
	if err != nil {
		return maintainers
	}

	// Simple email regex
	emailRegex := regexp.MustCompile(`[\w.+-]+@[\w.-]+\.\w+`)
	// GitHub username pattern (often in format @username or github.com/username)
	githubRegex := regexp.MustCompile(`(?:@|github\.com/)([\w-]+)`)

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var m MaintainerInfo

		if email := emailRegex.FindString(line); email != "" {
			m.Email = email
			// Try to extract name (text before email)
			idx := strings.Index(line, email)
			if idx > 0 {
				m.Name = strings.TrimSpace(strings.TrimRight(line[:idx], "<("))
			}
		}

		if gh := githubRegex.FindStringSubmatch(line); len(gh) > 1 {
			m.GitHub = gh[1]
		}

		if m.Email != "" || m.GitHub != "" {
			m.Role = "maintainer"
			maintainers = append(maintainers, m)
		}
	}

	return maintainers
}

func (s *LocalScanner) findVulnerabilityDisclosure() string {
	securityPaths := []string{".github/SECURITY.md", "SECURITY.md"}

	for _, p := range securityPaths {
		fullPath := filepath.Join(s.repoPath, p)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		text := strings.ToLower(string(content))
		if strings.Contains(text, "vulnerability") || strings.Contains(text, "disclosure") {
			return p
		}
	}

	return ""
}

func (s *LocalScanner) detectDistributionPoints() []DistributionPointInfo {
	var points []DistributionPointInfo

	// Check package.json for npm package name
	if content, err := os.ReadFile(filepath.Join(s.repoPath, "package.json")); err == nil {
		// Simple extraction - look for "name": "package-name"
		nameRegex := regexp.MustCompile(`"name"\s*:\s*"([^"]+)"`)
		if match := nameRegex.FindSubmatch(content); len(match) > 1 {
			pkgName := string(match[1])
			points = append(points, DistributionPointInfo{
				Type: "npm",
				Name: pkgName,
				URL:  "pkg:npm/" + pkgName,
			})
		}
	}

	// Check go.mod for module name
	if content, err := os.ReadFile(filepath.Join(s.repoPath, "go.mod")); err == nil {
		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "module ") {
				modName := strings.TrimSpace(strings.TrimPrefix(line, "module "))
				points = append(points, DistributionPointInfo{
					Type: "go",
					Name: modName,
					URL:  "pkg:golang/" + modName,
				})
				break
			}
		}
	}

	// Check Cargo.toml for crate name
	if content, err := os.ReadFile(filepath.Join(s.repoPath, "Cargo.toml")); err == nil {
		nameRegex := regexp.MustCompile(`name\s*=\s*"([^"]+)"`)
		if match := nameRegex.FindSubmatch(content); len(match) > 1 {
			crateName := string(match[1])
			points = append(points, DistributionPointInfo{
				Type: "cargo",
				Name: crateName,
				URL:  "pkg:cargo/" + crateName,
			})
		}
	}

	// Check pyproject.toml or setup.py for PyPI name
	if content, err := os.ReadFile(filepath.Join(s.repoPath, "pyproject.toml")); err == nil {
		nameRegex := regexp.MustCompile(`name\s*=\s*"([^"]+)"`)
		if match := nameRegex.FindSubmatch(content); len(match) > 1 {
			pyName := string(match[1])
			points = append(points, DistributionPointInfo{
				Type: "pypi",
				Name: pyName,
				URL:  "pkg:pypi/" + pyName,
			})
		}
	}

	return points
}

// detectAttestations scans workflow files for attestation generation (SLSA, SBOM, Sigstore)
func (s *LocalScanner) detectAttestations() []AttestationInfo {
	var attestations []AttestationInfo
	seenAttestations := make(map[string]bool)

	workflowDir := filepath.Join(s.repoPath, ".github", "workflows")
	files, err := os.ReadDir(workflowDir)
	if err != nil {
		return attestations
	}

	// Attestation patterns to look for
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

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if !strings.HasSuffix(f.Name(), ".yml") && !strings.HasSuffix(f.Name(), ".yaml") {
			continue
		}

		content, err := os.ReadFile(filepath.Join(workflowDir, f.Name()))
		if err != nil {
			continue
		}
		text := strings.ToLower(string(content))
		workflowName := f.Name()

		for pattern, info := range attestationPatterns {
			if strings.Contains(text, strings.ToLower(pattern)) && !seenAttestations[info.name] {
				attestations = append(attestations, AttestationInfo{
					Name:         info.name,
					PredicateURI: info.predicateURI,
					Location:     ".github/workflows/" + workflowName,
					Comment:      info.comment,
				})
				seenAttestations[info.name] = true
			}
		}
	}

	return attestations
}

// detectSecurityAssessments looks for security assessment and audit files
func (s *LocalScanner) detectSecurityAssessments() (*AssessmentInfo, []AssessmentInfo) {
	var selfAssessment *AssessmentInfo
	var thirdPartyAudits []AssessmentInfo

	// Look for self-assessment files
	selfAssessmentPaths := []string{
		"SECURITY_ASSESSMENT.md",
		"security-assessment.md",
		"docs/security-assessment.md",
		"SELF_ASSESSMENT.md",
		"self-assessment.md",
		"docs/self-assessment.md",
	}
	for _, p := range selfAssessmentPaths {
		fullPath := filepath.Join(s.repoPath, p)
		if info, err := os.Stat(fullPath); err == nil {
			selfAssessment = &AssessmentInfo{
				Evidence: p,
				Date:     info.ModTime().Format("2006-01-02"),
				Comment:  "Self-assessment document",
			}
			break
		}
	}

	// Look for third-party audit directories and files
	auditDirs := []string{"audits", "security/audits", "docs/audits", "audit-reports"}
	for _, dir := range auditDirs {
		dirPath := filepath.Join(s.repoPath, dir)
		entries, err := os.ReadDir(dirPath)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			// Look for audit report files (pdf, md, html)
			if strings.HasSuffix(name, ".pdf") || strings.HasSuffix(name, ".md") || strings.HasSuffix(name, ".html") {
				filePath := filepath.Join(dir, name)
				fullPath := filepath.Join(s.repoPath, filePath)
				info, err := os.Stat(fullPath)
				if err != nil {
					continue
				}

				// Try to extract auditor name from filename
				comment := "Third-party security audit"
				nameLower := strings.ToLower(name)
				knownAuditors := map[string]string{
					"trail_of_bits":   "Trail of Bits audit",
					"trailofbits":     "Trail of Bits audit",
					"openzeppelin":    "OpenZeppelin audit",
					"consensys":       "ConsenSys Diligence audit",
					"certik":          "CertiK audit",
					"quantstamp":      "Quantstamp audit",
					"halborn":         "Halborn audit",
					"cure53":          "Cure53 audit",
					"ncc":             "NCC Group audit",
					"ncc_group":       "NCC Group audit",
					"kudelski":        "Kudelski Security audit",
					"sigma_prime":     "Sigma Prime audit",
					"sigmaprime":      "Sigma Prime audit",
					"least_authority": "Least Authority audit",
					"leastauthority":  "Least Authority audit",
				}
				for keyword, desc := range knownAuditors {
					if strings.Contains(nameLower, keyword) {
						comment = desc
						break
					}
				}

				thirdPartyAudits = append(thirdPartyAudits, AssessmentInfo{
					Evidence: filePath,
					Date:     info.ModTime().Format("2006-01-02"),
					Comment:  comment,
				})
			}
		}
	}

	// Also check for single audit files at root level
	rootAuditFiles := []string{
		"AUDIT.md", "audit.md", "AUDIT_REPORT.md", "audit_report.md",
		"SECURITY_AUDIT.md", "security_audit.md",
	}
	for _, f := range rootAuditFiles {
		fullPath := filepath.Join(s.repoPath, f)
		if info, err := os.Stat(fullPath); err == nil {
			// Check if it looks like a third-party audit
			content, err := os.ReadFile(fullPath)
			if err == nil {
				contentLower := strings.ToLower(string(content))
				isThirdParty := strings.Contains(contentLower, "audit") &&
					(strings.Contains(contentLower, "trail of bits") ||
						strings.Contains(contentLower, "openzeppelin") ||
						strings.Contains(contentLower, "certik") ||
						strings.Contains(contentLower, "ncc group") ||
						strings.Contains(contentLower, "cure53") ||
						strings.Contains(contentLower, "external audit") ||
						strings.Contains(contentLower, "third-party"))

				if isThirdParty {
					thirdPartyAudits = append(thirdPartyAudits, AssessmentInfo{
						Evidence: f,
						Date:     info.ModTime().Format("2006-01-02"),
						Comment:  "Third-party security audit",
					})
				} else if selfAssessment == nil {
					// Use as self-assessment if no other found
					selfAssessment = &AssessmentInfo{
						Evidence: f,
						Date:     info.ModTime().Format("2006-01-02"),
						Comment:  "Security audit history",
					}
				}
			}
			break
		}
	}

	return selfAssessment, thirdPartyAudits
}

// detectSecurityChampions looks for security champions in SECURITY.md or other files
func (s *LocalScanner) detectSecurityChampions() []MaintainerInfo {
	var champions []MaintainerInfo

	// Try to find security contacts in SECURITY.md
	securityFiles := []string{
		"SECURITY.md",
		".github/SECURITY.md",
		"docs/SECURITY.md",
		"security/CONTACTS.md",
		"SECURITY_CONTACTS.md",
	}

	for _, sf := range securityFiles {
		fullPath := filepath.Join(s.repoPath, sf)
		content, err := os.ReadFile(fullPath)
		if err != nil {
			continue
		}

		text := string(content)
		lines := strings.Split(text, "\n")

		// Look for email patterns
		emailRegex := regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
		seenEmails := make(map[string]bool)

		// Look for emails in security-related context
		for _, line := range lines {
			lineLower := strings.ToLower(line)
			// Only extract emails from lines that look like contact info
			if strings.Contains(lineLower, "security") || strings.Contains(lineLower, "contact") ||
				strings.Contains(lineLower, "report") || strings.Contains(lineLower, "e-mail") ||
				strings.Contains(lineLower, "email") || strings.Contains(lineLower, "disclose") {
				emails := emailRegex.FindAllString(line, -1)
				for _, email := range emails {
					// Skip common non-person/example emails
					if strings.Contains(email, "noreply") || strings.Contains(email, "bot@") ||
						strings.Contains(email, "github.com") || strings.Contains(email, "example.com") ||
						strings.Contains(email, "example.org") {
						continue
					}
					if !seenEmails[email] {
						champions = append(champions, MaintainerInfo{
							Email: email,
							Role:  "Security Contact",
						})
						seenEmails[email] = true
					}
				}
			}
		}

		if len(champions) > 0 {
			break
		}
	}

	return champions
}
