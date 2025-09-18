package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

//go:embed exploited_packages.txt
var embeddedExploitedPackages string

// Package represents a parsed package from the exploited packages list
type Package struct {
	Name        string `json:"package"`
	Version     string `json:"version"`
	IsAffected  bool   `json:"isAffected"`
	IsWarning   bool   `json:"isWarning"`
	AffectedVersions []string `json:"affectedVersions,omitempty"`
}

// Result represents scan results for a single lockfile
type Result struct {
	LockFile string    `json:"lockFile"`
	Packages []Package `json:"packages"`
}

// ScanResult represents the complete scan output
type ScanResult struct {
	Root        string   `json:"root"`
	Results     []Result `json:"results"`
	AnyAffected bool     `json:"anyAffected"`
	AnyWarnings bool     `json:"anyWarnings"`
	Summary     Summary  `json:"summary"`
}

// Summary contains scan statistics
type Summary struct {
	TotalLockfiles   int `json:"totalLockfiles"`
	TotalPackages    int `json:"totalPackages"`
	TotalWarnings    int `json:"totalWarnings"`
	TotalCompromised int `json:"totalCompromised"`
}

func main() {
	startTime := time.Now()

	// Command line flags - clean and simple
	var (
		listPath    = flag.String("list-path", "", "Path to exploited packages list file (optional if embedded)")
		rootDir     = flag.String("root-dir", ".", "Root directory to scan")
		managersStr = flag.String("managers", "yarn,npm,pnpm,bun", "Package managers to scan (comma-separated)")
		includeStr  = flag.String("include", "", "Include patterns (comma-separated)")
		excludeStr  = flag.String("exclude", "**/node_modules/**,**/.pnpm-store/**,**/dist/**,**/build/**,**/tmp/**,**/.turbo/**", "Exclude patterns (comma-separated)")
		onlyAffected = flag.Bool("only-affected", false, "Show only affected packages")
		summary     = flag.Bool("summary", false, "Show only summary")
		quiet       = flag.Bool("quiet", false, "Suppress non-essential output")
		noColor     = flag.Bool("no-color", false, "Disable colored output")
		jsonFlag    = flag.Bool("json", false, "Output JSON")
		jsonPath    = flag.String("json-path", "", "Write JSON to file")
		version     = flag.Bool("version", false, "Show version information")
	)

	flag.Parse()

	// Handle version flag
	if *version {
		fmt.Printf("Shai-Hulud Scanner v%s\n", Version)
		fmt.Printf("Git Commit: %s\n", GitCommit)
		fmt.Printf("Build Time: %s\n", BuildTime)
		os.Exit(0)
	}

	// Validate required parameters
	if *listPath == "" && embeddedExploitedPackages == "" {
		fmt.Fprintf(os.Stderr, "Error: --list-path is required or embedded package list must be available\n")
		flag.Usage()
		os.Exit(1)
	}

	if *listPath != "" {
		if _, err := os.Stat(*listPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: list file not found: %s\n", *listPath)
			os.Exit(1)
		}
	}

	if _, err := os.Stat(*rootDir); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: root directory not found: %s\n", *rootDir)
		os.Exit(1)
	}

	// Parse managers - simple string split
	managers := parseCommaSeparated(*managersStr)
	if len(managers) == 0 {
		fmt.Fprintf(os.Stderr, "Error: no valid managers specified\n")
		os.Exit(1)
	}

	// Validate managers
	validManagers := []string{"yarn", "npm", "pnpm", "bun"}
	for _, manager := range managers {
		valid := false
		for _, vm := range validManagers {
			if manager == vm {
				valid = true
				break
			}
		}
		if !valid {
			fmt.Fprintf(os.Stderr, "Error: invalid manager '%s'. Valid options: %s\n", manager, strings.Join(validManagers, ", "))
			os.Exit(1)
		}
	}

	// Parse include/exclude patterns
	var include, exclude []string
	if *includeStr != "" {
		include = parseCommaSeparated(*includeStr)
	}
	if *excludeStr != "" {
		exclude = parseCommaSeparated(*excludeStr)
	}

	// Load exploited packages
	affected, err := loadExploitedPackages(*listPath)
	if err != nil {
		// If external file fails to load, try embedded file as fallback
		if *listPath != "" {
			fmt.Fprintf(os.Stderr, "Warning: Failed to load external packages file '%s': %v\n", *listPath, err)
			fmt.Fprintf(os.Stderr, "Falling back to embedded package list\n")
		}
		affected, err = loadEmbeddedExploitedPackages()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading embedded packages: %v\n", err)
			os.Exit(1)
		}
	}

	if len(affected) == 0 {
		source := *listPath
		if source == "" {
			source = "embedded package list"
		}
		fmt.Fprintf(os.Stderr, "Error: no valid package@version entries found in %s\n", source)
		os.Exit(1)
	}

	// Find lockfiles
	lockfiles, err := findLockfiles(*rootDir, managers, include, exclude)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error finding lockfiles: %v\n", err)
		os.Exit(1)
	}

	if len(lockfiles) == 0 {
		if !*jsonFlag {
			fmt.Printf("No lockfiles found under: %s\n", *rootDir)
		}
		os.Exit(0)
	}

	// Scan lockfiles
	results, anyAffected, anyWarnings := scanLockfiles(lockfiles, affected)

	// Build summary
	totalPackages := 0
	totalCompromised := 0
	totalWarnings := 0

	for _, result := range results {
		totalPackages += len(result.Packages)
		for _, pkg := range result.Packages {
			if pkg.IsAffected {
				totalCompromised++
			}
			if pkg.IsWarning {
				totalWarnings++
			}
		}
	}

	// Create output
	rootAbs, _ := filepath.Abs(*rootDir)
	scanResult := ScanResult{
		Root:        rootAbs,
		Results:     results,
		AnyAffected: anyAffected,
		AnyWarnings: anyWarnings,
		Summary: Summary{
			TotalLockfiles:   len(lockfiles),
			TotalPackages:    totalPackages,
			TotalWarnings:    totalWarnings,
			TotalCompromised: totalCompromised,
		},
	}

	// JSON output
	jsonOutput, err := json.MarshalIndent(scanResult, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating JSON: %v\n", err)
		os.Exit(1)
	}

	if *jsonFlag {
		fmt.Println(string(jsonOutput))
	}

	if *jsonPath != "" {
		if err := os.WriteFile(*jsonPath, jsonOutput, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON file: %v\n", err)
			os.Exit(1)
		}
	}

	// Human-readable output
	if !*jsonFlag {
		printResults(scanResult, *summary, *quiet, *onlyAffected, *noColor, startTime)
	}

	// Exit code based on findings
	if anyAffected {
		os.Exit(2)
	}
	os.Exit(0)
}

// parseCommaSeparated parses a comma-separated string into a slice
func parseCommaSeparated(s string) []string {
	if s == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// loadExploitedPackages loads and parses the exploited packages list
func loadExploitedPackages(path string) (map[string]map[string]bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	affected := make(map[string]map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse package@version
		re := regexp.MustCompile(`^(@?[^@/\s]+(?:/[^@/\s]+)?)@([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)$`)
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			name := matches[1]
			version := matches[2]

			// Normalize scoped packages
			if strings.Contains(name, "/") && !strings.HasPrefix(name, "@") {
				name = "@" + name
			}

			if affected[name] == nil {
				affected[name] = make(map[string]bool)
			}
			affected[name][version] = true
		}
	}

	return affected, scanner.Err()
}

// loadEmbeddedExploitedPackages loads the embedded exploited packages list
func loadEmbeddedExploitedPackages() (map[string]map[string]bool, error) {
	affected := make(map[string]map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(embeddedExploitedPackages))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse package@version
		re := regexp.MustCompile(`^(@?[^@/\s]+(?:/[^@/\s]+)?)@([0-9]+\.[0-9]+\.[0-9]+(?:\.[0-9]+)?)$`)
		matches := re.FindStringSubmatch(line)
		if len(matches) == 3 {
			name := matches[1]
			version := matches[2]

			// Normalize scoped packages
			if strings.Contains(name, "/") && !strings.HasPrefix(name, "@") {
				name = "@" + name
			}

			if affected[name] == nil {
				affected[name] = make(map[string]bool)
			}
			affected[name][version] = true
		}
	}

	return affected, scanner.Err()
}

// findLockfiles finds all relevant lockfiles for the specified managers
func findLockfiles(rootDir string, managers, include, exclude []string) ([]string, error) {
	var lockfiles []string
	var patterns []string

	// Build patterns based on managers
	for _, manager := range managers {
		switch manager {
		case "yarn":
			patterns = append(patterns, "yarn.lock")
		case "npm":
			patterns = append(patterns, "package-lock.json", "npm-shrinkwrap.json")
		case "pnpm":
			patterns = append(patterns, "pnpm-lock.yaml")
		case "bun":
			patterns = append(patterns, "bun.lock", "bun.lockb")
		}
	}

	// Find all files matching patterns
	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}

		if d.IsDir() {
			return nil
		}

		// Check if file matches any pattern
		for _, pattern := range patterns {
			if d.Name() == pattern {
				// Check include/exclude filters
				if shouldIncludePath(path, rootDir, include, exclude) {
					lockfiles = append(lockfiles, path)
				}
				break
			}
		}

		return nil
	})

	return lockfiles, err
}

// shouldIncludePath checks if a path should be included based on include/exclude patterns
func shouldIncludePath(fullPath, rootDir string, include, exclude []string) bool {
	// Get relative path from root
	relPath, err := filepath.Rel(rootDir, fullPath)
	if err != nil {
		return false
	}

	// Normalize path separators
	relPath = filepath.ToSlash(relPath)

	// Check exclude patterns first
	for _, pattern := range exclude {
		if matchesGlobPattern(relPath, pattern) {
			return false
		}
	}

	// If include patterns specified, path must match at least one
	if len(include) > 0 {
		for _, pattern := range include {
			if matchesGlobPattern(relPath, pattern) {
				return true
			}
		}
		return false
	}

	return true
}

// matchesPattern checks if a path matches a glob pattern
func matchesPattern(path, pattern string) bool {
	// Convert glob to regex
	regex := "^" + regexp.QuoteMeta(pattern)
	regex = strings.ReplaceAll(regex, "\\*\\*", ".*")
	regex = strings.ReplaceAll(regex, "\\*", "[^/]*")
	regex += "$"

	matched, _ := regexp.MatchString(regex, path)
	return matched
}

// Improved glob matching function
func matchesGlobPattern(path, pattern string) bool {
	// Handle common glob patterns more accurately
	if pattern == "**/node_modules/**" {
		return strings.Contains(path, "node_modules/")
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return strings.HasPrefix(path, prefix+"/") || path == strings.TrimSuffix(prefix, "/")
	}
	if strings.HasPrefix(pattern, "**/") {
		suffix := strings.TrimPrefix(pattern, "**/")
		return strings.Contains(path, "/"+suffix) || strings.HasPrefix(path, suffix)
	}

	// Fallback to simple regex conversion
	regex := "^" + regexp.QuoteMeta(pattern)
	regex = strings.ReplaceAll(regex, "\\*\\*", ".*")
	regex = strings.ReplaceAll(regex, "\\*", "[^/]*")
	regex += "$"

	matched, _ := regexp.MatchString(regex, path)
	return matched
}

// scanLockfiles scans all found lockfiles
func scanLockfiles(lockfiles []string, affected map[string]map[string]bool) ([]Result, bool, bool) {
	var results []Result
	anyAffected := false
	anyWarnings := false

	for _, lockfile := range lockfiles {
		packages, hasAffected, hasWarnings := scanLockfile(lockfile, affected)

		if len(packages) > 0 {
			results = append(results, Result{
				LockFile: lockfile,
				Packages: packages,
			})
		}

		if hasAffected {
			anyAffected = true
		}
		if hasWarnings {
			anyWarnings = true
		}
	}

	return results, anyAffected, anyWarnings
}

// scanLockfile scans a single lockfile
func scanLockfile(lockfile string, affected map[string]map[string]bool) ([]Package, bool, bool) {
	var packages []Package
	hasAffected := false
	hasWarnings := false

	// Determine file type and parse accordingly
	baseName := filepath.Base(lockfile)

	switch {
	case baseName == "yarn.lock":
		pkgs, affected, warnings := parseYarnLock(lockfile, affected)
		packages = append(packages, pkgs...)
		if affected { hasAffected = true }
		if warnings { hasWarnings = true }

	case baseName == "package-lock.json" || baseName == "npm-shrinkwrap.json":
		pkgs, affected, warnings := parseNPMLock(lockfile, affected)
		packages = append(packages, pkgs...)
		if affected { hasAffected = true }
		if warnings { hasWarnings = true }

	case baseName == "pnpm-lock.yaml":
		pkgs, affected, warnings := parsePNMLock(lockfile, affected)
		packages = append(packages, pkgs...)
		if affected { hasAffected = true }
		if warnings { hasWarnings = true }

	case baseName == "bun.lock" || baseName == "bun.lockb":
		// For now, skip binary bun.lockb files
		if baseName == "bun.lockb" {
			return packages, hasAffected, hasWarnings
		}
		pkgs, affected, warnings := parseBunLock(lockfile, affected)
		packages = append(packages, pkgs...)
		if affected { hasAffected = true }
		if warnings { hasWarnings = true }
	}

	return packages, hasAffected, hasWarnings
}

// parseYarnLock parses a yarn.lock file
func parseYarnLock(lockfile string, affected map[string]map[string]bool) ([]Package, bool, bool) {
	var packages []Package
	hasAffected := false
	hasWarnings := false

	content, err := os.ReadFile(lockfile)
	if err != nil {
		return packages, hasAffected, hasWarnings
	}

	lines := strings.Split(string(content), "\n")
	foundPackages := make(map[string]string) // name -> version

	i := 0
	for i < len(lines) {
		line := strings.TrimSpace(lines[i])

		// Look for package header lines
		if strings.Contains(line, "@") && strings.Contains(line, ":") {
			// Extract package name from header
			header := strings.Trim(line, `":`)
			name := extractPackageNameFromYarnHeader(header)
			if name == "" {
				i++
				continue
			}

			// Find version in the following lines
			version := ""
			j := i + 1
			for j < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[j]), "\"") {
				verLine := strings.TrimSpace(lines[j])
				if strings.HasPrefix(verLine, "version") {
					version = strings.Trim(strings.TrimPrefix(verLine, "version"), ` "`)
					break
				}
				j++
			}

			if version != "" {
				foundPackages[name] = version
			}
		}
		i++
	}

	// Check against affected packages
	for name, version := range foundPackages {
		if affectedVersions, exists := affected[name]; exists {
			isAffected := affectedVersions[version]
			isWarning := !isAffected && len(affectedVersions) > 0

			if isAffected || isWarning {
				var affectedVers []string
				for v := range affectedVersions {
					affectedVers = append(affectedVers, v)
				}

				packages = append(packages, Package{
					Name:             name,
					Version:          version,
					IsAffected:       isAffected,
					IsWarning:        isWarning,
					AffectedVersions: affectedVers,
				})

				if isAffected {
					hasAffected = true
				}
				if isWarning {
					hasWarnings = true
				}
			}
		}
	}

	return packages, hasAffected, hasWarnings
}

// extractPackageNameFromYarnHeader extracts package name from yarn.lock header
func extractPackageNameFromYarnHeader(header string) string {
	// Handle patterns like: @scope/package@^1.0.0, @scope/package@^2.0.0
	parts := strings.Split(header, ",")
	if len(parts) == 0 {
		return ""
	}

	// Take first part and extract package name
	firstPart := strings.TrimSpace(parts[0])
	atIndex := strings.LastIndex(firstPart, "@")
	if atIndex == -1 {
		return ""
	}

	name := firstPart[:atIndex]
	// Normalize scoped packages
	if strings.Contains(name, "/") && !strings.HasPrefix(name, "@") {
		name = "@" + name
	}

	return name
}

// parseNPMLock parses package-lock.json or npm-shrinkwrap.json
func parseNPMLock(lockfile string, affected map[string]map[string]bool) ([]Package, bool, bool) {
	var packages []Package
	hasAffected := false
	hasWarnings := false

	content, err := os.ReadFile(lockfile)
	if err != nil {
		return packages, hasAffected, hasWarnings
	}

	var lockfileData map[string]interface{}
	if err := json.Unmarshal(content, &lockfileData); err != nil {
		return packages, hasAffected, hasWarnings
	}

	// Parse packages section
	if packagesData, ok := lockfileData["packages"].(map[string]interface{}); ok {
		for key, pkgData := range packagesData {
			if pkg, ok := pkgData.(map[string]interface{}); ok {
				if key == "" {
					continue // Skip root package
				}

				// Extract package name from path
				name := extractPackageNameFromPath(key)
				if name == "" {
					continue
				}

				if version, ok := pkg["version"].(string); ok {
					if affectedVersions, exists := affected[name]; exists {
						isAffected := affectedVersions[version]
						isWarning := !isAffected && len(affectedVersions) > 0

						if isAffected || isWarning {
							var affectedVers []string
							for v := range affectedVersions {
								affectedVers = append(affectedVers, v)
							}

							packages = append(packages, Package{
								Name:             name,
								Version:          version,
								IsAffected:       isAffected,
								IsWarning:        isWarning,
								AffectedVersions: affectedVers,
							})

							if isAffected {
								hasAffected = true
							}
							if isWarning {
								hasWarnings = true
							}
						}
					}
				}
			}
		}
	}

	return packages, hasAffected, hasWarnings
}

// extractPackageNameFromPath extracts package name from node_modules path
func extractPackageNameFromPath(path string) string {
	// Handle patterns like: node_modules/@scope/package, node_modules/package
	cleanPath := strings.TrimPrefix(path, "/")
	cleanPath = strings.TrimPrefix(cleanPath, "node_modules/")
	if cleanPath == "" {
		return ""
	}

	// Normalize scoped packages
	if strings.Contains(cleanPath, "/") && !strings.HasPrefix(cleanPath, "@") {
		cleanPath = "@" + cleanPath
	}

	return cleanPath
}

// parsePNMLock parses pnpm-lock.yaml
func parsePNMLock(lockfile string, affected map[string]map[string]bool) ([]Package, bool, bool) {
	var packages []Package
	hasAffected := false
	hasWarnings := false

	content, err := os.ReadFile(lockfile)
	if err != nil {
		return packages, hasAffected, hasWarnings
	}

	// PNPM lockfiles are YAML, but we can parse them with simple string processing
	lines := strings.Split(string(content), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Look for package entries like: /package-name@version:
		if strings.HasPrefix(line, "/") && strings.Contains(line, "@") && strings.HasSuffix(line, ":") {
			// Remove the leading / and trailing :
			entry := strings.TrimSuffix(strings.TrimPrefix(line, "/"), ":")

			// Split into package name and version
			atIndex := strings.LastIndex(entry, "@")
			if atIndex == -1 {
				continue
			}

			name := entry[:atIndex]
			version := entry[atIndex+1:]

			// Normalize scoped packages
			if strings.Contains(name, "/") && !strings.HasPrefix(name, "@") {
				name = "@" + name
			}

			if affectedVersions, exists := affected[name]; exists {
				isAffected := affectedVersions[version]
				isWarning := !isAffected && len(affectedVersions) > 0

				if isAffected || isWarning {
					var affectedVers []string
					for v := range affectedVersions {
						affectedVers = append(affectedVers, v)
					}

					packages = append(packages, Package{
						Name:             name,
						Version:          version,
						IsAffected:       isAffected,
						IsWarning:        isWarning,
						AffectedVersions: affectedVers,
					})

					if isAffected {
						hasAffected = true
					}
					if isWarning {
						hasWarnings = true
					}
				}
			}
		}
	}

	return packages, hasAffected, hasWarnings
}

// parseBunLock parses bun.lock
func parseBunLock(lockfile string, affected map[string]map[string]bool) ([]Package, bool, bool) {
	var packages []Package
	hasAffected := false
	hasWarnings := false

	content, err := os.ReadFile(lockfile)
	if err != nil {
		return packages, hasAffected, hasWarnings
	}

	// Try to parse as JSON first (bun.lock can be JSON)
	var lockfileData map[string]interface{}
	if err := json.Unmarshal(content, &lockfileData); err != nil {
		// If JSON parsing fails, it might be the binary format
		// For now, we'll skip binary bun.lock files
		return packages, hasAffected, hasWarnings
	}

	// Parse packages section
	if packagesData, ok := lockfileData["packages"].(map[string]interface{}); ok {
		for key, pkgData := range packagesData {
			if pkg, ok := pkgData.(map[string]interface{}); ok {
				if key == "" {
					continue // Skip root package
				}

				// Bun format: packages["package@version"] = {version: "x.y.z"}
				// Extract package name from key (remove version part)
				atIndex := strings.LastIndex(key, "@")
				if atIndex == -1 {
					continue
				}

				name := key[:atIndex]
				if version, ok := pkg["version"].(string); ok {
					// Normalize scoped packages
					if strings.Contains(name, "/") && !strings.HasPrefix(name, "@") {
						name = "@" + name
					}

					if affectedVersions, exists := affected[name]; exists {
						isAffected := affectedVersions[version]
						isWarning := !isAffected && len(affectedVersions) > 0

						if isAffected || isWarning {
							var affectedVers []string
							for v := range affectedVersions {
								affectedVers = append(affectedVers, v)
							}

							packages = append(packages, Package{
								Name:             name,
								Version:          version,
								IsAffected:       isAffected,
								IsWarning:        isWarning,
								AffectedVersions: affectedVers,
							})

							if isAffected {
								hasAffected = true
							}
							if isWarning {
								hasWarnings = true
							}
						}
					}
				}
			}
		}
	}

	return packages, hasAffected, hasWarnings
}

// printResults prints human-readable results
func printResults(result ScanResult, summaryOnly, quiet, onlyAffected, noColor bool, startTime time.Time) {
	if summaryOnly {
		printSummary(result, noColor)
		return
	}

	fmt.Println("═══════════════════════════════════════════════════════════════")
	colorPrint("🔍 SCAN RESULTS\n", "cyan", noColor)
	fmt.Println("═══════════════════════════════════════════════════════════════")

	if result.AnyAffected {
		colorPrint("❌ SECURITY ISSUE FOUND!\n", "red", noColor)
		colorPrint("Compromised packages detected - immediate action required\n\n", "red", noColor)
	} else if result.AnyWarnings {
		colorPrint("⚠️  VULNERABILITY WARNING\n", "yellow", noColor)
		colorPrint("Current versions are SAFE, but vulnerable versions exist\n\n", "yellow", noColor)
	} else {
		colorPrint("✅ SCAN PASSED\n", "green", noColor)
		colorPrint("No security issues detected\n\n", "green", noColor)
	}

	// Show affected packages first
	affectedCount := 0
	warningCount := 0

	for _, res := range result.Results {
		for _, pkg := range res.Packages {
			if pkg.IsAffected {
				affectedCount++
			} else if pkg.IsWarning {
				warningCount++
			}
		}
	}

	if affectedCount > 0 {
		colorPrint("Compromised packages:\n", "red", noColor)
		for _, res := range result.Results {
			for _, pkg := range res.Packages {
				if pkg.IsAffected {
					colorPrint(fmt.Sprintf("  %s@%s\n", pkg.Name, pkg.Version), "red", noColor)
					colorPrint(fmt.Sprintf("    in: %s\n", res.LockFile), "gray", noColor)
					if len(pkg.AffectedVersions) > 0 {
						colorPrint(fmt.Sprintf("    affected: %s\n", strings.Join(pkg.AffectedVersions, ", ")), "red", noColor)
					}
				}
			}
		}
		fmt.Println()
	}

	if warningCount > 0 {
		colorPrint("Packages with vulnerabilities:\n", "yellow", noColor)
		for _, res := range result.Results {
			for _, pkg := range res.Packages {
				if pkg.IsWarning {
					colorPrint(fmt.Sprintf("  %s@%s (current version is safe)\n", pkg.Name, pkg.Version), "yellow", noColor)
					colorPrint(fmt.Sprintf("    in: %s\n", res.LockFile), "gray", noColor)
					if len(pkg.AffectedVersions) > 0 {
						colorPrint(fmt.Sprintf("    vulnerable: %s\n", strings.Join(pkg.AffectedVersions, ", ")), "yellow", noColor)
					}
				}
			}
		}
		fmt.Println()
	}

	printSummary(result, noColor)

	elapsed := time.Since(startTime)
	fmt.Println("═══════════════════════════════════════════════════════════════")
	colorPrint(fmt.Sprintf("⏱️  Scan completed in %v\n", elapsed.Round(time.Millisecond)), "cyan", noColor)
	fmt.Println("═══════════════════════════════════════════════════════════════")
}

// printSummary prints the scan summary
func printSummary(result ScanResult, noColor bool) {
	colorPrint("📊 Scan Summary:\n", "cyan", noColor)
	colorPrint(fmt.Sprintf("   Lockfiles scanned: %d\n", result.Summary.TotalLockfiles), "white", noColor)
	colorPrint(fmt.Sprintf("   Package entries checked: %d\n", result.Summary.TotalPackages), "white", noColor)

	if result.Summary.TotalCompromised > 0 {
		colorPrint(fmt.Sprintf("   Compromised packages: ❌ %d\n", result.Summary.TotalCompromised), "red", noColor)
	} else {
		colorPrint("   Compromised packages: ✅ 0\n", "green", noColor)
	}

	if result.Summary.TotalWarnings > 0 {
		colorPrint(fmt.Sprintf("   Warning packages: ⚠️ %d\n", result.Summary.TotalWarnings), "yellow", noColor)
	} else {
		colorPrint("   Warning packages: ✅ 0\n", "green", noColor)
	}
}

// colorPrint prints colored output if supported
func colorPrint(text, color string, noColor bool) {
	if noColor {
		fmt.Print(text)
		return
	}

	// ANSI color codes
	colors := map[string]string{
		"red":    "\033[31m",
		"green":  "\033[32m",
		"yellow": "\033[33m",
		"blue":   "\033[34m",
		"cyan":   "\033[36m",
		"white":  "\033[37m",
		"gray":   "\033[90m",
		"reset":  "\033[0m",
	}

	if code, exists := colors[color]; exists {
		fmt.Print(code + text + colors["reset"])
	} else {
		fmt.Print(text)
	}
}