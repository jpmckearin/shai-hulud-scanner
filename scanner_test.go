package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseCommaSeparated(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"yarn,npm,pnpm", []string{"yarn", "npm", "pnpm"}},
		{"yarn, npm , pnpm ", []string{"yarn", "npm", "pnpm"}},
		{"", []string{}},
		{"single", []string{"single"}},
	}

	for _, test := range tests {
		result := parseCommaSeparated(test.input)
		if len(result) != len(test.expected) {
			t.Errorf("parseCommaSeparated(%q) = %v, want %v", test.input, result, test.expected)
			continue
		}
		for i, v := range result {
			if v != test.expected[i] {
				t.Errorf("parseCommaSeparated(%q) = %v, want %v", test.input, result, test.expected)
				break
			}
		}
	}
}

func TestLoadExploitedPackages(t *testing.T) {
	// Create temporary file with test data
	content := `# Comment line
left-pad@1.3.0
@scoped/package@2.0.0
babel/core@7.15.0
invalid-line
   spaced-package@1.0.0`

	tmpFile, err := os.CreateTemp("", "test-packages-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	result, err := loadExploitedPackages(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// Check that valid packages were parsed (left-pad, @scoped/package, babel/core, spaced-package)
	if len(result) != 4 {
		t.Errorf("Expected 4 packages, got %d", len(result))
	}

	// Check unscoped package
	if result["left-pad"] == nil {
		t.Error("Expected left-pad to be parsed")
	} else if !result["left-pad"]["1.3.0"] {
		t.Error("Expected left-pad@1.3.0 to be marked as affected")
	}

	// Check scoped package (with @ prefix)
	if result["@scoped/package"] == nil {
		t.Error("Expected @scoped/package to be parsed")
	} else if !result["@scoped/package"]["2.0.0"] {
		t.Error("Expected @scoped/package@2.0.0 to be marked as affected")
	}

	// Check scoped package (without @ prefix - should be normalized)
	if result["@babel/core"] == nil {
		t.Error("Expected @babel/core to be parsed (normalized from babel/core)")
	} else if !result["@babel/core"]["7.15.0"] {
		t.Error("Expected @babel/core@7.15.0 to be marked as affected")
	}

	// Check spaced package (leading spaces should be trimmed)
	if result["spaced-package"] == nil {
		t.Error("Expected spaced-package to be parsed")
	} else if !result["spaced-package"]["1.0.0"] {
		t.Error("Expected spaced-package@1.0.0 to be marked as affected")
	}
}

func TestShouldIncludePath(t *testing.T) {
	tests := []struct {
		path     string
		rootDir  string
		include  []string
		exclude  []string
		expected bool
	}{
		{"/app/src/main.go", "/app", []string{}, []string{}, true},
		{"/app/node_modules/package.json", "/app", []string{}, []string{"**/node_modules/**"}, false},
		{"/app/src/app.js", "/app", []string{"src/**"}, []string{}, true},
		{"/app/dist/app.js", "/app", []string{"src/**"}, []string{}, false},
		{"/app/src/main.go", "/app", []string{"src/**"}, []string{"**/node_modules/**"}, true},
	}

	for _, test := range tests {
		result := shouldIncludePath(test.path, test.rootDir, test.include, test.exclude)
		if result != test.expected {
			t.Errorf("shouldIncludePath(%q, %q, %v, %v) = %v, want %v",
				test.path, test.rootDir, test.include, test.exclude, result, test.expected)
		}
	}
}

func TestExtractPackageNameFromYarnHeader(t *testing.T) {
	tests := []struct {
		header   string
		expected string
	}{
		{"left-pad@^1.0.0:", "left-pad"},
		{"@scoped/package@^2.0.0, @scoped/package@^2.1.0:", "@scoped/package"},
		{"package@^1.0.0:", "package"},
	}

	for _, test := range tests {
		result := extractPackageNameFromYarnHeader(test.header)
		if result != test.expected {
			t.Errorf("extractPackageNameFromYarnHeader(%q) = %q, want %q",
				test.header, result, test.expected)
		}
	}
}

func TestExtractPackageNameFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"node_modules/left-pad", "left-pad"},
		{"node_modules/@scoped/package", "@scoped/package"},
		{"packages/left-pad", "@packages/left-pad"}, // Function adds @ for scoped-like paths
		{"", ""},
	}

	for _, test := range tests {
		result := extractPackageNameFromPath(test.path)
		if result != test.expected {
			t.Errorf("extractPackageNameFromPath(%q) = %q, want %q",
				test.path, result, test.expected)
		}
	}
}

func TestScanLockfile(t *testing.T) {
	// Create temporary package-lock.json
	content := `{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/left-pad": {
				"version": "1.3.0",
				"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
			},
			"node_modules/safe-package": {
				"version": "1.0.0"
			}
		}
	}`

	// Create temp file path and close it immediately
	tmpFile, err := os.CreateTemp("", "package-lock-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close() // Close immediately to release handle on Windows
	defer os.Remove(tmpFile.Name())

	// Rename to exact filename that scanLockfile expects
	exactName := strings.Replace(tmpFile.Name(), filepath.Base(tmpFile.Name()), "package-lock.json", 1)
	if err := os.Rename(tmpFile.Name(), exactName); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(exactName)

	if err := os.WriteFile(exactName, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Create affected packages map
	affected := map[string]map[string]bool{
		"left-pad": {"1.3.0": true},
	}

	packages, hasAffected, hasWarnings := scanLockfile(exactName, affected)

	if !hasAffected {
		t.Error("Expected to find affected packages")
	}
	if hasWarnings {
		t.Error("Expected no warnings")
	}
	if len(packages) != 1 {
		t.Errorf("Expected 1 package, got %d", len(packages))
	}
	if len(packages) > 0 {
		if packages[0].Name != "left-pad" {
			t.Errorf("Expected package name 'left-pad', got %s", packages[0].Name)
		}
		if !packages[0].IsAffected {
			t.Error("Expected package to be marked as affected")
		}
	}
}

func TestJSONOutputFormat(t *testing.T) {
	// Test that JSON output matches expected format
	result := ScanResult{
		Root: "/test",
		Results: []Result{
			{
				LockFile: "package-lock.json",
				Packages: []Package{
					{
						Name:    "left-pad",
						Version: "1.3.0",
						IsAffected: true,
						AffectedVersions: []string{"1.3.0"},
					},
				},
			},
		},
		AnyAffected: true,
		AnyWarnings: false,
		Summary: Summary{
			TotalLockfiles:   1,
			TotalPackages:    1,
			TotalWarnings:    0,
			TotalCompromised: 1,
		},
	}

	jsonOutput, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	var parsed ScanResult
	if err := json.Unmarshal(jsonOutput, &parsed); err != nil {
		t.Fatal(err)
	}

	if parsed.Root != result.Root {
		t.Errorf("Root mismatch: got %s, want %s", parsed.Root, result.Root)
	}
	if parsed.AnyAffected != result.AnyAffected {
		t.Errorf("AnyAffected mismatch: got %v, want %v", parsed.AnyAffected, result.AnyAffected)
	}
	if parsed.Summary.TotalCompromised != result.Summary.TotalCompromised {
		t.Errorf("TotalCompromised mismatch: got %d, want %d",
			parsed.Summary.TotalCompromised, result.Summary.TotalCompromised)
	}
}

func TestMatchesGlobPattern(t *testing.T) {
	tests := []struct {
		path     string
		pattern  string
		expected bool
	}{
		{"src/main.go", "src/**", true},
		{"src/nested/file.go", "src/**", true},
		{"dist/main.go", "src/**", false},
		{"node_modules/package.json", "**/node_modules/**", true},
		{"src/node_modules/package.json", "**/node_modules/**", true},
		{"src/main.go", "**/node_modules/**", false},
	}

	for _, test := range tests {
		result := matchesGlobPattern(test.path, test.pattern)
		if result != test.expected {
			t.Errorf("matchesGlobPattern(%q, %q) = %v, want %v",
				test.path, test.pattern, result, test.expected)
		}
	}
}

func BenchmarkScanLockfile(b *testing.B) {
	// Create a larger package-lock.json for benchmarking
	content := `{
		"lockfileVersion": 2,
		"packages": {`

	for i := 0; i < 100; i++ {
		content += fmt.Sprintf(`
			"node_modules/package%d": {
				"version": "1.0.%d"
			}`, i, i)
		if i < 99 {
			content += ","
		}
	}
	content += `
		}
	}`

	tmpFile, err := os.CreateTemp("", "bench-package-lock-*.json")
	if err != nil {
		b.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		b.Fatal(err)
	}
	tmpFile.Close()

	affected := make(map[string]map[string]bool)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanLockfile(tmpFile.Name(), affected)
	}
}

// Test error handling for missing exploited packages file
func TestLoadExploitedPackagesFileNotFound(t *testing.T) {
	_, err := loadExploitedPackages("/nonexistent/file.txt")
	if err == nil {
		t.Error("Expected error for non-existent file")
	}
}

// Test warning scenarios - packages that exist in exploited list but different versions
func TestScanLockfileWarnings(t *testing.T) {
	content := `{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/left-pad": {
				"version": "1.2.0"
			},
			"node_modules/@scoped/package": {
				"version": "2.1.0"
			}
		}
	}`

	// Create temp file path and close it immediately
	tmpFile, err := os.CreateTemp("", "warning-test-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close() // Close immediately to release handle on Windows
	defer os.Remove(tmpFile.Name())

	// Rename to exact filename that scanLockfile expects
	exactName := strings.Replace(tmpFile.Name(), filepath.Base(tmpFile.Name()), "package-lock.json", 1)
	if err := os.Rename(tmpFile.Name(), exactName); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(exactName)

	if err := os.WriteFile(exactName, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Create affected packages map with different versions
	affected := map[string]map[string]bool{
		"left-pad":         {"1.3.0": true},
		"@scoped/package": {"2.0.0": true, "2.2.0": true},
	}

	packages, hasAffected, hasWarnings := scanLockfile(exactName, affected)

	if hasAffected {
		t.Error("Expected no affected packages")
	}
	if !hasWarnings {
		t.Error("Expected warnings for version mismatches")
	}
	if len(packages) != 2 {
		t.Errorf("Expected 2 packages, got %d", len(packages))
	}

	// Check that packages are marked as warnings
	for _, pkg := range packages {
		if !pkg.IsWarning {
			t.Errorf("Expected package %s to be marked as warning", pkg.Name)
		}
		if pkg.IsAffected {
			t.Errorf("Expected package %s to not be marked as affected", pkg.Name)
		}
	}
}

// Test Yarn lockfile parsing
func TestParseYarnLock(t *testing.T) {
	content := `# yarn lockfile v1
left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz"

@scoped/package@^2.0.0:
  version "2.0.0"
  resolved "https://registry.yarnpkg.com/@scoped/package/-/package-2.0.0.tgz"
`

	// Create temp file path and close it immediately
	tmpFile, err := os.CreateTemp("", "yarn-*.lock")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close() // Close immediately to release handle on Windows
	defer os.Remove(tmpFile.Name())

	// Rename to exact filename that scanLockfile expects
	exactName := strings.Replace(tmpFile.Name(), filepath.Base(tmpFile.Name()), "yarn.lock", 1)
	if err := os.Rename(tmpFile.Name(), exactName); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(exactName)

	if err := os.WriteFile(exactName, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	affected := map[string]map[string]bool{
		"left-pad":        {"1.3.0": true},
		"@scoped/package": {"2.0.0": true},
	}

	packages, hasAffected, hasWarnings := scanLockfile(exactName, affected)

	if !hasAffected {
		t.Error("Expected to find affected packages")
	}
	if hasWarnings {
		t.Error("Expected no warnings")
	}
	if len(packages) != 2 {
		t.Errorf("Expected 2 packages, got %d", len(packages))
	}
}

// Test pnpm lockfile parsing
func TestParsePnpmLock(t *testing.T) {
	content := `lockfileVersion: 5.4

packages:
  /left-pad@1.3.0:
    resolution: {integrity: sha512-...}
    engines: {node: '>=0.10.0'}

  /@scoped/package@2.0.0:
    resolution: {integrity: sha512-...}
    engines: {node: '>=0.10.0'}
`

	// Create temp file path and close it immediately
	tmpFile, err := os.CreateTemp("", "pnpm-lock-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close() // Close immediately to release handle on Windows
	defer os.Remove(tmpFile.Name())

	// Rename to exact filename that scanLockfile expects
	exactName := strings.Replace(tmpFile.Name(), filepath.Base(tmpFile.Name()), "pnpm-lock.yaml", 1)
	if err := os.Rename(tmpFile.Name(), exactName); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(exactName)

	if err := os.WriteFile(exactName, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	affected := map[string]map[string]bool{
		"left-pad":        {"1.3.0": true},
		"@scoped/package": {"2.0.0": true},
	}

	packages, hasAffected, hasWarnings := scanLockfile(exactName, affected)

	if !hasAffected {
		t.Error("Expected to find affected packages")
	}
	if hasWarnings {
		t.Error("Expected no warnings")
	}
	if len(packages) != 2 {
		t.Errorf("Expected 2 packages, got %d", len(packages))
	}
}

// Test malformed JSON handling
func TestScanMalformedJSON(t *testing.T) {
	content := `{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/left-pad": {
				"version": "1.3.0",
				"resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
			},
			"node_modules/safe-package": {
				"version": "1.0.0"
			}
		}
		// Missing closing brace - malformed JSON
	`

	tmpFile, err := os.CreateTemp("", "malformed-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	affected := map[string]map[string]bool{
		"left-pad": {"1.3.0": true},
	}

	packages, hasAffected, _ := scanLockfile(tmpFile.Name(), affected)

	// Should handle malformed JSON gracefully
	if hasAffected {
		t.Error("Expected no affected packages due to malformed JSON")
	}
	if len(packages) > 0 {
		t.Errorf("Expected no packages due to malformed JSON, got %d", len(packages))
	}
}

// Test version flag
func TestVersionFlag(t *testing.T) {
	// This test would require capturing stdout, which is complex in Go testing
	// For now, just ensure the Version constant is set
	if Version == "" {
		t.Error("Version constant should not be empty")
	}
}

// Test invalid manager validation
func TestInvalidManager(t *testing.T) {
	// Test would require setting up flag parsing
	// This is more of an integration test that would be covered by the action tests
	t.Skip("Manager validation is tested in action integration")
}

// Test large lockfile performance
func TestLargeLockfile(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large lockfile test in short mode")
	}

	// Create a large package-lock.json with many packages
	content := `{
		"lockfileVersion": 2,
		"packages": {`

	for i := 0; i < 1000; i++ {
		content += fmt.Sprintf(`
			"node_modules/package%d": {
				"version": "1.0.%d"
			}`, i, i%10)
		if i < 999 {
			content += ","
		}
	}
	content += `
		}
	}`

	// Create temp file path and close it immediately
	tmpFile, err := os.CreateTemp("", "large-package-lock-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close() // Close immediately to release handle on Windows
	defer os.Remove(tmpFile.Name())

	// Rename to exact filename that scanLockfile expects
	exactName := strings.Replace(tmpFile.Name(), filepath.Base(tmpFile.Name()), "package-lock.json", 1)
	if err := os.Rename(tmpFile.Name(), exactName); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(exactName)

	if err := os.WriteFile(exactName, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	affected := map[string]map[string]bool{
		"package5": {"1.0.5": true},
	}

	packages, hasAffected, hasWarnings := scanLockfile(exactName, affected)

	if !hasAffected {
		t.Error("Expected to find affected package")
	}
	if hasWarnings {
		t.Error("Expected no warnings")
	}
	if len(packages) != 1 {
		t.Errorf("Expected 1 affected package, got %d", len(packages))
	}
}

// Test mixed package types (regular and scoped)
func TestMixedPackageTypes(t *testing.T) {
	content := `{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/left-pad": {
				"version": "1.3.0"
			},
			"node_modules/@babel/core": {
				"version": "7.20.0"
			},
			"node_modules/@scoped/package": {
				"version": "2.0.0"
			}
		}
	}`

	// Create temp file path and close it immediately
	tmpFile, err := os.CreateTemp("", "mixed-packages-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close() // Close immediately to release handle on Windows
	defer os.Remove(tmpFile.Name())

	// Rename to exact filename that scanLockfile expects
	exactName := strings.Replace(tmpFile.Name(), filepath.Base(tmpFile.Name()), "package-lock.json", 1)
	if err := os.Rename(tmpFile.Name(), exactName); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(exactName)

	if err := os.WriteFile(exactName, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	affected := map[string]map[string]bool{
		"left-pad":        {"1.3.0": true},
		"@babel/core":    {"7.20.0": true},
		"@scoped/package": {"2.0.0": true},
	}

	packages, hasAffected, hasWarnings := scanLockfile(exactName, affected)

	if !hasAffected {
		t.Error("Expected to find affected packages")
	}
	if hasWarnings {
		t.Error("Expected no warnings")
	}
	if len(packages) != 3 {
		t.Errorf("Expected 3 packages, got %d", len(packages))
	}

	// Verify all package types are handled correctly
	found := make(map[string]bool)
	for _, pkg := range packages {
		found[pkg.Name] = true
		if !pkg.IsAffected {
			t.Errorf("Expected package %s to be affected", pkg.Name)
		}
	}

	expected := []string{"left-pad", "@babel/core", "@scoped/package"}
	for _, name := range expected {
		if !found[name] {
			t.Errorf("Expected to find package %s", name)
		}
	}
}

// Test edge case: empty lockfile
func TestEmptyLockfile(t *testing.T) {
	content := `{
		"lockfileVersion": 2,
		"packages": {}
	}`

	tmpFile, err := os.CreateTemp("", "empty-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	affected := map[string]map[string]bool{
		"left-pad": {"1.3.0": true},
	}

	packages, hasAffected, hasWarnings := scanLockfile(tmpFile.Name(), affected)

	if hasAffected {
		t.Error("Expected no affected packages in empty lockfile")
	}
	if hasWarnings {
		t.Error("Expected no warnings in empty lockfile")
	}
	if len(packages) != 0 {
		t.Errorf("Expected no packages in empty lockfile, got %d", len(packages))
	}
}

// Test edge case: lockfile with only root package
func TestRootOnlyLockfile(t *testing.T) {
	content := `{
		"lockfileVersion": 2,
		"packages": {
			"": {
				"version": "1.0.0"
			}
		}
	}`

	tmpFile, err := os.CreateTemp("", "root-only-*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	affected := map[string]map[string]bool{
		"root-package": {"1.0.0": true},
	}

	packages, hasAffected, hasWarnings := scanLockfile(tmpFile.Name(), affected)

	if hasAffected {
		t.Error("Expected no affected packages (root package should be ignored)")
	}
	if hasWarnings {
		t.Error("Expected no warnings")
	}
	if len(packages) != 0 {
		t.Errorf("Expected no packages (root should be ignored), got %d", len(packages))
	}
}

// Test semantic versioning edge cases
func TestSemanticVersionEdgeCases(t *testing.T) {
	content := `{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/package1": {
				"version": "1.0.0"
			},
			"node_modules/package2": {
				"version": "1.0.0-rc.1"
			},
			"node_modules/package3": {
				"version": "1.0.0+build.1"
			},
			"node_modules/package4": {
				"version": "2.0.0-alpha.1"
			}
		}
	}`

	// Create temp file path and close it immediately
	tmpFile, err := os.CreateTemp("", "semver-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close() // Close immediately to release handle on Windows
	defer os.Remove(tmpFile.Name())

	// Rename to exact filename that scanLockfile expects
	exactName := strings.Replace(tmpFile.Name(), filepath.Base(tmpFile.Name()), "package-lock.json", 1)
	if err := os.Rename(tmpFile.Name(), exactName); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(exactName)

	if err := os.WriteFile(exactName, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	affected := map[string]map[string]bool{
		"package1": {"1.0.0": true},
		"package2": {"1.0.0-rc.1": true},
		"package3": {"1.0.0+build.1": true},
		"package4": {"2.0.0-alpha.1": true},
	}

	packages, hasAffected, hasWarnings := scanLockfile(exactName, affected)

	if !hasAffected {
		t.Error("Expected to find affected packages")
	}
	if hasWarnings {
		t.Error("Expected no warnings")
	}
	if len(packages) != 4 {
		t.Errorf("Expected 4 packages, got %d", len(packages))
	}

	// Verify all packages are found correctly
	found := make(map[string]string)
	for _, pkg := range packages {
		found[pkg.Name] = pkg.Version
	}

	expected := map[string]string{
		"package1": "1.0.0",
		"package2": "1.0.0-rc.1",
		"package3": "1.0.0+build.1",
		"package4": "2.0.0-alpha.1",
	}

	for name, version := range expected {
		if found[name] != version {
			t.Errorf("Expected package %s version %s, got %s", name, version, found[name])
		}
	}
}

// Test multiple affected versions for same package
func TestMultipleAffectedVersions(t *testing.T) {
	content := `{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/vulnerable-pkg": {
				"version": "1.2.0"
			},
			"node_modules/safe-pkg": {
				"version": "2.0.0"
			}
		}
	}`

	// Create temp file path and close it immediately
	tmpFile, err := os.CreateTemp("", "multi-version-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close() // Close immediately to release handle on Windows
	defer os.Remove(tmpFile.Name())

	// Rename to exact filename that scanLockfile expects
	exactName := strings.Replace(tmpFile.Name(), filepath.Base(tmpFile.Name()), "package-lock.json", 1)
	if err := os.Rename(tmpFile.Name(), exactName); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(exactName)

	if err := os.WriteFile(exactName, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	affected := map[string]map[string]bool{
		"vulnerable-pkg": {"1.0.0": true, "1.1.0": true, "1.2.0": true, "1.3.0": true},
		"safe-pkg":      {"1.0.0": true, "2.1.0": true},
	}

	packages, hasAffected, hasWarnings := scanLockfile(exactName, affected)

	if !hasAffected {
		t.Error("Expected to find affected packages")
	}
	if !hasWarnings {
		t.Error("Expected warnings for safe-pkg with non-matching version")
	}
	if len(packages) != 2 {
		t.Errorf("Expected 2 packages (1 affected, 1 warning), got %d", len(packages))
	}

	// Find vulnerable-pkg and safe-pkg in results
	var vulnerablePkg, safePkg *Package
	for i := range packages {
		if packages[i].Name == "vulnerable-pkg" {
			vulnerablePkg = &packages[i]
		} else if packages[i].Name == "safe-pkg" {
			safePkg = &packages[i]
		}
	}

	if vulnerablePkg == nil {
		t.Error("vulnerable-pkg not found in results")
	} else {
		if vulnerablePkg.Version != "1.2.0" {
			t.Errorf("Expected vulnerable-pkg version 1.2.0, got %s", vulnerablePkg.Version)
		}
		if len(vulnerablePkg.AffectedVersions) != 4 {
			t.Errorf("Expected 4 affected versions for vulnerable-pkg, got %d", len(vulnerablePkg.AffectedVersions))
		}
		if !vulnerablePkg.IsAffected {
			t.Error("vulnerable-pkg should be marked as affected")
		}
	}

	if safePkg == nil {
		t.Error("safe-pkg not found in results")
	} else {
		if safePkg.Version != "2.0.0" {
			t.Errorf("Expected safe-pkg version 2.0.0, got %s", safePkg.Version)
		}
		if len(safePkg.AffectedVersions) != 2 {
			t.Errorf("Expected 2 affected versions for safe-pkg, got %d", len(safePkg.AffectedVersions))
		}
		if !safePkg.IsWarning {
			t.Error("safe-pkg should be marked as warning")
		}
	}
}

// Test case sensitivity in package names
func TestCaseSensitivity(t *testing.T) {
	content := `{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/Left-Pad": {
				"version": "1.3.0"
			},
			"node_modules/LEFT-PAD": {
				"version": "1.3.0"
			}
		}
	}`

	// Create temp file path and close it immediately
	tmpFile, err := os.CreateTemp("", "case-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close() // Close immediately to release handle on Windows
	defer os.Remove(tmpFile.Name())

	// Rename to exact filename that scanLockfile expects
	exactName := strings.Replace(tmpFile.Name(), filepath.Base(tmpFile.Name()), "package-lock.json", 1)
	if err := os.Rename(tmpFile.Name(), exactName); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(exactName)

	if err := os.WriteFile(exactName, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	affected := map[string]map[string]bool{
		"Left-Pad": {"1.3.0": true}, // Match case of first package in lockfile
	}

	packages, hasAffected, _ := scanLockfile(exactName, affected)

	// Should find the first case variant that matches
	if !hasAffected {
		t.Error("Expected to find affected packages")
	}
	if len(packages) != 1 {
		t.Errorf("Expected 1 package (matching case), got %d", len(packages))
	}
}

// Test embedded exploited packages functionality
func TestEmbeddedExploitedPackages(t *testing.T) {
	// Test that embedded packages can be loaded
	affected, err := loadEmbeddedExploitedPackages()
	if err != nil {
		t.Fatalf("Failed to load embedded packages: %v", err)
	}

	if len(affected) == 0 {
		t.Error("Embedded packages should not be empty")
	}

	// Verify some expected packages exist in embedded list
	expectedPackages := []string{"ace-colorpicker-rpk", "@ahmedhfarag/ngx-perfect-scrollbar", "angulartics2"}
	for _, pkg := range expectedPackages {
		if versions, exists := affected[pkg]; !exists || len(versions) == 0 {
			t.Errorf("Expected package %s not found in embedded list", pkg)
		}
	}
}

// Test output formatting with different modes
func TestOutputFormatting(t *testing.T) {
	// This is more of an integration test, but we can test the data structures
	result := ScanResult{
		Root:    "/test/path",
		Results: []Result{},
		Summary: Summary{TotalLockfiles: 5, TotalPackages: 100, TotalCompromised: 2, TotalWarnings: 3},
	}

	// Test JSON marshaling
	jsonData, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	var unmarshaled ScanResult
	if err := json.Unmarshal(jsonData, &unmarshaled); err != nil {
		t.Fatal(err)
	}

	if unmarshaled.Summary.TotalCompromised != 2 {
		t.Error("JSON marshaling/unmarshaling failed for compromised count")
	}
	if unmarshaled.Summary.TotalWarnings != 3 {
		t.Error("JSON marshaling/unmarshaling failed for warnings count")
	}
}

// Test comprehensive end-to-end scenario
func TestEndToEndScenario(t *testing.T) {
	// Create a comprehensive lockfile
	content := `{
		"lockfileVersion": 2,
		"packages": {
			"node_modules/lodash": {
				"version": "4.17.20"
			},
			"node_modules/react": {
				"version": "17.0.2"
			},
			"node_modules/@babel/core": {
				"version": "7.15.0"
			},
			"node_modules/shai-hulud-victim": {
				"version": "1.0.0"
			},
			"node_modules/safe-package": {
				"version": "2.0.0"
			},
			"node_modules/outdated-safe": {
				"version": "1.0.0"
			}
		}
	}`

	// Create temp file path and close it immediately
	tmpFile, err := os.CreateTemp("", "end-to-end-*.json")
	if err != nil {
		t.Fatal(err)
	}
	tmpFile.Close() // Close immediately to release handle on Windows
	defer os.Remove(tmpFile.Name())

	// Rename to exact filename that scanLockfile expects
	exactName := strings.Replace(tmpFile.Name(), filepath.Base(tmpFile.Name()), "package-lock.json", 1)
	if err := os.Rename(tmpFile.Name(), exactName); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(exactName)

	if err := os.WriteFile(exactName, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	// Create affected packages list that includes some real-world scenarios
	affected := map[string]map[string]bool{
		"lodash":            {"4.17.20": true, "4.17.21": true}, // Real vulnerability
		"shai-hulud-victim": {"1.0.0": true},                   // Hypothetical victim
		"@babel/core":       {"7.14.0": true, "7.15.1": true},  // Different version
		"safe-package":      {"1.0.0": true},                   // Different version
		"outdated-safe":     {"1.0.0": true, "1.5.0": true},    // Current is safe
	}

	packages, hasAffected, hasWarnings := scanLockfile(exactName, affected)

	if !hasAffected {
		t.Error("Expected to find affected packages")
	}
	if !hasWarnings {
		t.Error("Expected to find warnings for version mismatches")
	}

	// Should find both affected packages and warnings
	affectedCount := 0
	warningCount := 0
	for _, pkg := range packages {
		if pkg.IsAffected {
			affectedCount++
		}
		if pkg.IsWarning {
			warningCount++
		}
	}

	if affectedCount != 3 { // lodash, shai-hulud-victim, and outdated-safe
		t.Errorf("Expected 3 affected packages, got %d", affectedCount)
	}

	if warningCount != 2 { // @babel/core and safe-package (different versions)
		t.Errorf("Expected 2 warning packages, got %d", warningCount)
	}
}