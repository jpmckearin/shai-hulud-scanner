# GitHub Actions CI/CD

This repository includes GitHub Actions workflows for automated testing of the shai-hulud-scanner PowerShell script.

## Workflows

### 1. `test.yml` - Main Test Workflow

- **Triggers**: Push and Pull Requests to `main` and `develop` branches
- **Platform**: Ubuntu Latest
- **PowerShell**: Uses system default (PowerShell 7.x)
- **Features**:
  - Uses pre-installed Pester framework (no manual installation)
  - Runs all integration tests via `tests/Run-Pester.ps1`
  - Uploads test results as artifacts (30-day retention)
  - Publishes test results summary to GitHub Step Summary
  - Automatic TestResults directory creation

### 2. `test-matrix.yml` - Cross-Platform Testing

- **Triggers**: Push and Pull Requests to `main` and `develop` branches
- **Platforms**: Ubuntu, Windows, and macOS (latest versions)
- **PowerShell**: Version 7.4 (explicitly specified in matrix)
- **Features**:
  - Tests compatibility across all major operating systems
  - Matrix strategy for comprehensive testing
  - Platform-specific test result artifacts (30-day retention)
  - Individual GitHub Step Summary per platform

### 3. `quick-test.yml` - Quick Testing

- **Triggers**:
  - Manual dispatch (workflow_dispatch)
  - Pushes to `main` branch (only when `scan-shai-hulud.ps1` or `tests/**` files change)
- **Platform**: Ubuntu Latest
- **Features**:
  - Path-based triggers to avoid unnecessary runs
  - Manual trigger for on-demand testing
  - Shorter artifact retention (7 days vs 30)
  - Optimized for rapid feedback during development

## Test Configuration

The tests use Pester 5.x with the following configuration:

- **Test Path**: `./tests/`
- **Output Format**: NUnit XML
- **Results Location**: `./TestResults/Pester-TestResults.xml`
- **Verbosity**: Normal

## Running Tests Locally

To run the tests locally:

```powershell
# Install Pester if not already installed
Install-Module -Name Pester -Force -SkipPublisherCheck -AllowClobber

# Run all tests
pwsh -File tests/Run-Pester.ps1

# Run specific test tags
pwsh -File tests/Run-Pester.ps1 -Tags Integration
```

## Test Results

Test results are automatically:

1. **Uploaded as artifacts** for download and inspection
2. **Published to GitHub Step Summary** with parsed test statistics
3. **Retained for 30 days** in main workflows (7 days for quick-test)
4. **Platform-specific artifacts** in matrix builds for cross-platform analysis

## Package Manager Support

The tests verify support for all major JavaScript package managers:

- ✅ npm (`package-lock.json`, `npm-shrinkwrap.json`)
- ✅ yarn (`yarn.lock`)
- ✅ pnpm (`pnpm-lock.yaml`)
- ✅ bun (`bun.lock`)

## Continuous Integration Benefits

- **Automated Testing**: Every PR and push is automatically tested
- **Cross-Platform Validation**: Ensures compatibility across operating systems
- **Fast Feedback**: Quick identification of issues before merging
- **Test Artifacts**: Detailed test results available for debugging
- **Quality Gates**: Prevents merging of broken code
