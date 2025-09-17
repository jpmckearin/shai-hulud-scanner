# GitHub Actions CI/CD

This repository includes GitHub Actions workflows for automated testing of the shai-hulud-scanner PowerShell script.

## Workflows

### 1. `test.yml` - Main Test Workflow

- **Triggers**: Push and Pull Requests to `main` and `develop` branches
- **Platform**: Ubuntu Latest
- **PowerShell**: Version 7.4
- **Features**:
  - Installs Pester testing framework
  - Runs all integration tests
  - Uploads test results as artifacts
  - Publishes test results to GitHub

### 2. `test-matrix.yml` - Cross-Platform Testing

- **Triggers**: Push and Pull Requests to `main` and `develop` branches
- **Platforms**: Ubuntu, Windows, and macOS
- **PowerShell**: Version 7.4
- **Features**:
  - Tests compatibility across all major operating systems
  - Matrix strategy for comprehensive testing
  - Separate test result artifacts per platform

### 3. `quick-test.yml` - Quick Testing

- **Triggers**: Manual dispatch and pushes to `main` (only when script files change)
- **Platform**: Ubuntu Latest
- **Features**:
  - Lightweight testing for quick feedback
  - Manual trigger for on-demand testing
  - Path-based triggers to avoid unnecessary runs

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
2. **Published to GitHub** for inline viewing in PRs
3. **Retained for 30 days** in the artifacts

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
