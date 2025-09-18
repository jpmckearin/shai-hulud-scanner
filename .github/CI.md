# GitHub Actions CI/CD

This repository includes GitHub Actions workflows for automated testing of the shai-hulud-scanner Go implementation.

## Workflows

### 1. `test.yml` - Main Test Workflow

- **Triggers**: Push and Pull Requests to `main` and `develop` branches
- **Platform**: Ubuntu Latest
- **Go Version**: 1.22
- **Features**:
  - Runs comprehensive Go unit tests (`go test -v ./...`)
  - Builds scanner binary for validation
  - Tests scanner execution with sample data
  - Publishes test results summary to GitHub Step Summary

### 2. `test-matrix.yml` - Cross-Platform Testing

- **Triggers**: Push and Pull Requests to `main` and `develop` branches
- **Platforms**: Ubuntu, Windows, and macOS (latest versions)
- **Go Versions**: 1.21 and 1.22 (matrix testing)
- **Features**:
  - Tests compatibility across all major operating systems
  - Matrix strategy for comprehensive testing
  - Validates Go version compatibility
  - Individual GitHub Step Summary per platform/version combination

### 3. `quick-test.yml` - Quick Testing

- **Triggers**:
  - Manual dispatch (workflow_dispatch)
  - Pushes to `main` branch (only when core Go files change)
- **Platform**: Ubuntu Latest
- **Features**:
  - Path-based triggers for core files (`scanner.go`, `scanner_test.go`, `go.mod`, `action.yml`)
  - Manual trigger for on-demand testing
  - Optimized for rapid feedback during development

## Test Configuration

The tests use Go's built-in testing framework with the following features:

- **Test Framework**: Native Go testing (`testing` package)
- **Test Discovery**: Automatic discovery of `*_test.go` files
- **Coverage**: Comprehensive test coverage for core functionality
- **Parallel Execution**: Tests run in parallel for faster execution

## Running Tests Locally

To run the tests locally:

```bash
# Run all tests with verbose output
go test -v ./...

# Run tests with coverage report
go test -v -cover ./...

# Run specific test function
go test -v -run TestLoadExploitedPackages

# Build and test the scanner
go build -o scanner scanner.go
./scanner --help
./scanner --list-path exploited_packages.txt --root-dir . --json
```

## Test Results

Test results are automatically:

1. **Published to GitHub Step Summary** with execution status
2. **Validated for functionality** - builds and executes scanner
3. **Cross-platform verified** - tests compatibility across OSes
4. **Go version tested** - ensures compatibility with multiple Go versions

## Package Manager Support

The tests verify support for all major JavaScript package managers:

- ✅ npm (`package-lock.json`, `npm-shrinkwrap.json`)
- ✅ yarn (`yarn.lock`)
- ✅ pnpm (`pnpm-lock.yaml`)
- ✅ bun (`bun.lock`)

## Continuous Integration Benefits

- **Automated Testing**: Every PR and push is automatically tested
- **Cross-Platform Validation**: Ensures compatibility across operating systems
- **Multi-Version Go Support**: Tests against multiple Go versions
- **Fast Feedback**: Quick identification of issues before merging
- **Binary Validation**: Ensures scanner builds and executes correctly
- **Quality Gates**: Prevents merging of broken code

## Performance Characteristics

- **Test Execution**: ~10-30 seconds (much faster than PowerShell/Pester)
- **Binary Build**: ~5-15 seconds
- **Cross-Platform Matrix**: ~2-5 minutes total
- **No Dependencies**: Uses only Go's standard library and built-in tools
