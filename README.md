# Shai-Hulud Scanner

[![Test](https://github.com/jpmckearin/shai-hulud-scanner/actions/workflows/test.yml/badge.svg)](https://github.com/jpmckearin/shai-hulud-scanner/actions/workflows/test.yml)
[![Test Matrix](https://github.com/jpmckearin/shai-hulud-scanner/actions/workflows/test-matrix.yml/badge.svg)](https://github.com/jpmckearin/shai-hulud-scanner/actions/workflows/test-matrix.yml)
[![Quick Test](https://github.com/jpmckearin/shai-hulud-scanner/actions/workflows/quick-test.yml/badge.svg)](https://github.com/jpmckearin/shai-hulud-scanner/actions/workflows/quick-test.yml)

A PowerShell script that scans JavaScript/TypeScript lockfiles for known shai-hulud-affected packages.

## Description

Recursively scans under a root directory for lockfiles (yarn.lock, package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, bun.lock), compares resolved packages to a provided list of package@version entries, and reports matches. Output includes which installs are affected vs safe, with options for filtering, color/verbosity, JSON output, and CI-friendly exit codes.

## Usage

```powershell
pwsh -File .\scan-shai-hulud.ps1 -ListPath <String> -RootDir <String> [<CommonParameters>]
```

### Required Parameters

- **-ListPath** `<String>` - Path to a text file containing one package@version per line (comments with # are allowed)
- **-RootDir** `<String>` - Root directory to scan recursively for lockfiles

### Optional Parameters

- **-Include** `<String[]>` - Glob(s) to include, relative to RootDir (e.g. src/**, apps/*). When provided, only paths matching at least one include glob are scanned. Include narrows the scan set and does not override Exclude.
- **-Exclude** `<String[]>` - Glob(s) to exclude, relative to RootDir. Defaults: `**/node_modules/**`, `**/.pnpm-store/**`, `**/dist/**`, `**/build/**`, `**/tmp/**`, `**/.turbo/**`. Exclude is applied first and cannot be overridden by Include.
- **-Managers** `<String[]>` - One or more of: yarn, npm, pnpm, bun. Controls which lockfile types are scanned. Default: yarn, npm, pnpm, bun.
- **-Detailed** - Show per-package lines. This is the default behavior; specifying -Detailed is a no-op unless -Summary is also present.
- **-Summary** - Only show the list of repositories/lockfiles with matches; suppress per-package lines.
- **-OnlyAffected** - In detailed mode, show only entries where the resolved version is AFFECTED (hide safe entries).
- **-Quiet** - Suppress the "No matches" list and non-essential lines. Summary/match sections still print unless fully empty.
- **-NoColor** - Disable colored output.
- **-Json** - Also emit JSON results to stdout.
- **-JsonPath** `<String>` - Write JSON results to the specified file path.
- **-Help** - Show this help and exit.

## Examples

### Basic scan

```powershell
pwsh -File .\scan-shai-hulud.ps1 -ListPath .\exploited_packages.txt -RootDir .
```

Scans all supported lockfiles under the current repo, printing detailed results.

### Summary mode with only affected packages

```powershell
pwsh -File .\scan-shai-hulud.ps1 -ListPath .\exploited_packages.txt -RootDir . -OnlyAffected -Summary
```

Shows only repositories/lockfiles that contain affected installs and hides per-package lines.

### JSON output with specific managers

```powershell
pwsh -File .\scan-shai-hulud.ps1 -ListPath .\exploited_packages.txt -RootDir . -Managers yarn,pnpm,bun -Json -JsonPath .\results.json
```

Scans only yarn, pnpm, and bun lockfiles, prints JSON to stdout, and writes the same JSON to results.json.

### Filtered scanning

```powershell
pwsh -File .\scan-shai-hulud.ps1 -ListPath .\exploited_packages.txt -RootDir . -Include 'apps/**','packages/**' -Exclude '**/dist/**','**/node_modules/**'
```

Scans only under apps/ and packages/ while still honoring exclusions.

## Exit Codes

- **0**: Success; no affected installs found (or no lockfiles found)
- **1**: Invalid input (e.g., ListPath or RootDir not found; or list file empty/invalid)
- **2**: Success; at least one affected install found (useful for CI gating)

## Getting Help

For detailed help with all parameters and examples:

```powershell
Get-Help -Full .\scan-shai-hulud.ps1
```

## GitHub Action Usage

This repository also provides a reusable GitHub Action that can be integrated into any repository to automatically scan for compromised packages.

### Quick Start

Add this to your repository's `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Scan for compromised packages
        uses: jpmckearin/shai-hulud-scanner@main  # Pin to specific version for production
        with:
          fail-on-match: 'true'
```

> **Note**: For production use, consider pinning to a specific version (e.g., `@v1.0.0`) instead of `@main` to ensure consistent behavior.

### Action Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `list-path` | Path to exploited packages list file (optional - uses default if not provided) | No | Uses default list from scanner repository |
| `root-dir` | Root directory to scan | No | `.` |
| `managers` | Package managers to scan (comma-separated) | No | `yarn,npm,pnpm,bun` |
| `include` | Glob patterns to include (comma-separated) | No | - |
| `exclude` | Glob patterns to exclude (comma-separated) | No | - |
| `fail-on-match` | Fail the action if compromised packages are found | No | `true` |
| `only-affected` | Show only affected packages in output | No | `false` |
| `summary` | Show only summary output | No | `false` |
| `quiet` | Suppress non-essential output | No | `false` |
| `no-color` | Disable colored output | No | `false` |

### Action Outputs

| Output | Description |
|--------|-------------|
| `has-matches` | Whether any compromised packages were found |
| `match-count` | Number of compromised packages found |
| `warning-count` | Number of packages with vulnerable versions available |
| `json-output` | JSON output of scan results |

### Advanced Example

```yaml
name: Comprehensive Security Scan
on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      
      - name: Run comprehensive security scan
        uses: jpmckearin/shai-hulud-scanner@main
        with:
          # Optional: Use custom exploited packages list
          # list-path: 'security/exploited_packages.txt'
          root-dir: '.'
          managers: 'yarn,npm,pnpm,bun'
          include: 'apps/**,packages/**,src/**'
          exclude: '**/node_modules/**,**/dist/**,**/build/**'
          fail-on-match: 'true'
          only-affected: 'true'
          no-color: 'true'
      
      - name: Upload scan results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-scan-results
          path: security-scan-results.json
          retention-days: 30
```

### Setting Up for Your Company

1. **Add the workflow** to `.github/workflows/security-scan.yml` (no additional setup required!)

2. **Optional: Create a custom exploited packages list** if you want to add company-specific packages:

   ```bash
   # Create the file
   touch exploited_packages.txt
   
   # Add compromised packages (one per line)
   echo "@ahmedhfarag/ngx-perfect-scrollbar@20.0.20" >> exploited_packages.txt
   echo "@ahmedhfarag/ngx-virtual-scroller@4.0.4" >> exploited_packages.txt
   ```

3. **Configure branch protection** in your repository settings to require the security scan to pass before merging

4. **The action automatically uses the latest exploited packages list** from the scanner repository, so you get updates without any maintenance!

### Actions Examples

See the `examples/` directory for:

- `company-security-workflow.yml` - Full-featured workflow with PR comments and artifacts
- `basic-security-workflow.yml` - Minimal setup for quick integration
- `exploited_packages_template.txt` - Template for your compromised packages list
