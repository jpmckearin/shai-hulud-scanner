# Shai-Hulud Scanner

A PowerShell script that scans JavaScript/TypeScript lockfiles for known shai-hulud-affected packages.

## Description

Recursively scans under a root directory for lockfiles (yarn.lock, package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml), compares resolved packages to a provided list of package@version entries, and reports matches. Output includes which installs are affected vs safe, with options for filtering, color/verbosity, JSON output, and CI-friendly exit codes.

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
- **-Managers** `<String[]>` - One or more of: yarn, npm, pnpm. Controls which lockfile types are scanned. Default: yarn, npm, pnpm.
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
pwsh -File .\scan-shai-hulud.ps1 -ListPath .\exploited_packages.txt -RootDir . -Managers yarn,pnpm -Json -JsonPath .\results.json
```

Scans only yarn and pnpm lockfiles, prints JSON to stdout, and writes the same JSON to results.json.

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
