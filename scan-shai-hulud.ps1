<#
.SYNOPSIS
Scans JavaScript/TypeScript lockfiles for known shai-hulud-affected packages.

.DESCRIPTION
Recursively scans under a root directory for lockfiles (yarn.lock, package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, bun.lock),
compares resolved packages to a provided list of package@version entries, and reports matches. Output includes which installs
are affected vs safe, with options for filtering, color/verbosity, JSON output, and CI-friendly exit codes.

.PARAMETER ListPath
Path to a text file containing one package@version per line (comments with # are allowed).

.PARAMETER RootDir
Root directory to scan recursively for lockfiles.

.PARAMETER Include
Glob(s) to include, relative to RootDir (e.g. src/**, apps/*). When provided, only paths matching at least one include glob are scanned.
Include narrows the scan set and does not override Exclude.

.PARAMETER Exclude
Glob(s) to exclude, relative to RootDir. Defaults: **/node_modules/**, **/.pnpm-store/**, **/dist/**, **/build/**, **/tmp/**, **/.turbo/**
Exclude is applied first and cannot be overridden by Include.

.PARAMETER Managers
One or more of: yarn, npm, pnpm, bun. Controls which lockfile types are scanned. Default: yarn, npm, pnpm, bun.

.PARAMETER Detailed
Show per-package lines. This is the default behavior; specifying -Detailed is a no-op unless -Summary is also present.

.PARAMETER Summary
Only show the list of repositories/lockfiles with matches; suppress per-package lines.

.PARAMETER OnlyAffected
In detailed mode, show only entries where the resolved version is AFFECTED (hide safe entries).

.PARAMETER Quiet
Suppress the "No matches" list and non-essential lines. Summary/match sections still print unless fully empty.

.PARAMETER NoColor
Disable colored output.

.PARAMETER Json
Also emit JSON results to stdout.

.PARAMETER JsonPath
Write JSON results to the specified file path.

.PARAMETER Help
Show this help and exit.

.EXAMPLE
pwsh -File .\scan-shai-hulud.ps1 -ListPath .\exploited_packages.txt -RootDir .
Scans all supported lockfiles under the current repo, printing detailed results.

.EXAMPLE
pwsh -File .\scan-shai-hulud.ps1 -ListPath .\exploited_packages.txt -RootDir . -OnlyAffected -Summary
Shows only repositories/lockfiles that contain affected installs and hides per-package lines.

.EXAMPLE
pwsh -File .\scan-shai-hulud.ps1 -ListPath .\exploited_packages.txt -RootDir . -Managers yarn,pnpm,bun -Json -JsonPath .\results.json
Scans only yarn, pnpm, and bun lockfiles, prints JSON to stdout, and writes the same JSON to results.json.

.EXAMPLE
pwsh -File .\scan-shai-hulud.ps1 -ListPath .\exploited_packages.txt -RootDir . -Include 'apps/**','packages/**' -Exclude '**/dist/**','**/node_modules/**'
Scans only under apps/ and packages/ while still honoring exclusions.

.NOTES
Exit codes:
 - 0: success; no compromised packages found (or no lockfiles found)
 - 1: invalid input (e.g., ListPath or RootDir not found; or list file empty/invalid)
 - 2: success; at least one compromised package found (useful for CI gating)
#>

param(
  [Parameter(Mandatory = $true)]
  [ValidateScript({ Test-Path $_ -PathType Leaf })]
  [string]$ListPath,
  [Parameter(Mandatory = $true)]
  [ValidateScript({ Test-Path $_ -PathType Container })]
  [string]$RootDir,
  [string[]]$Include = @(),
  [string[]]$Exclude = @('**/node_modules/**', '**/.pnpm-store/**', '**/dist/**', '**/build/**', '**/tmp/**', '**/.turbo/**'),
  [ValidateSet('yarn', 'npm', 'pnpm', 'bun')]
  [string[]]$Managers = @('yarn', 'npm', 'pnpm', 'bun'),
  [switch]$Detailed,   # default true unless -Summary
  [switch]$Summary,
  [switch]$OnlyAffected,
  [switch]$Quiet,      # suppress no-match listing
  [switch]$NoColor,
  [switch]$Json,       # also emit JSON to stdout
  [string]$JsonPath,   # or write JSON to this path
  [switch]$Help
)

if ($Help) {
  try { Get-Help -Detailed $MyInvocation.MyCommand.Path | more } catch { Write-Host "Run: Get-Help $($MyInvocation.MyCommand.Path) -Detailed" }
  exit 0
}

# Path validation is now handled by ValidateScript attributes

$startTime = Get-Date

# Parse affected packages into Name -> set of Versions, plus HashSet of names
$affected = @{}
$affectedNames = New-Object System.Collections.Generic.HashSet[string]
(Get-Content -LiteralPath $ListPath) |
Where-Object { $_ -and ($_ -notmatch '^\s*#') } |
ForEach-Object {
  if ($_ -match '^\s*(?<name>@?[^@/\s]+(?:/[^@/\s]+)?)@(?<ver>[0-9]+\.[0-9]+\.[0-9]+)\s*$') {
    $name = $matches['name']
    $ver = $matches['ver']
    
    # Normalize scoped package names: ensure @ prefix for scoped packages
    if ($name -match '^[^@/]+/') {
      $name = '@' + $name
    }
    
    if (-not $affected.ContainsKey($name)) { $affected[$name] = New-Object System.Collections.Generic.HashSet[string] }
    $null = $affected[$name].Add($ver)
    $null = $affectedNames.Add($name)
  }
}

if ($affected.Count -eq 0) {
  Write-Error "No valid package@version entries parsed from $ListPath"
  exit 1
}

$allPatterns = @()
if ($Managers -contains 'yarn') { $allPatterns += 'yarn.lock' }
if ($Managers -contains 'npm') { $allPatterns += 'package-lock.json', 'npm-shrinkwrap.json' }
if ($Managers -contains 'pnpm') { $allPatterns += 'pnpm-lock.yaml' }
if ($Managers -contains 'bun') { $allPatterns += 'bun.lock', 'bun.lockb' }
if ($allPatterns.Count -eq 0) { $allPatterns = @('yarn.lock', 'package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb') }

$lockFiles = Get-ChildItem -Path $RootDir -Recurse -File -ErrorAction SilentlyContinue -Include $allPatterns
if ($lockFiles.Count -eq 0) {
  if (-not $Json) { Write-Output "No lockfiles found under: $RootDir" }
  exit 0
}

# Collect per-lock results for reporting
$byLock = @{}
$anyAffected = $false
$anyWarnings = $false

function Write-Color([string]$text, [string]$color) {
  if ($NoColor) { Write-Host $text; return }
  if ($color) { Write-Host $text -ForegroundColor $color } else { Write-Host $text }
}

function Test-PathMatchesGlobs([string]$path, [string[]]$globs) {
  if (-not $globs -or $globs.Count -eq 0) { return $false }
  $unix = $path -replace '\\', '/'
  foreach ($g in $globs) {
    $pattern = ($g -replace '\\.', '\\.') -replace '\*\*', '.*' -replace '\*', '[^/]*'
    if ($unix -match "^$pattern$") { return $true }
  }
  return $false
}

function Test-PathIncluded([string]$fullPath) {
  $relBase = (Resolve-Path -LiteralPath $RootDir).Path
  $rel = [System.IO.Path]::GetRelativePath($relBase, (Resolve-Path -LiteralPath $fullPath).Path)
  if (Test-PathMatchesGlobs $rel $Exclude) { return $false }
  if ($Include -and $Include.Count -gt 0) {
    return (Test-PathMatchesGlobs $rel $Include)
  }
  return $true
}

# Apply path filters up-front so excluded lockfiles never appear in output
$lockFiles = $lockFiles | Where-Object { Test-PathIncluded $_.FullName }

foreach ($lock in $lockFiles) {
  $foundPackages = @{}
  $extName = [System.IO.Path]::GetFileName($lock.FullName)

  if (-not (Test-PathIncluded $lock.FullName)) { continue }

  if ($extName -eq 'yarn.lock') {
    $lines = Get-Content -LiteralPath $lock.FullName -ErrorAction SilentlyContinue
    if (-not $lines) { continue }

    $i = 0
    while ($i -lt $lines.Count) {
      $line = $lines[$i]

      # Match stanza header line(s): pkg@range, pkg@range, ... (quoted or unquoted)
      if ($line -match '^\s*(?<hdr>.+?)\s*:\s*$') {
        $header = $matches['hdr']
        # Split multiple entries (handles quoted and unquoted keys)
        $keys = ($header -split '\s*,\s*') |
        ForEach-Object { $_ -replace '^\s*"', '' -replace '"\s*$', '' }

        # Extract package names (before the last @)
        $pkgNames = $keys |
        ForEach-Object {
          if ($_ -match '^(?<name>@?[^@/\s]+(?:/[^@/\s]+)?)@') { $matches['name'] }
        } |
        Where-Object { $_ } |
        Sort-Object -Unique

        # Find the 'version "x.y.z"' line within this stanza block
        $version = $null
        $j = $i + 1
        while ($j -lt $lines.Count -and -not [string]::IsNullOrWhiteSpace($lines[$j])) {
          $verLine = $lines[$j]
          if ($verLine -match '^\s*version\s+"(?<v>[^\"]+)"') {
            $version = $matches['v']
            break
          }
          $j++
        }

        if ($version) {
          foreach ($pkg in $pkgNames) {
            if ($affectedNames.Contains($pkg)) {
              if (-not $foundPackages.ContainsKey($pkg)) { $foundPackages[$pkg] = New-Object System.Collections.Generic.HashSet[string] }
              $null = $foundPackages[$pkg].Add($version)
            }
          }
        }

        # Jump to end of stanza (blank line or EOF)
        while ($j -lt $lines.Count -and -not [string]::IsNullOrWhiteSpace($lines[$j])) { $j++ }
        $i = $j + 1
        continue
      }

      $i++
    }
  }
  elseif (($extName -eq 'package-lock.json') -or ($extName -eq 'npm-shrinkwrap.json')) {
    try { 
      $obj = Get-Content -LiteralPath $lock.FullName -Raw | ConvertFrom-Json -ErrorAction Stop 
    }
    catch { 
      $obj = $null
      if (-not $Json) { Write-Color ("Warning: failed to parse JSON lock: {0}" -f $lock.FullName) 'Yellow' }
    }
    if ($null -ne $obj) {
      if ($obj.PSObject.Properties.Name -contains 'packages' -and $obj.packages) {
        foreach ($kv in $obj.packages.GetEnumerator()) {
          $key = [string]$kv.Key
          if ([string]::IsNullOrEmpty($key)) { continue }
          if ($key -match '(?:^|/)node_modules/(?<nm>.+)$') {
            $nm = $matches['nm']
            $nm = $nm -replace '^node_modules/', ''
            $ver = $kv.Value.version
            if ($nm -and $ver -and $affectedNames.Contains($nm)) {
              if (-not $foundPackages.ContainsKey($nm)) { $foundPackages[$nm] = New-Object System.Collections.Generic.HashSet[string] }
              $null = $foundPackages[$nm].Add($ver)
            }
          }
        }
      }
      if ($obj.PSObject.Properties.Name -contains 'dependencies' -and $obj.dependencies) {
        function _walkDeps($deps) {
          if ($null -eq $deps) { return }
          if ($deps -is [System.Collections.IDictionary]) {
            foreach ($name in $deps.Keys) {
              $node = $deps[$name]
              $ver = $node.version
              if ($name -and $ver -and $affectedNames.Contains($name)) {
                if (-not $foundPackages.ContainsKey($name)) { $foundPackages[$name] = New-Object System.Collections.Generic.HashSet[string] }
                $null = $foundPackages[$name].Add($ver)
              }
              if ($node -and $node.PSObject.Properties.Name -contains 'dependencies' -and $node.dependencies) { _walkDeps $node.dependencies }
            }
          }
          else {
            foreach ($prop in $deps.PSObject.Properties.Name) {
              $node = $deps.$prop
              $ver = $node.version
              if ($prop -and $ver -and $affectedNames.Contains($prop)) {
                if (-not $foundPackages.ContainsKey($prop)) { $foundPackages[$prop] = New-Object System.Collections.Generic.HashSet[string] }
                $null = $foundPackages[$prop].Add($ver)
              }
              if ($node -and $node.PSObject.Properties.Name -contains 'dependencies' -and $node.dependencies) { _walkDeps $node.dependencies }
            }
          }
        }
        _walkDeps $obj.dependencies
      }
    }
  }
  elseif ($extName -eq 'pnpm-lock.yaml') {
    $lines = Get-Content -LiteralPath $lock.FullName -ErrorAction SilentlyContinue
    if ($lines) {
      foreach ($ln in $lines) {
        # Match "/name@1.2.3:" or "/@scope/name@1.2.3:"
        if ($ln -match '^\s*/(?<pkg>@?[^/@\s]+(?:/[^/@\s]+)?)@(?<ver>[0-9]+\.[0-9]+\.[0-9]+)\s*:') {
          $pkg = $matches['pkg']; $ver = $matches['ver']
          if ($pkg -and $ver -and $affectedNames.Contains($pkg)) {
            if (-not $foundPackages.ContainsKey($pkg)) { $foundPackages[$pkg] = New-Object System.Collections.Generic.HashSet[string] }
            $null = $foundPackages[$pkg].Add($ver)
          }
          continue
        }
        # Match "/name/1.2.3:" or "/@scope/name/1.2.3:"
        if ($ln -match '^\s*/(?<pkg>@?[^/\s]+(?:/[^/\s]+)?)/(?<ver>[0-9]+\.[0-9]+\.[0-9]+)\s*:') {
          $pkg = $matches['pkg']; $ver = $matches['ver']
          if ($pkg -and $ver -and $affectedNames.Contains($pkg)) {
            if (-not $foundPackages.ContainsKey($pkg)) { $foundPackages[$pkg] = New-Object System.Collections.Generic.HashSet[string] }
            $null = $foundPackages[$pkg].Add($ver)
          }
          continue
        }
      }
    }
  }
  elseif (($extName -eq 'bun.lock') -or ($extName -eq 'bun.lockb')) {
    try {
      if ($extName -eq 'bun.lock') {
        # Text-based bun.lock file (JSONC format)
        $content = Get-Content -LiteralPath $lock.FullName -Raw -ErrorAction Stop
        $obj = $content | ConvertFrom-Json -ErrorAction Stop
      }
      else {
        # Binary bun.lockb file - we can't parse this directly
        # Skip binary lockfiles for now as they require special handling
        continue
      }
      
      if ($obj -and $obj.packages) {
        foreach ($prop in $obj.packages.PSObject.Properties) {
          $pkgName = $prop.Name
          $pkgData = $prop.Value
          if ($pkgData -is [array] -and $pkgData.Count -ge 1) {
            # Extract package name and version from the package key
            # Format: "package@version" or "@scope/package@version"
            if ($pkgName -match '^(.+?)@([0-9]+\.[0-9]+\.[0-9]+.*)$') {
              $name = $matches[1]
              $version = $matches[2]
              
              if ($name -and $version -and $affectedNames.Contains($name)) {
                if (-not $foundPackages.ContainsKey($name)) { $foundPackages[$name] = New-Object System.Collections.Generic.HashSet[string] }
                $null = $foundPackages[$name].Add($version)
              }
            }
          }
        }
      }
    }
    catch {
      if (-not $Json) { Write-Color ("Warning: failed to parse Bun lockfile: {0}" -f $lock.FullName) 'Yellow' }
    }
  }

  # Integrate found packages for this lock into report
  if ($foundPackages.Count -gt 0) {
    foreach ($pkg in $foundPackages.Keys) {
      if ($affected.ContainsKey($pkg)) {
        if (-not $byLock.ContainsKey($lock.FullName)) { $byLock[$lock.FullName] = @{} }
        foreach ($version in ($foundPackages[$pkg] | Sort-Object)) {
          $isAffected = $affected[$pkg].Contains($version)
          $isWarning = -not $isAffected  # Package name matches but version is safe
          if ($isAffected) { $anyAffected = $true }
          if ($isWarning) { $anyWarnings = $true }
          $entry = [pscustomobject]@{
            Package          = $pkg
            Version          = $version
            IsAffected       = $isAffected
            IsWarning        = $isWarning
            AffectedVersions = @($affected[$pkg] | Sort-Object)
          }
          $byLock[$lock.FullName]["$pkg@$version"] = $entry
        }
      }
    }
  }
}

# Pretty print summary report
function Get-RelativePath([string]$basePath, [string]$fullPath) {
  try { return [System.IO.Path]::GetRelativePath($basePath, $fullPath) } catch {
    if ($fullPath.StartsWith($basePath, [System.StringComparison]::OrdinalIgnoreCase)) {
      $trimmed = $fullPath.Substring($basePath.Length)
      if ($trimmed.StartsWith([System.IO.Path]::DirectorySeparatorChar)) { return $trimmed.Substring(1) }
      return $trimmed
    }
    return $fullPath
  }
}

$_base = (Resolve-Path -LiteralPath $RootDir).Path
$locksWithMatches = New-Object System.Collections.Generic.List[string]
$locksWithoutMatches = New-Object System.Collections.Generic.List[string]

foreach ($lock in $lockFiles) {
  $rel = Get-RelativePath -basePath $_base -fullPath (Resolve-Path -LiteralPath $lock.FullName).Path
  if ($byLock.ContainsKey($lock.FullName) -and $byLock[$lock.FullName].Count -gt 0) {
    $locksWithMatches.Add($rel)
  }
  else {
    $locksWithoutMatches.Add($rel)
  }
}

# Header: compromised packages found
if (-not $Quiet -and -not $Json -and $anyAffected) { Write-Color "Compromised packages found (name and version match)" 'Red' }
if ($locksWithMatches.Count -gt 0 -and $anyAffected) {
  foreach ($lock in $lockFiles) {
    $rel = Get-RelativePath -basePath $_base -fullPath (Resolve-Path -LiteralPath $lock.FullName).Path
    if ($locksWithMatches -contains $rel) {
      if (-not $Json) { Write-Color (" - {0}" -f $rel) 'Red' }
      if ($byLock.ContainsKey($lock.FullName)) {
        $byLock[$lock.FullName].GetEnumerator() |
        Sort-Object Key |
        ForEach-Object {
          $entry = $_.Value
          if (-not $entry.IsAffected) { return }  # Only show actually compromised packages here
          $affectedList = ($entry.AffectedVersions -join ', ')
          $line = ("   {0} resolved {1} (AFFECTED; compromised versions: {2})" -f $entry.Package, $entry.Version, $affectedList)
          if (-not $Json) { Write-Color $line 'Red' }
        }
      }
    }
  }
}
# Only show "None" if there are no compromised packages AND no warnings
if (-not $anyAffected -and -not $anyWarnings) {
  if (-not $Quiet -and -not $Json) { Write-Color " - None" 'Red' }
}

if (-not $Quiet -and -not $Json) { Write-Host "" }

# Header: warning packages (name matches but version is safe)
if (-not $Quiet -and -not $Json -and $anyWarnings) { Write-Color "⚠️  Warning: Packages with compromised versions available (current versions are safe)" 'Yellow' }
if ($anyWarnings) {
  foreach ($lock in $lockFiles) {
    $rel = Get-RelativePath -basePath $_base -fullPath (Resolve-Path -LiteralPath $lock.FullName).Path
    if ($byLock.ContainsKey($lock.FullName)) {
      $warningEntries = $byLock[$lock.FullName].GetEnumerator() | Where-Object { $_.Value.IsWarning }
      if ($warningEntries) {
        if (-not $Json) { Write-Color (" - {0}" -f $rel) 'Yellow' }
        $warningEntries |
        Sort-Object Key |
        ForEach-Object {
          $entry = $_.Value
          $affectedList = ($entry.AffectedVersions -join ', ')
          $line = ("   {0} resolved {1} (safe; avoid versions: {2})" -f $entry.Package, $entry.Version, $affectedList)
          if (-not $Json) { Write-Color $line 'Yellow' }
        }
      }
    }
  }
}

if (-not $Quiet -and -not $Json) { Write-Host "" }

# Header: no compromised packages (show for files that were scanned but had no issues)
if (-not $Quiet -and -not $Json -and $locksWithoutMatches.Count -gt 0) {
  Write-Host "No compromised packages found (all versions are safe)"
  $locksWithoutMatches | Sort-Object | ForEach-Object { Write-Host (" - {0}" -f $_) }
}

# Optional JSON output
if ($Json -or $JsonPath) {
  $jsonObj = @{
    root        = (Resolve-Path -LiteralPath $RootDir).Path
    results     = @()
    anyAffected = $anyAffected
    anyWarnings = $anyWarnings
    summary     = @{
      totalLockfiles   = $lockFiles.Count
      totalPackages    = ($byLock.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
      totalWarnings    = ($byLock.Values | ForEach-Object { ($_.GetEnumerator() | Where-Object { $_.Value.IsWarning } | Measure-Object).Count } | Measure-Object -Sum).Sum
      totalCompromised = ($byLock.Values | ForEach-Object { ($_.GetEnumerator() | Where-Object { $_.Value.IsAffected } | Measure-Object).Count } | Measure-Object -Sum).Sum
    }
  }
  
  # Only include lockfiles that have actual matches
  foreach ($lock in $lockFiles) {
    if ($byLock.ContainsKey($lock.FullName) -and $byLock[$lock.FullName].Count -gt 0) {
      $rel = Get-RelativePath -basePath $_base -fullPath (Resolve-Path -LiteralPath $lock.FullName).Path
      $packages = $byLock[$lock.FullName].GetEnumerator() | Sort-Object Key | ForEach-Object { $_.Value }
      $jsonObj.results += [pscustomobject]@{ lockFile = $rel; packages = $packages }
    }
  }
  
  $jsonText = $jsonObj | ConvertTo-Json -Depth 6
  if ($Json) { Write-Output $jsonText }
  if ($JsonPath) { $jsonText | Out-File -FilePath $JsonPath -Encoding utf8 }
}

# Footer summary
$elapsed = (Get-Date) - $startTime
$totalLocks = $lockFiles.Count
$totalMatches = ($byLock.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
$totalWarnings = ($byLock.Values | ForEach-Object { ($_.GetEnumerator() | Where-Object { $_.Value.IsWarning } | Measure-Object).Count } | Measure-Object -Sum).Sum

if (-not $Json) {
  Write-Host ""
  Write-Host "📊 Scan Summary:" -ForegroundColor Cyan
  Write-Host "   Lockfiles scanned: $totalLocks" -ForegroundColor White
  Write-Host "   Package entries checked: $($totalMatches | ForEach-Object { if ($_) { $_ } else { 0 } })" -ForegroundColor White
  Write-Host "   Compromised packages: " -NoNewline -ForegroundColor White
  $compromisedCount = ($byLock.Values | ForEach-Object { ($_.GetEnumerator() | Where-Object { $_.Value.IsAffected } | Measure-Object).Count } | Measure-Object -Sum).Sum
  if ($compromisedCount -gt 0) {
    Write-Host "❌ $compromisedCount" -ForegroundColor Red
  }
  else {
    Write-Host "✅ 0" -ForegroundColor Green
  }
  Write-Host "   Warning packages: " -NoNewline -ForegroundColor White
  if ($totalWarnings -gt 0) {
    Write-Host "⚠️  $totalWarnings" -ForegroundColor Yellow
  }
  else {
    Write-Host "✅ 0" -ForegroundColor Green
  }
  Write-Host "   Scan duration: $($elapsed.ToString())" -ForegroundColor Gray
}

if ($anyAffected) { exit 2 } else { exit 0 }