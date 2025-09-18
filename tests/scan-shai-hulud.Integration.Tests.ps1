# Requires -Version 5.0

Describe 'scan-shai-hulud.ps1 integration' -Tag 'Integration' {
  BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $scriptPath = Join-Path $repoRoot 'scan-shai-hulud.ps1'
    
    # Create temporary test exploited packages file
    $script:tmpListPath = Join-Path ([System.IO.Path]::GetTempPath()) ("hulud_test_" + [guid]::NewGuid() + ".txt")
    $testPackages = @(
      '@ahmedhfarag/ngx-perfect-scrollbar@20.0.20',
      '@ahmedhfarag/ngx-virtual-scroller@4.0.4',
      'left-pad@1.3.0'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath $script:tmpListPath -Value $testPackages -Encoding UTF8

    # Debug: Verify paths exist
    if (-not (Test-Path $scriptPath)) {
      throw "Script not found: $scriptPath"
    }
    if (-not (Test-Path $script:tmpListPath)) {
      throw "Test list file not found: $script:tmpListPath"
    }
    
    $script:tmpRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("hulud_it_" + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $script:tmpRoot | Out-Null

    # Minimal yarn.lock with one affected package and one safe package
    $yarnLock = @(
      '"@ahmedhfarag/ngx-perfect-scrollbar@^20.0.0":',
      '  version "20.0.20"',
      '',
      'left-pad@^1.3.0:',
      '  version "1.3.0"'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $script:tmpRoot 'yarn.lock') -Value $yarnLock -Encoding UTF8

    # Minimal pnpm-lock.yaml with one affected package
    $pnpm = @(
      'packages:',
      '  /@ahmedhfarag/ngx-virtual-scroller@4.0.4:',
      '    resolution: {integrity: sha512-abc}',
      '  /left-pad@1.3.0:',
      '    resolution: {integrity: sha512-def}'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $script:tmpRoot 'pnpm-lock.yaml') -Value $pnpm -Encoding UTF8

    # Minimal bun.lock with one affected package
    $bunLock = @(
      '{',
      '  "lockfileVersion": 0,',
      '  "workspaces": {',
      '    "": {',
      '      "dependencies": {',
      '        "@ahmedhfarag/ngx-perfect-scrollbar": "^20.0.0"',
      '      }',
      '    }',
      '  },',
      '  "packages": {',
      '    "@ahmedhfarag/ngx-perfect-scrollbar@20.0.20": ["@ahmedhfarag/ngx-perfect-scrollbar@20.0.20", {}, "npm-@ahmedhfarag-ngx-perfect-scrollbar-20.0.20"],',
      '    "left-pad@1.3.0": ["left-pad@1.3.0", {}, "npm-left-pad-1.3.0"]',
      '  }',
      '}'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $script:tmpRoot 'bun.lock') -Value $bunLock -Encoding UTF8
  }

  AfterAll {
    if (Test-Path -LiteralPath $script:tmpRoot) {
      Remove-Item -LiteralPath $script:tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $script:tmpListPath) {
      Remove-Item -LiteralPath $script:tmpListPath -Force -ErrorAction SilentlyContinue
    }
  }

  It 'returns exit code 2 when affected installs are found' {
    $jsonOut = Join-Path $script:tmpRoot 'results.json'
    
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $script:tmpRoot -Json -JsonPath $jsonOut 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    
    $exitCode | Should -Be 2

    Test-Path -LiteralPath $jsonOut | Should -BeTrue
    $json = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
    $json.anyAffected | Should -BeTrue
    ($json.results | Where-Object { $_.lockFile -like '*yarn.lock' -or $_.lockFile -like '*pnpm-lock.yaml' -or $_.lockFile -like '*bun.lock' }).Count | Should -BeGreaterThan 0

    $allPackages = @()
    foreach ($r in $json.results) { $allPackages += $r.packages }
    ($allPackages | Where-Object { $_.IsAffected }).Count | Should -BeGreaterThan 0
  }

  It 'returns exit code 0 when no lockfiles are present' {
    $emptyDir = Join-Path $script:tmpRoot 'empty'
    New-Item -ItemType Directory -Path $emptyDir | Out-Null
    
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $emptyDir 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    
    $exitCode | Should -Be 0
  }

  It 'correctly parses bun.lock files' {
    $bunDir = Join-Path $script:tmpRoot 'bun-test'
    New-Item -ItemType Directory -Path $bunDir | Out-Null
    
    # Create a bun.lock file with affected packages
    $bunLock = @(
      '{',
      '  "lockfileVersion": 0,',
      '  "packages": {',
      '    "@ahmedhfarag/ngx-perfect-scrollbar@20.0.20": ["@ahmedhfarag/ngx-perfect-scrollbar@20.0.20", {}, "npm-@ahmedhfarag-ngx-perfect-scrollbar-20.0.20"]',
      '  }',
      '}'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $bunDir 'bun.lock') -Value $bunLock -Encoding UTF8
    
    $jsonOut = Join-Path $bunDir 'results.json'
    
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $bunDir -Managers bun -Json -JsonPath $jsonOut 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    
    $exitCode | Should -Be 2
    Test-Path -LiteralPath $jsonOut | Should -BeTrue
    
    $json = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
    $json.anyAffected | Should -BeTrue
    ($json.results | Where-Object { $_.lockFile -like '*bun.lock' }).Count | Should -Be 1
    
    $bunResult = $json.results | Where-Object { $_.lockFile -like '*bun.lock' }
    $bunResult.packages.Count | Should -BeGreaterThan 0
    ($bunResult.packages | Where-Object { $_.Package -eq '@ahmedhfarag/ngx-perfect-scrollbar' -and $_.IsAffected }).Count | Should -Be 1
  }

  It 'correctly identifies warning packages (name matches but version is safe)' {
    $warningDir = Join-Path $script:tmpRoot 'warning-test'
    New-Item -ItemType Directory -Path $warningDir | Out-Null
    
    # Create a yarn.lock with packages that have compromised versions available but are using safe versions
    $yarnLock = @(
      'left-pad@^2.0.0:',
      '  version "2.0.0"',
      '',
      'lodash@^4.17.21:',
      '  version "4.17.21"'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $warningDir 'yarn.lock') -Value $yarnLock -Encoding UTF8
    
    $jsonOut = Join-Path $warningDir 'results.json'
    
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $warningDir -Managers yarn -Json -JsonPath $jsonOut 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    
    # Should exit with 0 (no compromised packages, warnings don't affect exit code)
    $exitCode | Should -Be 0
    Test-Path -LiteralPath $jsonOut | Should -BeTrue
    
    $json = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
    $json.anyAffected | Should -BeFalse
    $json.anyWarnings | Should -BeTrue
    
    $yarnResult = $json.results | Where-Object { $_.lockFile -like '*yarn.lock' }
    $yarnResult.packages.Count | Should -BeGreaterThan 0
    
    # Check that left-pad is identified as a warning (name matches but version is safe)
    $leftPadPackage = $yarnResult.packages | Where-Object { $_.Package -eq 'left-pad' }
    $leftPadPackage | Should -Not -BeNullOrEmpty
    $leftPadPackage.IsAffected | Should -BeFalse
    $leftPadPackage.IsWarning | Should -BeTrue
    $leftPadPackage.Version | Should -Be '2.0.0'
  }

  It 'correctly handles JSON output parsing' {
    # Test that the scanner produces valid JSON
    $testDir = Join-Path $script:tmpRoot 'json-test'
    New-Item -ItemType Directory -Path $testDir | Out-Null
    
    $yarnLock = @(
      'left-pad@^1.3.0:',
      '  version "1.3.0"'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $testDir 'yarn.lock') -Value $yarnLock -Encoding UTF8
    
    $jsonOut = Join-Path $testDir 'results.json'
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $testDir -Json -JsonPath $jsonOut 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    
    # Should exit with 2 (compromised packages found)
    $exitCode | Should -Be 2
    
    # JSON should be valid
    $json = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
    $json | Should -Not -BeNullOrEmpty
    $json.anyAffected | Should -BeTrue
    $json.anyWarnings | Should -BeFalse
    $json.summary | Should -Not -BeNullOrEmpty
    $json.results | Should -Not -BeNullOrEmpty
  }
}