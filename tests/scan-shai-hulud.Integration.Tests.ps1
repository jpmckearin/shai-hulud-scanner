# Requires -Version 5.0

Describe 'scan-shai-hulud.ps1 integration' -Tag 'Integration' {
  BeforeAll {
    $repoRoot = Split-Path -Parent $PSScriptRoot
    $scriptPath = Join-Path $repoRoot 'scan-shai-hulud.ps1'
    $listPath = Join-Path $repoRoot 'exploited_packages.txt'

    # Debug: Verify paths exist
    if (-not (Test-Path $scriptPath)) {
      throw "Script not found: $scriptPath"
    }
    if (-not (Test-Path $listPath)) {
      throw "List file not found: $listPath"
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
  }

  It 'returns exit code 2 when affected installs are found' {
    $jsonOut = Join-Path $script:tmpRoot 'results.json'
    
    & pwsh -NoProfile -File $scriptPath -ListPath $listPath -RootDir $script:tmpRoot -Json -JsonPath $jsonOut 2>&1 | Out-Null
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
    
    & pwsh -NoProfile -File $scriptPath -ListPath $listPath -RootDir $emptyDir 2>&1 | Out-Null
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
      '  "workspaces": {',
      '    "": {',
      '      "dependencies": {',
      '        "@ahmedhfarag/ngx-perfect-scrollbar": "^20.0.0"',
      '      }',
      '    }',
      '  },',
      '  "packages": {',
      '    "@ahmedhfarag/ngx-perfect-scrollbar@20.0.20": ["@ahmedhfarag/ngx-perfect-scrollbar@20.0.20", {}, "npm-@ahmedhfarag-ngx-perfect-scrollbar-20.0.20"]',
      '  }',
      '}'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $bunDir 'bun.lock') -Value $bunLock -Encoding UTF8
    
    $jsonOut = Join-Path $bunDir 'results.json'
    
    & pwsh -NoProfile -File $scriptPath -ListPath $listPath -RootDir $bunDir -Managers bun -Json -JsonPath $jsonOut 2>&1 | Out-Null
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
}