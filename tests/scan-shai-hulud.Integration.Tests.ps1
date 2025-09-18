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

  It 'correctly handles multiple package managers parameter' {
    $testDir = Join-Path $script:tmpRoot 'managers-test'
    New-Item -ItemType Directory -Path $testDir | Out-Null

    # Create yarn and npm lockfiles with compromised package
    $yarnLock = 'left-pad@^1.3.0:`n  version "1.3.0"'
    Set-Content -LiteralPath (Join-Path $testDir 'yarn.lock') -Value $yarnLock -Encoding UTF8

    $npmLock = '{"lockfileVersion": 2, "packages": {"node_modules/left-pad": {"version": "1.3.0"}}}'
    Set-Content -LiteralPath (Join-Path $testDir 'package-lock.json') -Value $npmLock -Encoding UTF8

    # Test comma-separated managers (should work without parameter binding errors)
    $jsonOut = Join-Path $testDir 'results.json'
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $testDir -Managers 'yarn,npm,pnpm,bun' -Json -JsonPath $jsonOut 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE

    $exitCode | Should -Not -Be 1  # Should not be parameter error
    $json = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
    $json.anyAffected | Should -BeTrue
  }

  It 'correctly handles include and exclude parameters as arrays' {
    # Test that include/exclude arrays are handled properly
    $testDir = Join-Path $script:tmpRoot 'filters-test'
    New-Item -ItemType Directory -Path $testDir | Out-Null
    
    # Create subdirectories
    $srcDir = Join-Path $testDir 'src'
    $distDir = Join-Path $testDir 'dist'
    New-Item -ItemType Directory -Path $srcDir | Out-Null
    New-Item -ItemType Directory -Path $distDir | Out-Null
    
    # Create lockfiles in both directories
    $yarnLock = @(
      'left-pad@^1.3.0:',
      '  version "1.3.0"'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $srcDir 'yarn.lock') -Value $yarnLock -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $distDir 'yarn.lock') -Value $yarnLock -Encoding UTF8
    
    # Test with include and exclude parameters - should not fail with parameter binding errors
    $jsonOut = Join-Path $testDir 'results.json'
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $testDir -Include 'src/**' -Exclude '**/dist/**' -Json -JsonPath $jsonOut 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    
    # Should succeed
    $exitCode | Should -Be 2
    
    # Should only find the src lockfile, not the dist one
    $json = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
    $json.results.Count | Should -Be 1
    $json.results[0].lockFile | Should -Match 'src[/\\]yarn\.lock$'
  }

  It 'handles ValidateScript parameter validation correctly' {
    # Test that ValidateScript attributes work correctly
    $nonExistentList = Join-Path $script:tmpRoot 'nonexistent.txt'
    $nonExistentDir = Join-Path $script:tmpRoot 'nonexistent'
    
    # Test invalid ListPath
    & pwsh -NoProfile -File $scriptPath -ListPath $nonExistentList -RootDir $script:tmpRoot 2>&1 | Out-Null
    $LASTEXITCODE | Should -Be 1
    
    # Test invalid RootDir  
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $nonExistentDir 2>&1 | Out-Null
    $LASTEXITCODE | Should -Be 1
    
    # Test invalid Manager
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $script:tmpRoot -Managers invalid-manager 2>&1 | Out-Null
    $LASTEXITCODE | Should -Be 1
  }

  It 'correctly scopes package names with @ prefix normalization' {
    # Test that scoped packages are properly normalized (with/without @ prefix)
    $testDir = Join-Path $script:tmpRoot 'scoped-test'
    New-Item -ItemType Directory -Path $testDir | Out-Null
    
    # Create test list with scoped package WITHOUT @ prefix
    $scopedListPath = Join-Path $testDir 'scoped_packages.txt'
    Set-Content -LiteralPath $scopedListPath -Value 'ahmedhfarag/ngx-perfect-scrollbar@20.0.20' -Encoding UTF8
    
    # Create yarn.lock with scoped package WITH @ prefix
    $yarnLock = @(
      '"@ahmedhfarag/ngx-perfect-scrollbar@^20.0.0":',
      '  version "20.0.20"'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $testDir 'yarn.lock') -Value $yarnLock -Encoding UTF8
    
    $jsonOut = Join-Path $testDir 'results.json'
    & pwsh -NoProfile -File $scriptPath -ListPath $scopedListPath -RootDir $testDir -Json -JsonPath $jsonOut 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    
    # Should find the match despite @ prefix normalization
    $exitCode | Should -Be 2
    $json = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
    $json.anyAffected | Should -BeTrue
  }

  It 'handles npm-shrinkwrap.json files' {
    # Test npm-shrinkwrap.json support
    $testDir = Join-Path $script:tmpRoot 'shrinkwrap-test'
    New-Item -ItemType Directory -Path $testDir | Out-Null
    
    $shrinkwrap = @(
      '{',
      '  "lockfileVersion": 2,',
      '  "packages": {',
      '    "node_modules/left-pad": {',
      '      "version": "1.3.0",',
      '      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"',
      '    }',
      '  }',
      '}'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $testDir 'npm-shrinkwrap.json') -Value $shrinkwrap -Encoding UTF8
    
    $jsonOut = Join-Path $testDir 'results.json'
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $testDir -Managers npm -Json -JsonPath $jsonOut 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    
    $exitCode | Should -Be 2
    $json = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
    ($json.results | Where-Object { $_.lockFile -like '*npm-shrinkwrap.json' }).Count | Should -Be 1
  }

  It 'correctly handles empty exploited packages list' {
    # Test behavior with empty/invalid exploited packages list
    $testDir = Join-Path $script:tmpRoot 'empty-list-test'
    New-Item -ItemType Directory -Path $testDir | Out-Null
    
    # Create empty exploited packages list
    $emptyListPath = Join-Path $testDir 'empty_packages.txt'
    Set-Content -LiteralPath $emptyListPath -Value '' -Encoding UTF8
    
    # Should exit with code 1 (invalid input)
    & pwsh -NoProfile -File $scriptPath -ListPath $emptyListPath -RootDir $testDir 2>&1 | Out-Null
    $LASTEXITCODE | Should -Be 1
  }

  It 'correctly handles comments in exploited packages list' {
    # Test that comments are properly ignored
    $testDir = Join-Path $script:tmpRoot 'comments-test'
    New-Item -ItemType Directory -Path $testDir | Out-Null
    
    $commentListPath = Join-Path $testDir 'comment_packages.txt'
    $commentList = @(
      '# This is a comment',
      'left-pad@1.3.0',
      '# Another comment',
      '',
      '   # Indented comment'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath $commentListPath -Value $commentList -Encoding UTF8
    
    $yarnLock = @(
      'left-pad@^1.3.0:',
      '  version "1.3.0"'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $testDir 'yarn.lock') -Value $yarnLock -Encoding UTF8
    
    $jsonOut = Join-Path $testDir 'results.json'
    & pwsh -NoProfile -File $scriptPath -ListPath $commentListPath -RootDir $testDir -Json -JsonPath $jsonOut 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    
    # Should find the one valid package entry
    $exitCode | Should -Be 2
    $json = Get-Content -LiteralPath $jsonOut -Raw | ConvertFrom-Json
    $json.anyAffected | Should -BeTrue
  }

  It 'correctly handles Summary and OnlyAffected flags' {
    # Test output filtering flags
    $testDir = Join-Path $script:tmpRoot 'flags-test'
    New-Item -ItemType Directory -Path $testDir | Out-Null
    
    $yarnLock = @(
      'left-pad@^1.3.0:',
      '  version "1.3.0"',
      '',
      'safe-package@^1.0.0:',
      '  version "1.0.0"'
    ) -join [Environment]::NewLine
    Set-Content -LiteralPath (Join-Path $testDir 'yarn.lock') -Value $yarnLock -Encoding UTF8
    
    # Test Summary flag
    $jsonOut1 = Join-Path $testDir 'summary.json'
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $testDir -Summary -Json -JsonPath $jsonOut1 2>&1 | Out-Null
    $LASTEXITCODE | Should -Be 2
    
    # Test OnlyAffected flag  
    $jsonOut2 = Join-Path $testDir 'affected.json'
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $testDir -OnlyAffected -Json -JsonPath $jsonOut2 2>&1 | Out-Null
    $LASTEXITCODE | Should -Be 2
    
    # Both should produce valid JSON
    $json1 = Get-Content -LiteralPath $jsonOut1 -Raw | ConvertFrom-Json
    $json2 = Get-Content -LiteralPath $jsonOut2 -Raw | ConvertFrom-Json
    $json1.anyAffected | Should -BeTrue
    $json2.anyAffected | Should -BeTrue
  }

  It 'correctly handles JSON-only mode without console output' {
    # Test that -Json mode suppresses non-JSON output
    $testDir = Join-Path $script:tmpRoot 'json-only-test'
    New-Item -ItemType Directory -Path $testDir | Out-Null
    
    # Test with no lockfiles (should output nothing to console)
    $output = & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $testDir -Json 2>&1
    $exitCode = $LASTEXITCODE
    
    $exitCode | Should -Be 0
    # In JSON mode with no lockfiles, should get empty/minimal output
    $output | Should -Not -Match "No lockfiles found"
  }

  It 'correctly handles bun.lockb binary files' {
    # Test that script handles bun.lockb files (even if it can't parse them)
    $testDir = Join-Path $script:tmpRoot 'bun-lockb-test'
    New-Item -ItemType Directory -Path $testDir | Out-Null
    
    # Create a fake bun.lockb file (binary format not parseable)
    $binaryContent = [byte[]](1, 2, 3, 4, 5)
    [System.IO.File]::WriteAllBytes((Join-Path $testDir 'bun.lockb'), $binaryContent)
    
    # Should not crash when encountering binary file
    $jsonOut = Join-Path $testDir 'results.json'
    & pwsh -NoProfile -File $scriptPath -ListPath $script:tmpListPath -RootDir $testDir -Managers bun -Json -JsonPath $jsonOut 2>&1 | Out-Null
    $exitCode = $LASTEXITCODE
    
    # Should succeed (no crash) even if it can't parse binary format
    $exitCode | Should -BeIn @(0, 2)
  }
}