param(
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version = '1.0.1',

    [switch]$SkipBuild
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$binRoot = Join-Path $projectRoot 'bin'
$buildRoot = Join-Path $projectRoot 'build-full-flow'
$runId = [Guid]::NewGuid().ToString('N')
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('qt-license-full-flow-' + $runId)
$oldOnboarding = $env:QTLIC_SKIP_ONBOARDING
$oldPlatform = $env:QT_QPA_PLATFORM

function Invoke-Step([string]$Name, [scriptblock]$Action) {
    Write-Output "RUN  $Name"
    & $Action
    Write-Output "PASS $Name"
}

function Assert-LastExit([string]$Name) {
    if ($LASTEXITCODE -ne 0) {
        throw "$Name failed with exit code $LASTEXITCODE"
    }
}

function Test-GuiStartup([string]$Directory) {
    $issuer = $null
    $collector = $null
    try {
        $issuer = Start-Process -FilePath (Join-Path $Directory 'QtLicenseIssuer.exe') `
            -WorkingDirectory $Directory -WindowStyle Hidden -PassThru
        $collector = Start-Process -FilePath (Join-Path $Directory 'QtHardwareCollector.exe') `
            -WorkingDirectory $Directory -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 3
        $issuer.Refresh()
        $collector.Refresh()
        if ($issuer.HasExited) { throw "QtLicenseIssuer exited early: $($issuer.ExitCode)" }
        if ($collector.HasExited) { throw "QtHardwareCollector exited early: $($collector.ExitCode)" }
    }
    finally {
        if ($issuer -and -not $issuer.HasExited) {
            Stop-Process -Id $issuer.Id -ErrorAction SilentlyContinue
        }
        if ($collector -and -not $collector.HasExited) {
            Stop-Process -Id $collector.Id -ErrorAction SilentlyContinue
        }
    }
}

function Assert-ArchiveSafe([string]$Path) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $forbidden = @($archive.Entries | Where-Object {
            $_.FullName -match '(?i)(^|/)(runtime-config\.json|qtlicense_runtime_config\.h)$' -or
            $_.FullName -match '(?i)\.(qtkv|qtlic|qreq)$'
        })
        if ($forbidden.Count -ne 0) {
            throw "Sensitive file found in archive $Path`: $($forbidden.FullName -join ', ')"
        }
    }
    finally {
        $archive.Dispose()
    }
}

New-Item -ItemType Directory -Path $testRoot | Out-Null
try {
    $versionHeader = Get-Content -LiteralPath (Join-Path $projectRoot 'core\version.h') -Raw
    if ($versionHeader -notmatch ('QTLIC_VERSION_STR\s+"' + [regex]::Escape($Version) + '"')) {
        throw "core/version.h does not match requested version $Version"
    }

    if (-not $SkipBuild) {
        Invoke-Step 'Release build' {
            if (-not (Test-Path -LiteralPath $buildRoot)) {
                New-Item -ItemType Directory -Path $buildRoot | Out-Null
            }
            Push-Location $buildRoot
            try {
                & qmake ..\LicenseSystem.pro 'CONFIG+=release'
                Assert-LastExit 'qmake'
                & mingw32-make -j4
                Assert-LastExit 'mingw32-make'
            }
            finally {
                Pop-Location
            }
        }
    }

    Invoke-Step 'Core regression suite' {
        & (Join-Path $binRoot 'license-core-tests.exe')
        Assert-LastExit 'license-core-tests'
    }

    Invoke-Step 'Issuer UI state smoke suite' {
        try {
            $env:QTLIC_SKIP_ONBOARDING = '1'
            $env:QT_QPA_PLATFORM = 'offscreen'
            & (Join-Path $binRoot 'issuer-ui-smoke-tests.exe')
            Assert-LastExit 'issuer-ui-smoke-tests'
        }
        finally {
            if ($null -eq $oldOnboarding) {
                Remove-Item Env:QTLIC_SKIP_ONBOARDING -ErrorAction SilentlyContinue
            } else {
                $env:QTLIC_SKIP_ONBOARDING = $oldOnboarding
            }
            if ($null -eq $oldPlatform) {
                Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue
            } else {
                $env:QT_QPA_PLATFORM = $oldPlatform
            }
        }
    }

    Invoke-Step 'Real-world CLI round trip' {
        & (Join-Path $PSScriptRoot 'real_world_cli.ps1') -BinDirectory $binRoot
    }

    Invoke-Step "v$Version release packaging" {
        & (Join-Path $projectRoot 'scripts\package-release.ps1') -Version $Version
    }

    $distRoot = Join-Path $projectRoot 'dist'
    $appZip = Join-Path $distRoot "qt-offline-license-system-v$Version-windows-x64.zip"
    $sdkZip = Join-Path $distRoot "qt-offline-license-runtime-sdk-v$Version.zip"
    $sumPath = Join-Path $distRoot 'SHA256SUMS.txt'
    foreach ($artifact in @($appZip, $sdkZip, $sumPath)) {
        if (-not (Test-Path -LiteralPath $artifact -PathType Leaf)) {
            throw "Release artifact missing: $artifact"
        }
    }

    Invoke-Step 'Release SHA-256 verification' {
        $declared = Get-Content -LiteralPath $sumPath
        foreach ($artifact in @($appZip, $sdkZip)) {
            $name = Split-Path -Leaf $artifact
            $expectedLine = $declared | Where-Object { $_ -match ('\s+' + [regex]::Escape($name) + '$') }
            if (-not $expectedLine) { throw "Missing checksum for $name" }
            $expected = ($expectedLine -split '\s+')[0].ToLowerInvariant()
            $actual = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $expected) { throw "Checksum mismatch for $name" }
        }
    }

    Invoke-Step 'Release sensitive-file scan' {
        Assert-ArchiveSafe $appZip
        Assert-ArchiveSafe $sdkZip
    }

    $appExtract = Join-Path $testRoot 'app'
    $sdkExtract = Join-Path $testRoot 'sdk'
    Expand-Archive -LiteralPath $appZip -DestinationPath $appExtract
    Expand-Archive -LiteralPath $sdkZip -DestinationPath $sdkExtract
    $appDirectory = (Get-ChildItem -LiteralPath $appExtract -Directory | Select-Object -First 1).FullName

    Invoke-Step 'Packaged core tests' {
        & (Join-Path $appDirectory 'license-core-tests.exe')
        Assert-LastExit 'packaged license-core-tests'
    }

    Invoke-Step 'Packaged GUI startup' {
        $env:QTLIC_SKIP_ONBOARDING = '1'
        Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue
        Test-GuiStartup $appDirectory
    }

    Invoke-Step 'Runtime SDK standalone build' {
        $sdkDirectory = (Get-ChildItem -LiteralPath $sdkExtract -Directory | Select-Object -First 1).FullName
        $smokeProject = Join-Path $sdkDirectory 'examples\smoke\smoke.pro'
        $sdkBuild = Join-Path $sdkExtract 'build-smoke'
        New-Item -ItemType Directory -Path $sdkBuild | Out-Null
        Push-Location $sdkBuild
        try {
            & qmake $smokeProject 'CONFIG+=release'
            Assert-LastExit 'runtime SDK qmake'
            & mingw32-make -j4
            Assert-LastExit 'runtime SDK build'
            & (Join-Path $sdkBuild 'bin\runtime-sdk-smoke.exe')
            Assert-LastExit 'runtime SDK smoke executable'
        }
        finally {
            Pop-Location
        }
    }

    Invoke-Step 'Git diff whitespace check' {
        & git -C $projectRoot diff --check
        Assert-LastExit 'git diff --check'
    }

    Write-Output 'ALL FULL-FLOW SCENARIOS PASSED'
}
finally {
    if ($null -eq $oldOnboarding) {
        Remove-Item Env:QTLIC_SKIP_ONBOARDING -ErrorAction SilentlyContinue
    } else {
        $env:QTLIC_SKIP_ONBOARDING = $oldOnboarding
    }
    if ($null -eq $oldPlatform) {
        Remove-Item Env:QT_QPA_PLATFORM -ErrorAction SilentlyContinue
    } else {
        $env:QT_QPA_PLATFORM = $oldPlatform
    }
    $resolvedRoot = [System.IO.Path]::GetFullPath($testRoot)
    $resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $isExpected = (Split-Path -Leaf $resolvedRoot).StartsWith(
        'qt-license-full-flow-', [System.StringComparison]::Ordinal)
    $isInsideTemp = $resolvedRoot.StartsWith(
        $resolvedTemp, [System.StringComparison]::OrdinalIgnoreCase)
    if ($isExpected -and $isInsideTemp -and (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
