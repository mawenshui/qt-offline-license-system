param(
    [string]$BinDirectory = (Join-Path (Split-Path $PSScriptRoot -Parent) 'bin')
)

$ErrorActionPreference = 'Stop'
$cli = Join-Path $BinDirectory 'qt-license-cli.exe'
if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) {
    throw "CLI not found: $cli"
}

$runId = [Guid]::NewGuid().ToString('N')
$productId = 'QtLicenseRealWorld-' + $runId
$testRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('qt-license-real-world-' + $runId)
$null = New-Item -ItemType Directory -Path $testRoot
$utf8 = New-Object System.Text.UTF8Encoding($false)
$oldPassword = $env:QTLIC_PASSWORD
$stateRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) `
    'qt-license-cli\qt-license-state'
$stateDirectory = Join-Path $stateRoot $productId

function Write-Utf8Json([string]$Path, $Value) {
    $json = $Value | ConvertTo-Json -Depth 20 -Compress
    [System.IO.File]::WriteAllText($Path, $json, $utf8)
}

function Invoke-Cli([string]$Name, [int]$ExpectedExit, [string[]]$CommandArgs) {
    $savedErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $cli @CommandArgs 2>&1
        $actualExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorAction
    }
    if ($actualExit -ne $ExpectedExit) {
        throw "$Name failed: expected exit $ExpectedExit, actual $actualExit`n$($output -join [Environment]::NewLine)"
    }
    Write-Output "PASS $Name"
}

try {
    $env:QTLIC_PASSWORD = 'real-world-test-password'

    $vault = Join-Path $testRoot 'issuer.qtkv'
    $request = Join-Path $testRoot 'device.qreq'
    $runtime = Join-Path $testRoot 'runtime.json'
    $runtimeHeader = Join-Path $testRoot 'runtime_config.h'
    $durationLicense = Join-Path $testRoot 'duration.qtlic'
    $runtimeLicense = Join-Path $testRoot 'runtime-quota.qtlic'

    Invoke-Cli 'create vault' 0 @('init', $vault, $productId)
    Invoke-Cli 'collect local hardware' 0 @('collect', $productId, $request)
    $collectedRequest = Get-Content -LiteralPath $request -Raw | ConvertFrom-Json
    if (@($collectedRequest.hardware).Count -lt 2) {
        throw 'real hardware collection did not produce multiple independent claims'
    }
    Write-Output 'PASS collect multiple hardware claims'
    Invoke-Cli 'export runtime configuration' 0 @(
        'export-runtime', $vault, $runtime, $runtimeHeader)
    Invoke-Cli 'issue validity-duration license' 0 @(
        'issue', $vault, $request, $durationLicense,
        'validity_duration', '604800', 'Customer-001')
    Invoke-Cli 'issue actual-runtime license' 0 @(
        'issue', $vault, $request, $runtimeLicense,
        'runtime_quota', '604800', 'Customer-001')
    Invoke-Cli 'inspect signed license' 0 @('inspect', $runtime, $durationLicense)
    Invoke-Cli 'verify validity-duration license' 0 @(
        'verify', $runtime, $durationLicense, $request)
    Invoke-Cli 'verify actual-runtime license' 0 @(
        'verify', $runtime, $runtimeLicense, $request)

    $wrongRequest = Get-Content -LiteralPath $request -Raw | ConvertFrom-Json
    $wrongRequest.product_id = 'OtherProduct'
    $wrongRequestPath = Join-Path $testRoot 'wrong-product.qreq'
    Write-Utf8Json $wrongRequestPath $wrongRequest
    Invoke-Cli 'reject request for another product' 1 @(
        'verify', $runtime, $durationLicense, $wrongRequestPath)

    $tamperedLicense = Join-Path $testRoot 'tampered.qtlic'
    Copy-Item -LiteralPath $durationLicense -Destination $tamperedLicense
    $tampered = Get-Content -LiteralPath $tamperedLicense -Raw | ConvertFrom-Json
    $first = $tampered.ciphertext.Substring(0, 1)
    $replacement = if ($first -eq 'A') { 'B' } else { 'A' }
    $tampered.ciphertext = $replacement + $tampered.ciphertext.Substring(1)
    Write-Utf8Json $tamperedLicense $tampered
    Invoke-Cli 'reject tampered license' 3 @(
        'verify', $runtime, $tamperedLicense, $request)

    $badRuntime = Get-Content -LiteralPath $runtime -Raw | ConvertFrom-Json
    $keyProperty = $badRuntime.product_decryption_keys.PSObject.Properties | Select-Object -First 1
    $keyProperty.Value = 'YQ'
    $badRuntimePath = Join-Path $testRoot 'bad-runtime.json'
    Write-Utf8Json $badRuntimePath $badRuntime
    Invoke-Cli 'reject malformed runtime key' 1 @(
        'inspect', $badRuntimePath, $durationLicense)

    $requestObject = $collectedRequest
    $batchHardware = @()
    foreach ($item in $requestObject.hardware) {
        $batchHardware += @{
            slot = [string]$item.slot
            type = [string]$item.type
            hashes = @([string]$item.hash)
        }
    }
    $batch = @{
        schema = 'qt-license-batch'
        version = 1
        defaults = @{
            product_id = $productId
            license_mode = 'validity_duration'
            max_runtime_seconds = 604800
            binding_mode = 'all'
            features = @('basic')
        }
        records = @(
            @{
                row_id = '1'; customer_id = 'C001'; output_name = 'C001.qtlic'
                hardware = $batchHardware
            },
            @{
                row_id = '2'; customer_id = 'C002'; output_name = 'C002.qtlic'
                hardware = $batchHardware
            }
        )
    }
    $batchPath = Join-Path $testRoot 'batch.json'
    $batchOutput = Join-Path $testRoot 'batch-output'
    Write-Utf8Json $batchPath $batch
    Invoke-Cli 'issue atomic batch' 0 @('batch', $vault, $batchPath, $batchOutput)
    $hasManifest = Test-Path -LiteralPath (Join-Path $batchOutput 'batch-manifest.json')
    $hasFirstLicense = Test-Path -LiteralPath (Join-Path $batchOutput 'licenses\C001.qtlic')
    $hasSecondLicense = Test-Path -LiteralPath (Join-Path $batchOutput 'licenses\C002.qtlic')
    if (-not $hasManifest -or -not $hasFirstLicense -or -not $hasSecondLicense) {
        throw 'batch output is incomplete'
    }
    Write-Output 'PASS batch artifacts complete'
    Write-Output 'ALL REAL-WORLD CLI SCENARIOS PASSED'
}
finally {
    $env:QTLIC_PASSWORD = $oldPassword
    $resolvedStateRoot = [System.IO.Path]::GetFullPath($stateRoot)
    $resolvedStateDirectory = [System.IO.Path]::GetFullPath($stateDirectory)
    $isTestState = $productId.StartsWith('QtLicenseRealWorld-', [System.StringComparison]::Ordinal)
    $isInsideStateRoot = $resolvedStateDirectory.StartsWith(
        $resolvedStateRoot + [System.IO.Path]::DirectorySeparatorChar,
        [System.StringComparison]::OrdinalIgnoreCase)
    if ($isTestState -and $isInsideStateRoot -and (Test-Path -LiteralPath $resolvedStateDirectory)) {
        Remove-Item -LiteralPath $resolvedStateDirectory -Recurse -Force
    }
    $resolvedRoot = [System.IO.Path]::GetFullPath($testRoot)
    $resolvedTemp = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $isInsideTemp = $resolvedRoot.StartsWith($resolvedTemp, [System.StringComparison]::OrdinalIgnoreCase)
    if ($isInsideTemp -and (Test-Path -LiteralPath $resolvedRoot)) {
        Remove-Item -LiteralPath $resolvedRoot -Recurse -Force
    }
}
