param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version,

    [string]$QtBin = (Split-Path -Parent (Get-Command qmake -ErrorAction Stop).Source)
)

$ErrorActionPreference = 'Stop'

$projectRoot = Split-Path -Parent $PSScriptRoot
$distRoot = Join-Path $projectRoot 'dist'
$stageRoot = Join-Path $distRoot "stage-v$Version"
$appStage = Join-Path $stageRoot "qt-offline-license-system-v$Version-windows-x64"
$sdkStage = Join-Path $stageRoot "qt-offline-license-runtime-sdk-v$Version"
$windeployqt = Join-Path $QtBin 'windeployqt.exe'
$qmake = Join-Path $QtBin 'qmake.exe'

if (-not (Test-Path -LiteralPath $windeployqt -PathType Leaf)) {
    throw "windeployqt.exe not found under QtBin: $QtBin"
}
if (-not (Test-Path -LiteralPath $qmake -PathType Leaf)) {
    throw "qmake.exe not found under QtBin: $QtBin"
}
$qtPluginRoot = (& $qmake -query QT_INSTALL_PLUGINS | Select-Object -First 1)
if ([string]::IsNullOrWhiteSpace($qtPluginRoot)) {
    throw 'qmake did not report QT_INSTALL_PLUGINS'
}
$qtPluginRoot = $qtPluginRoot.Trim()
$windowsPlatformPlugin = Join-Path $qtPluginRoot 'platforms\qwindows.dll'
if (-not (Test-Path -LiteralPath $windowsPlatformPlugin -PathType Leaf)) {
    throw "Required Qt platform plugin not found: $windowsPlatformPlugin"
}

$requiredBinaries = @(
    'QtLicenseIssuer.exe',
    'QtHardwareCollector.exe',
    'qt-license-cli.exe',
    'license-core-tests.exe',
    'libsodium-26.dll'
)
foreach ($name in $requiredBinaries) {
    $path = Join-Path (Join-Path $projectRoot 'bin') $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Missing Release binary: $path"
    }
}

if (Test-Path -LiteralPath $stageRoot) {
    Remove-Item -LiteralPath $stageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $appStage, $sdkStage -Force | Out-Null

foreach ($name in $requiredBinaries) {
    Copy-Item -LiteralPath (Join-Path (Join-Path $projectRoot 'bin') $name) -Destination $appStage
}
Copy-Item -LiteralPath (Join-Path $projectRoot 'README.md') -Destination $appStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'CHANGELOG.md') -Destination $appStage
New-Item -ItemType Directory -Path (Join-Path $appStage 'licenses') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $projectRoot 'third_party\libsodium\LICENSE') `
    -Destination (Join-Path $appStage 'licenses\libsodium-LICENSE.txt')

foreach ($name in @('QtLicenseIssuer.exe', 'QtHardwareCollector.exe',
                     'qt-license-cli.exe', 'license-core-tests.exe')) {
    & $windeployqt --release --no-translations --no-opengl-sw --no-plugins `
        (Join-Path $appStage $name)
    if ($LASTEXITCODE -ne 0) { throw "windeployqt failed for $name" }
}
$platformStage = Join-Path $appStage 'platforms'
New-Item -ItemType Directory -Path $platformStage -Force | Out-Null
Copy-Item -LiteralPath $windowsPlatformPlugin -Destination $platformStage
$windowsStylePlugin = Join-Path $qtPluginRoot 'styles\qwindowsvistastyle.dll'
if (Test-Path -LiteralPath $windowsStylePlugin -PathType Leaf) {
    $styleStage = Join-Path $appStage 'styles'
    New-Item -ItemType Directory -Path $styleStage -Force | Out-Null
    Copy-Item -LiteralPath $windowsStylePlugin -Destination $styleStage
}

$runtimeSources = @(
    'crypto_provider.cpp', 'crypto_provider.h',
    'hardware_fingerprint.cpp', 'hardware_fingerprint.h',
    'license_codec.cpp', 'license_codec.h',
    'license_runtime.cpp', 'license_runtime.h',
    'license_types.cpp', 'license_types.h',
    'offline_time_guard.cpp', 'offline_time_guard.h'
)
New-Item -ItemType Directory -Path (Join-Path $sdkStage 'src'),
    (Join-Path $sdkStage 'docs'), (Join-Path $sdkStage 'third_party\libsodium') -Force | Out-Null
foreach ($name in $runtimeSources) {
    Copy-Item -LiteralPath (Join-Path $projectRoot "core\$name") `
        -Destination (Join-Path $sdkStage 'src')
}
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\runtime-sdk\QtLicenseRuntime.pri') `
    -Destination $sdkStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\runtime-sdk\README.md') `
    -Destination $sdkStage
Copy-Item -LiteralPath (Join-Path $projectRoot 'packaging\runtime-sdk\examples') `
    -Destination $sdkStage -Recurse
$integrationGuideName = 'Qt' + (-join @(
    [char]0x5e94, [char]0x7528, [char]0x63a5, [char]0x5165,
    [char]0x6307, [char]0x5357)) + '.md'
$securityGuideName = (-join @(
    [char]0x5b89, [char]0x5168, [char]0x8fb9, [char]0x754c,
    [char]0x4e0e, [char]0x8fd0, [char]0x7ef4, [char]0x6307,
    [char]0x5357)) + '.md'
Copy-Item -LiteralPath (Join-Path $projectRoot (Join-Path 'docs' $integrationGuideName)) `
    -Destination (Join-Path $sdkStage 'docs')
Copy-Item -LiteralPath (Join-Path $projectRoot (Join-Path 'docs' $securityGuideName)) `
    -Destination (Join-Path $sdkStage 'docs')
Copy-Item -LiteralPath (Join-Path $projectRoot 'third_party\libsodium\LICENSE') `
    -Destination (Join-Path $sdkStage 'third_party\libsodium')
Copy-Item -LiteralPath (Join-Path $projectRoot 'third_party\libsodium\libsodium.pri') `
    -Destination (Join-Path $sdkStage 'third_party\libsodium')
Copy-Item -LiteralPath (Join-Path $projectRoot 'third_party\libsodium\libsodium-win64') `
    -Destination (Join-Path $sdkStage 'third_party\libsodium') -Recurse

$appArchive = Join-Path $distRoot "qt-offline-license-system-v$Version-windows-x64.zip"
$sdkArchive = Join-Path $distRoot "qt-offline-license-runtime-sdk-v$Version.zip"
foreach ($archive in @($appArchive, $sdkArchive)) {
    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
}
Compress-Archive -LiteralPath $appStage -DestinationPath $appArchive -CompressionLevel Optimal
Compress-Archive -LiteralPath $sdkStage -DestinationPath $sdkArchive -CompressionLevel Optimal

$checksums = foreach ($archive in @($appArchive, $sdkArchive)) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    "$hash  $(Split-Path -Leaf $archive)"
}
$checksums | Set-Content -LiteralPath (Join-Path $distRoot 'SHA256SUMS.txt') -Encoding ascii

Write-Output $appArchive
Write-Output $sdkArchive
Write-Output (Join-Path $distRoot 'SHA256SUMS.txt')
