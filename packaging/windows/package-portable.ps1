param(
    [string]$TargetDir = "",
    [string]$DistDir = "dist"
)

$ErrorActionPreference = "Stop"

if ($TargetDir -ne "") {
    $env:CARGO_TARGET_DIR = $TargetDir
}
$effectiveTarget = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { "target" }

Write-Output "Building release binaries (--locked --release)..."
cargo build --release --locked -p r3x-app -p r3x-daemon -p r3x-cli
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$stage = Join-Path $DistDir "r3x-0.1.0-windows-x86_64-portable"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Path $stage -Force | Out-Null

$releaseBinDir = Join-Path $effectiveTarget "release"
foreach ($bin in @("r3x-app.exe", "r3x-daemon.exe", "r3x.exe")) {
    Copy-Item (Join-Path $releaseBinDir $bin) (Join-Path $stage $bin) -Force
    Copy-Item (Join-Path $releaseBinDir $bin) (Join-Path $DistDir $bin) -Force
}

Copy-Item "LICENSE.txt" (Join-Path $stage "LICENSE.txt") -Force
Copy-Item "THIRD-PARTY-NOTICES.md" (Join-Path $stage "THIRD-PARTY-NOTICES.md") -Force
Copy-Item "resources\core-manifests" (Join-Path $stage "core-manifests") -Recurse -Force

$zipPath = Join-Path $DistDir "r3x-0.1.0-windows-x86_64-portable.zip"
if (Test-Path $zipPath) { Remove-Item -Force $zipPath }
Compress-Archive -Path "$stage\*" -DestinationPath $zipPath -CompressionLevel Optimal

& "$PSScriptRoot\..\generate-sbom.ps1" -OutPath (Join-Path $DistDir "r3x-sbom.cdx.json")

$checksumLines = @()
foreach ($f in @("r3x-app.exe", "r3x-daemon.exe", "r3x.exe", "r3x-0.1.0-windows-x86_64-portable.zip", "r3x-sbom.cdx.json")) {
    $p = Join-Path $DistDir $f
    if (Test-Path $p) {
        $h = (Get-FileHash -Path $p -Algorithm SHA256).Hash.ToLowerInvariant()
        $checksumLines += "$h  $f"
    }
}
$checksumLines | Set-Content -Path (Join-Path $DistDir "SHA256SUMS.txt") -Encoding UTF8
Write-Output "Packaged portable archive at $zipPath"
