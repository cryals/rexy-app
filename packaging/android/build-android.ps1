param(
    [string]$TargetDir = "E:\r3x-android-target",
    [switch]$Release = $false
)

$ErrorActionPreference = "Stop"
$ndkBin = "$env:LOCALAPPDATA\Android\Sdk\ndk\27.2.12479018\toolchains\llvm\prebuilt\windows-x86_64\bin"
if (!(Test-Path $ndkBin)) {
    throw "Android NDK 27.2.12479018 toolchain not found at $ndkBin"
}

$env:CARGO_TARGET_DIR = $TargetDir
$env:CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER = "$ndkBin\aarch64-linux-android29-clang.cmd"
$env:CC_aarch64_linux_android = "$ndkBin\aarch64-linux-android29-clang.cmd"
$env:AR_aarch64_linux_android = "$ndkBin\llvm-ar.exe"

$profileFlag = if ($Release) { "--release" } else { "" }
if ($Release) {
    cargo build --lib --target aarch64-linux-android --release --locked
} else {
    cargo build --lib --target aarch64-linux-android --locked
}
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

$profileDir = if ($Release) { "release" } else { "debug" }
$soSrc = Join-Path $TargetDir "aarch64-linux-android\$profileDir\libr3x_app_lib.so"
$jniOut = "platform\android\app\src\main\jniLibs\arm64-v8a"
New-Item -ItemType Directory -Path $jniOut -Force | Out-Null
Copy-Item $soSrc (Join-Path $jniOut "libr3x_app_lib.so") -Force

$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
Push-Location "platform\android"
$task = if ($Release) { "assembleRelease" } else { "assembleDebug" }
gradle $task
$gradleCode = $LASTEXITCODE
Pop-Location
exit $gradleCode
