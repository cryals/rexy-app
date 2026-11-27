#!/usr/bin/env bash
set -euo pipefail

export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
NDK_BIN="${ANDROID_NDK_HOME:-$ANDROID_HOME/ndk/27.2.12479018}/toolchains/llvm/prebuilt/linux-x86_64/bin"

export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$NDK_BIN/aarch64-linux-android29-clang"
export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android29-clang"
export AR_aarch64_linux_android="$NDK_BIN/llvm-ar"

cargo build --lib --target aarch64-linux-android --release --locked
mkdir -p platform/android/app/src/main/jniLibs/arm64-v8a
cp target/aarch64-linux-android/release/libr3x_app_lib.so platform/android/app/src/main/jniLibs/arm64-v8a/libr3x_app_lib.so

(cd platform/android && gradle assembleRelease)
