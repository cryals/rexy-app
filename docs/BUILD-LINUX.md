# Building R3X for Linux

## 1. System Dependencies

Install Slint (Skia/Winit/Wayland/X11), D-Bus (`keyring` Secret Service), and packaging tools:

=== "Ubuntu / Debian"

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  libdbus-1-dev libfontconfig1-dev libfreetype-dev \
  libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev \
  libgl1-mesa-dev libglu1-mesa-dev pkg-config \
  desktop-file-utils appstream dpkg-dev
```

=== "Fedora"

```bash
sudo dnf install -y dbus-devel fontconfig-devel freetype-devel \
  libxkbcommon-devel libxkbcommon-x11-devel wayland-devel \
  mesa-libGL-devel mesa-libGLU-devel pkgconf-pkg-config \
  desktop-file-utils libappstream-glib rpm-build
```

=== "Arch Linux"

```bash
sudo pacman -S --needed dbus fontconfig freetype2 \
  libxkbcommon libxkbcommon-x11 wayland mesa glu pkgconf \
  desktop-file-utils appstream
```

## 2. Building Workspace Binaries

```bash
cargo build --release --locked -p r3x-app -p r3x-daemon -p r3x-cli
```

Binaries are written to `target/release/{r3x-app,r3x-daemon,r3x}`.

## 3. Packaging (`.deb`, AppImage / Portable Tarball, RPM Spec)

- **Debian package:** `./packaging/linux/build-deb.sh` -> `dist/r3x_0.1.0_<arch>.deb` (includes `dev.rexy.r3x.desktop`, `dev.rexy.r3x.metainfo.xml`, and `resources/core-manifests/`).
- **AppImage / Portable Tarball:** `./packaging/linux/build-appimage.sh` -> `dist/R3X-0.1.0-<arch>.AppImage` (when `appimagetool` is installed) or `dist/r3x-0.1.0-linux-<arch>-portable.tar.gz`.
- **RPM:** `packaging/linux/r3x.spec` installs all three binaries plus `.desktop` and `.metainfo.xml` descriptors.

## 4. Verification Status Note

Linux compilation, testing, packaging, `.desktop` validation, and AppStream metadata checks are wired into `.github/workflows/linux.yml` and `.github/workflows/ci.yml` on `ubuntu-24.04`. Interactive Wayland/X11 GUI walkthroughs on physical Linux hardware have not yet been executed locally on this Windows workstation.
