Name:           r3x
Version:        0.1.0
Release:        1%{?dist}
Summary:        R3X (Rexy) Universal Multi-Core VPN & Proxy Client
License:        GPL-3.0-only
URL:            https://github.com/cryals/rexy-app

%description
Rust + Material 3 Expressive native Slint multi-core VPN & Proxy client.

%install
mkdir -p %{buildroot}%{_bindir} %{buildroot}%{_datadir}/applications %{buildroot}%{_datadir}/metainfo
install -m755 target/release/r3x-app %{buildroot}%{_bindir}/r3x-app
install -m755 target/release/r3x-daemon %{buildroot}%{_bindir}/r3x-daemon
install -m755 target/release/r3x %{buildroot}%{_bindir}/r3x
install -m644 packaging/linux/dev.rexy.r3x.desktop %{buildroot}%{_datadir}/applications/dev.rexy.r3x.desktop
install -m644 packaging/linux/dev.rexy.r3x.metainfo.xml %{buildroot}%{_datadir}/metainfo/dev.rexy.r3x.metainfo.xml

%files
%{_bindir}/r3x-app
%{_bindir}/r3x-daemon
%{_bindir}/r3x
%{_datadir}/applications/dev.rexy.r3x.desktop
%{_datadir}/metainfo/dev.rexy.r3x.metainfo.xml
