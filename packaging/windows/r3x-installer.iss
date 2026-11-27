#define MyAppName "R3X"
#define MyAppVersion "0.1.0"
#define MyAppPublisher "R3X Contributors"
#define MyAppURL "https://github.com/cryals/rexy-app"
#define MyAppExeName "r3x-app.exe"

[Setup]
AppId={{7E8A559B-9E14-4C94-82B3-59C68D9013A7}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
DefaultDirName={autopf}\R3X
DefaultGroupName=R3X
DisableProgramGroupPage=yes
LicenseFile=..\..\LICENSE.txt
OutputDir=..\..\dist
OutputBaseFilename=r3x-{#MyAppVersion}-windows-x86_64-setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
Source: "..\..\dist\r3x-app.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\r3x-daemon.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dist\r3x.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\THIRD-PARTY-NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\resources\core-manifests\*"; DestDir: "{app}\core-manifests"; Flags: ignoreversion recursesubdirs

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional shortcuts:"

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch R3X"; Flags: nowait postinstall skipifsilent
