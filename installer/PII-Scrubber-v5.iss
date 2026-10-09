#define MyAppName "PII Scrubber V5"
#define MyAppVersion "5.0.0"
#define MyAppExeName "PII-Scrubber-v5.exe"

[Setup]
AppId={{5E731D63-2F8C-4FC5-A7D2-B8A81B4125F0}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\PII Scrubber V5
DefaultGroupName=PII Scrubber V5
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
OutputDir=..\installer-output-v5
OutputBaseFilename=PII-Scrubber-v5-Setup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest

[Files]
Source: "..\dist\PII-Scrubber-v5\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\PII Scrubber V5"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\PII Scrubber V5"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch PII Scrubber V5"; Flags: nowait postinstall skipifsilent
