#define MyAppName "PII Scrubber"
#define MyAppVersion "4.0.1"
#define MyAppExeName "PII-Scrubber-v4.exe"

[Setup]
AppId={{E99B9E0A-823B-4BCE-A5C2-3BB0416D3975}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\PII Scrubber
DefaultGroupName=PII Scrubber
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
OutputDir=..\installer-output
OutputBaseFilename=PII-Scrubber-Setup
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest

[Files]
Source: "..\dist\PII-Scrubber-v4\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\PII Scrubber"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\PII Scrubber"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"; Flags: unchecked

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch PII Scrubber"; Flags: nowait postinstall skipifsilent
