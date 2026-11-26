#define MyAppName "Network Scan"
#define MyAppVersion "1.0.0"

[Setup]
AppId={{6F1C7A52-3B0E-4C57-9A55-4E7E2C1D9B10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher=Network Scan
DefaultDirName={autopf}\Network Scan
DefaultGroupName=Network Scan
OutputDir=..\dist
OutputBaseFilename=NetworkScan-Setup
SetupIconFile=..\app.ico
UninstallDisplayIcon={app}\NetworkScan.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "..\publish\NetworkScan.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Network Scan"; Filename: "{app}\NetworkScan.exe"
Name: "{group}\Uninstall Network Scan"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Network Scan"; Filename: "{app}\NetworkScan.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\NetworkScan.exe"; Description: "Launch Network Scan"; Flags: nowait postinstall skipifsilent
