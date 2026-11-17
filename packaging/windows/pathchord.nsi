Unicode True
RequestExecutionLevel admin
SetCompressor /SOLID lzma
!include "MUI2.nsh"
!ifndef APP_ROLE
  !error "APP_ROLE must be ingress or egress"
!endif
!if "${APP_ROLE}" == "ingress"
  !define SERVICE_ID "PathChordIngressd"
  !define CONFIG_TEMPLATE "..\common\default-config.yaml"
!else if "${APP_ROLE}" == "egress"
  !define SERVICE_ID "PathChordEgressd"
  !define CONFIG_TEMPLATE "egress.yaml"
!else
  !error "invalid APP_ROLE"
!endif
!define DAEMON_NAME "pathchord-${APP_ROLE}d"
!ifndef APP_VERSION
  !define APP_VERSION "0.1.0"
!endif
!ifndef DAEMON_BINARY_PATH
  !error "DAEMON_BINARY_PATH is required"
!endif
!ifndef CTL_BINARY_PATH
  !error "CTL_BINARY_PATH is required"
!endif
!ifndef OUTPUT_PATH
  !define OUTPUT_PATH "${DAEMON_NAME}-${APP_VERSION}-setup.exe"
!endif
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${DAEMON_NAME}"
Name "PathChord ${APP_ROLE} ${APP_VERSION}"
OutFile "${OUTPUT_PATH}"
InstallDir "$PROGRAMFILES64\PathChord"
InstallDirRegKey HKLM "${UNINSTALL_KEY}" "InstallLocation"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
Function .onInit
  SetRegView 64
  SetShellVarContext all
  ReadRegStr $0 HKLM "Software\PathChord" "Role"
  StrCmp $0 "" legacy_check
  StrCmp $0 "${APP_ROLE}" done
  MessageBox MB_ICONSTOP "Uninstall the other PathChord role before installing ${APP_ROLE}. Private state is preserved."
  Abort
  legacy_check:
  ReadRegStr $0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\PathChord" "InstallLocation"
  StrCmp $0 "" done
  MessageBox MB_ICONSTOP "Uninstall the legacy combined PathChord package before selecting a role."
  Abort
  done:
FunctionEnd
Section "PathChord ${APP_ROLE}" SecRuntime
  SectionIn RO
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File "install-service.ps1"
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$PLUGINSDIR\install-service.ps1" -Action Stop -Role ${APP_ROLE}'
  Pop $0
  StrCmp $0 "0" +2
    Abort "Could not stop the existing service."
  SetOutPath "$INSTDIR"
  File /oname=${DAEMON_NAME}.exe "${DAEMON_BINARY_PATH}"
  File /oname=pathchordctl.exe "${CTL_BINARY_PATH}"
  File "..\..\LICENSE"
  File "..\common\pathchord.1"
  SetOutPath "$APPDATA\PathChord\config\${APP_ROLE}"
  IfFileExists "$APPDATA\PathChord\config\${APP_ROLE}\${APP_ROLE}.yaml" config_exists
    File /oname=${APP_ROLE}.yaml "${CONFIG_TEMPLATE}"
  config_exists:
  CreateDirectory "$APPDATA\PathChord\data\${APP_ROLE}"
  CreateDirectory "$APPDATA\PathChord\credentials\${APP_ROLE}"
  CreateDirectory "$APPDATA\PathChord\logs\${APP_ROLE}"
  SetOutPath "$INSTDIR\services"
  File "${DAEMON_NAME}.xml"
  File "install-service.ps1"
  FileOpen $0 "$INSTDIR\services\role.txt" w
  FileWrite $0 "${APP_ROLE}"
  FileClose $0
  nsExec::ExecToLog 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$INSTDIR\services\install-service.ps1" -Action Prepare -Role ${APP_ROLE}'
  Pop $0
  StrCmp $0 "0" +2
    Abort "Could not protect the role's private directories."
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\PathChord" "Role" "${APP_ROLE}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "PathChord ${APP_ROLE}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
SectionEnd
Section "Uninstall"
  SetRegView 64
  SetShellVarContext all
  IfFileExists "$INSTDIR\${DAEMON_NAME}-service.exe" 0 +3
    ExecWait '"$INSTDIR\${DAEMON_NAME}-service.exe" stop'
    ExecWait '"$INSTDIR\${DAEMON_NAME}-service.exe" uninstall'
  Delete "$INSTDIR\${DAEMON_NAME}.exe"
  Delete "$INSTDIR\pathchordctl.exe"
  Delete "$INSTDIR\pathchord.1"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\${DAEMON_NAME}-service.exe"
  Delete "$INSTDIR\${DAEMON_NAME}-service.xml"
  Delete "$INSTDIR\uninstall.exe"
  RMDir /r "$INSTDIR\services"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  DeleteRegKey HKLM "Software\PathChord"
SectionEnd
