; PathChord Windows installer.
; Build with packaging/windows/build.ps1 so the binary and version are
; supplied explicitly from the Cargo workspace.
Unicode True
RequestExecutionLevel admin
SetCompressor /SOLID lzma
SetDatablockOptimize on

!include "MUI2.nsh"
!include "FileFunc.nsh"
!cd "${__FILEDIR__}"

!ifndef APP_VERSION
  !define APP_VERSION "0.1.0"
!endif
!ifndef BINARY_PATH
  !define BINARY_PATH "..\..\target\release\pathchord.exe"
!endif
!ifndef OUTPUT_PATH
  !define OUTPUT_PATH "PathChord-${APP_VERSION}-windows-x86_64-setup.exe"
!endif
!define PRODUCT_NAME "PathChord"
!define PRODUCT_PUBLISHER "PathChord contributors"
!define PRODUCT_WEB_SITE "https://github.com/KagurazakaNyaa/PathChord"
!define PRODUCT_DIR "PathChord"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

Name "${PRODUCT_NAME} ${APP_VERSION}"
OutFile "${OUTPUT_PATH}"
InstallDir "$PROGRAMFILES\${PRODUCT_DIR}"
InstallDirRegKey HKLM "${UNINSTALL_KEY}" "InstallLocation"
ShowInstDetails show
ShowUninstDetails show

!define MUI_ABORTWARNING
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

VIProductVersion "${APP_VERSION}.0"
VIAddVersionKey /LANG=1033 "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey /LANG=1033 "CompanyName" "${PRODUCT_PUBLISHER}"
VIAddVersionKey /LANG=1033 "FileDescription" "PathChord proxy runtime"
VIAddVersionKey /LANG=1033 "FileVersion" "${APP_VERSION}"
VIAddVersionKey /LANG=1033 "LegalCopyright" "GPL-3.0-only"

; The packaged service definitions are compatible with WinSW.  WinSW is
; intentionally not bundled: obtain the audited version used by the operator,
; place winsw.exe in the installation directory, and run
; services\install-service.ps1 from an elevated PowerShell prompt.
Section "PathChord runtime" SecRuntime
  SectionIn RO
  SetOutPath "$INSTDIR"
  File "${BINARY_PATH}"
  File "..\..\LICENSE"
  File "..\common\pathchord.1"
  File "..\common\default-config.yaml"

  SetOutPath "$COMMONAPPDATA\PathChord\config"
  IfFileExists "$COMMONAPPDATA\PathChord\config\ingress.yaml" config_exists
    File /oname=ingress.yaml "..\common\default-config.yaml"
  config_exists:

  CreateDirectory "$COMMONAPPDATA\PathChord\data"
  CreateDirectory "$COMMONAPPDATA\PathChord\credentials"
  CreateDirectory "$COMMONAPPDATA\PathChord\logs"

  SetOutPath "$INSTDIR\services"
  File "pathchord-ingress.xml"
  File "pathchord-egress.xml"
  File "install-service.ps1"
  File "README.md"

  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "DisplayVersion" "${APP_VERSION}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKLM "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  ; If WinSW wrappers were installed, let them stop and unregister cleanly.
  IfFileExists "$INSTDIR\pathchord-ingress-service.exe" 0 +3
    ExecWait '"$INSTDIR\pathchord-ingress-service.exe" stop'
    ExecWait '"$INSTDIR\pathchord-ingress-service.exe" uninstall'
  IfFileExists "$INSTDIR\pathchord-egress-service.exe" 0 +3
    ExecWait '"$INSTDIR\pathchord-egress-service.exe" stop'
    ExecWait '"$INSTDIR\pathchord-egress-service.exe" uninstall'

  Delete "$INSTDIR\pathchord.exe"
  Delete "$INSTDIR\pathchord.1"
  Delete "$INSTDIR\default-config.yaml"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\uninstall.exe"
  Delete "$INSTDIR\pathchord-ingress-service.exe"
  Delete "$INSTDIR\pathchord-egress-service.exe"
  Delete "$INSTDIR\pathchord-ingress-service.xml"
  Delete "$INSTDIR\pathchord-egress-service.xml"
  Delete "$INSTDIR\pathchord-ingress.xml"
  Delete "$INSTDIR\pathchord-egress.xml"
  RMDir /r "$INSTDIR\services"
  RMDir "$INSTDIR"
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
SectionEnd
