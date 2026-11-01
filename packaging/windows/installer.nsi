; Pocketwire Bridge installer for Windows. Per-user: no administrator rights, installs to
; %LocalAppData%\Programs\Pocketwire. Build with build.sh (makensis runs on Linux too).
;   makensis -DVERSION=0.3.0 -DARCH=amd64 -DSRC=<dir with both exes> -DOUT=<setup.exe> installer.nsi

Unicode true
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef ARCH
  !define ARCH "amd64"
!endif

!define APP "Pocketwire Bridge"
!define GUI "PocketwireBridge.exe"
!define CLI "pocketwire.exe"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\PocketwireBridge"

Name "${APP}"
OutFile "${OUT}"
InstallDir "$LOCALAPPDATA\Programs\Pocketwire"
InstallDirRegKey HKCU "${UNINST_KEY}" "InstallLocation"
RequestExecutionLevel user
SetCompressor /SOLID lzma
BrandingText "pocketwire.app"

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${APP}"
VIAddVersionKey "FileDescription" "${APP} installer"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "CompanyName" "Pocketwire"
VIAddVersionKey "LegalCopyright" "Pocketwire"

!define MUI_ICON "pocketwire.ico"
!define MUI_UNICON "pocketwire.ico"
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE "Install ${APP}"
!define MUI_WELCOMEPAGE_TEXT "The Bridge lets your AI agents send texts from your phone, with your approval. It runs in the background with an icon in the tray.$\r$\n$\r$\nKeep this computer on and connected to your Android phone through KDE Connect.$\r$\n$\r$\nVersion ${VERSION}."
!define MUI_COMPONENTSPAGE_NODESC
!define MUI_FINISHPAGE_RUN "$INSTDIR\${GUI}"
!define MUI_FINISHPAGE_RUN_TEXT "Start ${APP} and pair this computer"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Function .onInit
!if "${ARCH}" == "amd64"
  ${IfNot} ${RunningX64}
    MessageBox MB_ICONSTOP "This installer is for 64-bit Windows." /SD IDOK
    Abort
  ${EndIf}
!endif
FunctionEnd

; A silent install (winget, or an update) has no finish page, so start the Bridge here: in the
; background when this computer is already paired, otherwise with its page open for pairing.
Function .onInstSuccess
  ${If} ${Silent}
    ${If} ${FileExists} "$APPDATA\pocketwire\config.json"
      Exec '"$INSTDIR\${GUI}" --background'
    ${Else}
      Exec '"$INSTDIR\${GUI}"'
    ${EndIf}
  ${EndIf}
FunctionEnd

; Stop a running copy so its files can be replaced.
!macro StopBridge
  nsExec::Exec 'taskkill /IM "${GUI}" /F'
  Pop $0
  Sleep 500
!macroend

Section "${APP}" SecMain
  SectionIn RO
  !insertmacro StopBridge
  ; A scheduled task left by `pocketwire service install` in older versions.
  nsExec::Exec 'schtasks /Delete /F /TN "Pocketwire Bridge"'
  Pop $0
  SetOutPath "$INSTDIR"
  File "${SRC}\${GUI}"
  File "${SRC}\${CLI}"
  File "pocketwire.ico"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortCut "$SMPROGRAMS\${APP}.lnk" "$INSTDIR\${GUI}" "" "$INSTDIR\pocketwire.ico"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${APP}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "Publisher" "Pocketwire"
  WriteRegStr HKCU "${UNINST_KEY}" "URLInfoAbout" "https://pocketwire.app"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\pocketwire.ico"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Start when I sign in" SecAutostart
  nsExec::Exec '"$INSTDIR\${CLI}" _installer autostart-on'
  Pop $0
SectionEnd

Section "Add pocketwire to PATH (command line)" SecPath
  nsExec::Exec '"$INSTDIR\${CLI}" _installer path-add'
  Pop $0
SectionEnd

Section "Uninstall"
  !insertmacro StopBridge
  nsExec::Exec '"$INSTDIR\${CLI}" _installer autostart-off'
  Pop $0
  nsExec::Exec '"$INSTDIR\${CLI}" _installer path-remove'
  Pop $0
  Delete "$SMPROGRAMS\${APP}.lnk"
  Delete "$INSTDIR\${GUI}"
  Delete "$INSTDIR\${CLI}"
  Delete "$INSTDIR\pocketwire.ico"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINST_KEY}"
  ; The pairing in %AppData%\pocketwire stays, so reinstalling needs no new code.
SectionEnd
