;
; uninstall-wireshark.nsi
;

; Create an installer that only writes an uninstaller.
; https://nsis.sourceforge.io/Signing_an_Uninstaller

!include "wireshark-common.nsh"
!include 'LogicLib.nsh'
!include x64.nsh
!include "StrFunc.nsh"
${UnStrRep}

SetCompress off
OutFile "${STAGING_DIR}\uninstall_wireshark_installer.exe"

InstType "un.Default (keep Personal Settings and Npcap)"
InstType "un.All (remove all)"

; Uninstaller icon
UninstallIcon "..\..\resources\icons\wiresharkinst.ico"

!include "MUI.nsh"

!define MUI_UNICON "..\..\resources\icons\wiresharkinst.ico"

; Uninstall stuff (NSIS 2.08: "\r\n" don't work here)
!define MUI_UNCONFIRMPAGE_TEXT_TOP "The following ${PROGRAM_NAME} installation will be removed. Click 'Next' to continue."
; Uninstall stuff (this text isn't used with the MODERN_UI!)
;UninstallText "This will uninstall ${PROGRAM_NAME}.\r\nBefore starting the uninstallation, make sure ${PROGRAM_NAME} is not running.\r\nClick 'Next' to continue."

!define MUI_UNFINISHPAGE_NOAUTOCLOSE
!define MUI_WELCOMEPAGE_TITLE_3LINES
!define MUI_FINISHPAGE_TITLE_3LINES

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_COMPONENTS
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

; ============================================================================
; Section macros
; ============================================================================
!include "Sections.nsh"

; ============================================================================
; Uninstall page configuration
; ============================================================================
ShowUninstDetails show

; ============================================================================
; Functions and macros
; ============================================================================

Function .onInit
  ; MUST be the absolute path to our staging directory.
  WriteUninstaller "${STAGING_DIR}\${UNINSTALLER_NAME}"
  SetErrorLevel 0
  Quit
FunctionEnd

Var EXTENSION
Function un.Disassociate
  Push $R0
!insertmacro PushFileExtensions

  Pop $EXTENSION
  ${DoUntil} $EXTENSION == ${FILE_EXTENSION_MARKER}
    ReadRegStr $R0 HKCR $EXTENSION ""
    StrCmp $R0 ${WIRESHARK_ASSOC} un.Disassociate.doDeregister
    Goto un.Disassociate.end
un.Disassociate.doDeregister:
    ; The extension is associated with Wireshark so, we must destroy this!
    DeleteRegKey HKCR $EXTENSION
    DetailPrint "Deregistered file type: $EXTENSION"
un.Disassociate.end:
    Pop $EXTENSION
  ${Loop}

  Pop $R0
FunctionEnd

Section "-Required"
SectionEnd

!define EXECUTABLE_MARKER "EXECUTABLE_MARKER"
Var EXECUTABLE

Section /o "Un.USBPcap" un.SecUSBPcap
;-------------------------------------------
SectionIn 2
${If} ${RunningX64}
    ${DisableX64FSRedirection}
    SetRegView 64
${EndIf}
ReadRegStr $1 HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\USBPcap" "UninstallString"
${If} ${RunningX64}
    ${EnableX64FSRedirection}
    SetRegView 32
${EndIf}
${If} $1 != ""
    ${UnStrRep} $2 '$1' '\Uninstall.exe' ''
    ${UnStrRep} $3 '$2' '"' ''
    ExecWait '$1 _?=$3' $0
    DetailPrint "USBPcap uninstaller returned $0"
    ${If} $0 == "0"
        Delete "$3\Uninstall.exe"
        Delete "$INSTDIR\extcap\USBPcapCMD.exe"
    ${EndIf}
${EndIf}
ClearErrors
SectionEnd


Section "Uninstall" un.SecUinstall
;-------------------------------------------
;
; UnInstall for every user
;
SectionIn 1 2
SetShellVarContext all

!insertmacro IsWiresharkRunning

Push "${EXECUTABLE_MARKER}"
Push "${PROGRAM_NAME}"
Push "capinfos"
Push "captype"
Push "dumpcap"
Push "editcap"
Push "mergecap"
Push "randpkt"
Push "rawshark"
Push "reordercap"
Push "text2pcap"
Push "tshark"

!ifdef MMDBRESOLVE_EXE
Push "mmdbresolve"
!endif

Pop $EXECUTABLE
${DoUntil} $EXECUTABLE == ${EXECUTABLE_MARKER}

  ; IsWiresharkRunning should make sure everything is closed down so we *shouldn't* run
  ; into any problems here.
  Delete "$INSTDIR\$EXECUTABLE.exe"
  IfErrors 0 deletionSuccess
    MessageBox MB_OK "$EXECUTABLE.exe could not be removed. Is it in use?" /SD IDOK IDOK 0
    Abort "$EXECUTABLE.exe could not be removed. Aborting the uninstall process."

deletionSuccess:
  Pop $EXECUTABLE

${Loop}


DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_NAME}"
DeleteRegKey HKEY_LOCAL_MACHINE "Software\${PROGRAM_NAME}"
DeleteRegKey HKEY_LOCAL_MACHINE "Software\Microsoft\Windows\CurrentVersion\App Paths\${PROGRAM_NAME}.exe"

Call un.Disassociate

DeleteRegKey HKCR ${WIRESHARK_ASSOC}
DeleteRegKey HKCR "${WIRESHARK_ASSOC}\Shell\open\command"
DeleteRegKey HKCR "${WIRESHARK_ASSOC}\DefaultIcon"

Delete "$INSTDIR\*.dll"
Delete "$INSTDIR\*.exe"
Delete "$INSTDIR\*.html"
Delete "$INSTDIR\*.qm"
Delete "$INSTDIR\accessible\*.*"
Delete "$INSTDIR\AUTHORS-SHORT"
Delete "$INSTDIR\COPYING*"
Delete "$INSTDIR\audio\*.*"
Delete "$INSTDIR\bearer\*.*"
Delete "$INSTDIR\diameter\*.*"
Delete "$INSTDIR\extcap\androiddump.*"
Delete "$INSTDIR\extcap\ciscodump.*"
Delete "$INSTDIR\extcap\etwdump.*"
Delete "$INSTDIR\extcap\randpktdump.*"
Delete "$INSTDIR\extcap\sshdump.*"
Delete "$INSTDIR\extcap\udpdump.*"
Delete "$INSTDIR\extcap\wifidump.*"
Delete "$INSTDIR\gpl-2.0-standalone.html"
Delete "$INSTDIR\Acknowledgements.md"
Delete "$INSTDIR\help\*.*"
Delete "$INSTDIR\iconengines\*.*"
Delete "$INSTDIR\imageformats\*.*"
Delete "$INSTDIR\mediaservice\*.*"
Delete "$INSTDIR\networkinformation\*.*"
Delete "$INSTDIR\platforms\*.*"
Delete "$INSTDIR\playlistformats\*.*"
Delete "$INSTDIR\printsupport\*.*"
Delete "$INSTDIR\share\glib-2.0\schemas\*.*"
Delete "$INSTDIR\snmp\*.*"
Delete "$INSTDIR\snmp\mibs\*.*"
Delete "$INSTDIR\styles\translations\*.*"
Delete "$INSTDIR\styles\*.*"
Delete "$INSTDIR\protobuf\*.*"
Delete "$INSTDIR\tls\*.*"
Delete "$INSTDIR\tpncp\*.*"
Delete "$INSTDIR\translations\*.*"
Delete "$INSTDIR\ui\*.*"
Delete "$INSTDIR\wimaxasncp\*.*"
Delete "$INSTDIR\ws.css"
; previous versions installed these files
Delete "$INSTDIR\*.manifest"
; previous versions installed this file
Delete "$INSTDIR\AUTHORS-SHORT-FORMAT"
Delete "$INSTDIR\README*"
Delete "$INSTDIR\NEWS.txt"
Delete "$INSTDIR\manuf"
Delete "$INSTDIR\wka"
Delete "$INSTDIR\services"
Delete "$INSTDIR\pdml2html.xsl"
Delete "$INSTDIR\pcrepattern.3.txt"
Delete "$INSTDIR\user-guide.chm"
Delete "$INSTDIR\example_snmp_users_file"
Delete "$INSTDIR\ipmap.html"
Delete "$INSTDIR\radius\*.*"
Delete "$INSTDIR\dtds\*.*"

RMDir "$INSTDIR\accessible"
RMDir "$INSTDIR\audio"
RMDir "$INSTDIR\bearer"
RMDir "$INSTDIR\extcap"
RMDir "$INSTDIR\iconengines"
RMDir "$INSTDIR\imageformats"
RMDir "$INSTDIR\mediaservice"
RMDir "$INSTDIR\networkinformation"
RMDir "$INSTDIR\platforms"
RMDir "$INSTDIR\playlistformats"
RMDir "$INSTDIR\printsupport"
RMDir "$INSTDIR\styles\translations"
RMDir "$INSTDIR\styles"
RMDir "$SMPROGRAMS\${PROGRAM_NAME}"
RMDir "$INSTDIR\help"
RMDir /r "$INSTDIR\Wireshark User's Guide"
RMDir "$INSTDIR\diameter"
RMDir "$INSTDIR\snmp\mibs"
RMDir "$INSTDIR\snmp"
RMDir "$INSTDIR\radius"
RMDir "$INSTDIR\dtds"
RMDir "$INSTDIR\protobuf"
RMDir "$INSTDIR\tls"
RMDir "$INSTDIR\tpncp"
RMDir "$INSTDIR\translations"
RMDir "$INSTDIR\ui"
RMDir "$INSTDIR\wimaxasncp"
RMDir "$INSTDIR"

SectionEnd ; "Uinstall"

Section "Un.Plugins" un.SecPlugins
;-------------------------------------------
SectionIn 1 2
;Delete "$INSTDIR\plugins\${VERSION}\*.*"
;Delete "$INSTDIR\plugins\*.*"
;RMDir "$INSTDIR\plugins\${VERSION}"
;RMDir "$INSTDIR\plugins"
RMDir /r "$INSTDIR\plugins"
SectionEnd

Section "Un.Global Profiles" un.SecProfiles
;-------------------------------------------
SectionIn 1 2
RMDir /r "$INSTDIR\profiles"
SectionEnd

Section "Un.Global Settings" un.SecGlobalSettings
;-------------------------------------------
SectionIn 1 2
Delete "$INSTDIR\cfilters"
Delete "$INSTDIR\colorfilters"
Delete "$INSTDIR\dfilters"
Delete "$INSTDIR\enterprises.tsv"
Delete "$INSTDIR\init.lua"
Delete "$INSTDIR\console.lua"
Delete "$INSTDIR\dtd_gen.lua"
Delete "$INSTDIR\smi_modules"
RMDir "$INSTDIR"
SectionEnd

Section /o "Un.Personal Settings" un.SecPersonalSettings
;-------------------------------------------
SectionIn 2
SetShellVarContext current
Delete "$APPDATA\${PROGRAM_NAME}\*.*"
RMDir "$APPDATA\${PROGRAM_NAME}"
DeleteRegKey HKCU "Software\${PROGRAM_NAME}"
SectionEnd

;VAR un.NPCAP_UNINSTALL

Section /o "Un.Npcap" un.SecNpcap
;-------------------------------------------
SectionIn 2
ReadRegStr $1 HKEY_LOCAL_MACHINE "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst" "UninstallString"
;IfErrors un.lbl_npcap_notinstalled ;if RegKey is unavailable, Npcap is not installed
${If} $1 != ""
  ;MessageBox MB_OK "Npcap $1" /SD IDOK
  ExecWait '$1' $0
  DetailPrint "Npcap uninstaller returned $0"
  ;SetRebootFlag true
${EndIf}
;un.lbl_npcap_notinstalled:
SectionEnd

Section "-Un.Finally"
;-------------------------------------------
SectionIn 1 2

!insertmacro UpdateIcons

; this test must be done after all other things uninstalled (e.g. Global Settings)
IfFileExists "$INSTDIR" 0 NoFinalErrorMsg
    MessageBox MB_OK "Unable to remove $INSTDIR." /SD IDOK IDOK 0 ; skipped if dir doesn't exist
NoFinalErrorMsg:
SectionEnd

!insertmacro MUI_UNFUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecUinstall} "Uninstall all ${PROGRAM_NAME} components."
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecPlugins} "Uninstall all Plugins (even from previous ${PROGRAM_NAME} versions)."
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecProfiles} "Uninstall all global configuration profiles."
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecGlobalSettings} "Uninstall global settings like: $INSTDIR\cfilters"
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecPersonalSettings} "Uninstall personal settings like your preferences file from your profile: $PROFILE."
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecNpcap} "Call Npcap's uninstall program."
  !insertmacro MUI_DESCRIPTION_TEXT ${un.SecUSBPcap} "Call USBPcap's uninstall program."
!insertmacro MUI_UNFUNCTION_DESCRIPTION_END
