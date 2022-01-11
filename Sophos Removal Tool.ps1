#######################################################################
#                Sophos Removal Tool v2.0                             #  
#     By Drew Yeskatalas // modified by Nelson Orellana for 2022 use. #
#                                                                     #
#     This tool will stop all running Sophos Services and tasks,      #
#     seek out uninstall strings for associated Sophos Products,      #
#     And silently remove them.                                       # 
#                                                                     #
#     The tool will then remove all Sophos services and directories   #
#     from Program Files,  Program Files (x86), and ProgramData       #
#                                                                     #
# ***Note: This tool needs to be run as an admin with Sophos Admin    #
#                  or Local Administrator rights.                     #
#                                                                     #
#######################################################################
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  # Relaunch as an elevated process:
  Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}
#Disable Tamper Protection (may require reboot) //removing this as I do not require this for my purpose.

#Stop All Sophos Services

net stop "Sophos AutoUpdate Service"
net stop "Sophos Agent"
net stop "SAVService"
net stop "SAVAdminService"
net stop "Sophos Message Router"
net stop "Sophos Web Control Service"
net stop "swi_service"
net stop "swi_update"
net stop "SntpService"
net stop "Sophos System Protection Service"
net stop "Sophos Web Control Service"
net stop "Sophos Endpoint Defense Service"
net stop "HitmanPro.Alert service"
net stop "Sophos Clean Service"
net stop "Sophos MCS Agent"
net stop "Sophos MCS Client"
net stop "Sophos Device Encryption Service"
net stop "Sophos Health Service"
net stop "Sophos Safestore Service"
net stop "Sophos File Scanner Service"

#Redundant "Stop Sophos Services" check

wmic service where "caption like '%Sophos%'" call stopservice

#Kill all Sophos Services

taskkill /f /im ALMon.exe
taskkill /f /im ALsvc.exe
taskkill /f /im swi_fc.exe
taskkill /f /im swi_filter.exe
taskkill /f /im spa.exe
taskkill /f /im "Sophos UI.exe"
taskkill /f /im SophosDiag.exe
taskkill /f /im SavApi.exe

#Uninstall Sophos Network Threat Protection
$SNTPVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Network Threat Protection" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SNTPVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos System Protection
$SSPVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos System Protection" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SSPVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos Client Firewall
$SCFVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Client Firewall" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SCFVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos Anti-Virus
$SAVVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Anti-Virus" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SAVVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos Remote Management System
$SRMSVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Remote Management System" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SRMSVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos AutoUpdate
$SAUVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos AutoUpdate" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SAUVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos Endpoint Defense
$SEDVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos EndpointDefense" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEDVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        cmd /c "$uninst"
    }
}

Start-Sleep -Seconds 30

#Uninstall Sophos EndPoint Firewall
$SEPFVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Endpoint Firewall" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEPFVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos EndPoint Self Help
$SEPSHVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Endpoint Self Help" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SEPSHVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos Heartbeat
$SHBVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Heartbeat" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SHBVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos Management
$SMGMTVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Management" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SMGMTVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos AMSI Protection
$SAMSIPVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos AMSI Protection" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SAMSIPVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos File Scanner
$SFSVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos File Scanner" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SFSVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos ML Engine
$SMEVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos ML Engine" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SMEVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos Standalone Engine
$SSAEVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Standalone Engine" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SSAEVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos UI
$SUIVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Endpoint Agent" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SUIVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos Hitman Service
$SHSVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Exploit Protection" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SHSVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Uninstall Sophos Clean 
$SCSVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
    Get-ItemProperty |
        Where-Object {$_.DisplayName -match "Sophos Clean" } |
            Select-Object -Property DisplayName, UninstallString

ForEach ($ver in $SCSVer) {

    If ($ver.UninstallString) {

        $uninst = $ver.UninstallString
        Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
    }

}

Start-Sleep -Seconds 30

#Directory Cleanup --added sub directories as windows has issues removing them even with -recursive.

Remove-Item -LiteralPath "C:\Program Files\Sophos\Endpoint Self Help" -Force -Recurse
Remove-Item -LiteralPath "C:\Program Files\Sophos\Sophos AMSI Protection" -Force -Recurse
Remove-Item -LiteralPath "C:\Program Files\Sophos\SophosUI" -Force -Recurse
Remove-Item -LiteralPath "C:\Program Files\Sophos" -Force -Recurse
Remove-Item -LiteralPath "C:\Program Files (x86)\Sophos\Sophos AMSI Protection" -Force -Recurse
Remove-Item -LiteralPath "C:\Program Files (x86)\Sophos\Sophos Data Protection" -Force -Recurse
Remove-Item -LiteralPath "C:\Program Files (x86)\Sophos" -Force -Recurse
Remove-Item -LiteralPath "C:\ProgramData\Sophos\Management Communications System" -Force -Recurse
Remove-Item -LiteralPath "C:\ProgramData\Sophos\Remote Management System" -Force -Recurse
Remove-Item -LiteralPath "C:\ProgramData\Sophos\Sophos AMSI Protection" -Force -Recurse
Remove-Item -LiteralPath "C:\ProgramData\Sophos\Sophos Anti-Virus" -Force -Recurse
Remove-Item -LiteralPath "C:\ProgramData\Sophos\Sophos Data Protection" -Force -Recurse
Remove-Item -LiteralPath "C:\ProgramData\Sophos\Sophos Diagnostic Utility" -Force -Recurse
Remove-Item -LiteralPath "C:\ProgramData\Sophos\Sophos File Scanner" -Force -Recurse
Remove-Item -LiteralPath "C:\ProgramData\Sophos\Sophos UI" -Force -Recurse
Remove-Item -LiteralPath "C:\ProgramData\Sophos\Web Intelligence" -Force -Recurse
Remove-Item -LiteralPath "C:\ProgramData\Sophos" -Force -Recurse

#Remove Registry Keys

REG Delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /v "Sophos AutoUpdate Monitor" /f
REG Delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /v "Sophos UI.exe" /f

#Redundant "Stop Sophos Services" check

wmic service where "caption like '%Sophos%'" call stopservice

#Sophos Services Removal

sc.exe delete "SAVService"
sc.exe delete "SAVAdminService"
sc.exe delete "Sophos Web Control Service"
sc.exe delete "Sophos AutoUpdate Service"
sc.exe delete "Sophos Agent"
sc.exe delete "SAVService"
sc.exe delete "SAVAdminService"
sc.exe delete "Sophos Message Router"
sc.exe delete "swi_service"
sc.exe delete "swi_update"
sc.exe delete "SntpService"
sc.exe delete "Sophos System Protection Service"
sc.exe delete "Sophos Endpoint Defense Service"
sc.exe delete "HitmanPro.Alert service"

