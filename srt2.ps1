#######################################################################
#                Sophos Removal Tool v2.0_NO2                         #  
#                Orginally By Drew Yeskatalas                         #
#        Re-Created by Nelson Orellana for 2022 use.                  #
#     This tool will stop all running Sophos Services and tasks,      #
#     seek out uninstall strings for associated Sophos Products,      #
#     And silently remove them.                                       # 
#     The tool will then remove all Sophos services and directories   #
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
# adding admin Owner group for C: root folders....
Function createAdminRights{
    $acl_directories = "C:\ProgramData\Sophos", "C:\ProgramData\HitmanPro.Alert", "C:\Program Files\Sophos", "C:\Program Files (x86)\Sophos", "C:\Program Files (x86)\HitmanPro.Alert"
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Domain Admins", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    write-host ("*** creating admin rights rules for this script to work properly...")
    foreach ($DirFile in $acl_directories) {
        takeown /f "$DirFile" /r /a /D y
        $acl = get-acl $DirFile
        $acl.AddAccessRule($rule)
        Set-Acl $DirFile $acl
    }

} 

#Stop All Sophos Services
Function stop_DemSophosServices{
    $services = 'Sophos AutoUpdate Service', 'hmpalertsvc', 'Sophos Agent', 'SAVService', 'SAVAdminService', 'Sophos Message Router', 'Sophos Web Control Service', 'swi_service', 'swi_update', 'SntpService', 'Sophos System Protection Service', 'Sophos Web Control Service', 'Sophos Endpoint Defense Service', 'HitmanPro.Alert service', 'Sophos Clean Service', 'Sophos MCS Agent', 'Sophos MCS Client' , 'Sophos Device Encryption Service', 'Sophos Health Service', 'Sophos Safestore Service', 'Sophos File Scanner Service', 'Sophos Device Control Service' #turned into an array as the list was just too long, so why not make it a function.

    write-host ("*** running loop to stop all Sophos services...")
    foreach ($element in $services) {
    net stop $element
    }
}

#Kill all Sophos Services
function sophosServicesAnFonem_taskkill{
    $tasks2kill = 'ALMon.exe', 'ALsvc.exe', 'swi_fc.exe', 'swi_filter.exe', 'spa.exe', 'Sophos UI.exe', 'SophosDiag.exe', 'SavApi.exe', 'SEDService.exe', 'hmpalert.exe', 'EXPTelem.exe'

    write-host ("*** force killing any Sophos Services..")
    foreach ($item in $tasks2kill) {
    taskkill /f /im $item
    }
}

#uninstall everything with sophos
function sophosRegistry_Removal {
    $sName = 'Sophos Network Threat Protection', 'Sophos System Protection', 'Sophos Client Firewall', 'Sophos Anti-Virus', 'Sophos Remote Management System', 'Sophos AutoUpdate', 'Sophos Endpoint Defense', 'Sophos Endpoint Firewall', 'Sophos Endpoint Self Help', 'Sophos Heartbeat', 'Sophos Management', 'Sophos AMSI Protection', 'Sophos File Scanner', 'Sophos ML Engine', 'Sophos Standalone Engine', 'Sophos Endpoint Agent', 'Sophos Exploit Protection', 'Sophos Clean', 'Sophos Management Communications System', 'Sophos Health', 'Sophos Diagnostic Utility', 'Sophos Data Protection Agent 2.1.182.0'
    write-host ("*** unininstalling Sophos and its related software..")
    foreach ($regItemd in $sName)  {
        $StartVer = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  |
            Get-ItemProperty |
                Where-Object {$_.DisplayName -match "$sName" } |
                    Select-Object -Property DisplayName, UninstallString

        ForEach ($ver in $StartVer) {

            If ($ver.UninstallString) {

                $uninst = $ver.UninstallString
                Start-Process cmd "/c $uninst /qn REBOOT=SUPPRESS /PASSIVE" -NoNewWindow
        }

        }

        Start-Sleep -Seconds 30
    }
}

#Directory Cleanup --added sub directories as windows has issues removing them even with -recursive.
function sophosDirectory_Removal {
    $pathsTodelete = 'C:\Program Files\Sophos\Endpoint Self Help', 'C:\Program Files\Sophos\Sophos AMSI Protection', 'C:\Program Files\Sophos\SophosUI', 'C:\Program Files\Sophos', 'C:\Program Files (x86)\Sophos\Sophos AMSI Protection', 'C:\Program Files (x86)\Sophos\Sophos Data Protection', 'C:\Program Files (x86)\Sophos', 'C:\ProgramData\HitanPro.Alert', 'C:\ProgramData\Sophos\Management Communications System', 'C:\ProgramData\Sophos\Remote Management System', 'C:\ProgramData\Sophos\Sophos AMSI Protection', 'C:\ProgramData\Sophos\Sophos Anti-Virus', 'C:\ProgramData\Sophos\Sophos Data Protection', 'C:\ProgramData\Sophos\Sophos Diagnostic Utility', 'C:\ProgramData\Sophos\Sophos File Scanner', 'C:\ProgramData\Sophos\Sophos UI', 'C:\ProgramData\Sophos\Web Intelligence', 'C:\ProgramData\Sophos', 'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Sophos', 'C:\ProgramData\Sophos\Safestore', 'C:\ProgramData\Sophos\Sophos Tamper Protection', 'C:\ProgramData\Sophos\Web Intelligence'
    write-host ("*** cleaning directories related to Sophos...")
    foreach ($dirItem in $pathsTodelete) {
        #Get-ChildItem "$dirItem" -Include * -Recurse
        Remove-Item "$dirItem" -Recurse
    }
}

#Sophos Services Removal
function sophosService_Removal {
    $sc_itemsArray = 'SAVService', 'SAVAdminService', 'Sophos Web Control Service', 'Sophos AutoUpdate Service', 'Sophos Agent', 'Sophos Message Router', 'swi_service', 'swi_update', 'SntpService', 'Sophos System Protection Service', 'Sophos Endpoint Defense Service', 'HitmanPro.Alert service'
    write-host ("*** removing Sophos Services now that they are stopped...")
    foreach ($sc_item in $sc_itemsArray) {
        sc.exe delete $sc_item
    }
}

stop_DemSophosServices
wmic service where "caption like '%Sophos%'" call stopservice #Redundant "Stop Sophos Services" check
sophosServicesAnFonem_taskkill
sophosRegistry_Removal
createAdminRights
stop_DemSophosServices # rerun to make sure services are stopped before removing directories, as they will not remove if they are being used.
sophosDirectory_Removal
#Remove Registry Keys
write-host ("*** deleting misc. sophos registry values...")
REG Delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /v "Sophos AutoUpdate Monitor" /f
REG Delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" /v "Sophos UI.exe" /f
Remove-Item -path "HKLM:\SOFTWARE\WOW6432Node\Sophos" -Recurse
Remove-Item -Path "HKLM:\SOFTWARE\Sophos" -Recurse
Remove-Item -Path "HKLM:\SOFTWARE\HitmanPro.Alert" -Recurse
wmic service where "caption like '%Sophos%'" call stopservice #Redundant "Stop Sophos Services" check
sophosService_Removal
