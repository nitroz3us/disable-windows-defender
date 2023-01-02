<# 
    #################
    ## IMPORTANT!! ##
    #################
   
    ### ONLY FOR WINDOWS 11 ###
    1. Boot in Safe Mode
    2. Disable Windows Update
    3. Run powershell as admin
    4. Set-ExecutionPolicy RemoteSigned
    5. Place script in C:\ and run it
    
    Windows 11: 
    C:\Program Files\Windows Defender - TrustedInstaller
    C:\ProgramData\Microsoft\Windows Defender - SYSTEM
    C:\Windows\system32\MpCmdRun.exe - TrustedInstaller
    C:\Windows\SysWOW64\MpCmdRun.exe - TrustedInstaller

    Windows 10:
    C:\Program Files\Windows Defender - This folder contains the executables and other files for Windows Defender.
    C:\ProgramData\Microsoft\Windows Defender - This folder contains data and configuration files for Windows Defender
    C:\Windows\System32\drivers\wd\ - This folder contains the Windows Defender driver files.
#>

# Adding exception for all drive letters (C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z)
67..90 | foreach-object{
    $drive_letters = [char]$_
    Add-MpPreference -ExclusionPath "$($drive_letters):\" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "$($drive_letters):\*" -ErrorAction SilentlyContinue

}

# $os = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
# $elevated = $false
# if ($os -like "*Windows 10*") {
#     $url = "https://download.sysinternals.com/files/PSTools.zip"
#     $output = ".\PSTools.zip"
#     $extractPath = ".\extracted"

#     Invoke-WebRequest -Uri $url -OutFile $output
#     Expand-Archive -Path $output -DestinationPath $extractPath

#     $psexec = "$extractPath\psexec.exe"
#     & $psexec -i -s powershell
#     $elevated = $true
# }
# else {
#     Write-Host "This script is not compatible with this version of Windows." -ForegroundColor Red 
#     exit
# }

Write-Host "Checking if user is booted in Safe Mode." -ForegroundColor Yellow
$bootupState = (Get-WmiObject -Class Win32_ComputerSystem | Select-Object -ExpandProperty BootupState).ToLower()
$check_boot = $false
# Check if the system is booted in Safe mode
if ($bootupState -like "*safe*") {
    Write-Host "The system is booted in Safe mode." -ForegroundColor Green
    $check_boot = $true
}
else {
    Write-Host "The system is not booted in Safe mode."
    Write-Host ""
    Write-Host "[!] Please boot in Safe mode and try again." -ForegroundColor Yellow
    exit
}

# if ($elevated) {
#     Write-Host "Elevated as SYSTEM." -ForegroundColor Green
# }
# else {
#     Write-Host "Not elevated as SYSTEM." -ForegroundColor Yellow 
#     Write-Host "Will continue as Administrator" -ForegroundColor Yellow 
# }

# Disable UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force


# Disable list of engines
## WORK ON THIS FIRST ##
Write-Host "Disable Windows Defender engines (Set-MpPreference)" -ForegroundColor Yellow 
Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableCatchupFullScan $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableCatchupQuickScan $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableCpuThrottleOnIdleScans $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableDatagramProcessing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableDnsOverTcpParsing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableDnsParsing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableEmailScanning $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableGradualRelease $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableHttpParsing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableInboundConnectionFiltering $true -ErrorAction SilentlyContinue
Set-MpPreference -DisablePrivacyMode $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableRdpParsing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableRemovableDriveScanning $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableRestorePoint $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningNetworkFiles $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableSshParsing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableTlsParsing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableArchiveScanning $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableAutoExclusions $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableIntrusionPreventionSystem $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $true -ErrorAction SilentlyContinue


Write-Host "Set default actions to NoAction (Set-MpPreference)" -ForegroundColor Yellow
# Set default actions to NoAction, so that no alerts are shown, and no actions are taken
# Allow actions would be better in my opinion
Set-MpPreference -LowThreatDefaultAction NoAction -ErrorAction SilentlyContinue
Set-MpPreference -ModerateThreatDefaultAction NoAction -ErrorAction SilentlyContinue
Set-MpPreference -HighThreatDefaultAction NoAction -ErrorAction SilentlyContinue

# Disable Windows Defender.
# editing HKLM:\SOFTWARE\Microsoft\Windows Defender\ requires to be SYSTEM
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
if (Test-Path $registryPath) {
    if (!(Get-ItemProperty -Path $registryPath -Name "DisableAntiSpyware")) {
        New-ItemProperty -Path $registryPath -Name "DisableAntiSpyware" -Value 1 -PropertyType DWORD -Force
        Write-Host "DisableAntiSpyware property has been created."
        Write-Host "Windows Defender has been disabled."
    }
    elseif ((Get-ItemProperty -Path $registryPath -Name "DisableAntiSpyware").DisableAntiSpyware -eq 1) {
        Write-Host "Windows Defender is already disabled."
    }else{
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1
        Write-Host "Windows Defender has been disabled."
 
    }
}else{
    Write-Host "Your system does not have the Windows Defender registry key."
    Write-Host "Windows Defender is already disabled."
}

### WORK ON THIS ###
# Deleting Windows Defender folders & files requires to be SYSTEM
# Write-Host "Delete Windows Defender (files, services, drivers)" -ForegroundColor Yellow
# Write-Host ""

# Delete Windows Defender files
# Windows 10
# C:\Program Files\Windows Defender - This folder contains the executables and other files for Windows Defender. - TrustedInstaller
# C:\ProgramData\Microsoft\Windows Defender - This folder contains data and configuration files for Windows Defender. - SYSTEM

# Delete Windows Defender drivers - SYSTEM
# Remove-Item "C:\Windows\System32\drivers\wd\" -Recurse -Force
### WORK ON THIS ###


# Delete Windows Defender services from registry (HKLM) - [NEED elevate to SYSTEM]
$service_list = @( "WdNisSvc" , "WinDefend")
foreach($svc in $service_list) {
    if($("
    \$svc")) {
        if($(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc").Start -eq 4) {
            Write-Host "Service $svc already disabled" -ForegroundColor Yellow
        } else {
            Write-Host "Disable service $svc (Please REBOOT)" -ForegroundColor Yellow
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 4
        }
    } else {
        Write-Host "Service $svc already deleted" -ForegroundColor Yellow
    }
}

# Delete Windows Defender drivers from registry (HKLM) - [NEED elevate to SYSTEM]
$driver_list = @("WdnisDrv", "wdboot", "wdfilter")
foreach($drv in $driver_list) {
    if($("HKLM:\SYSTEM\CurrentControlSet\Services\$drv")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv").Start -eq 4) {
            Write-Host "Driver $drv already disabled" -ForegroundColor Yellow
        } else {
            Write-Host "Disable driver $drv (Please REBOOT)" -ForegroundColor Yellow
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv" -Name Start -Value 4            
        }
    } else {
        Write-Host "Driver $drv already deleted" -ForegroundColor Yellow
    }
}

# Check list of service running or not
Write-Host "Check disabled engines (Get-MpPreference)" -ForegroundColor Yellow
Get-MpPreference | fl disable*

Write-Host ""
Write-Host "Some engines might return False, ignore them" -ForegroundColor Yellow


# Check if Windows Defender service running or not
if($(GET-Service -Name WinDefend).Status -eq "Still Running") {   
    Write-Host "Windows Defender Service is still running (Please REBOOT)" -ForegroundColor Yellow
} else {
    Write-Host "Windows Defender Service is not running" -ForegroundColor Yellow
}

Write-Host ""
Write-Host " [+] Please REBOOT your system to complete the process. Thank you." -ForegroundColor Green
