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
    C:\ProgramData\Microsoft\Windows Defender - This folder contains data and configuration files for Windows Defender.
    C:\Windows\system32\MpCmdRun.exe - This is the main executable for Windows Defender.
    C:\Windows\SysWOW64\MpCmdRun.exe - This is a version of the MpCmdRun.exe executable that is used on 64-bit systems.
    C:\Windows\System32\Windows Defender - This folder contains additional files and resources for Windows Defender.
#>

# Adding exception for all drive letters (C, D, E, F, G, H, I, J, K, L, M, N, O, P, Q, R, S, T, U, V, W, X, Y, Z)
67..90 | foreach-object{
    $drive_letters = [char]$_
    Add-MpPreference -ExclusionPath "$($drive_letters):\" -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionProcess "$($drive_letters):\*" -ErrorAction SilentlyContinue

}
# Disable UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force


# Disable Windows Defender Tamper Protection
if($("HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection")) {
    if($(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection").Start -eq 0) {
        Write-Host "TamperProtection service already disabled"
    } else {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection" -Name Start -Value 0
        Write-Host "TamperProtection service has been disabled service (Please REBOOT)"
    }
} else {
    Write-Host "TamperProtection ervice already disabled"
}

# Disable Windows Defender Tamper Protection Source
if($("HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtectionSource")) {
    if($(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtectionSource").Start -eq 0) {
        Write-Host "TamperProtectionSource service already disabled"
    } else {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtectionSource" -Name Start -Value 0
        Write-Host "TamperProtectionSource service has been disabled service (Please REBOOT)"
    }
} else {
    Write-Host "TamperProtectionSource service already disabled"
}

# Disable list of engines
## WORK ON THIS FIRST ##
Write-Host "Disable Windows Defender engines (Set-MpPreference)"
Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableCatchupFullScan $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableCatchupQuickScan $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableCpuThrottleOnIdleScans $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableDatagramProcessing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableDnsOverTcpParsing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableDnsParsing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableEmailScanning $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableFtpParsing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableGradualRelease $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableHttpParsing $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableInboundConnectionFiltering $true -ErrorAction SilentlyContinue
Set-MpPreference -DisableNetworkProtectionPerfTelemetry $true -ErrorAction SilentlyContinue
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


Write-Host "Set default actions to NoAction (Set-MpPreference)"
# Set default actions to NoAction, so that no alerts are shown, and no actions are taken
# Allow actions would be better in my opinion
Set-MpPreference -LowThreatDefaultAction NoAction -ErrorAction SilentlyContinue
Set-MpPreference -ModerateThreatDefaultAction NoAction -ErrorAction SilentlyContinue
Set-MpPreference -HighThreatDefaultAction NoAction -ErrorAction SilentlyContinue

# Disable Windows Defender
if($("HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender")) {
    if($(Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender").DisableAntiSpyware -eq 1) {
        Write-Host "DisableAntiSpyware service already disabled"
    } else {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtectionSource" -Name Start -Value 1
        Write-Host "DisableAntiSpyware service has been disabled service (Please REBOOT)"
    }
} else {
    Write-Host "DisableAntiSpyware service already disabled"
}


Write-Host "Delete Windows Defender (files, services, drivers)"
Write-Host ""
# Delete Windows Defender files
# If unable to delete, silently continue
Remove-Item "C:\ProgramData\Microsoft\Windows Defender\" -Recurse -Force -ErrorAction SilentlyContinue   
Remove-Item "C:\Program Files (x86)\Windows Defender\" -Recurse -Force  -ErrorAction SilentlyContinue
Remove-Item "C:\Program Files (Arm)\Windows Defender\" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "C:\Program Files\Windows Defender\" -Recurse -Force -ErrorAction SilentlyContinue


# Delete Windows Defender drivers
Remove-Item "C:\Windows\System32\drivers\wd\" -Recurse -Force

# Delete Windows Defender services from registry (HKLM)
$service_list = @( "Sense", "WdNisSvc" , "WinDefend")
foreach($svc in $service_list) {
    if($("HKLM:\SYSTEM\CurrentControlSet\Services\$svc")) {
        if($(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc").Start -eq 4) {
            Write-Host "Service $svc already disabled"
        } else {
            Write-Host "Disable service $svc (Please REBOOT)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 4
        }
    } else {
        Write-Host "Service $svc already deleted"
    }
}




# Delete Windows Defender drivers from registry (HKLM)
$driver_list = @("WdnisDrv", "wdboot", "wdfilter")
foreach($drv in $driver_list) {
    if($("HKLM:\SYSTEM\CurrentControlSet\Services\$drv")) {
        if( $(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv").Start -eq 4) {
            Write-Host "Driver $drv already disabled"
        } else {
            Write-Host "Disable driver $drv (Please REBOOT)"
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv" -Name Start -Value 4            
        }
    } else {
        Write-Host "Driver $drv already deleted"
    }
}

# Check list of service running or not
Write-Host "Check disabled engines (Get-MpPreference)"
Get-MpPreference | fl disable*

Write-Host ""
Write-Host "Some engines might return False, ignore them"


# Check if Windows Defender service running or not
if($(GET-Service -Name WinDefend).Status -eq "Still Running") {   
    Write-Host "Windows Defender Service is still running (Please REBOOT)"
} else {
    Write-Host "Windows Defender Service is not running"
}

Write-Host ""
Write-Host " [+] Please REBOOT your system to complete the process. Thank you."
