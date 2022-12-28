# Set-MpPreference command to disable everything, and then adding exception for all drive letters, and disabling all available engines
67..90|foreach-object{
    $drive = [char]$_
    Add-MpPreference -ExclusionPath "$($drive):\" 
    Add-MpPreference -ExclusionProcess "$($drive):\*" 
}
<# 
    #################
    ## IMPORTANT!! ##
    #################

    1. Boot in Safe Mode
    2. Disable Windows Update
    3. Run powershell as admin
    4. Set-ExecutionPolicy RemoteSigned
    5. Place script in C:\ and run it
#>


# Disable UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force


# Disable Windows Defender Tamper Protection
if($("HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection")) {
    if($(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection").Start -eq 0) {
        Write-Host "Service $svc already disabled"
    } else {
        Write-Host "Disable service $svc (Please REBOOT)"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtection" -Name Start -Value 0
    }
} else {
    Write-Host "Service already disabled"
}

# Disable Windows Defender Tamper Protection Source
if($("HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtectionSource")) {
    if($(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtectionSource").Start -eq 0) {
        Write-Host "Service $svc already disabled"
    } else {
        Write-Host "Disabled service (Please REBOOT)"
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features\TamperProtectionSource" -Name Start -Value 0
    }
} else {
    Write-Host "Service already disabled"
}

# Disable list of engines
Write-Host "Disable Windows Defender engines (Set-MpPreference)"
Set-MpPreference -DisableArchiveScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableAutoExclusions 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableCatchupFullScan 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableCatchupQuickScan 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableCpuThrottleOnIdleScans 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableDatagramProcessing 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableDnsOverTcpParsing 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableDnsParsing 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableEmailScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableFtpParsing 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableGradualRelease 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableHttpParsing 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableInboundConnectionFiltering 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableNetworkProtectionPerfTelemetry 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisablePrivacyMode 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRdpParsing 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRemovableDriveScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableRestorePoint 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningNetworkFiles 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableSshParsing 1 -ErrorAction SilentlyContinue
Set-MpPreference -DisableTlsParsing 1 -ErrorAction SilentlyContinue


Write-Host "Set default actions to NoAction (Set-MpPreference)"

# Set default actions to NoAction, so that no alerts are shown, and no actions are taken
# Allow actions would be better in my opinion
Set-MpPreference -LowThreatDefaultAction NoAction -ErrorAction SilentlyContinue
Set-MpPreference -ModerateThreatDefaultAction NoAction -ErrorAction SilentlyContinue
Set-MpPreference -HighThreatDefaultAction NoAction -ErrorAction SilentlyContinue

Write-Host "Delete Windows Defender (files, services, drivers)"

Write-Host ""
# Delete Windows Defender files
Remove-Item "C:\ProgramData\Microsoft\Windows Defender\" -Recurse -Force   
Remove-Item "C:\Program Files (x86)\Windows Defender\" -Recurse -Force
Remove-Item "C:\Program Files (Arm)\Windows Defender\" -Recurse -Force
Remove-Item "C:\Program Files\Windows Defender\" -Recurse -Force 

# Delete Windows Defender drivers
Remove-Item "C:\Windows\System32\drivers\wd\" -Recurse -Force

# Delete Windows Defender services and drivers from registry (HKLM)
$service_list = @("WdNisSvc", "WinDefend", "Sense")
foreach($svc in $service_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc")) {
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
$driver_list = @("WdnisDrv", "wdfilter", "wdboot")
foreach($drv in $driver_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv")) {
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
Write-Host "-DisableFtpParsing probably not disabled (bug)"


# Check if Windows Defender service running or not
if($(GET-Service -Name WinDefend).Status -eq "Still Running") {   
    Write-Host "Windows Defender Service is still running (Please REBOOT)"
} else {
    Write-Host "Windows Defender Service is not running"
}
