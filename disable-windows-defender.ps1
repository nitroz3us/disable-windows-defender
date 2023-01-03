<# 
    #################
    ## IMPORTANT!! ##
    #################
   
    ######
    1. Boot in Safe Mode
    2. Disable Windows Update
    3. Run powershell as admin
    4. Set-ExecutionPolicy RemoteSigned
    5. Place script in C:\ and run it

    Windows 10/11:
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

# Disable UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force

# Disable list of engines
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
# Set-MpPreference -DisableFtpParing $true -ErrorAction SilentlyContinue
# Set-MpPreference -DisableNetworkProtectionPerfTelemetry $true -ErrorAction SilentlyContinue
# Set-MpPreference -DisableSmtpParsing $true -ErrorAction SilentlyContinue


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
        Write-Host "DisableAntiSpyware property has been created." -ForegroundColor Yellow
        Write-Host "Windows Defender has been disabled." -ForegroundColor Green
    }
    elseif ((Get-ItemProperty -Path $registryPath -Name "DisableAntiSpyware").DisableAntiSpyware -eq 1) {
        Write-Host "Windows Defender is already disabled." -ForegroundColor Green
    }else{
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1
        Write-Host "Windows Defender has been disabled." -ForegroundColor Green
 
    }
}else{
    Write-Host "Your system does not have the Windows Defender registry key." -ForegroundColor Yellow
    Write-Host "Windows Defender is already disabled." -ForegroundColor Green
}

Write-Host "Deleting Windows Defender (files, services, drivers)" -ForegroundColor Yellow
# Define the paths to the folders to be deleted
if (Test-Path "C:\Windows\System32\drivers\wd\") {
    # If the folder exists, output a message indicating that it was not deleted
    Write-Host "The C:\Windows\System32\drivers\wd\ is not deleted." -ForegroundColor Yellow
    Write-Host "The C:\Windows\System32\drivers\wd\ will be deleting." -ForegroundColor Yellow
    Remove-Item "C:\Windows\System32\drivers\wd\" -Recurse -Force
}
else {
    # If the folder does not exist, output a message indicating that it was deleted
    Write-Host "The C:\Windows\System32\drivers\wd\ has already been deleted." -ForegroundColor Green
}

# Delete Windows Defender services from registry (HKLM)
$service_list = @( "WdNisSvc" , "WinDefend")
foreach($svc in $service_list) {
    if($(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc")) {
        if($(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc").Start -eq 4) {
            Write-Host "$svc service has already been deleted" -ForegroundColor Green
        } else {
            Write-Host "$svc service has been deleted (Please REBOOT)" -ForegroundColor Green
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$svc" -Name Start -Value 4
        }
    } else {
        Write-Host "$svc service has already been deleted" -ForegroundColor Green
    }
}

# Delete Windows Defender drivers from registry (HKLM)
$driver_list = @("WdnisDrv", "wdboot", "wdfilter")
foreach($drv in $driver_list) {
    if($("HKLM:\SYSTEM\CurrentControlSet\Services\$drv")) {
        if($(Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv").Start -eq 4) {
            Write-Host "$drv driver has already been disabled" -ForegroundColor Green
        } else {
            Write-Host "$drv driver has been disabled (Please REBOOT)" -ForegroundColor Green
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$drv" -Name Start -Value 4            
        }
    } else {
        Write-Host "$drv driver has already been disabled" -ForegroundColor Green
    }
}

# Disable Windows Update Service
Write-Host "Disabling Windows Update Service" -ForegroundColor Yellow
# Get the Windows Update service
$wuauserv = Get-Service -Name "wuauserv"
# Stop the service
Stop-Service $wuauserv
# Set the service startup type to disabled
Set-Service -Name "wuauserv" -StartupType Disabled
# Confirm that the service has been disabled
$wuauserv | Select-Object -Property Name, StartupType, Status
if ($wuauserv.StartType -eq "Disabled" -and $wuauserv.Status -eq "Stopped") {
    Write-Host "Windows Update has been disabled." -ForegroundColor Green
}
else {
    Write-Host "Windows Update has not been disabled." -ForegroundColor Red
}

# Set the Windows Update service to disabled via Registry
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv" -Name "Start" -Value 4
# Confirm the change by reading the Start value via Registry
$startValue = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv").Start
if ($startValue -eq 4) {
    Write-Host "The Windows Update service has been disabled." -ForegroundColor Green
}
else {
    Write-Host "The Windows Update service has not been disabled. Please check the registry." -ForegroundColor Yellow
}


# Check list of service running or not
Write-Host "Check disabled engines (Get-MpPreference)" -ForegroundColor Yellow
Get-MpPreference | fl disable*

Write-Host ""
Write-Host "Some engines might return False, ignore" -ForegroundColor Yellow

# Check if Windows Defender service running or not
if($(GET-Service -Name WinDefend).Status -eq "Still Running") {   
    Write-Host "Windows Defender Service is still running (Please REBOOT)" -ForegroundColor Yellow
} else {
    Write-Host "Windows Defender Service is not running" -ForegroundColor Green
}

Write-Host ""
Write-Host " [+] Please REBOOT your system to complete the process. Thank you." -ForegroundColor Green
