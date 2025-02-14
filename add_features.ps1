# dev:@cla-cif updated: february 2025

# Check if running as Administrator
$IsAdmin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$IsAdminRole = [Security.Principal.WindowsBuiltInRole]::Administrator

if ($IsAdmin.IsInRole($IsAdminRole)) {
    Write-Host "Running as Administrator..." -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "This script requires Administrator privileges." -ForegroundColor Red
    $response = Read-Host "Would you like to run this script as Administrator (Y/N)?"
    if ($response -eq 'Y') {
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File $PSCommandPath" -Verb runAs
        exit
    } else {
        Write-Host "Exiting script..." -ForegroundColor Red
        exit
    }
}

# Introduction
$confirmation = Read-Host "Do you want to read the introduction? (Y/N)"
if ($confirmation -eq 'Y') {
    $introduction = @"
        The script restores features that were disabled by the remove_features script.
        SMB1 features must be restored using the source file from the ISO image.
"@
Write-Host $introduction
Write-Host ""
}else {
    Write-Host ""
}

# Hyper-V Enable
Write-Host "This script will enable Hyper-V features:" -ForegroundColor Cyan
Write-Host "1. Hyper-V"
Write-Host "2. FabricShieldedTools"
Write-Host "3. DiskIo-QoS"
Write-Host ""

$confirmation = Read-Host "Are you sure you want to enable these Hyper-V features (Y/N)?"
Write-Host ""
if ($confirmation -eq 'Y') {
    Write-Host "Checking processor compatibility for Hyper-V..." -ForegroundColor Cyan
    $processor = Get-WmiObject Win32_Processor | Select-Object -First 1 Name, VirtualizationFirmwareEnabled, SecondLevelAddressTranslationExtensions
    if ($processor.VirtualizationFirmwareEnabled -eq $true -and $processor.SecondLevelAddressTranslationExtensions -eq $true) {
        Write-Host "Virtualization is enabled in the firmware and SLAT is supported." -ForegroundColor Green
        Write-Host "Installing Hyper-V:" -ForegroundColor Cyan
        Install-WindowsFeature -Name Hyper-V -IncludeManagementTools 
        Write-Host "Enabling Fabric Shielded Tools:" -ForegroundColor Cyan
        Add-WindowsFeature -Name FabricShieldedTools -IncludeManagementTools
        Write-Host "Enabling DiskIo QoS:" -ForegroundColor Cyan
        Add-WindowsFeature -Name DiskIo-QoS -IncludeManagementTools
        Write-Host "Hyper-V features have been processed." -ForegroundColor Green
        Get-WindowsFeature -Name Hyper-V
        Write-Host ""
    } else {
        Write-Host "Either virtualization is not enabled or SLAT is not supported. Hyper-V features were not enabled." -ForegroundColor Yellow
        $processor | Format-Table Name, VirtualizationFirmwareEnabled, SecondLevelAddressTranslationExtensions
    }
} else {
    Write-Host "Hyper-V features were not enabled." -ForegroundColor Yellow
    Write-Host ""
}


# Internet Explorer Enabled
Write-Host "This script will enable Internet Explorer features:" -ForegroundColor Cyan
$confirmation = Read-Host "Are you sure you want to enable Internet Explorer features (Y/N)?"
Write-Host ""
if ($confirmation -eq 'Y' -or $confirmation -eq 'y') {
    Write-Host "Checking compatibility for Internet Explorer..." -ForegroundColor Cyan
    $ieFeature = Get-WindowsOptionalFeature -Online | Where-Object FeatureName -Like "Internet-Explorer-*"
    if ($ieFeature.State -eq "Disabled") {
        Write-Host "Enabling Internet Explorer..." -ForegroundColor Cyan
        dism.exe /online /enable-feature /featurename:Internet-Explorer-Optional-amd64
        Write-Host "Internet Explorer features have been processed." -ForegroundColor Green
    } elseif ($ieFeature.State -eq "Enabled") {
        Write-Host "Internet Explorer is already enabled." -ForegroundColor Green
    } else {
        Write-Host "Internet Explorer is not supported on this system." -ForegroundCnolor Yellow
    }
} else {
    Write-Host "Internet Explorer was not enabled." -ForegroundColor Yellow
    Write-Host""
}

# Prompt user if they want to restart the server
$restart = Read-Host "Restart to apply changes. Do you want to restart the server now? (Y/N)" 

if ($restart -eq "Y" -or $restart -eq "y") {
    # Restart the server
    Shutdown.exe /r /f /t 5
    Write-Host ""
    Write-Host "The server is restarting..." -ForegroundColor Green
} else {
    exit
}

