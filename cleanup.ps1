<#
ACS DATA SYSTEMS
# dev: Claudia Cifaldi - PS Onsite Thiene
# last update: february 2025
#>

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
        This script will reduce the size of the Windows Component store folder (WinSxS) by 
        deleting outdated versions of Windows components.
"@
Write-Host $introduction
Write-Host ""
}else {
    Write-Host ""
}

# Cleanup
$confirmation = Read-Host "Do you want to clean up the Windows Components store folder? (Y/N)"
if ($confirmation -eq 'Y') {
    Write-Host "processing..." -ForegroundColor Cyan
    Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase
    Write-Host ""
} else {
    Write-Host "The Windows Components store folder was not modified" -ForegroundColor Yellow
    Write-Host ""
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