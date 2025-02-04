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

# Admin section starts here
Write-Host "This script will remove the following features:" -ForegroundColor Cyan
Write-Host "01. WINS"
Write-Host "02. HostGuardianServiceRole"
Write-Host "03. Multipath-IO"
Write-Host "04. IPAM"
Write-Host "05. ISNS"
Write-Host "06. MSMQ"
Write-Host "07. Containers"
Write-Host "08. Migration"
Write-Host "09. FAX"
Write-Host "10. Wireless Networking"
Write-Host "11. Microsoft-Windows-Subsystem-Linux"
Write-Host "12. SMS"
Write-Host "13. SMS-Proxy"
Write-Host "14. Storage-Replica"
Write-Host "15. SMTP-server"
Write-Host ""

$confirmation = Read-Host "Are you sure you want to remove these features (Y/N)?"
if ($confirmation -eq 'Y') {
    Write-Host ""
    Write-Host "removing wins:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name wins -IncludeManagementTools -Remove
    Write-Host "removing HostGuardianServiceRole:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name HostGuardianServiceRole -IncludeManagementTools -Remove
    Write-Host "removing Multipath-IO:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name Multipath-IO -IncludeManagementTools -Remove
    Write-Host "removing IPAM:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name IPAM -IncludeManagementTools -Remove
    Write-Host "removing ISNS:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name ISNS -IncludeManagementTools -Remove
    Write-Host "removing MSMQ:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name MSMQ -IncludeManagementTools -Remove
    Write-Host "removing Containers:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name Containers -IncludeManagementTools -Remove
    Write-Host "removing Migration:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name Migration -IncludeManagementTools -Remove
    Write-Host "removing FAX:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name FAX -IncludeManagementTools -Remove
    Write-Host "removing Wireless-Networking:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name Wireless-Networking -IncludeManagementTools -Remove
    Write-Host "removing MS Windows Subsystem Linux:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name Microsoft-Windows-Subsystem-Linux -IncludeManagementTools -Remove
    Write-Host "removing SMS:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name SMS -IncludeManagementTools -Remove
    Write-Host "removing SMS Proxy:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name SMS-Proxy -IncludeManagementTools -Remove
    Write-Host "removing Storage Replica:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name Storage-Replica -IncludeManagementTools -Remove
    Write-Host "removing SMTP-server:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name smtp-server -IncludeManagementTools -Remove
    
    Write-Host "All selected features have been processed." -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "No features were removed." -ForegroundColor Yellow
    Write-Host ""
}

# Hyper-V Removal
Write-Host "This script will remove Hyper-V features:" -ForegroundColor Cyan
Write-Host "01. Hyper-V"
Write-Host "02. FabricShieldedTools"
Write-Host "03. DiskIo-QoS"
Write-Host ""

$confirmation = Read-Host "Are you sure you want to remove these Hyper-V features (Y/N)?"
if ($confirmation -eq 'Y') {
     Write-Host "removing Hyper-V:" -ForegroundColor Cyan
     Remove-WindowsFeature -Name Hyper-V -IncludeManagementTools -Remove
     Write-Host "removing Fabric Shielded Tools:" -ForegroundColor Cyan
     Remove-WindowsFeature -Name FabricShieldedTools -IncludeManagementTools -Remove
     Write-Host "removing DiskIo Qos:" -ForegroundColor Cyan
     Remove-WindowsFeature -Name DiskIo-QoS -IncludeManagementTools -Remove

    Write-Host "Hyper-V features have been processed." -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "Hyper-V features were not removed." -ForegroundColor Yellow
    Write-Host ""
}

# SMB1 Removal
Write-Host "This script will remove SMB1 features:" -ForegroundColor Cyan
$confirmation = Read-Host "Are you sure you want to remove the SMB1 features (Y/N)?"
if ($confirmation -eq 'Y') {
    Write-Host "removing SMB1:" -ForegroundColor Cyan
    Remove-WindowsFeature -Name FS-SMB1 -IncludeManagementTools -Remove
    Write-Host "SMB1 features have been processed." -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "SMB1 features were not removed." -ForegroundColor Yellow
    Write-Host ""
}

#Internet Explorer Disable
Write-Host "This script will disable Internet Explorer features:" -ForegroundColor Cyan
$confirmation = Read-Host "Are you sure you want to disable Internet Explorer features (Y/N)?"
if ($confirmation -eq 'Y') {
    Write-Host "disabling Internet Explorer:" -ForegroundColor Cyan
    Disable-WindowsOptionalFeature -FeatureName Internet-Explorer-Optional-amd64 -Online -NoRestart
    Write-Host "Internet Explorer features have been processed." -ForegroundColor Green
    Write-Host ""
} else {
    Write-Host "Internet Explorer features were not disabled." -ForegroundColor Yellow
    Write-Host ""
}

# Features Install
Write-Host "This script will install the following features:" -ForegroundColor Cyan
Write-Host "01. Telnet-client"
Write-Host "02. TFTP-client"
Write-Host "03. NET-Framework-Core"
Write-Host ""

$confirmation = Read-Host "Do you want to proceed with installing these features (Y/N)?"
if ($confirmation -eq 'Y') {
     Write-Host "installing Telnet Client:" -ForegroundColor Cyan
     Add-WindowsFeature -Name Telnet-client -IncludeManagementTools
     Write-Host "installing TFTP Client:" -ForegroundColor Cyan
     Add-WindowsFeature -Name TFTP-client -IncludeManagementTools
     Write-Host "installing .NET Framework:" -ForegroundColor Cyan
     Add-WindowsFeature -Name NET-Framework-Core -IncludeManagementTools
     Write-Host "All selected features have been processed." -ForegroundColor Green
     Write-Host ""
} else {
    Write-Host "No features were installed." -ForegroundColor Yellow
    Write-Host ""
}

# SCSI Paravirtual registry modification
$confirmation = Read-Host "Have you installed SCSI VMWare Paravirtual (Y/N)?"
if ($confirmation -eq 'Y') {
    Write-Host "The script will modify the registry to optimize performance of VMware Paravirtual SCSI." -ForegroundColor Cyan
    $response = Read-Host "Do you want to modify the registry (Y/N)?"
    if ($response -eq 'Y') {
        REG ADD "HKLM\SYSTEM\CurrentControlSet\services\pvscsi\Parameters\Device" /v DriverParameter /t REG_SZ /d "RequestRingPages=32,MaxQueueDepth=254" /f
        Write-Host "Registry key modified successfully." -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host "The registry was not modified." -ForegroundColor Yellow
        Write-Host ""
    }
} else {
    Write-Host "No changes were made." -ForegroundColor Yellow
    Write-Host ""
}

# Run PowerShell and DISM commands
Write-Host "This script will execute PowerShell commands to modify the following parameters:" -ForegroundColor Cyan
Write-Host "01. Disable LMHOSTS"
Write-Host "02. Disable Domain Name Devolution"
Write-Host "03. ActiveSetup"
Write-Host "04. Unregister Automatic Device Join"
Write-Host "05. Disable NetBIOS over TCP/IP"
Write-Host "06. Enable NETAdapterRSS"
Write-Host "07. Rename NETAdapter to LAN"
Write-Host "08. Clean up disk space."
Write-Host ""

Write-Host "processing ..."-ForegroundColor Cyan
Enable-PSRemoting -Force
Write-Host "disabling LMHOSTS..." -ForegroundColor Cyan
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' -Name EnableLMHOSTS -Value 0 -Force
Write-Host "disabling Domain Name Devolution..." -ForegroundColor Cyan
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name UseDomainNameDevolution -Value 0 -Force
Write-Host "disabling ActiveSetup..." -ForegroundColor Cyan
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}' -Name 'IsInstalled' -Value 0 -Force
Write-Host "unregistering Automatic Device Join..." -ForegroundColor Cyan
Unregister-ScheduledTask -TaskName Automatic-Device-Join
Write-Host "disabling NetBIOS over TCP/IP..." -ForegroundColor Cyan
(Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IpEnabled='true'").SetTcpipNetbios(2)
Set-NetAdapterBinding -Name "Ethernet0" -ComponentID "ms_netbios" -AllBindings -Enabled $False
Write-Host "enabling NETAdapterRSS..." -ForegroundColor Cyan
Enable-NetAdapterRss -Name "Ethernet0"
Write-Host "renaming NETAdapter to LAN..." -ForegroundColor Cyan
Rename-NetAdapter -Name "Ethernet0" -NewName "LAN"
Write-Host "cleaning up disk..." -ForegroundColor Cyan
Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase

Write-Host "All commands have been processed." -ForegroundColor Green
Write-Host ""

# Recap table of the Windows Features
Write-Host "Install state of the features processed with this script" -ForegroundColor Cyan
@("wins", "HostGuardianServiceRole", "Multipath-IO", "IPAM", "ISNS", "MSMQ", "Containers", "Migration", "FAX", "Wireless-Networking", "Microsoft-Windows-Subsystem-Linux", "SMS", "SMS-Proxy", "Storage-Replica", "smtp-server", "FS-SMB1", "Hyper-V", "Telnet-client", "TFTP-client", "NET-Framework-Core") | 
    ForEach-Object { Get-WindowsFeature -Name $_ } | 
    Select-Object Name, InstallState | 
    Format-Table -AutoSize

# Prompt user if they want to restart the computer
$restart = Read-Host "Do you want to restart the computer? (Y/N)"

if ($restart -eq "Y" -or $restart -eq "y") {
    # Restart the computer
    Shutdown.exe /r /f /t 5
    Write-Host "The computer is restarting..." -ForegroundColor Green
} else {
    exit
}