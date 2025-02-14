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
# Show Get-TLS
Write-Host ""
Write-Host "These are the current TLS settings:" -ForegroundColor Cyan

function Test-TlsVersion {
    $protocols = @("TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3")
    $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"

    $results = @()  # Create an array to store results

    foreach ($protocol in $protocols) {
        $clientKey = "$registryPath\$protocol\Client"
        $serverKey = "$registryPath\$protocol\Server"

        try {
            # Default values (assume "System Default" unless found in registry)
            $clientEnabled = "Default"
            $serverEnabled = "Default"

            # Check Client Key
            if (Test-Path $clientKey) {
                $clientReg = Get-ItemProperty -Path $clientKey -ErrorAction SilentlyContinue
                if ($null -ne $clientReg.Enabled) { $clientEnabled = if ($clientReg.Enabled -eq 1) { "Yes" } else { "No" } }
            }

            # Check Server Key
            if (Test-Path $serverKey) {
                $serverReg = Get-ItemProperty -Path $serverKey -ErrorAction SilentlyContinue
                if ($null -ne $serverReg.Enabled) { $serverEnabled = if ($serverReg.Enabled -eq 1) { "Yes" } else { "No" } }
            }

            # Store results
            $results += [PSCustomObject]@{
                "TLS Version"   = $protocol
                "Client Enabled" = $clientEnabled
                "Server Enabled" = $serverEnabled
            }
        }
        catch {
            # If any error occurs, still continue
            $results += [PSCustomObject]@{
                "TLS Version"   = $protocol
                "Client Enabled" = "Error"
                "Server Enabled" = "Error"
            }
        }
    }

    # Display results in a table
    $results | Format-Table -AutoSize
}

# Check TLS versions on the local machine
Test-TlsVersion

# Disable TLS1.0, 1.1 and Enable 1.2
Write-Host ""
Write-Host "This script will disale TLS 1.0, TLS 1.1 and enable TLS 1.2 for .NET" -ForegroundColor Cyan
$confirmation = Read-Host "Do you want want to proceed (Y/N)?"
if ($confirmation -eq 'Y') {

# Disable TLS 1.0
Write-Host ""
If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force | Out-Null
    }
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    
    If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Force | Out-Null
    }
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'TLS 1.0 has been disabled.' -ForegroundColor Green

# Disable TLS 1.1
    If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Force | Out-Null
    }
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    
    If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Force | Out-Null
    }
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'TLS 1.1 has been disabled.' -ForegroundColor Green
    
# Enable TLS 1.2
If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null

If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client')) {
New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.2 has been enabled.' -ForegroundColor Green

# Enable TLS 1.2 for .NET 3.5
If (-Not (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727')) {
    New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -Name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727' -Name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

If (-Not (Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727')) {
    New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v2.0.50727' -Name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.2 for .NET 3.5 has been enabled.' -ForegroundColor Green

# Enable TLS 1.2 for .NET 4.x
If (-Not (Test-Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319')) {
    New-Item 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null

If (-Not (Test-Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319')) {
    New-Item 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SystemDefaultTlsVersions' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -value '1' -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.2 for .NET 4.x  has been enabled.' -ForegroundColor Green
Write-Host""
<#
# Disable TLS 1.3
If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force | Out-Null
    }
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    
    If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force | Out-Null
    }
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'Enabled' -value '0' -PropertyType 'DWord' -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'DisabledByDefault' -value 1 -PropertyType 'DWord' -Force | Out-Null
    Write-Host 'TLS 1.3 has been disabled.' -ForegroundColor Green
    #>
} else {
    Write-Host "TLS settings were not modified" -ForegroundColor Yellow
    Write-Host ""
}

# Ask if Enable TLS1.3
Write-Host "This script will enable TLS 1.3" -ForegroundColor Cyan
$confirmation = Read-Host "Do you want want to enable TLS 1.3 (Y/N)?"
if ($confirmation -eq 'Y') {
# Enable TLS 1.3
Write-Host ""
If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null

If (-Not (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client')) {
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Force | Out-Null
}
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'Enabled' -value '1' -PropertyType 'DWord' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client' -Name 'DisabledByDefault' -value 0 -PropertyType 'DWord' -Force | Out-Null
Write-Host 'TLS 1.3 has been enabled.' -ForegroundColor Green
Write-Host ""
} else {
    Write-Host "TLS 1.3 was not enabled" -ForegroundColor Yellow
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
