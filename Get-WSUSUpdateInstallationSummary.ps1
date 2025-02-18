# Load the WSUS PowerShell module
Import-Module UpdateServices

# Connect to the WSUS Server
$wsus = Get-WsusServer -Name "srvwsus.ani.it" -PortNumber 8530

# Email configuration
$SMTPServer = "srvexchange01.ani.it"
$SMTPPort = 587
#$SMTPUser = "your-email@yourdomain.com"
#$SMTPPassword = "your-password"
$From = "WSUS <wsus@ani.it>"
$To = "Recipient Name <ced@ani.it>"
$Subject = "WSUS Computer Status Report - $(Get-Date -Format yyyyMMdd)"

# Initialize an array to store the report data
$reportData = @()

# Fetch all computer targets
$computers = $wsus.GetComputerTargets()

foreach ($computer in $computers) {
    # Fetch the update summary for the computer
    $summary = $computer.GetUpdateInstallationSummary()

    # Check if the computer has at least one update (needed, failed, or pending)
    if (($summary.NotInstalledCount -gt 0) -or 
        ($summary.FailedCount -gt 0) -or 
        ($summary.DownloadedCount -gt 0)) {

        # Add the computer details and update summary to the report
        $reportData += [PSCustomObject]@{
            ComputerName       = $computer.FullDomainName
            IPAddress          = $computer.IPAddress
            NeededUpdates      = $summary.NotInstalledCount
            FailedUpdates      = $summary.FailedCount
            PendingUpdates     = $summary.DownloadedCount
        }
    }
}

# Generate the report as a string
if ($reportData.Count -gt 0) {
    # Format the report with custom column spacing
    $header = "Computer Name                 IP Addres        Needed   Failed   Pending "
    $separator = "-------------------------------------------------------------------------------------------"
    $rows = foreach ($entry in $reportData) {
        "{0,-25} {1,-20} {2,-15} {3,-15} {4,-15}" -f $entry.ComputerName, $entry.IPAddress, $entry.NeededUpdates, $entry.FailedUpdates, $entry.PendingUpdates
    }

    # Combine the header, separator, and rows into the full report
    $formattedReport = $header + "`n" + $separator + "`n" + ($rows -join "`n")

    # Send the report via email
    $emailBody = @"
Buongiorno,

Di seguito l'elenco dei computer che hanno bisogno di aggiornamenti:

$formattedReport

"@

    Send-MailMessage -SmtpServer $SMTPServer -Port $SMTPPort -From $From -To $To -Subject $Subject -Body $emailBody -BodyAsHtml:$false 
    Write-Host "Report sent to $To successfully."
} else {
    Write-Host "No computers with updates found. Report not sent."
}
