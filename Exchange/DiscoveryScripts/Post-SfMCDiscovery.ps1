param(
    [Parameter(Mandatory=$false)] [string]$OutputPath
)
function Get-FolderPath {   
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the location"
    $folderBrowser.SelectedPath = "C:\"
    $folderPath = $folderBrowser.ShowDialog()
    [string]$oPath = $folderBrowser.SelectedPath
    return $oPath
}
## Work with discovery data
Clear-Host
Add-Type -AssemblyName System.Windows.Forms
# Determine the current location which will be used to store the results
[boolean]$validPath = $false
while($validPath -eq $false) {
    if($OutputPath -like $null) {
        Write-Host "Select the location for the customer results." -ForegroundColor Yellow
        $OutputPath = Get-FolderPath
    }
    else {
        if($OutputPath.Substring($OutputPath.Length-1,1) -eq "\") {$OutputPath = $OutputPath.Substring(0,$OutputPath.Length-1)}
    }
    if(Test-Path -Path $OutputPath) {$validPath = $true}
    else {
        Write-Warning "An invalid path for the output was provided. Please select the location."
        Start-Sleep -Seconds 3
        $OutputPath = Get-FolderPath
    }
}
## Set a timer
Write-host " "
Write-host -ForegroundColor Cyan "==============================================================================="
Write-host " "
Write-Host -ForegroundColor Cyan " The SfMC Email Discovery process is about to begin processing data. "
Write-host -ForegroundColor Cyan " It will take some time to complete depending on the customer environment. "
Write-host " "
Write-host -ForegroundColor Cyan "==============================================================================="
Write-host " "
Start-Sleep -Seconds 3
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()
Get-ChildItem -Path $OutputPath -Filter *.zip | Select FullName,Name | ForEach-Object {
    if($_.Name -notlike "*OrgSettings*") {
        $serverName = $_.Name.Substring(0,$_.Name.IndexOf("-Settings"))
        $serverPath = $null
        $serverPath = "$outputPath\$serverName"
        try{Expand-Archive -Path $_.FullName -DestinationPath $serverPath -ErrorAction Stop -Force}
        catch{$zipName = $_.FullName
            Write-Warning "Unable to extract $zipName."
        }
    }
}
Write-host " "
Write-host -ForegroundColor Cyan "==============================================================================="
Write-host " "
Write-Host -ForegroundColor Cyan " The SfMC Email Discovery is merging the CSV data. "
Write-host " "
Write-host -ForegroundColor Cyan "==============================================================================="
Write-host " "
Get-ChildItem $outputPath -Filter *ActiveSyncVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ActiveSyncVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *AutodiscoverVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\AutodiscoverVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Bios.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Bios.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ClientAccessServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ClientAccessServer.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ComputerSystem.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ComputerSystem.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *CrashControl.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\CrashControl.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Culture.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Culture.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *DatabaseAvailabilityGroup.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\DatabaseAvailabilityGroup.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *DatabaseAvailabilityGroupNetwork.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\DatabaseAvailabilityGroupNetwork.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Disk.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Disk.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *EcpVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\EcpVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *EventLogLevel.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\EventLogLevel.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ExchangeCertificate.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\ExchangeCertificate.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ExchangeServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ExchangeServer.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *FrontendTransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\FrontendTransportService.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *HotFix.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\HotFix.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ImapSettings.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ImapSettings.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *LogFile.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\LogFile.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *LogicalDisk.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\LogicalDisk.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MailboxDatabase.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Sort-Object -Unique -Property Name | Export-Csv $outputPath\MailboxDatabase.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MailboxServer.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\MailboxServer.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MailboxTransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\MailboxTransportService.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *MapiVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\MapiVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Memory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Memory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *NetAdapter.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\NetAdapter.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *NetIPAddress.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\NetIPAddress.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *NetOffloadGlobalSetting.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\NetOffloadGlobalSetting.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *NetRoute.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\NetRoute.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *OabVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\OabVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *OperatingSystem.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\OperatingSystem.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *OutlookAnywhere.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\OutlookAnywhere.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *OwaVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\OwaVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Partition.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Partition.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *PopSettings.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\PopSettings.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *PowerShellVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\PowerShellVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Processor.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Processor.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *Product.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Product.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *RpcClientAccess.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\RpcClientAccess.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ReceiveConnector.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ReceiveConnector.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ScheduledTask.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ScheduledTask.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ServerComponentState.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ServerComponentState.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *ServerHealth.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\ServerHealth.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *-Service.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\Service.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *TransportAgent.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\TransportAgent.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *TransportPipeline.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\TransportPipeline.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *-TransportService.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\TransportService.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *WebServicesVirtualDirectory.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\WebServicesVirtualDirectory.csv -NoTypeInformation -Append
Get-ChildItem $outputPath -Filter *WindowsFeature.csv -Recurse | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $outputPath\WindowsFeature.csv -NoTypeInformation -Append

$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
Write-host " "
Write-host -ForegroundColor Cyan  "==================================================="
Write-Host -ForegroundColor Cyan " SfMC Email Discovery data processing has finished!"
Write-Host -ForegroundColor Cyan "          Total time: $($totalTime) seconds"
Write-host -ForegroundColor Cyan "==================================================="
Write-host " "
