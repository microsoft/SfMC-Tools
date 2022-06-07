<#//***********************************************************************
//
// Get-ExchangeServerDiscovery.ps1
// Modified 14 January 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v4.1
//
//***********************************************************************
//
// Copyright (c) 2018 Microsoft Corporation. All rights reserved.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//**********************************************************************​
#>

param( [Parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$creds)
Clear-Host
Write-Host -ForegroundColor Yellow '//***********************************************************************'
Write-Host -ForegroundColor Yellow '//'
Write-Host -ForegroundColor Yellow '// Copyright (c) 2018 Microsoft Corporation. All rights reserved.'
Write-Host -ForegroundColor Yellow '//'
Write-Host -ForegroundColor Yellow '// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR'
Write-Host -ForegroundColor Yellow '// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,'
Write-Host -ForegroundColor Yellow '// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE'
Write-Host -ForegroundColor Yellow '// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER'
Write-Host -ForegroundColor Yellow '// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,'
Write-Host -ForegroundColor Yellow '// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN'
Write-Host -ForegroundColor Yellow '// THE SOFTWARE.'
Write-Host -ForegroundColor Yellow '//'
Write-Host -ForegroundColor Yellow '//**********************************************************************​'
Start-Sleep -Seconds 2
function Write-Log {
    param( [string]$Message, [string]$Cmdlet )
    [pscustomobject]@{
        Time = (Get-Date -f o)
        Cmdlet = $Cmdlet
        Message = $Message
    } | Export-Csv -Path "$outputPath\$ServerName-LogFile.csv" -Append -NoTypeInformation
 }
 function Get-ServerData {
	param ([string]$ServerName)
	foreach ($h in $hash.GetEnumerator()) {
		$Result = $null
        $CommandName = $h.Name 
		$Command = $h.Value
        $Error.Clear()
        Write-Log -Message $Command -Cmdlet $CommandName
        try{$Result = Invoke-Expression $h.Value}
        catch{Write-Log -Message $Error.Exception.ErrorRecord -Cmdlet $CommandName}
		if($Result -ne $null) {	$Result | Export-Csv $outputPath\$ServerName-$CommandName.csv -NoTypeInformation -Force}
	}
}
function Zip-CsvResults {
	## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    ## Attempt to zip the results
    try {[System.IO.Compression.ZipFile]::CreateFromDirectory($outputPath, $zipFolder)}
    catch {
        try{Remove-Item -Path $zipFolder -Force -ErrorAction SilentlyContinue}
        catch{Write-Warning "Failed to remove file."}
        $zipFile = [System.IO.Compression.ZipFile]::Open($zipFolder, 'update')
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
        Get-ChildItem -Path $outputPath | Select FullName | ForEach-Object {
            try{[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipFile, $_.FullName, (Split-Path $_.FullName -Leaf), $compressionLevel) | Out-Null }
            catch {Write-Warning "failed to add"}
        }
        $zipFile.Dispose()
    }
}
$ServerName = $env:COMPUTERNAME
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn
## Set the destination for the data collection output
$outputPath = "$env:ExchangeInstallPath\Logging\SfMC Discovery\Server Settings"
if(!(Test-Path $outputPath)) {
    New-Item -Path $outputPath -ItemType Directory | Out-Null
}
else {Get-ChildItem -Path $outputPath | Remove-Item -Confirm:$False -Force }
Get-ChildItem -Path "$env:ExchangeInstallPath\Logging\SfMC Discovery" -Filter $env:COMPUTERNAME*.zip | Remove-Item -Confirm:$False -ErrorAction Ignore
## Data collection starts
## General information
Get-ExchangeServer $ServerName -Status -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName  | Export-Clixml $outputPath\$ServerName-ExchangeServer.xml
Get-ExchangeCertificate -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ExchangeCertificate.xml
Get-EventLogLevel -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-EventLogLevel.xml
Get-HealthReport * -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-HealthReport.xml
Get-ServerComponentState $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ServerComponentState.xml
Get-ServerHealth $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ServerHealth.xml
Get-ServerMonitoringOverride $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ServerMonitoringOverride.xml
## Client access settings
Get-AutodiscoverVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-AutodiscoverVirtualDirectory.xml
Get-ClientAccessServer $ServerName -WarningAction Ignore -IncludeAlternateServiceAccountCredentialStatus -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ClientAccessServer.xml
Get-EcpVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-EcpVirtualDirectory.xml
Get-WebServicesVirtualDirectory  -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-WebServicesVirtualDirectory.xml
Get-MapiVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MapiVirtualDirectory.xml
Get-ActiveSyncVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ActiveSyncVirtualDirectory.xml
Get-OabVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-OabVirtualDirectory.xml
Get-OwaVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-OwaVirtualDirectory.xml
Get-OutlookAnywhere -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-OutlookAnywhere.xml
Get-PowerShellVirtualDirectory -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-PowerShellVirtualDirectory.xml
Get-RpcClientAccess -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-RpcClientAccess.xml
## Transport settings
Get-ReceiveConnector -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ReceiveConnector.xml
Get-ImapSettings -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-ImapSettings.xml
Get-PopSettings -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-PopSettings.xml
Get-TransportAgent -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-TransportAgent.xml
Get-TransportService $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-TransportService.xml
Get-MailboxTransportService -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MailboxTransportService.xml
Get-FrontendTransportService $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-FrontendTransportService.xml
Get-TransportPipeline -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-TransportPipeline.xml
## Mailbox settings
Get-DatabaseAvailabilityGroup (Get-Cluster).Name -Status -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-DatabaseAvailabilityGroup.xml
Get-DatabaseAvailabilityGroupNetwork (Get-Cluster).Name -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-DatabaseAvailabilityGroupNetwork.xml
Get-MailboxDatabase -Server $ServerName -WarningAction Ignore -Status -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MailboxDatabase.xml
Get-MailboxServer $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-MailboxServer.xml
Get-PublicFolderDatabase -Server $ServerName -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName | Export-Clixml $outputPath\$ServerName-PublicFolderDatabase.xml
## Convert the XML into CSV files
Get-ChildItem $outputPath -Filter *.xml | ForEach-Object { Import-Clixml $_.FullName | Export-Csv $outputPath\$($_.BaseName).csv -NoTypeInformation -Force }
Get-ChildItem $outputPath -Filter *.xml | Remove-Item
$hash = @{
'Partition' = 'Get-Disk | where {$_.Number -notlike $null} | ForEach-Object { Get-Partition -DiskNumber $_.Number | Select * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName }'
'Disk' = 'Get-Disk | where {$_.Number -notlike $null} | Select * -ExcludeProperty SerializationData, PSComputerName, RunspaceId, PSShowComputerName'
'WindowsFeature'='Get-WindowsFeature -ErrorAction SilentlyContinue  | Where {$_.Installed -eq $True} | Select-Object @{Name="ServerName"; Expression = {$ServerName}},Name,DisplayName,Installed,InstallState,FeatureType';
'HotFix'='Get-HotFix -WarningAction Ignore -ErrorAction SilentlyContinue  | Select-Object @{Name="ServerName"; Expression = {$ServerName}},Description,HotFixID,InstalledBy,InstalledOn';
'Culture'='Get-Culture -ErrorAction SilentlyContinue  | Select @{Name="ServerName"; Expression = {$ServerName}},LCID,Name,DisplayName';
'NetAdapter'='Get-NetAdapter -ErrorAction SilentlyContinue  | Select-Object SystemName,MacAddress,Status,LinkSpeed,MediaType,DriverFileName,InterfaceAlias,ifIndex,IfDesc,DriverVersion,Name,DeviceID';
'NetIPAddress'='Get-NetIPAddress -ErrorAction SilentlyContinue  | Where {($_.IPv4Address -ne $null -or $_.IPv6Address -ne $null) -and ($_.IPv4Address -notlike "127*" -and $_.IPv4Address -notlike "169*")} | select @{Name="ServerName"; Expression = {$ServerName}},InterfaceAlias,IPv4Address,IPv6Address,SuffixOrigin,PrefixLength | ? {$_.InterfaceAlias -notlike "*Loopback*"}';
'NetOffloadGlobalSetting'='Get-NetOffloadGlobalSetting -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}},ReceiveSideScaling,ReceiveSegmentCoalescing,Chimney,TaskOffload,NetworkDirect,NetworkDirectAcrossIPSubnets,PacketCoalescingFilter';
'NetRoute'='Get-NetRoute  -ErrorAction SilentlyContinue | select @{Name="ServerName"; Expression = {$ServerName}},DestinationPrefix,NextHop,RouteMetric';
'ScheduledTask'='Get-ScheduledTask -ErrorAction SilentlyContinue  | Where {$_.State -ne "Disabled"} | Select @{Name="ServerName"; Expression = {$ServerName}},TaskPath,TaskName,State';
'Service'='Get-WmiObject -Query "select * from win32_service" -ErrorAction SilentlyContinue  | Select @{Name="ServerName"; Expression = {$ServerName}},Name,ProcessID,StartMode,State,Status';
'Processor'='Get-WmiObject -Query "select * from Win32_Processor" -ErrorAction SilentlyContinue  | Select @{Name="ServerName"; Expression = {$ServerName}},Caption,DeviceID, Manufacturer,Name,SocketDesignation,MaxClockSpeed,AddressWidth,NumberOfCores,NumberOfLogicalProcessors';
'Product'='Get-WmiObject -Query "select * from Win32_Product"  -ErrorAction SilentlyContinue | Select @{Name="ServerName"; Expression = {$ServerName}}, Name, Description, Vendor, Version, IdentifyingNumber, InstallDate, InstallLocation, PackageCode, PackageName, Language';
'LogicalDisk'='Get-WmiObject -Query "select * from Win32_LogicalDisk"  -ErrorAction SilentlyContinue | Select @{Name="ServerName"; Expression = {$ServerName}}, Name, Description, Size, FreeSpace, FileSystem, VolumeName';
'Bios'='Get-WmiObject -Query "select * from win32_BIOS" -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}}, Name,SMBIOSBIOSVersion,Manufacturer,Version';
'OperatingSystem'='Get-WmiObject -Query "select * from Win32_OperatingSystem" -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}}, BuildNumber,Version,WindowsDirectory,LastBootUpTime,ServicePackMajorVersion,ServicePackMinorVersion,TotalVirtualMemorySize,TotalVisibleMemorySize';
'ComputerSystem'='Get-WmiObject -Query "select * from Win32_Computersystem" -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}}, Name,Domain,Manufacturer,Model';
'Memory'='Get-WmiObject -Query "select * from Win32_PhysicalMemory" -ErrorAction SilentlyContinue  | Select @{Name="ServerName"; Expression = {$ServerName}}, Capacity, DataWidth, Speed, DeviceLocator, Tag, TypeDetail, Manufacturer, PartNumber';
'PageFile'='Get-WmiObject -Query "select * from Win32_PageFile" -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}},Compressed,Description,Drive,Encrypted,FileName,FileSize,FreeSpace,InitialSize,MaximumSize,System';
'CrashControl'='Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\crashcontrol -ErrorAction SilentlyContinue  | select @{Name="ServerName"; Expression = {$ServerName}},autoreboot,crashdumpenabled,DumpFile,LogEvent,MiniDumpDir,MiniDumpsCount,OverWrite,LastCrashTime'
}
Get-ServerData -ServerName $ServerName
Write-Log -Message "Attempting to zip results" -Cmdlet "ZipCsvResults"
$ts = Get-Date -f yyyyMMddHHmmss
[string]$zipFolder = "$env:ExchangeInstallPath\Logging\SfMC Discovery\$ServerName-Settings-$ts.zip"
$zipReady = $false
$zipAttempt = 0
while($zipReady -eq $false) {
    if(Get-Item -Path $zipFolder -ErrorAction Ignore) { $zipReady = $true }
    else {
        if($zipAttempt -eq 3) { $zipReady = $true }
        else {
            Zip-CsvResults
            $zipAttempt++
            Start-Sleep -Seconds 10
        }
    }
}
## Clean up
Remove-PSSession -Name SfMCSrvDis -ErrorAction Ignore | Out-Null

# SIG # Begin signature block
# MIInswYJKoZIhvcNAQcCoIInpDCCJ6ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3a2fCv83gN6dG
# AzWdIpLu3C1e13BM5m0dR2fHufx/A6CCDYUwggYDMIID66ADAgECAhMzAAACU+OD
# 3pbexW7MAAAAAAJTMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwOTAyMTgzMzAwWhcNMjIwOTAxMTgzMzAwWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDLhxHwq3OhH+4J+SX4qS/VQG8HybccH7tnG+BUqrXubfGuDFYPZ29uCuHfQlO1
# lygLgMpJ4Geh6/6poQ5VkDKfVssn6aA1PCzIh8iOPMQ9Mju3sLF9Sn+Pzuaie4BN
# rp0MuZLDEXgVYx2WNjmzqcxC7dY9SC3znOh5qUy2vnmWygC7b9kj0d3JrGtjc5q5
# 0WfV3WLXAQHkeRROsJFBZfXFGoSvRljFFUAjU/zdhP92P+1JiRRRikVy/sqIhMDY
# +7tVdzlE2fwnKOv9LShgKeyEevgMl0B1Fq7E2YeBZKF6KlhmYi9CE1350cnTUoU4
# YpQSnZo0YAnaenREDLfFGKTdAgMBAAGjggGCMIIBfjAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUlZpLWIccXoxessA/DRbe26glhEMw
# VAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMwMDEyKzQ2NzU5ODAfBgNVHSMEGDAW
# gBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8v
# d3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIw
# MTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDEx
# XzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AKVY+yKcJVVxf9W2vNkL5ufjOpqcvVOOOdVyjy1dmsO4O8khWhqrecdVZp09adOZ
# 8kcMtQ0U+oKx484Jg11cc4Ck0FyOBnp+YIFbOxYCqzaqMcaRAgy48n1tbz/EFYiF
# zJmMiGnlgWFCStONPvQOBD2y/Ej3qBRnGy9EZS1EDlRN/8l5Rs3HX2lZhd9WuukR
# bUk83U99TPJyo12cU0Mb3n1HJv/JZpwSyqb3O0o4HExVJSkwN1m42fSVIVtXVVSa
# YZiVpv32GoD/dyAS/gyplfR6FI3RnCOomzlycSqoz0zBCPFiCMhVhQ6qn+J0GhgR
# BJvGKizw+5lTfnBFoqKZJDROz+uGDl9tw6JvnVqAZKGrWv/CsYaegaPePFrAVSxA
# yUwOFTkAqtNC8uAee+rv2V5xLw8FfpKJ5yKiMKnCKrIaFQDr5AZ7f2ejGGDf+8Tz
# OiK1AgBvOW3iTEEa/at8Z4+s1CmnEAkAi0cLjB72CJedU1LAswdOCWM2MDIZVo9j
# 0T74OkJLTjPd3WNEyw0rBXTyhlbYQsYt7ElT2l2TTlF5EmpVixGtj4ChNjWoKr9y
# TAqtadd2Ym5FNB792GzwNwa631BPCgBJmcRpFKXt0VEQq7UXVNYBiBRd+x4yvjqq
# 5aF7XC5nXCgjbCk7IXwmOphNuNDNiRq83Ejjnc7mxrJGMIIHejCCBWKgAwIBAgIK
# YQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlm
# aWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEw
# OTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYD
# VQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+la
# UKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc
# 6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4D
# dato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+
# lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nk
# kDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6
# A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmd
# X4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL
# 5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zd
# sGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3
# T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS
# 4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRI
# bmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTAL
# BgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBD
# uRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFf
# MDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEF
# BQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1h
# cnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkA
# YwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn
# 8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7
# v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0b
# pdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/
# KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvy
# CInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBp
# mLJZiWhub6e3dMNABQamASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJi
# hsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYb
# BL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbS
# oqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sL
# gOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtX
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGYQwghmAAgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAJT44Pelt7FbswAAAAA
# AlMwDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIO8O
# CMgt2RK3IPOef7efNG4A8wD6EL1zALdxA16uasg2MEQGCisGAQQBgjcCAQwxNjA0
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQu
# Y29tIDANBgkqhkiG9w0BAQEFAASCAQBctiwP6K4XeA+r36tsn3Sp4gSCDVhuSXzP
# E/K6LzusSaUqKZQY0WNHzc1tvFO+OKpeeWGKkyvgh7Tgs1jRN1LMZSdCvfidUPuP
# Brh1HsjGyUS+ASG12kWU7HP+i+uFi94pkxxY58vUlf0yiUeSxYeLSqzi9HkMf1vi
# pMsdmy4a9PwmQI6e78/bDxPfc10zunQZvpvLVlse9fO5uE/86+sMk+4YSRSChiuE
# UwvPtPawxExFGNNb6+4n/nHfIACUv/73Cgix/fkd0QN7W3SvBQ5P71qm304YFF9Y
# d0O50Jrrvy+Yi25AtWlAWzMC8g1LVlHH/Fc/hhrtwnXXPCF7chiZoYIXDDCCFwgG
# CisGAQQBgjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglg
# hkgBZQMEAgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEE
# AYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIInr4d4vNx4k3n8HdYLF/DkwCYwbLXOo
# n97xkccOb53JAgZihLYMQVgYEzIwMjIwNTI1MjAyMDA3LjY0OVowBIACAfSggdSk
# gdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNV
# BAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1U
# aGFsZXMgVFNTIEVTTjpDNEJELUUzN0YtNUZGQzElMCMGA1UEAxMcTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgU2VydmljZaCCEV8wggcQMIIE+KADAgECAhMzAAABo/uas457
# hkNPAAEAAAGjMA0GCSqGSIb3DQEBCwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwMB4XDTIyMDMwMjE4NTExNloXDTIzMDUxMTE4NTExNlowgc4xCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29m
# dCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVT
# TjpDNEJELUUzN0YtNUZGQzElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# U2VydmljZTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAO+9TcrLeyoK
# cCqLbNtz7Nt2JbP1TEzzMhi84gS6YLI7CF6dVSA5I1bFCHcw6ZF2eF8Qiaf0o2XS
# Xf/jp5sgmUYtMbGi4neAtWSNK5yht4iyQhBxn0TIQqF+NisiBxW+ehMYWEbFI+7c
# SdX/dWw+/Y8/Mu9uq3XCK5P2G+ZibVwOVH95+IiTGnmocxWgds0qlBpa1rYg3bl8
# XVe5L2qTUmJBvnQpx2bUru70lt2/HoU5bBbLKAhCPpxy4nmsrdOR3Gv4UbfAmtpQ
# ntP758NRPhg1bACH06FlvbIyP8/uRs3x2323daaGpJQYQoZpABg62rFDTJ4+e06t
# t+xbfvp8M9lo8a1agfxZQ1pIT1VnJdaO98gWMiMW65deFUiUR+WngQVfv2gLsv6o
# 7+Ocpzy6RHZIm6WEGZ9LBt571NfCsx5z0Ilvr6SzN0QbaWJTLIWbXwbUVKYebrXE
# VFMyhuVGQHesZB+VwV386hYonMxs0jvM8GpOcx0xLyym42XA99VSpsuivTJg4o8a
# 1ACJbTBVFoEA3VrFSYzOdQ6vzXxrxw6i/T138m+XF+yKtAEnhp+UeAMhlw7jP99E
# AlgGUl0KkcBjTYTz+jEyPgKadrU1of5oFi/q9YDlrVv9H4JsVe8GHMOkPTNoB402
# 8j88OEe426BsfcXLki0phPp7irW0AbRdAgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQU
# UFH7szwmCLHPTS9Bo2irLnJji6owHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacb
# UzUZ6XIwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAo
# MSkuY3JsMGwGCCsGAQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5t
# aWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1w
# JTIwUENBJTIwMjAxMCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggr
# BgEFBQcDCDANBgkqhkiG9w0BAQsFAAOCAgEAWvLep2mXw6iuBxGu0PsstmXI5gLm
# gPkTKQnjgZlsoeipsta9oku0MTVxlHVdcdBbFcVHMLRRkUFIkfKnaclyl5eyj03w
# eD6b/pUfFyDZB8AZpGUXhTYLNR8PepM6yD6g+0E1nH0MhOGoE6XFufkbn6eIdNTG
# uWwBeEr2DNiGhDGlwaUH5ELz3htuyMyWKAgYF28C4iyyhYdvlG9VN6JnC4mc/EIt
# 50BCHp8ZQAk7HC3ROltg1gu5NjGaSVdisai5OJWf6e5sYQdDBNYKXJdiHei1N7K+
# L5s1vV+C6d3TsF9+ANpioBDAOGnFSYt4P+utW11i37iLLLb926pCL4Ly++GU0wlz
# Yfn7n22RyQmvD11oyiZHhmRssDBqsA+nvCVtfnH183Df5oBBVskzZcJTUjCxaagD
# K7AqB6QA3H7l/2SFeeqfX/Dtdle4B+vPV4lq1CCs0A1LB9lmzS0vxoRDusY80DQi
# 10K3SfZK1hyyaj9a8pbZG0BsBp2Nwc4xtODEeBTWoAzF9ko4V6d09uFFpJrLoV+e
# 8cJU/hT3+SlW7dnr5dtYvziHTpZuuRv4KU6F3OQzNpHf7cBLpWKRXRjGYdVnAGb8
# NzW6wWTjZjMCNdCFG7pkKLMOGdqPDFdfk+EYE5RSG9yxS76cPfXqRKVtJZScIF64
# ejnXbFIs5bh8KwEwggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0G
# CSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3Jp
# dHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9
# uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZr
# BxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk
# 2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxR
# nOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uD
# RedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGa
# RnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fz
# pk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG
# 4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGU
# lNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLE
# hReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0w
# ggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+
# gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNV
# HSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0l
# BAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0P
# BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9
# lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQu
# Y29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3Js
# MFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJ
# KoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEG
# k5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2
# LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7nd
# n/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSF
# QrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy8
# 7JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8
# x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2f
# pCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz
# /gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQ
# KBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAx
# M328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGby
# oYIC0jCCAjsCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0
# byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpDNEJELUUzN0YtNUZGQzEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsO
# AwIaAxUAHl/pXkLMAbPapCwa+GXc3SlDDROggYMwgYCkfjB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOY4bsswIhgPMjAyMjA1
# MjUxMzAwNTlaGA8yMDIyMDUyNjEzMDA1OVowdzA9BgorBgEEAYRZCgQBMS8wLTAK
# AgUA5jhuywIBADAKAgEAAgInIQIB/zAHAgEAAgITZjAKAgUA5jnASwIBADA2Bgor
# BgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAID
# AYagMA0GCSqGSIb3DQEBBQUAA4GBABCUD8Jy/0Sn0n1g0yFyYoKTDg+TTCX8YT6S
# F/DcawVvyHy/sv3NwuVTX2HVlSensqnwubrOqKyjTZPXd1xBbVfVQAS9W+dvQ+5k
# HJq8gp5xrgVWb0kdINan5a7soKRPaTaMA4amiGqBUFTjFCz412btYyRTtxm4h8+C
# 0Hp09tIMMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTACEzMAAAGj+5qzjnuGQ08AAQAAAaMwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqG
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgwAQaX3dzIDeT
# FfZRbfy+dhFZI4pAl4PtnFhlfRivXZswgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
# MIG9BCCM+LiwBnHMMoOd/sgbaYxpwvEJlREZl/pTPklz6euN/jCBmDCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABo/uas457hkNPAAEAAAGj
# MCIEICGSDoreVLUeebZ0FCk4X5gbrwc9sF+o7+YiZJ7rlxTpMA0GCSqGSIb3DQEB
# CwUABIICAJdBzaAlMAKgQ2uqgq35PHv+aFSctuOghZfFW+ahV4iHrIRk2UjT/H+i
# sU607uZ0sPFBuiJVys3WBGHDo7PVHqerYihKwoMyHd9GpQC7E/wsVkbbUbW6g0VQ
# gOIqAPax0RpvdGyGx1eNzYaDLIGpN08DaRbLwNj/KOFhpG82QTvDJjjo9GXUACo3
# FqpezYwG6mb6PQh2iKV1O4Ui3luhoNNNqxoYLo9S189x6aXB6bdI6BaoV8+a2q+T
# EgcToZTnYbA75OlRkRzIQDSbOruTTFswaQBQnf6CZSp4Hulf+rUqLBjiua0Qij7G
# tCUmMIpC+Rk/+TnIXdmRTCnp2I08RxLDhrfTQM0pv0RzLmsxm0iMmp2Wb+sekVGV
# OywYuS13bt27L//LYy9QwPtLQToY3bR1Vf1KoSKLbqsoA1AO/wDa9NzlW/5jYcYp
# gd4PVqVdg2Db4n9r7ha7Chty8IIdj0l56cql6hlhRCc2SNePiSXGen7RteUUk7G7
# 0mZ87B3a6EqJXcxvTwObqIky1GUua1rtdiXKZFFyLESj5+jASCyqo3Bqil4jKJWL
# eGP0H8rJDyHX6vpOC+FGwqMfIXzFqSZZy+JnQbv1SGTxBhL9+gqz4zNbhuhlNA93
# l9nMwjAj+AQHDDAaU7lb0dB7qcaotjV8wZDz7GoGhbDWMkb0Ul0O
# SIG # End signature block
