<#//***********************************************************************
//
// SfMC-Discovery.ps1
// Modified 16 May 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// .VERSION 3.6
//
// .SYNOPSIS
//  Collect Exchange configuration via PowerShell
// 
// .DESCRIPTION
//  This script will run Get commands in your Exchange Management Shell to collect configuration data via PowerShell
//
// .PARAMETERS
//    ExchangeServer - The ExchangeServer parameter is required to make the initial remote PowerShell session to retrieve list of Exchange servers in the organization and is used to collect the Exchange organization settings.
//    UserName - The UserName parameter specifies the Exchange admin account used to run the data collection scripts
//    ServerName - The ServerName parameter specifies a single Exchange server to collect data against.
//    DagName - The DagName parameter specifies the name of the Exchange database availability group to collect data against.
//    OutputPath - The OutputPath parameters specifies the location for the data collection results.
//    ScriptPath - The ScriptPath parameter specifies the location for the data collection scripts.
//    ADSite - The ADSite parameter specifies the Active Directory site for the Exchange servers to collect data against.
//    OrgSettings - The OrgSettings parameter specifies whether or not Exchange organization settings are collected.
//    ServerSettings - The ServerSettings parameter specifies wheter or no Exchange server settings are collected.
//
//.EXAMPLES
// .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -DagName E19DAG1 -OutputPath c:\Temp\Results
// This example collects the Exchange organization settings and Exchange server settings for the E19DAG1 database availability group and saves the results in C:\Temp\Results
//
// .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results
// This example collects the Exchange organization settings and Exchange server settings for all Exchange servers in the organization and saves the results in c:\Temp\Results
//
// .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results -ServerSettings:$False
// This example collects only the Exchange organization settings and saves the results to c:\Temp\Results
//
// .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results -OrgSettings:$False -ServerName clt-e19-mbx3.resource.local
// This example collects only the Exchange server settings for clt-e19-mbx3.resource.local and saves the results to c:\Temp\Results
//
//.NOTES
//  Exchange server specified should be the latest version in the environment
// 
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
param(
    [Parameter(Mandatory=$true)] [string]$ExchangeServer,
    [Parameter(Mandatory=$false)] [string]$UserName,
    [Parameter(Mandatory=$false)] [string]$ServerName,
    [Parameter(Mandatory=$false)] [string]$DagName,
    [Parameter(Mandatory=$false)] [string]$OutputPath,
    [Parameter(Mandatory=$false)] [string]$ScriptPath,
    [Parameter(Mandatory=$false)] [string]$ADSite,
    [boolean]$OrgSettings=$true,
    [boolean]$ServerSettings=$true
)
Clear-Host
#region Disclaimer
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
#endregion
#Start-Sleep -Seconds 2
function Start-Cleanup {
    Remove-PSSession -Name SfMC -ErrorAction Ignore
    Remove-PSSession -Name SfMCOrgDis -ErrorAction Ignore
    Get-PSSession -Name SfMCSrvDis -ErrorAction Ignore | Remove-PSSession -ErrorAction Ignore
}
function Get-FolderPath {   
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the location"
    $folderBrowser.SelectedPath = "C:\"
    $folderPath = $folderBrowser.ShowDialog()
    [string]$oPath = $folderBrowser.SelectedPath
    return $oPath
}
function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    if($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        return $true
    }
    else {
        return $false
    }
}
function Test-ADAuthentication {
    $UserName = $creds.UserName
    $UserName = $UserName.Substring(0, $UserName.IndexOf("@"))
    $Password = $creds.GetNetworkCredential().Password
    #(New-Object DirectoryServices.DirectoryEntry "",$username,$password).PsBase.Name -ne $null
    $Root = "LDAP://" + ([ADSI]'').distinguishedName
    $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root,$UserName,$Password)
    if(!$Domain) { Write-Warning "Something went wrong" }
    else {
        if ($Domain.name -ne $null) { return $true }
        else {return $false}
    }
}
#region CheckAdmin
if(-not (Is-Admin)) {
	Write-host;Write-Warning "The SfMC-Discovery.ps1 script needs to be executed in elevated mode. Please start PowerShell 'as Administrator' and try again." 
	Write-host;Start-Sleep -Seconds 2;
	exit
}
#endregion
#region CheckPowerShell
if(($PSVersionTable).PSVersion -like "4*") {
    Write-Host; Write-Warning "The SfMC-Discovery.ps1 script must be executed using Windows PowerShell version 5.0 or higher"
    Write-Host; Start-Sleep -Seconds 2
    exit
}
#endregion
Write-Host " "
Write-Host " "
Write-Host -ForegroundColor Cyan "==============================================================================="
Write-Host " "
Write-Host -ForegroundColor Cyan " The SfMC Email Discovery process is about to begin gathering data. "
Write-Host -ForegroundColor Cyan " It will take some time to complete depending on the size of your environment. "
Write-Host " "
Write-Host -ForegroundColor Cyan "==============================================================================="
Write-Host " "

## Script block to initiate Exchange server discovery
$scriptBlock1 = {
    Unregister-ScheduledTask -TaskName ExchangeServerDiscovery -Confirm:$False
    $scriptFile = $env:ExchangeInstallPath +"Scripts\Get-ExchangeServerDiscovery.ps1"
    $scriptFile = "`"$scriptFile`""
    $Sta = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -file $scriptFile"
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    $Stt = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMilliseconds(5000)
    Register-ScheduledTask ExchangeServerDiscovery -Action $Sta -Principal $STPrin -Trigger $Stt
}
## Script block to initiate Exchange organization discovery
$scriptBlock2 = {
    Unregister-ScheduledTask -TaskName ExchangeOrgDiscovery -Confirm:$False
    $scriptFile = $env:ExchangeInstallPath +"Scripts\Get-ExchangeOrgDiscovery.ps1"
    $scriptFile = "`"$scriptFile`""
    $Sta = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -file $scriptFile"
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    $Stt = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMilliseconds(5000)
    Register-ScheduledTask ExchangeOrgDiscovery -Action $Sta -Principal $STPrin -Trigger $Stt
}
## Script block to determine Exchange install path for server
$scriptBlock3 = {
    $env:ExchangeInstallPath
}
#region ScriptLocation
#Determine location of scripts
Add-Type -AssemblyName System.Windows.Forms
[boolean]$validPath = $false
while($validPath -eq $false) {
    if($ScriptPath -like $null) {[string]$scriptPath = (Get-Location).Path}
    else{
        if($ScriptPath.Substring($ScriptPath.Length-1,1) -eq "\") {$ScriptPath = $ScriptPath.Substring(0,$ScriptPath.Length-1)}
    }
    if(Test-Path -Path $ScriptPath) {$validPath = $true}
    else {
        Write-Warning "An invalid path to the scripts was provided. Please select the location."
        Start-Sleep -Seconds 3
        $ScriptPath = Get-FolderPath
    }
}
#endregion
#region OutputPath
# Determine the current location which will be used to store the results
[boolean]$validPath = $false
while($validPath -eq $false) {
    if($OutputPath -like $null) {
        Write-Host "Select the location where to save the data." -ForegroundColor Yellow
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
#Create a new subfolder for the current results
$timeStamp = Get-Date -Format yyyyMMddHHmmss
New-Item -Path $OutputPath -Name $timeStamp -ItemType Directory | Out-Null
$OriginalPath = $OutputPath
$OutputPath = "$OutputPath\$timeStamp"
#endregion
#region GetAdminCreds
## Get the current user name and prompt for credentials
if($UserName -like $null) {
    $domain = $env:USERDNSDOMAIN
    $UserName = $env:USERNAME
    $UserName = "$UserName@$domain"
}
$validCreds = $false
[int]$credAttempt = 0
while($validCreds -eq $false) {
    Write-Host "Please enter the Exchange admin credentials using UPN format" -ForegroundColor Green
    Start-Sleep -Seconds 2
    $upnFound = $false
    while($upnFound -eq $false) {
        $creds = [System.Management.Automation.PSCredential](Get-Credential -UserName $UserName.ToLower() -Message "Exchange admin credentials using UPN")
        if($creds.UserName -like "*@*") {$upnFound = $True}
        else {Write-Warning "The username must be in UPN format. (ex. jimm@contoso.com)"}
    }
    $validCreds =  Test-ADAuthentication
    if($validCreds -eq $false) {
        Write-Warning "Unable to validate your credentials. Please try again."
        $credAttempt++
    }
    if($credAttempt -eq 3) {
        Write-Warning "Too many credential failures. Exiting script."
        exit
    }
}
#endregion
## Set the idle time for the remote PowerShell session
$SessionOption = New-PSSessionOption -IdleTimeout 300000 -OperationTimeout 300000 -OutputBufferingMode Drop
## Create an array for the list of Exchange servers
$servers = New-Object System.Collections.ArrayList
## Set a timer for the data collection process
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()
#region GetExchangeServerList
## Connect to the Exchange server to get a list of servers for data collection
$isConnected = $false
[int]$retryAttempt = 0
while($isConnected -eq $false) {
    $Error.Clear()
    try {Import-PSSession (New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://$ExchangeServer/Powershell -AllowRedirection -Authentication Kerberos -Name SfMC -WarningAction Ignore -Credential $creds -ErrorAction Ignore -SessionOption $SessionOption) -WarningAction Ignore -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null}
    catch {
        Write-Warning "Unable to create a remote PowerShell session with $ExchangeServer."
        Start-Sleep -Seconds 2
        $ExchangeServer = Read-Host "Please enter the FQDN of another Exchange Server: "
    }
    $Error.Clear()
    try{$testServer = Get-ExchangeServer $ExchangeServer -ErrorAction Ignore}
    catch{$retryAttempt++}
    if($testServer -like $null) {
        if($retryAttempt -eq 4) {
            Write-Warning "Maximum number of attempts has been reached. Check credentials and try again. Exiting script."
            exit
        }
    }
    else{$isConnected = $true}
}
[string]$orgName = (Get-OrganizationConfig).Name
#Check if running against a single server
if($ServerName -notlike $null) {
    $CheckServer = (Get-ExchangeServer -Identity $ServerName -ErrorAction Ignore).Fqdn
    if($CheckServer -notlike $null) {
        $servers.Add($CheckServer) | Out-Null
    }
    else {
        Write-Warning "Unable to find an Exchange server with the name $ServerName. Exiting script"
        Start-Cleanup
        exit
    }
}
#check if running against a single DAG
else {
    if($DagName -notlike $null) { 
        Get-DatabaseAvailabilityGroup $DagName -ErrorAction Ignore | Select -ExpandProperty Servers | ForEach-Object { $servers.Add((Get-ExchangeServer $_ ).Fqdn) | Out-Null}
        if($servers.Count -eq 0){
            Write-Warning "Unable to find a database availability group with the name $DagName. Exiting script"
            Start-Cleanup
            exit
        }
    }
    #check if running against an AD site
    else {
        if($ADSite -notlike $null) {
            Get-ExchangeServer | Where {$_.Site -like "*$ADSite*" -and $_.ServerRole -ne "Edge"} | ForEach-Object { $servers.Add($_.Fqdn) | Out-Null}
            if($servers.Count -eq 0){
                Write-Warning "Unable to find any Exchange servers is the $ADSite site. Exiting script"
                Start-Cleanup
                exit
            }
        }
        #otherwise run against all servers
        else {Get-ExchangeServer | Where { $_.ServerRole -ne "Edge"} | ForEach-Object { $servers.Add($_.Fqdn) | Out-Null } }
    }
}
#endregion
Write-host -ForegroundColor Cyan "Collecting data now, please be patient. This will take some time to complete!"
#region GetExchOrgSettings
## Collect Exchange organization settings
if($OrgSettings) {
    Write-Host -ForegroundColor Cyan "Starting data collection for Exchange organization settings..." -NoNewline
    ## Get the Exchange install path for this server    
    $exchInstallPath = Invoke-Command -Credential $creds -ScriptBlock $scriptBlock3 -ComputerName $ExchangeServer -ErrorAction Stop
    $orgResultPath = $exchInstallPath
    ## Copy the discovery script to the Exchange server
    $Session = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name CopyOrgScript
    Copy-Item "$ScriptPath\Get-ExchangeOrgDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $Session
    ## Initiate the data collection on the Exchange server
    try {Invoke-Command -Credential $creds -ScriptBlock $scriptBlock2 -ComputerName $ExchangeServer -ArgumentList $creds -InDisconnectedSession -ErrorAction Stop -SessionName SfMCOrgDis -SessionOption $SessionOption | Out-Null}
    catch {
        Write-Host "FAILED"
        Write-Warning "Unable to collect Exchange organization settings."
    }
    Invoke-Command -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeOrgDiscovery.ps1" -Confirm:$false} -Session $Session
    Remove-PSSession -Name CopyOrgScript -ErrorAction Ignore
    Write-Host "STARTED"
}
#endregion
#region GetExchServerSettings
if($ServerSettings) {
    Write-Host "Starting data collection on the Exchange servers..." -ForegroundColor Cyan -NoNewline
    $sAttempted = 0
    ## Collect server specific data from all the servers
    foreach ($s in $servers) {
        ## Get the Exchange install path for this server
        $exchInstallPath = $null
        $PercentComplete = (($sAttempted/$servers.Count)*100)
        $PercentComplete = [math]::Round($PercentComplete)
        Write-Progress -Activity "Exchange Discovery Assessment" -Status "Starting data collection on $s.....$PercentComplete% complete" -PercentComplete $PercentComplete
        if(Test-Connection -ComputerName $s -Count 2 -ErrorAction Ignore) {
            $exchInstallPath = Invoke-Command -Credential $creds -ScriptBlock $scriptBlock3 -ComputerName $ExchangeServer -ErrorAction Stop
            ## Create an array to store paths for data retrieval
            if($exchInstallPath -notlike $null) {
                New-Object -TypeName PSCustomObject -Property @{
                    ServerName = $s
                    ExchInstallPath = $exchInstallPath
                } | Export-Csv -Path $OutputPath\ExchInstallPaths.csv -NoTypeInformation -Append
                ## Copy the discovery script to the Exchange server
                $Session = New-PSSession -ComputerName $s -Credential $creds -Name CopyServerScript -SessionOption $SessionOption
                Copy-Item "$ScriptPath\Get-ExchangeServerDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $Session
                ## Initiate the data collection on the Exchange server
                try{ Invoke-Command -Credential $creds -ScriptBlock $scriptBlock1 -ComputerName $s -ArgumentList $creds -InDisconnectedSession -ErrorAction Stop -SessionName SfMCSrvDis -SessionOption $SessionOption | Out-Null}
                catch{ Write-Warning "Unable to initiate data collection on $s."}
                Invoke-Command -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeServerDiscovery.ps1" -Confirm:$false} -Session $Session -ErrorAction Ignore
                Remove-PSSession -Name CopyServerScript -ErrorAction Ignore
            }
            else {Out-File $OutputPath\FailedServers.txt -InputObject "Unable to determine the Exchange install path on $s" -Append}
        }
        else {Out-File $OutputPath\FailedServers.txt -InputObject "Unable to connect to $s" -Append}
        $sAttempted++
    }
    Write-Host "STARTED"
}
#endregion
## Check for results
Write-Host "Attempting to retrieve results..." -ForegroundColor Cyan
#region CollectResults
[int]$fileCheckAttempt = 0
if($OrgSettings) {$orgResultsIn = $false}
## Get list of servers and install paths to retrieve data
if($ServerSettings) {
    $Servers = Import-Csv $OutputPath\ExchInstallPaths.csv
    $serverCount = $servers.ServerName.Count
}
else {$serverCount = 1}
$totalServerCount = $serverCount
$foundCount = 0
## Attempt to retrieve the data multiple times
while($fileCheckAttempt -lt 4) {
    if($serverCount -gt 0 -or $orgResultsIn -eq $false) { 
        ## Wait x minutes before attempting to retrieve the data
        $waitTimer = New-Object -TypeName System.Diagnostics.Stopwatch
        $waitTimer.Start()
        while($waitTimer.ElapsedMilliseconds -lt 60000){
            $TimeRemaining = $waitTimer.ElapsedMilliseconds/1000
            $TimeRemaining = 120 - [math]::Round($TimeRemaining)
            Write-Progress -Activity "Exchange Discovery Assessment" -Status "Waiting two minutes before attempting to retrive data... $TimeRemaining seconds remaining" -PercentComplete (($waitTimer.ElapsedMilliseconds/120000)*100)
            Start-Sleep -Seconds 1
        }
    }
    else {break}
    ## Check for results and retrieve if missing
    $fileCheckResult = $False
    if($OrgSettings) {
        if($orgResultsIn -eq $false) {
            Write-Host "Retrieving Exchange organization settings..." -ForegroundColor Cyan -NoNewline
            if(Get-Item $OutputPath\*OrgSettings* -ErrorAction Ignore) { 
                Write-Host "FOUND" -ForegroundColor White
                $orgResultsIn = $true
            }
            else {
                $sourcePath = $orgResultPath
                $sourcePath = $sourcePath+"Logging\SfMC Discovery"
                $Session = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name OrgResults
                $scriptBlock5 = {$orgFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip").FullName; return $orgFile}
                $orgResult = Invoke-Command -ScriptBlock $scriptBlock5 -Session $Session -ErrorAction Ignore
                if($orgResult -notlike $null ) {
                    Copy-Item $orgResult -Destination $OutputPath -Force -FromSession $Session -ErrorAction Ignore
                    if(Get-Item $OutputPath\*OrgSettings* -ErrorAction Ignore) { 
                        Write-Host "FOUND" -ForegroundColor White
                        $orgResultsIn = $true
                        Invoke-Command -ScriptBlock {Unregister-ScheduledTask -TaskName ExchangeOrgDiscovery -Confirm:$False} -Session $Session
                        Remove-PSSession -Name OrgResults -ErrorAction Ignore -Confirm:$False
                    }
                }
                else {
                    Write-Host "NOT FOUND" -ForegroundColor Red
                }
            }
        }
    }
    $fileCheckResult = $False
    ## Create an array to track remaining servers to pull results
    [System.Collections.ArrayList]$NotFoundList = @()
    [int]$sAttempted = 0
    if($ServerSettings) {
        Write-Host "Retrieving Exchange server settings..." -ForegroundColor Cyan -NoNewline
        $servers | ForEach-Object {
            $s = $_.ServerName.Substring(0, $_.ServerName.IndexOf("."))
            $sourcePath = $_.ExchInstallPath
            $sourcePath = $sourcePath+"Logging\SfMC Discovery"
            ## Check if server results have been received
            $PercentComplete = (($sAttempted/$servers.Count)*100)
            $PercentComplete = [math]::Round($PercentComplete)
            Write-Progress -Activity "Exchange Discovery Assessment" -Status "Retrieving data from $s.....$PercentComplete% complete" -PercentComplete (($foundCount/$totalServerCount)*100)
            if(!(Get-Item $OutputPath\$s* -ErrorAction Ignore)) { 
                ## Attempt to copy results from Exchange server
                $Session = New-PSSession -ComputerName $_.ServerName -Credential $creds -Name ServerResults
                $scriptBlock5 = {$serverFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\$env:COMPUTERNAME*.zip").FullName; return $serverFile}
                $serverResult = Invoke-Command -ScriptBlock $scriptBlock5 -Session $Session -ErrorAction Ignore
                if($serverResult -notlike $null) {
                    Copy-Item $serverResult -Destination $OutputPath -Force -FromSession $Session -ErrorAction Ignore 
                    ## Check if the results were found
                    if(Get-Item $OutputPath\$s* -ErrorAction Ignore) {
                        $foundCount++
                        $scripBlock4 = {Unregister-ScheduledTask -TaskName ExchangeServerDiscovery -Confirm:$False}
                        Invoke-Command -ScriptBlock $scripBlock4 -Session $Session -ErrorAction Ignore
                        Remove-PSSession -Name ServerResults -ErrorAction Ignore -Confirm:$False
                        $sAttempted++
                    }
                }
                ## Add server to array to check again
                else {$NotFoundList.Add($_) | Out-Null}
            }
        }
    }
    if($foundCount -eq $totalServerCount) { Write-Host "FOUND"; $ServerSettings = $False}
    else{
        if($foundCount -gt 0) {Write-Host "$foundCount of $totalServerCount FOUND" -ForegroundColor Yellow}
        else {Write-Host "NOT FOUND" -ForegroundColor Red}
    }
    $Servers = $NotFoundList
    $serverCount = $servers.ServerName.Count
    $fileCheckAttempt++
}
foreach($s in $NotFoundList) {
    $mServer = $s.ServerName
    Out-File $OutputPath\FailedServers.txt -InputObject "Unable to retrieve data for $mServer" -Append
}
#endregion
Write-Host " "
$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
$timeStamp = Get-Date -Format yyyyMMddHHmmss
Compress-Archive -Path $OutputPath -DestinationPath "$OriginalPath\DiscoveryResults-$timeStamp.zip"
Write-host " "
Write-host -ForegroundColor Cyan  "==================================================="
Write-Host -ForegroundColor Cyan " SfMC Email Discovery data collection has finished!"
Write-Host -ForegroundColor Cyan "          Total collection time: $($totalTime) seconds"
Write-Host -ForegroundColor Cyan "    Please upload results to SfMC. - Thank you!!!"
Write-host -ForegroundColor Cyan "==================================================="
Write-host " "
Start-Cleanup

# SIG # Begin signature block
# MIInswYJKoZIhvcNAQcCoIInpDCCJ6ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC5wsuxGPKDmXVP
# QLKrOTVfEbXhumBHPKPm7Y7ffn4O1qCCDYUwggYDMIID66ADAgECAhMzAAACU+OD
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
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIC5N
# VqeQgz7Q1se+ASYlPXcEGxSmAFAkTHiFzpe7GOHKMEQGCisGAQQBgjcCAQwxNjA0
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQu
# Y29tIDANBgkqhkiG9w0BAQEFAASCAQCcA4xk2KqOUfg6SBQRCj5Gdz1DEfRXEaZw
# k/MtMsmA+4QglepHDP4x+69Dt9fb9jNYMYWUzJpQ1ItbqPyZdJbi++K1WrQscTad
# mA6APChFbJXvmOX8+VpzRveBiqEGM2MmZb1yI9UUJ0bcBDo+rjme0W7tsXvelBHP
# 7c9qeAYtwsWaKe5yDX5RKo/8pEJZuyP7GsD4bLbopAgt2TcZv3UYm/swqJkNl/Zt
# 1JVag3RvYK59uflw+COA1MbSOFdzxEORJ+Ku7Id+P5oqzXFC0qZ8EAIhDCGRTiU0
# mbYVR26LRi40mhTNvyix5+n6Hycz+O/l4iEYIYAfVND8BfUl9lzRoYIXDDCCFwgG
# CisGAQQBgjcDAwExghb4MIIW9AYJKoZIhvcNAQcCoIIW5TCCFuECAQMxDzANBglg
# hkgBZQMEAgEFADCCAVUGCyqGSIb3DQEJEAEEoIIBRASCAUAwggE8AgEBBgorBgEE
# AYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEINK2jQk9lo5Eav5sMyWlotk7NjATHtYg
# wGQY9H/fX9EiAgZihLYMQZgYEzIwMjIwNTI1MjAyMDEwLjU1NlowBIACAfSggdSk
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
# SIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQglw3vdlG2oaZo
# /KeCOA5f/TV6WUOBRTcRiRXh/ha1c9YwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHk
# MIG9BCCM+LiwBnHMMoOd/sgbaYxpwvEJlREZl/pTPklz6euN/jCBmDCBgKR+MHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABo/uas457hkNPAAEAAAGj
# MCIEICGSDoreVLUeebZ0FCk4X5gbrwc9sF+o7+YiZJ7rlxTpMA0GCSqGSIb3DQEB
# CwUABIICAB2dPatN5vqjP0H5PCdpe1LB61Gt0kw/mYh/UoN/f4Kd29SmuO+AWKhW
# LsR0VTh3YXP3vRZlQK+T24suyq4e82+hXwiVZZcBb3TY3KsKc5tPyODnupWJaIvy
# nZPOYM/w1lOmrkpkxkgxstqcF2eMj7LkgJSvfdj3gtyUL7chSOSWkrgg5SopEljs
# QxpRS1xU7bgo32/fJx5WLYIOXVglAtsNxZPtezs92SWnNpiCyyazNRkpNd1mWVLQ
# Mf3XZKNFMsUBHgB6+SKdsucNOWVgi8vCA+xTxIz2wGGWZeS5GdiFxYWESKcXyheh
# djvAfS0gv4nxiLzRdwbP7L/w7xFL47Ir/tg7ttWp4C/HiKtRlGggwi6iYG5v/IYH
# j6FwL0UwQadJSmKAiR/naWwcVSz6u0bj+ok0xoI9GkeCnVhiDd6cbS8+sHxprFFA
# 6qUcoh/ItZz08Srio8S+2XZcwvZIPoJWeDgGF574L+qncZi2bX7QnOg4x+4CgphB
# ViGvpHfn3aNFT4lM+SdgTFK3jDN95I9ql9StXrg/I0vwKaXTs/w1HxED/q/hYbda
# hTYDmS96tVFbD9YwuaZkgoY3KvquQCWPkEvINidAQ7vHldojq4ku3+uztRDfZhMI
# m3lNkSR4hnhSdoWQAZzsBt087PEVWzETb0Ry5LIn6T3galh/Px4B
# SIG # End signature block
