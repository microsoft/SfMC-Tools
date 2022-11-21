<#//***********************************************************************
//
// SfMC-Discovery.ps1
// Modified 18 November 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// .VERSION 20221118.1228
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
//    ServerSettings - The ServerSettings parameter specifies whether or not Exchange server settings are collected.
//    HealthChecker - The HealthChecker parameter specifies whether or not the Exchange HealthChecker script is run against each server
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
// 3.7 - Update adds copying the HealthChecker.ps1 script to the Exchange servers for additional data collection
// 20220823.1657 - Logging, option to include HealthChecker (no longer mandatory), invoke-command only run remotely
// 20220908.1039 - Allow run from Exchange server using logged on user credentials
// 20221102.0949 - Allow run from Exchange server on Windows Server 2012 R2
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
    [Parameter(Mandatory=$false)] [boolean]$OrgSettings=$true,
    [Parameter(Mandatory=$false)] [boolean]$ServerSettings=$true,
    [Parameter(Mandatory=$false)] [boolean]$HealthChecker=$true
)
function Write-Verbose {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '', Justification = 'In order to log Write-Verbose from Shared functions')]
    [CmdletBinding()]
    param(
        [Parameter(Position = 1, ValueFromPipeline)]
        [string]$Message
    )

    process {
        #write to the debug log and call Write-Verbose normally
        Write-VerboseLog $Message
        Microsoft.PowerShell.Utility\Write-Verbose $Message
    }
}
function Write-VerboseLog ($Message) {
    $Script:Logger = $Script:Logger | Write-LoggerInstance $Message
}
# Common method used to handle Invoke-Command within a script.
# Avoids using Invoke-Command when running locally on a server.
function Invoke-ScriptBlockHandler {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $ComputerName,

        [Parameter(Mandatory = $true)]
        [scriptblock]
        $ScriptBlock,

        [string]
        $ScriptBlockDescription,

        [object]
        $ArgumentList,

        [bool]
        $IncludeNoProxyServerOption,

        [scriptblock]
        $CatchActionFunction,

        [System.Management.Automation.PSCredential]$Credential,
        [bool]$IsExchangeServer
    )
    begin {
        Write-Verbose "Calling: $($MyInvocation.MyCommand)"
        $returnValue = $null
    }
    process {

        if (-not([string]::IsNullOrEmpty($ScriptBlockDescription))) {
            Write-Verbose "Description: $ScriptBlockDescription"
        }

        try {

            if (($ComputerName).Split(".")[0] -ne $env:COMPUTERNAME) {

                $params = @{
                    ComputerName = $ComputerName
                    ScriptBlock  = $ScriptBlock
                    ErrorAction  = "Ignore"
                }

                if ($Credential -notlike $null -and $IsExchangeServer -eq $false) {
                    Write-Verbose "Including Credential"
                    $params.Add("Credential", $Credential)
                }

                if ($IncludeNoProxyServerOption) {
                    Write-Verbose "Including SessionOption"
                    $params.Add("SessionOption", (New-PSSessionOption -ProxyAccessType NoProxyServer))
                }

                if ($null -ne $ArgumentList) {
                    Write-Verbose "Running Invoke-Command with argument list"
                    $params.Add("ArgumentList", $ArgumentList)
                } else {
                    Write-Verbose "Running Invoke-Command without argument list"
                }
                Write-Verbose "Running Invoke-Command using the following: "
                Write-Verbose ($params | Out-String)
                $returnValue = Invoke-Command @params
            } else {

                if ($null -ne $ArgumentList) {
                    Write-Verbose "Running Script Block Locally with argument list"

                    # if an object array type expect the result to be multiple parameters
                    if ($ArgumentList.GetType().Name -eq "Object[]") {
                        Write-Verbose "Running Invoke-Command using the following: "
                Write-Verbose ($params | ForEach-Object{ [pscustomobject]$_ })
                        $returnValue = & $ScriptBlock @ArgumentList
                    } else {
                        Write-Verbose "Running Invoke-Command using the following: "
                Write-Verbose ($params | ForEach-Object{ [pscustomobject]$_ })
                        $returnValue = & $ScriptBlock @ArgumentList
                    }
                } else {
                    Write-Verbose "Running Script Block Locally without argument list"
                    Write-Verbose "Running Invoke-Command using the following: "
                Write-Verbose ($params | ForEach-Object{ [pscustomobject]$_ })
                    $returnValue = & $ScriptBlock
                }
            }
        } catch {
            Write-Verbose "Failed to run $($MyInvocation.MyCommand)"
            Invoke-CatchActionError $CatchActionFunction
        }
    }
    end {
        Write-Verbose "Exiting: $($MyInvocation.MyCommand)"
        return $returnValue
    }
}
function Invoke-CatchActionError {
    [CmdletBinding()]
    param(
        [scriptblock]$CatchActionFunction
    )

    if ($null -ne $CatchActionFunction) {
        & $CatchActionFunction
    }
}
function Get-NewLoggerInstance {
    [CmdletBinding()]
    param(
        [string]$LogDirectory = (Get-Location).Path,
        [ValidateNotNullOrEmpty()][string]$LogName = "Script_Logging",
        [bool]$AppendDateTime = $true,
        [bool]$AppendDateTimeToFileName = $true,
        [int]$MaxFileSizeMB = 10,
        [int]$CheckSizeIntervalMinutes = 10,
        [int]$NumberOfLogsToKeep = 10
    )

    $fileName = if ($AppendDateTimeToFileName) { "{0}_{1}.txt" -f $LogName, ((Get-Date).ToString('yyyyMMddHHmmss')) } else { "$LogName.txt" }
    $fullFilePath = [System.IO.Path]::Combine($LogDirectory, $fileName)

    if (-not (Test-Path $LogDirectory)) {
        try {
            New-Item -ItemType Directory -Path $LogDirectory -ErrorAction Stop | Out-Null
        } catch {
            throw "Failed to create Log Directory: $LogDirectory"
        }
    }

    return [PSCustomObject]@{
        FullPath                 = $fullFilePath
        AppendDateTime           = $AppendDateTime
        MaxFileSizeMB            = $MaxFileSizeMB
        CheckSizeIntervalMinutes = $CheckSizeIntervalMinutes
        NumberOfLogsToKeep       = $NumberOfLogsToKeep
        BaseInstanceFileName     = $fileName.Replace(".txt", "")
        Instance                 = 1
        NextFileCheckTime        = ((Get-Date).AddMinutes($CheckSizeIntervalMinutes))
        PreventLogCleanup        = $false
        LoggerDisabled           = $false
    } | Write-LoggerInstance -Object "Starting Logger Instance $(Get-Date)"
}
function Write-LoggerInstance {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$LoggerInstance,

        [Parameter(Mandatory = $true, Position = 1)]
        [object]$Object
    )
    process {
        if ($LoggerInstance.LoggerDisabled) { return }

        if ($LoggerInstance.AppendDateTime -and
            $Object.GetType().Name -eq "string") {
            $Object = "[$([System.DateTime]::Now)] : $Object"
        }

        # Doing WhatIf:$false to support -WhatIf in main scripts but still log the information
        $Object | Out-File $LoggerInstance.FullPath -Append -WhatIf:$false

        #Upkeep of the logger information
        if ($LoggerInstance.NextFileCheckTime -gt [System.DateTime]::Now) {
            return
        }

        #Set next update time to avoid issues so we can log things
        $LoggerInstance.NextFileCheckTime = ([System.DateTime]::Now).AddMinutes($LoggerInstance.CheckSizeIntervalMinutes)
        $item = Get-ChildItem $LoggerInstance.FullPath

        if (($item.Length / 1MB) -gt $LoggerInstance.MaxFileSizeMB) {
            $LoggerInstance | Write-LoggerInstance -Object "Max file size reached rolling over" | Out-Null
            $directory = [System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)
            $fileName = "$($LoggerInstance.BaseInstanceFileName)-$($LoggerInstance.Instance).txt"
            $LoggerInstance.Instance++
            $LoggerInstance.FullPath = [System.IO.Path]::Combine($directory, $fileName)

            $items = Get-ChildItem -Path ([System.IO.Path]::GetDirectoryName($LoggerInstance.FullPath)) -Filter "*$($LoggerInstance.BaseInstanceFileName)*"

            if ($items.Count -gt $LoggerInstance.NumberOfLogsToKeep) {
                $item = $items | Sort-Object LastWriteTime | Select-Object -First 1
                $LoggerInstance | Write-LoggerInstance "Removing Log File $($item.FullName)" | Out-Null
                $item | Remove-Item -Force
            }
        }
    }
    end {
        return $LoggerInstance
    }
}
function Get-FolderPath {   
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the location"
    $folderBrowser.SelectedPath = "C:\"
    $folderPath = $folderBrowser.ShowDialog()
    [string]$oPath = $folderBrowser.SelectedPath
    return $oPath
}
function Test-ADAuthentication {
    $UserName = $creds.UserName
    $Password = $creds.GetNetworkCredential().Password
    $Root = "LDAP://" + ([ADSI]'').distinguishedName
    $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root,$UserName,$Password)
    if(!$Domain) { Write-Warning "Something went wrong" }
    else {
        if ($Domain.name -ne $null) { return $true }
        else {return $false}
    }
}
function Start-Cleanup {
    Get-PSSession -Name SfMC* -ErrorAction Ignore | Remove-PSSession -ErrorAction Ignore
}
function Check-RunningFromExchangeServer {
    # Determine if script is running from an Exchange Server
    param(
        [Parameter(Mandatory = $true)] [string]$ComputerName
    )
    $isExchangeServer = $false
    try{
        $adDomain = (Get-ADDomain -ErrorAction Ignore).DistinguishedName
    }
    catch {
        Write-Verbose "Unable to determine Active Directory domain"
    }
    if($adDomain -notlike $null) {
        try {
            $exchContainer = Get-ADObject -LDAPFilter "(objectClass=msExchConfigurationContainer)" -SearchBase "CN=Services,CN=Configuration,$adDomain" -SearchScope OneLevel -ErrorAction Ignore
            if(Get-ADObject -Filter 'objectClass -eq "msExchExchangeServer" -and name -eq $ComputerName' -SearchBase $exchContainer -SearchScope Subtree -ErrorAction Ignore) {
                $isExchangeServer = $true
                Write-VerboseLog "Found Exchange server with the name $ComputerName"
            }
            else {
                Write-Verbose "Unable to locate Exchange server with the name $ComputerName"
            }
        }
        catch {
            Write-Verbose "Unable to locate Exchange configuration container"
        }
    }
    return $isExchangeServer
}

Add-Type -AssemblyName System.Windows.Forms
$Script:Logger = Get-NewLoggerInstance -LogName "SfMCDiscovery-$((Get-Date).ToString("yyyyMMddhhmmss"))-Debug" -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue

#region SfMCBanner
Write-Host " "
Write-Host " "
Write-Host -ForegroundColor Cyan "==============================================================================="
Write-Host " "
Write-Host -ForegroundColor Cyan " The SfMC Email Discovery process is about to begin gathering data. "
Write-Host -ForegroundColor Cyan " It will take some time to complete depending on the size of your environment. "
Write-Host " "
Write-Host -ForegroundColor Cyan "==============================================================================="
Write-Host " "
#endregion

#region ScriptBlocks
## Script block to initiate Exchange server discovery
$ExchangeServerDiscovery = {
    param([boolean]$HealthChecker)
    Unregister-ScheduledTask -TaskName ExchangeServerDiscovery -TaskPath \ -Confirm:$False -ErrorAction Ignore
    $startInDirectory = $env:ExchangeInstallPath +"Scripts"
    $scriptFile = ".\Get-ExchangeServerDiscovery.ps1"
    $Sta = New-ScheduledTaskAction -Execute "Powershell.exe" -WorkingDirectory $startInDirectory  -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -Command `"& $scriptFile -HealthChecker:`$$HealthChecker`""
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    $Stt = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMilliseconds(5000)
    Register-ScheduledTask ExchangeServerDiscovery -Action $Sta -Principal $STPrin -Trigger $Stt
}
## Script block to initiate Exchange organization discovery
$ExchangeOrgDiscovery = {
    Unregister-ScheduledTask -TaskName ExchangeOrgDiscovery -TaskPath \ -Confirm:$False -ErrorAction Ignore
    $scriptFile = $env:ExchangeInstallPath +"Scripts\Get-ExchangeOrgDiscovery.ps1"
    $scriptFile = "`"$scriptFile`""
    $Sta = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -file $scriptFile"
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    $Stt = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMilliseconds(5000)
    Register-ScheduledTask ExchangeOrgDiscovery -Action $Sta -Principal $STPrin -Trigger $Stt
}
#endregion

#region CheckRunningOnExchange
$ComputerName = $env:COMPUTERNAME
$isExchangeServer = Check-RunningFromExchangeServer -ComputerName $ComputerName
#endregion

#region CheckPowerShell
if(!($isExchangeServer)) {
    Write-Verbose "Verifying PowerShell version."
    if(($PSVersionTable).PSVersion -like "4*") {
        Write-Verbose "PowerShell version 5.0 or higher is required to run this script."
        Write-Host; Write-Warning "The SfMC-Discovery.ps1 script must be executed using Windows PowerShell version 5.0 or higher"
        Write-Host; Start-Sleep -Seconds 2
        exit
    }
}
#endregion

#region Determine location of scripts
Write-Verbose "Checking for the location of the discovery scripts."
[boolean]$validPath = $false
while($validPath -eq $false) {
    if($ScriptPath -like $null) {[string]$scriptPath = (Get-Location).Path}
    else{
        if($ScriptPath.Substring($ScriptPath.Length-1,1) -eq "\") {$ScriptPath = $ScriptPath.Substring(0,$ScriptPath.Length-1)}
    }
    if(Test-Path -Path $ScriptPath) {$validPath = $true}
    else {
        Write-Warning "An invalid path to the scripts was provided. Please select the location."
        Start-Sleep -Seconds 1
        $ScriptPath = Get-FolderPath
    }
}
#endregion

#region Check and get HealthChecker
if($HealthChecker -and $ServerSettings) {
    if(Get-Item $ScriptPath\HealthChecker.ps1 -ErrorAction Ignore) {
        $HCPresent = $true
    } else {
    $HCPresent = $false
    }
    try { Invoke-WebRequest -Uri "https://github.com/microsoft/CSS-Exchange/releases/latest/download/HealthChecker.ps1" -OutFile "$ScriptPath\HealthChecker.ps1"
    }
    catch {
        if($HCPresent) {
            Write-Verbose "Unable to download the latest version of the HealthChecker script."
            Write-Host "Unable to download the latest version of the HealthChecker script."
        }
        else {
            Write-Verbose "Unable to download the HealthChecker script. Please download and save to the script path."
            Write-Warning "Unable to download the HealthChecker script. Please download and save to the script path."
            exit
        }
    }
}
#endregion

#region Determine the location for the results
Write-Verbose "Checking for the location for the output."
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
#Credentials only needed when not running from an Exchange server
if(!($isExchangeServer)) {
    Write-Verbose "Prompting for Exchange admin credentials."
    if($UserName -like $null) {
        $domain = $env:USERDNSDOMAIN
        $UserName = $env:USERNAME
        $UserName = "$UserName@$domain"
    }
    $validCreds = $false
    [int]$credAttempt = 0
    while($validCreds -eq $false) {
        Write-Host "Please enter the Exchange admin credentials using UPN format" -ForegroundColor Green
        Start-Sleep -Seconds 1
        $upnFound = $false
        while($upnFound -eq $false) {
            $creds = [System.Management.Automation.PSCredential](Get-Credential -UserName $UserName.ToLower() -Message "Exchange admin credentials using UPN")
            if($creds.UserName -like "*@*") {$upnFound = $True}
            else {
                Write-Warning "The username must be in UPN format. (ex. jimm@contoso.com)"
                Write-Verbose "Invalid username format provided."
            }
        }
        $validCreds =  Test-ADAuthentication
        if($validCreds -eq $false) {
            Write-Warning "Unable to validate your credentials. Please try again."
            Write-Verbose "Unable to validate credentials."
            $credAttempt++
        }
        if($credAttempt -eq 3) {
            Write-Warning "Too many credential failures. Exiting script."
            Write-Verbose "Too many credential failures."
            exit
        }
    }
}
#endregion

## Set the idle time for the remote PowerShell session
$SessionOption = New-PSSessionOption -IdleTimeout 180000 -OperationTimeout 300000 -OutputBufferingMode Drop
## Create an array for the list of Exchange servers
$ServerList = New-Object System.Collections.ArrayList
## Set a timer for the data collection process
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()

#region ConnectExchangePowerShell
$isConnected = $false
try{ 
    Get-ExchangeServer $ExchangeServer -ErrorAction Ignore | Out-Null
    $isConnected = $true
}
catch {
    Write-Verbose "Exchange PowerShell session was not found."
}
[int]$retryAttempt = 0
Write-Verbose "Attempting to connect to Exchange remote PowerShell to get a list of servers for data collection."
while($isConnected -eq $false) {
    $Error.Clear()
    $params = @{
        ConfigurationName = "Microsoft.Exchange"
        ConnectionUri = "http://$ExchangeServer/Powershell"
        AllowRedirection = $null
        Authentication = "Kerberos"
        ErrorAction = "Ignore"
        SessionOption = $SessionOption
        WarningAction = "Ignore"
        Name = "SfMC"
    }
    if(!($isExchangeServer)) { $params.Add("Credential", $creds) }
    try {Import-PSSession (New-PSSession @params) -WarningAction Ignore -DisableNameChecking -AllowClobber -ErrorAction Stop | Out-Null}
    catch {
        Write-Verbose "Unable to create a remote PowerShell session with $ExchangeServer."
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
            Write-Verbose "Unable to connect to Exchange remote PowerShell."
            exit
        }
    }
    else{$isConnected = $true}
}
#endregion

#region GetExchangeServerList
## Connect to the Exchange server to get a list of servers for data collection
#Check if running against a single server
if($ServerName -notlike $null) {
    Write-Verbose "Verifying $ServerName is a valid Exchange server."
    $CheckServer = Get-ExchangeServer -Identity $ServerName -ErrorAction Ignore | select Fqdn, Name, DistinguishedName, OriginatingServer
    if($CheckServer -notlike $null) {
        $ServerList.Add($CheckServer) | Out-Null
        Write-Verbose "Data collection will only run against $ServerName."
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
        Get-DatabaseAvailabilityGroup $DagName -ErrorAction Ignore | Select -ExpandProperty Servers | ForEach-Object { $ServerList.Add((Get-ExchangeServer $_ | select Fqdn, Name, DistinguishedName, OriginatingServer)) | Out-Null}
        if($ServerList.Count -eq 0){
            Write-Verbose "Unable to find a database availability group with the name $DagName."
            Write-Warning "Unable to find a database availability group with the name $DagName. Exiting script"
            Start-Cleanup
            exit
        }
        else {
            Write-Verbose "Data collection will only run against the database availability group named $DagName."
        }
    }
    #check if running against an AD site
    else {
        if($ADSite -notlike $null) {
            Write-Verbose "Checking for Exchange servers in the AD site named $ADSite."
            Get-ExchangeServer | Where {$_.Site -like "*$ADSite*" -and $_.ServerRole -ne "Edge"} | select Fqdn, Name, DistinguishedName, OriginatingServer | ForEach-Object { $ServerList.Add($_) | Out-Null}
            if($ServerList.Count -eq 0){
                Write-Verbose "Unable to find any Exchange servers is the $ADSite site."
                Write-Warning "Unable to find any Exchange servers is the $ADSite site. Exiting script"
                Start-Cleanup
                exit
            }
            else {
                Write-Verbose "Data collection will only run against Exchange servers in the $ADSite Active Directory site."
            }
        }
        #otherwise run against all servers
        else {
            Write-Verbose "Data collection will run against all Exchange servers in the organization."
            Get-ExchangeServer | Where { $_.ServerRole -ne "Edge"} | select Fqdn, Name, DistinguishedName, OriginatingServer | ForEach-Object { $ServerList.Add($_) | Out-Null }
        }
    }
}
#endregion

Write-Host -ForegroundColor Cyan "Collecting data now, please be patient. This will take some time to complete!"

#region GetExchOrgSettings
## Collect Exchange organization settings
if($OrgSettings) {
    Write-Host -ForegroundColor Cyan "Starting data collection for Exchange organization settings..."
    ## Copy the discovery script to the Exchange server
    if($isExchangeServer) {
        Copy-Item "$ScriptPath\Get-ExchangeOrgDiscovery.ps1" -Destination "$env:ExchangeInstallPath\Scripts" -Force
        Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeOrgDiscovery.ps1" -Confirm:$false
        Invoke-ScriptBlockHandler -ScriptBlock $ExchangeOrgDiscovery -ComputerName $ComputerName | Out-Null
    }
    else {
        $s = Get-ExchangeServer $ExchangeServer
        $Filter = "(&(name=$($s.Name))(ObjectClass=msExchExchangeServer))"
        [string]$RootOU = $s.DistinguishedName
        $Searcher = New-Object DirectoryServices.DirectorySearcher
        $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($RootOU)")
        $Searcher.Filter = $Filter
        $Searcher.SearchScope = "Base"
        $SearcherResult = ($Searcher.FindAll()).Properties.msexchinstallpath
        [string]$exchInstallPath = $null
            if(($SearcherResult | Get-Member | select -First 1 TypeName).TypeName -notlike "*String*") {
                $SearcherResult| ForEach-Object { [string]$exchInstallPath = $exchInstallPath+[System.Text.Encoding]::ASCII.GetString($_) }
            }
            else {$exchInstallPath = $SearcherResult}
        $orgResultPath = $exchInstallPath
        $OrgSession = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name SfMCOrgDiscovery -SessionOption $SessionOption
        Copy-Item "$ScriptPath\Get-ExchangeOrgDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $OrgSession -ErrorAction Ignore
        ## Initiate the data collection on the Exchange server
        Write-Verbose "Starting data collection for Exchange organization settings."
        Invoke-ScriptBlockHandler -ScriptBlock $ExchangeOrgDiscovery -ComputerName $ExchangeServer -Credential $creds | Out-Null #-ArgumentList $creds 
        Write-Verbose "Unblocking the PowerShell script."
        Invoke-ScriptBlockHandler -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeOrgDiscovery.ps1" -Confirm:$false} -Credential $creds -ComputerName $ExchangeServer # -Session $OrgSession
        Remove-PSSession -Name SfMCOrgDiscovery -ErrorAction Ignore
    }
}       
#endregion

#region GetExchServerSettings
$ServerSettingsTimer = New-Object -TypeName System.Diagnostics.Stopwatch
$ServerSettingsTimer.Start()
if($ServerSettings) {
    Write-Host "Starting data collection on the Exchange servers..." -ForegroundColor Cyan
    $sAttempted = 0
    ## Collect server specific data from all the servers
    foreach ($s in $ServerList) {
        ## Get the Exchange install path for this server
        $exchInstallPath = $null
        $PercentComplete = (($sAttempted/$ServerList.Count)*100)
        $PercentComplete = [math]::Round($PercentComplete)
        Write-Progress -Activity "Exchange Discovery Assessment" -Status "Starting data collection on $($s.Name).....$PercentComplete% complete" -PercentComplete $PercentComplete
        if(Test-Connection -ComputerName $s.Fqdn -Count 2 -ErrorAction Ignore) {
            Write-Verbose "Getting Exchange install path for $($s.Name)."
            #$s = Get-ExchangeServer $s.DistinguishedName
            $Filter = "(&(name=$($s.Name))(ObjectClass=msExchExchangeServer))"
            [string]$RootOU = $s.DistinguishedName
            $Searcher = New-Object DirectoryServices.DirectorySearcher
            $Searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($RootOU)")
            $Searcher.Filter = $Filter
            $Searcher.SearchScope = "Base"
            $SearcherResult = ($Searcher.FindAll()).Properties.msexchinstallpath
            [string]$exchInstallPath = $null
            if(($SearcherResult | Get-Member | select -First 1 TypeName).TypeName -notlike "*String*") {
                $SearcherResult| ForEach-Object { [string]$exchInstallPath = $exchInstallPath+[System.Text.Encoding]::ASCII.GetString($_) }
            }
            else {$exchInstallPath = $SearcherResult}
            #$exchInstallPath = (Get-ADObject -Filter "name -eq '$($s.Name)' -and ObjectClass -eq 'msExchExchangeServer'" -SearchBase $s.DistinguishedName -Properties msExchInstallPath -Server $s.OriginatingServer).msExchInstallPath
            ## Create an array to store paths for data retrieval
            if($exchInstallPath -notlike $null) {
                New-Object -TypeName PSCustomObject -Property @{
                    ServerName = $s.Fqdn
                    ExchInstallPath = $exchInstallPath
                } | Export-Csv -Path $OutputPath\ExchInstallPaths.csv -NoTypeInformation -Append
                ## Copy the discovery script to the Exchange server
                if($isExchangeServer) {
                    $exchInstallPath = $exchInstallPath.Replace(":","$")
                    $exchInstallPath = "\\$($s.Fqdn)\$exchInstallPath"
                    try {
                        Copy-Item "$ScriptPath\Get-ExchangeServerDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ErrorAction Ignore
                    }
                    catch {
                        Write-Verbose "Failed to copy Get-ExchangeServerDiscovery script to $s"
                    }
                    if($HealthChecker) { 
                        try {
                            Copy-Item "$ScriptPath\HealthChecker.ps1" -Destination "$exchInstallPath\Scripts" -Force -ErrorAction Ignore
                        }
                        catch {
                            Write-Verbose "Failed to copy HealthChecker script to $s"
                        }
                    }
                }
                else {
                    $ServerSession = New-PSSession -ComputerName $s.fqdn -Credential $creds -Name SfMCSrvDis -SessionOption $SessionOption -ErrorAction Ignore
                    if($ServerSession) {
                        try {
                            Copy-Item "$ScriptPath\Get-ExchangeServerDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $ServerSession -ErrorAction Ignore
                        }
                        catch {
                            Write-Verbose "Failed to copy Get-ExchangeServerDiscovery to $s"
                        }
                        if($HealthChecker) { Copy-Item "$ScriptPath\HealthChecker.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $ServerSession } #-ErrorAction Ignore }
                        Remove-PSSession -Name SfMCSrvDis -ErrorAction Ignore
                    }
                    else {
                        Out-File $OutputPath\FailedServers.txt -InputObject "Unable to establish session on $s" -Append
                    }
                }
                ## Initiate the data collection on the Exchange server
                Write-Verbose "Starting data collection on the Exchange server $($s.Name)."
                Invoke-ScriptBlockHandler -ScriptBlock $ExchangeServerDiscovery -ComputerName $s.Fqdn -ArgumentList $HealthChecker -Credential $creds -IsExchangeServer $isExchangeServer | Out-Null
                Write-Verbose "Unblocking the script file on server $($s.Name)."
                Invoke-ScriptBlockHandler -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeServerDiscovery.ps1" -Confirm:$false} -Credential $creds -ComputerName $s.fqdn -IsExchangeServer $isExchangeServer
                        
            }
            else {
                Out-File $OutputPath\FailedServers.txt -InputObject "Unable to determine the Exchange install path on $s" -Append
                Write-Verbose "Failed to determine the Exchange install path for $s."
            }
        }
        else {Out-File $OutputPath\FailedServers.txt -InputObject "Unable to connect to $s" -Append}
        $sAttempted++
    }
    Write-Verbose "Exchange server data collection started."
}
#endregion

#region PauseForDataCollection
## Wait 5 minutes from the start of script before attempting to retrieve the data
$ServerSettingsTimer.Stop()
$ServerRunTime = $ServerSettingsTimer.Elapsed.TotalSeconds
if($ServerRunTime -lt 300) {
    $TimeToWait = 300 - $ServerRunTime
    if($TimeToWait -gt 1) {
        $TimeRemaining = [math]::Round($TimeToWait)
        Write-Verbose "Waiting $TimeRemaining before attempting data retrieval."
        while($TimeRemaining -gt 0) {
            Write-Progress -Activity "Exchange Discovery Assessment" -Status "Waiting for data collection to complete before attempting to retrive data... $TimeRemaining seconds remaining" -PercentComplete ((($TimeToWait-$TimeRemaining)/$TimeToWait)*100)
            Start-Sleep -Seconds 1
            $TimeRemaining = $TimeRemaining - 1
        }
    }
}
#endregion

#region CollectOrgResults
if($OrgSettings) {
    [int]$OrgResultsAttempt = 0
    [bool]$OrgResultsFound = $false
    Write-Host "Attempting to retrieve Exchange organization settings..." -ForegroundColor Cyan -NoNewline
    while($OrgResultsAttempt -lt 4 -and $OrgResultsFound -eq $false) {
        $OrgResultsAttempt++
        $sourcePath = $orgResultPath+"Logging\SfMC Discovery"
        if($isExchangeServer) {
             if(Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip" -ErrorAction Ignore) {
                Write-Verbose "Attempting to copy Exchange org results to output location."
                Copy-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip" -Destination $OutputPath -Force -ErrorAction Ignore
                Write-Verbose "Results found for Exchange organization settings."
                Write-Host "FOUND" -ForegroundColor White
                $OrgResultsFound = $true
             }
        }
        else {
            $Session = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name OrgResults -SessionOption $SessionOption
            Write-Verbose "Attempting to located Exchange organization results."
            $orgResult = Invoke-ScriptBlockHandler -ScriptBlock {$orgFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip").FullName; return $orgFile} -ComputerName $ExchangeServer -Credential $creds
        
            if($orgResult -notlike $null ) {
                Write-Verbose "Attempting to copy Exchange org results to output location."
                Copy-Item $orgResult -Destination $OutputPath -Force -FromSession $Session -ErrorAction Ignore
                Write-Verbose "Verifying Exchange org results were received."
                if(Get-Item $OutputPath\*OrgSettings* -ErrorAction Ignore) { 
                    Write-Host "FOUND" -ForegroundColor White
                    Write-Verbose "Results found for Exchange organization settings."
                    $OrgResultsFound = $true
                    Write-Verbose "Removing scheduled task for Exchange org discovery."
                    Invoke-ScriptBlockHandler -ScriptBlock {Unregister-ScheduledTask -TaskName ExchangeOrgDiscovery -Confirm:$False} -ComputerName $ExchangeServer -Credential $creds
                    Remove-PSSession -Name OrgResults -ErrorAction Ignore -Confirm:$False
                }                
                else {
                    Write-Verbose "Copy of Exchange organization results failed."
                }
            }
        }
        if($OrgResultsFound -eq $false) {
            Write-Verbose "Results for the Exchange organization discovery were not found."
            Write-Host "NOT FOUND" -ForegroundColor Red
            ## Wait x minutes before attempting to retrieve the data
            $TimeToWait = 120
            $TimeRemaining = $TimeToWait
            Write-Verbose "Waiting two minutes before attempting to retrieve Exchange organization results."
            while($TimeRemaining -gt 0) {
                Write-Progress -Activity "Exchange Discovery Assessment" -Status "Waiting for data collection to complete before attempting to retrive data... $TimeRemaining seconds remaining" -PercentComplete ((($TimeToWait-$TimeRemaining)/$TimeToWait)*100)
                Start-Sleep -Seconds 1
                $TimeRemaining = $TimeRemaining - 1
            }
        }
    }
}
#endregion

#region CollectServerResults
[int]$ServerResultsAttempt = 0
[bool]$ServerResultsFound = $false
## Create an array to track remaining servers to pull results
[System.Collections.ArrayList]$NotFoundList = @()
if($ServerSettings){
    ## Get list of servers and install paths to retrieve data
    [System.Collections.ArrayList]$ExchangeServers = Import-Csv $OutputPath\ExchInstallPaths.csv
    [int]$serverCount = $ExchangeServers.Count
    [int]$totalServerCount = $serverCount
    [int]$foundCount = 0
    ## Attempt to retrieve the data multiple times
    while($ServerResultsAttempt -lt 4 -and $ServerResultsFound -eq $false) {
        $ServersNotFound = New-Object System.Collections.ArrayList

        ## Check for results and retrieve if missing
        [int]$sAttempted = 0
        Write-Verbose "Attempting to retrieve Exchange server setting results."
        Write-Host "Attempting to retrieve Exchange server settings..." -ForegroundColor Cyan -NoNewline
        foreach($s in $ExchangeServers) {
                $CustomObject = New-Object -TypeName psobject
            $serverName = $s.ServerName
            $NetBIOSName= $ServerName.Substring(0, $ServerName.IndexOf("."))
            ## Check if server results have been received
            $PercentComplete = (($sAttempted/$ExchangeServers.Count)*100)
            $PercentComplete = [math]::Round($PercentComplete)
            Write-Progress -Activity "Exchange Discovery Assessment" -Status "Retrieving data from $serverName.....$PercentComplete% complete" -PercentComplete $PercentComplete
            if(!(Get-Item $OutputPath\$serverName* -ErrorAction Ignore)) { 
                ## Attempt to copy results from Exchange server
                $params = @{
                    Destination = $OutputPath
                    Force = $null
                    ErrorAction = 'Ignore'
                }
                if(!($isExchangeServer)) {
                    $Session = New-PSSession -ComputerName $serverName -Credential $creds -Name ServerResults -SessionOption $SessionOption
                    $params.Add("FromSession",$Session) | Out-Null
                }
                Write-Verbose "Attempting to retrieve results from $($serverName)."
                $serverResult = Invoke-ScriptBlockHandler -ScriptBlock {$serverFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\$env:COMPUTERNAME*.zip").FullName; return $serverFile} -ComputerName $serverName -Credential $creds -IsExchangeServer $isExchangeServer
                if($serverResult -notlike $null) {
                    Write-Verbose "Attempting to copy results from $ServerName."
                    if($isExchangeServer) {
                        $serverResult = $serverResult.Replace(":","$")
                        $serverResult = "\\$serverName\$serverResult"
                    }
                    $params.Add("Path",$serverResult) | Out-Null
                    Copy-Item @params
                    ## Check if the results were found
                    if(Get-Item $OutputPath\$NetBIOSName* -ErrorAction Ignore) {
                        Write-Verbose "Results from $ServerName were received."
                        $foundCount++
                        Write-Verbose "Attempting to remove scheduled task from $($serverName)."
                        Invoke-ScriptBlockHandler -ScriptBlock {Unregister-ScheduledTask -TaskName ExchangeServerDiscovery -Confirm:$False} -ComputerName $serverName -Credential $creds -IsExchangeServer $isExchangeServer
                        Remove-PSSession -Name ServerResults -ErrorAction Ignore -Confirm:$False
                    }
                    else {
                        Write-Verbose "Failed to copy results from $ServerName."
                        $CustomObject | Add-Member -MemberType NoteProperty -Name "ServerName" -Value $s.ServerName -Force
                        $CustomObject | Add-Member -MemberType NoteProperty -Name "ExchInstallPath" -Value $s.ExchInstallPath -Force
                        $ServersNotFound.Add($CustomObject) | Out-Null
                    }
                }
                ## Add server to array to check again
                else {
                    Write-Verbose "Results from $ServerName were not found. Adding to retry list."
                    $CustomObject | Add-Member -MemberType NoteProperty -Name "ServerName" -Value $s.ServerName -Force
                    $CustomObject | Add-Member -MemberType NoteProperty -Name "ExchInstallPath" -Value $s.ExchInstallPath -Force
                    $ServersNotFound.Add($CustomObject) | Out-Null
                }
            }
            $sAttempted++
        }
        if($foundCount -eq $totalServerCount) { 
            Write-Verbose "All results retrieved for Exchange server discovery."
            Write-Host "FOUND";
            $ServerResultsFound = $true
        }
        else{
            if($foundCount -gt 0) {
                Write-Verbose "Not all results were retrieved for Exchange server discovery."
                Write-Host "$foundCount of $totalServerCount FOUND" -ForegroundColor Yellow
            }
            else {
                Write-Verbose "No Exchange server settings results were found."
                Write-Host "NOT FOUND" -ForegroundColor Red
            }
            ## Wait x minutes before attempting to retrieve the data
            $TimeToWait = 120
            $TimeRemaining = [math]::Round($TimeToWait)
            Write-Verbose "Waiting two minutes before attempting to retrieve results again."
            while($TimeRemaining -gt 0) {
                Write-Progress -Activity "Exchange Discovery Assessment" -Status "Waiting for data collection to complete before attempting to retrive data... $TimeRemaining seconds remaining" -PercentComplete ((($TimeToWait-$TimeRemaining)/$TimeToWait)*100)
                Start-Sleep -Seconds 1
                $TimeRemaining = $TimeRemaining - 1
            }
        }
        $ExchangeServers = New-Object System.Collections.ArrayList
        $ServersNotFound | ForEach-Object { $ExchangeServers.Add($_) | Out-Null }
        $serverCount = $ExchangeServers.Count
        $ServerResultsAttempt++
    }
}
foreach($s in $ServersNotFound) {
    Out-File $OutputPath\FailedServers.txt -InputObject "Unable to retrieve data for $($s.ServerName)" -Append
}
#endregion
Write-Host " "
$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
$timeStamp = Get-Date -Format yyyyMMddHHmmss
Write-Verbose "Compressing results into zip file for upload."
if(($PSVersionTable).PSVersion -like "5*") {
    Compress-Archive -Path $OutputPath -DestinationPath "$OriginalPath\DiscoveryResults-$timeStamp.zip"
}
else {
    ## Zip up the data collection results
    Add-Type -AssemblyName System.IO.Compression.Filesystem 
    ## Attempt to zip the results
    $zipFolder = "$OriginalPath\DiscoveryResults-$timeStamp.zip"
    try {[System.IO.Compression.ZipFile]::CreateFromDirectory($OutputPath, $zipFolder)}
    catch {
        $zipFile = [System.IO.Compression.ZipFile]::Open($zipFolder, 'update')
        $compressionLevel = [System.IO.Compression.CompressionLevel]::Fastest
        Get-ChildItem -Path $outputPath | Select FullName | ForEach-Object {
            try{[System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zipFile, $_.FullName, (Split-Path $_.FullName -Leaf), $compressionLevel) | Out-Null }
            catch {Write-Warning "failed to add"}
        }
        $zipFile.Dispose()
    }
}

Write-host " "
Write-host -ForegroundColor Cyan  "==================================================="
Write-Host -ForegroundColor Cyan " SfMC Email Discovery data collection has finished!"
Write-Host -ForegroundColor Cyan "          Total collection time: $($totalTime) seconds"
Write-Host -ForegroundColor Cyan "    Please upload results to SfMC. - Thank you!!!"
Write-host -ForegroundColor Cyan "==================================================="
Write-host " "
Start-Cleanup

# SIG # Begin signature block
# MIInwQYJKoZIhvcNAQcCoIInsjCCJ64CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBVS4VGKVWASXEv
# wWR7zkggQ/8dFhJ1vWjD35fe4z2YgKCCDXYwggX0MIID3KADAgECAhMzAAACy7d1
# OfsCcUI2AAAAAALLMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NTU5WhcNMjMwNTExMjA0NTU5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC3sN0WcdGpGXPZIb5iNfFB0xZ8rnJvYnxD6Uf2BHXglpbTEfoe+mO//oLWkRxA
# wppditsSVOD0oglKbtnh9Wp2DARLcxbGaW4YanOWSB1LyLRpHnnQ5POlh2U5trg4
# 3gQjvlNZlQB3lL+zrPtbNvMA7E0Wkmo+Z6YFnsf7aek+KGzaGboAeFO4uKZjQXY5
# RmMzE70Bwaz7hvA05jDURdRKH0i/1yK96TDuP7JyRFLOvA3UXNWz00R9w7ppMDcN
# lXtrmbPigv3xE9FfpfmJRtiOZQKd73K72Wujmj6/Su3+DBTpOq7NgdntW2lJfX3X
# a6oe4F9Pk9xRhkwHsk7Ju9E/AgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUrg/nt/gj+BBLd1jZWYhok7v5/w4w
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ3MDUyODAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAJL5t6pVjIRlQ8j4dAFJ
# ZnMke3rRHeQDOPFxswM47HRvgQa2E1jea2aYiMk1WmdqWnYw1bal4IzRlSVf4czf
# zx2vjOIOiaGllW2ByHkfKApngOzJmAQ8F15xSHPRvNMmvpC3PFLvKMf3y5SyPJxh
# 922TTq0q5epJv1SgZDWlUlHL/Ex1nX8kzBRhHvc6D6F5la+oAO4A3o/ZC05OOgm4
# EJxZP9MqUi5iid2dw4Jg/HvtDpCcLj1GLIhCDaebKegajCJlMhhxnDXrGFLJfX8j
# 7k7LUvrZDsQniJZ3D66K+3SZTLhvwK7dMGVFuUUJUfDifrlCTjKG9mxsPDllfyck
# 4zGnRZv8Jw9RgE1zAghnU14L0vVUNOzi/4bE7wIsiRyIcCcVoXRneBA3n/frLXvd
# jDsbb2lpGu78+s1zbO5N0bhHWq4j5WMutrspBxEhqG2PSBjC5Ypi+jhtfu3+x76N
# mBvsyKuxx9+Hm/ALnlzKxr4KyMR3/z4IRMzA1QyppNk65Ui+jB14g+w4vole33M1
# pVqVckrmSebUkmjnCshCiH12IFgHZF7gRwE4YZrJ7QjxZeoZqHaKsQLRMp653beB
# fHfeva9zJPhBSdVcCW7x9q0c2HVPLJHX9YCUU714I+qtLpDGrdbZxD9mikPqL/To
# /1lDZ0ch8FtePhME7houuoPcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCGaEwghmdAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAALLt3U5+wJxQjYAAAAAAsswDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEICEFZbJ8r+rzXXMaIR2xiXt2
# I3NG845I9kTt0ZtqlhhaMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAkwx6jO1dOTQz1O9rkgGDFhKBA1wiNnUgOAVViyC3GsWdG6nrTfUn2
# wvI/MOzOa1tb13bxToxv9tzJ74LivgSWBwmilZtyQ+H1PgtvrppY19W+/2bQkA4U
# sfDSYCSHhkCvmyS6gFJpvACDkn02s95AJyibuq4IslHgXk7Aidf21e/2VBYpcJzq
# Ilj4l+3PkQ9CC1GA6uLa488RkLDBo/jRYmKePuALXbtexLUL4a5lKTuR4rqTCMlO
# zvb3Fpvk5nWwUkSlNWozz9Hbs7nHMKlZTqgDapUBRfEKrELNFBnMFQCYxOA05Kb7
# wOnlvQBoBalEsdQVX2Rq5eRWZy9GWJJsoYIXKTCCFyUGCisGAQQBgjcDAwExghcV
# MIIXEQYJKoZIhvcNAQcCoIIXAjCCFv4CAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIHLjHsNp/oZWy/2DIhK1ih84ZzwHco//3h0g0AqI+Fh5AgZjdM2+
# b8cYEzIwMjIxMTE4MjA1MDA1LjcxOVowBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046MkFENC00QjkyLUZBMDExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF4MIIHJzCCBQ+gAwIBAgITMwAAAbHKkEPuC/ADqwABAAABsTAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIxNTlaFw0yMzEyMTQyMDIxNTlaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjJBRDQt
# NEI5Mi1GQTAxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAhqKrPtXsG8fsg4w8R4Mz
# ZTAKkzwvEBQ94ntS+72rRGIMF0GCyEL9IOt7f9gkGoamfbtrtdY4y+KIFR8w19/n
# U3EoWhJfrYamrfpgtFmTaE3XCKCsI7rnrPmlVOMmndDyN1gAlfeu4l5rdxx9ODEC
# BPdS/+w/jDT7JkBhrYllqVXcwGAgWLdXAoUDgKVByv5XhKkbOrPx9qppuZjKm4nf
# lmfwb/bTWkA3aMMQ67tBoMLSsbIN3BJNWZdwczjoQVXo3YXr2fB+PYNmHviCcDUM
# Hs0Vxmf7i/WSpBafsDMEn6WY7G8qtRGVX+7X0zDVg/7NVDLMqfn/iv++5hJGP+2F
# mv4WZkBS1MBpwvOi4EQ25pIG45jWTffR4ynyed1I1SxSOP+efuBx0WrN1A250lv5
# fGZHCL0vCMDT/w+U6wpNnxfDoQRY9Ut82iNK5alkxNozPP/DNI+nknTaSliaR2Xn
# SXDIZEs7lfuJYg0qahfJJ1CZF2IYxOS9FK1crEigSb8QnEJoj6ThLf4FYpYLTsRX
# lPdQbvBsVvgt++BttooznwfK0DKMOc718SLS+unwkVO0aF23CEQSStoy0ZW34K+c
# bRmUfia+k9E+4luoTnT17oKqYfDNO5Rk8UwVa8mfh8+/R3fZaz2O/ZhiYT/RZHV9
# Quz5PHGlaCfXPQ8A6zFJlE8CAwEAAaOCAUkwggFFMB0GA1UdDgQWBBT0m2eR7w2t
# hIr18WehUTSmvQ45kzAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEA2Oc3kmql5VKE
# itAhoBCc1U6/VwMSYKQPqhC59f00Y5fbwnD+B2Qa0wnJqADSVVu6bBCVrks+EGbk
# uMhRb/lpiHNKVnuXF4PKTDnvCnYCqgwAmbttdxe0m38fJpGU3fmECEFX4OYacEhF
# wTkLZtIUVjdqwPnQpRII+YqX/Q0Vp096g2puPllSdrxUB8xIOx3F7LGOzyv/1Wmr
# LyWAhUGpGte0W3qfX4YWkn7YCM+yl887tj5j+jO/l1MRi6bl4MsN0PW2FCYeRbyz
# QEENsg5Pd351Z08ROR/nR8z+cAuQwR29ijaDKIms5IbRr1nZL/qZskFSuCuSA+nY
# eMuTJxHg2HCXrt6ECFbEkYoPaBGTzxPYopcuJEcChhNlWkduCRguykEsmz0LvtmS
# 7Fe68g4Zoh3sQkIE5VEwnKC3HwVemhK7eNYR1q7RYExfGFUDMQdO7tQpbcPD4oaB
# btFGWGu3nz1IryWs9K88zo8+eoQV/o9SxNU7Rs6TMqcLdM6C6LgmGVaWKKC0S2DV
# KU8zFx0y5z25h1ZJ7X/Zhaav1mtXVG6+lJIq8ktJgOU5/pomumdftgosxGjIp3NO
# Ry9fDUll+KQl4YmN9GzZxPYkhuI0QYriLmytBtUK+AK91hURVldVbUjP8sksr1ds
# iQwyOYQIkSxrTuhp0pw7h5329jphgEYwggdxMIIFWaADAgECAhMzAAAAFcXna54C
# m0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0yMTA5MzAxODIyMjVaFw0zMDA5MzAxODMy
# MjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51
# yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveVU3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY
# 6GB9alKDRLemjkZrBxTzxXb1hlDcwUTIcVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9
# cmmvHaus9ja+NSZk2pg7uhp7M62AW36MEBydUv626GIl3GoPz130/o5Tz9bshVZN
# 7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHINSi947SHJMPgyY9+tVSP3PoFVZhtaDua
# Rr3tpK56KTesy+uDRedGbsoy1cCGMFxPLOJiss254o2I5JasAUq7vnGpF1tnYN74
# kpEeHT39IM9zfUGaRnXNxF803RKJ1v2lIH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2
# K26oElHovwUDo9Fzpk03dJQcNIIP8BDyt0cY7afomXw/TNuvXsLz1dhzPUNOwTM5
# TI4CvEJoLhDqhFFG4tG9ahhaYQFzymeiXtcodgLiMxhy16cg8ML6EgrXY28MyTZk
# i1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9Q
# BXpsxREdcu+N+VLEhReTwDwV2xo3xwgVGD94q0W29R6HXtqPnhZyacaue7e3Pmri
# Lq0CAwEAAaOCAd0wggHZMBIGCSsGAQQBgjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUC
# BBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTuMB0GA1UdDgQWBBSfpxVdAF5iXYP05dJl
# pxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9y
# eS5odG0wEwYDVR0lBAwwCgYIKwYBBQUHAwgwGQYJKwYBBAGCNxQCBAweCgBTAHUA
# YgBDAEEwCwYDVR0PBAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU
# 1fZWy4/oolxiaNE9lJBb186aGMQwVgYDVR0fBE8wTTBLoEmgR4ZFaHR0cDovL2Ny
# bC5taWNyb3NvZnQuY29tL3BraS9jcmwvcHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIw
# MTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEBBE4wTDBKBggrBgEFBQcwAoY+aHR0cDov
# L3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0w
# Ni0yMy5jcnQwDQYJKoZIhvcNAQELBQADggIBAJ1VffwqreEsH2cBMSRb4Z5yS/yp
# b+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulm
# ZzpTTd2YurYeeNg2LpypglYAA7AFvonoaeC6Ce5732pvvinLbtg/SHUB2RjebYIM
# 9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRWqveVtihVJ9AkvUCgvxm2EhIRXT0n4ECW
# OKz3+SmJw7wXsFSFQrP8DJ6LGYnn8AtqgcKBGUIZUnWKNsIdw2FzLixre24/LAl4
# FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3Uw
# xTSwethQ/gpY3UA8x1RtnWN0SCyxTkctwRQEcb9k+SS+c23Kjgm9swFXSVRk2XPX
# fx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu+yFUa2pFEUep8beuyOiJXk+d0tBMdrVX
# VAmxaQFEfnyhYWxz/gq77EFmPWn9y8FBSX5+k77L+DvktxW/tM4+pTFRhLy/AsGC
# onsXHRWJjXD+57XQKBqJC4822rpM+Zv/Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU
# 5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEG
# ahC0HVUzWLOhcGbyoYIC1DCCAj0CAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjJBRDQtNEI5Mi1GQTAxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQDtZLG+pANsDu/LLr1OfTA/kEbHK6CBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA5yHvHTAiGA8yMDIyMTExODE5NDYzN1oYDzIwMjIxMTE5MTk0NjM3WjB0MDoG
# CisGAQQBhFkKBAExLDAqMAoCBQDnIe8dAgEAMAcCAQACAhMbMAcCAQACAhFPMAoC
# BQDnI0CdAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEA
# AgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEACGAuESCl8C9hSCFw
# uCmxkwqQMA864JWYtH7k0Tfme484ZKfAQ6L91Y/PXYPxQHkyI1dlWKWBP5CMR5ON
# Xz4liz2wt6g6mPN4P2dt6J4L5clbPG2EFw0/wn0vrrKv93ruZWQh/3HTihtHjfF8
# vlY91WpbapAUS+wS4LSRcr/jQJQxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbHKkEPuC/ADqwABAAABsTANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCA4yq2S4RfFL32Nh3VMb5m4KnjhWrGZuKhn3jtgwrbRQDCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EIIPtDYsUW9+p4OjL2Cm7fm3p1h6usM7RwxOU4iib
# NM9sMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGx
# ypBD7gvwA6sAAQAAAbEwIgQgURH8lTINxRNs6wKM4DuHbgnbd0VFGUKLqvTGMeeZ
# hXQwDQYJKoZIhvcNAQELBQAEggIAHRpiw3BipRMMRe4HK5AqW3RwrsgeZ14Cyz52
# 33U9G7cC7L5gE+Fba1zBKhMwQeB6sJgy0quhPxarnH3sGI+5pzgRmEZrsQBoeckb
# IJgpLTQC8eUMyUxwgSDKu/AAAfM03bxOSfoSuEZwOr1uik3LqiYZeDYbuB1OvA6+
# Lg21wseo2MQdHT1r7Ud2z3kV6lH5kFM8iJkOuvuGqLPeKnRR/O5D6bG+P4sHaely
# 2+p+Ho+Zk86OR2i9ABJoeJ3g/Z17s7GlTQ18QcTAEKjinI7NMhq7yuEpBjoBVVlt
# EYZ+IywXffm6J5gq4BwuFUTVUL3eGp5UsPvbQgE93MTKQpyRf8EHMLYc6aMZVHV3
# 5RSAWLmIr2hnpP3BsOXMzKWseE4JB4QfaMOWAN0HzZXAIId0aUI6LljVaaSsPbUd
# k047ttsku/MRhEcUelVGjys+ME+7b5KKW3iMCQLfj1pPuC4WFw0MZ0WfTlBrSJvb
# 0XHN8pIAGhvtBxt2bjXnj4kdXAofFRsZGz1Lmyp6V0Rfn4mR/Dane3YstX2YzQa5
# hemi9zdSKRHj24VZm4gqXJSWZIlH9PuRhlQey9OOVD3Cq46QzDXFNIhK0fHzfAIR
# ugYIY2fqWU66eIsh+Z2wtQr7mnZjba9u5SSD50C9/fjIYSVrc2FgQjlhyBcTLHcL
# yXaqUnI=
# SIG # End signature block
