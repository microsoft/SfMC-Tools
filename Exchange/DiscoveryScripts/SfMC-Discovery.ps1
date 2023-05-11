<#//***********************************************************************
//
// SfMC-Discovery.ps1
// Modified 10 May 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// .VERSION 20230510.1045
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
// 20230510.1045 - Bug fix for timespan
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
function Check-OrgCollectionStarted{
    Write-Verbose "Checking if Exchange organization data collection started on $($ExchangeServer)."
    $StartCheck = Invoke-ScriptBlockHandler -ScriptBlock {Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1125 -After (Get-Date -Date (Get-Date).AddMinutes(-2) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $ExchangeServer -Credential $creds
    if($StartCheck -notlike $null) {
        Write-Verbose "Exchange organization data collection has started on $($ExchangeServer)."
    }
    else {
        Write-Verbose "Exchange organization data collection failed to start on $($ExchangeServer)."
        Write-VerboseLog "Checking for Exchange organization scheduled task on $($ExchangeServer)."
        $OrgTask = Invoke-ScriptBlockHandler -ScriptBlock {Get-ScheduledTask ExchangeOrgDiscovery -ErrorAction Ignore -TaskPath \ } -ComputerName $ExchangeServer -Credential $creds
        if($OrgTask -like $null) {
            Write-Verbose "Failed to create scheduled task on $($ExchangeServer)."
        }
        else {
            Write-Verbose "Exchange organization scheduled task found on $($ExchangeServer)."
            Write-Verbose "Attempting to start the Exchange organization scheduled task on $($ExchangeServer)."
            Invoke-ScriptBlockHandler -ScriptBlock {Start-ScheduledTask ExchangeOrgDiscovery -TaskPath \ -ErrorAction Ignore } -ComputerName $ExchangeServer -Credential $creds
        }
    }        
}
function Check-ServerCollectionStarted{
    Write-Verbose "Checking if Exchange server data collection started on $($ExchangeServer)."
    $StartCheck = Invoke-ScriptBlockHandler -ScriptBlock {Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1031 -After (Get-Date -Date (Get-Date).AddMinutes(-2) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $s.Fqdn -Credential $creds
    if($StartCheck -notlike $null) {
        Write-VerboseLog "Exchange server data collection has started on $($s.Name)."
    }
    else {
        Write-VerboseLog "Exchange server data collection failed to start on $($s.Name)."
        Write-VerboseLog "Checking for Exchange server scheduled task on $($s.Name)."
        $ServerTask = Invoke-ScriptBlockHandler -ScriptBlock {Get-ScheduledTask ExchangeServerDiscovery -ErrorAction Ignore -TaskPath \ } -ComputerName $s.Fqdn -Credential $creds
        if($ServerTask -like $null) {
            Write-Verbose "Failed to create scheduled task on $($s.Name)."
        }
        else {
            Write-Verbose "Exchange server scheduled task found on $($s.Name)."
            Write-Verbose "Attempting to start the Exchange server scheduled task on $($s.Name)."
            Invoke-ScriptBlockHandler -ScriptBlock {Start-ScheduledTask ExchangeServerDiscovery -TaskPath \ -ErrorAction Ignore } -ComputerName $s.Fqdn -Credential $creds
        }
    }        
}

Add-Type -AssemblyName System.Windows.Forms
$Script:Logger = Get-NewLoggerInstance -LogName "SfMCDiscovery-$((Get-Date).ToString("yyyyMMddhhmmss"))-Debug" -AppendDateTimeToFileName $false -ErrorAction SilentlyContinue

#region SfMCBanner
Write-Host " "
Write-Host " "
Write-Host -ForegroundColor Cyan "=====================SfMC Discovery version 20230421.1909====================="
Write-Host " "
Write-Host -ForegroundColor Cyan "  "
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
    Register-ScheduledTask ExchangeServerDiscovery -Action $Sta -Principal $STPrin
    Start-ScheduledTask ExchangeServerDiscovery -ErrorAction Ignore
}
## Script block to initiate Exchange organization discovery
$ExchangeOrgDiscovery = {
    Unregister-ScheduledTask -TaskName ExchangeOrgDiscovery -TaskPath \ -Confirm:$False -ErrorAction Ignore
    $scriptFile = $env:ExchangeInstallPath +"Scripts\Get-ExchangeOrgDiscovery.ps1"
    $scriptFile = "`"$scriptFile`""
    $Sta = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-ExecutionPolicy Unrestricted -WindowStyle Hidden -file $scriptFile"
    $STPrin = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    Register-ScheduledTask ExchangeOrgDiscovery -Action $Sta -Principal $STPrin
    Start-ScheduledTask ExchangeOrgDiscovery -ErrorAction Ignore
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
    $OrgStartTime = Get-Date
    Write-Host -ForegroundColor Cyan "Starting data collection for Exchange organization settings..."
    ## Copy the discovery script to the Exchange server
    if($isExchangeServer) {
        Copy-Item "$ScriptPath\Get-ExchangeOrgDiscovery.ps1" -Destination "$env:ExchangeInstallPath\Scripts" -Force
        Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeOrgDiscovery.ps1" -Confirm:$false
        Invoke-ScriptBlockHandler -ScriptBlock $ExchangeOrgDiscovery -ComputerName $ComputerName | Out-Null
        Check-OrgCollectionStarted
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
        Write-Verbose "Found install path for $ExchangeServer`: $SearcherResult"
        $orgResultPath = $exchInstallPath
        $OrgSession = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name SfMCOrgDiscovery -SessionOption $SessionOption
        Copy-Item "$ScriptPath\Get-ExchangeOrgDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $OrgSession -ErrorAction Ignore
        ## Initiate the data collection on the Exchange server
        Write-Verbose "Unblocking the PowerShell script."
        Invoke-ScriptBlockHandler -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeOrgDiscovery.ps1" -Confirm:$false} -Credential $creds -ComputerName $ExchangeServer
        Write-Verbose "Starting data collection for Exchange organization settings."
        Invoke-ScriptBlockHandler -ScriptBlock $ExchangeOrgDiscovery -ComputerName $ExchangeServer -Credential $creds | Out-Null
        Check-OrgCollectionStarted
        Remove-PSSession -Name SfMCOrgDiscovery -ErrorAction Ignore
    }
}       
#endregion

#region GetExchServerSettings
$ServerSettingsTimer = New-Object -TypeName System.Diagnostics.Stopwatch
$ServerSettingsTimer.Start()
$ServerStart = Get-Date
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
            Write-Verbose "Found install path for $($s.Name)`: $SearcherResult"
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
                        Write-Verbose "Get-ExchangeServerDiscovery script successfully copied to $s"
                    }
                    catch {
                        Write-Verbose "Failed to copy Get-ExchangeServerDiscovery script to $s"
                    }
                    if($HealthChecker) { 
                        try {
                            Copy-Item "$ScriptPath\HealthChecker.ps1" -Destination "$exchInstallPath\Scripts" -Force -ErrorAction Ignore
                            Write-Verbose "HealthChecker script successfully copied to $s"
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
                            Write-Verbose "Get-ExchangeServerDiscovery script successfully copied to $s"
                            Write-Verbose "Unblocking the script file on server $($s.Name)."
                            Invoke-ScriptBlockHandler -ScriptBlock {Unblock-File -Path "$env:ExchangeInstallPath\Scripts\Get-ExchangeServerDiscovery.ps1" -Confirm:$false} -Credential $creds -ComputerName $s.fqdn -IsExchangeServer $isExchangeServer
                        }
                        catch {
                            Write-Verbose "Failed to copy Get-ExchangeServerDiscovery to $s"
                        }
                        if($HealthChecker) { 
                            Copy-Item "$ScriptPath\HealthChecker.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $ServerSession 
                            Write-Verbose "HealthChecker script successfully copied to $s"
                        }
                        Remove-PSSession -Name SfMCSrvDis -ErrorAction Ignore
                    }
                    else {
                        Out-File $OutputPath\FailedServers.txt -InputObject "Unable to establish session on $s" -Append
                    }
                }
                ## Initiate the data collection on the Exchange server
                Write-Verbose "Starting data collection on the Exchange server $($s.Name)."
                Invoke-ScriptBlockHandler -ScriptBlock $ExchangeServerDiscovery -ComputerName $s.Fqdn -ArgumentList $HealthChecker -Credential $creds -IsExchangeServer $isExchangeServer | Out-Null
                Check-ServerCollectionStarted
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

#region CollectOrgResults
if($OrgSettings) {
    [int]$OrgResultsAttempt = 0
    [bool]$OrgResultsFound = $false
    Write-Host "Attempting to retrieve Exchange organization settings..." -ForegroundColor Cyan -NoNewline
    while($OrgResultsAttempt -lt 4 -and $OrgResultsFound -eq $false) {
        $OrgResultsAttempt++
        $sourcePath = $orgResultPath+"Logging\SfMC Discovery"
        if($isExchangeServer) {
            #Check the event log to see if data collection completed
            Write-Verbose "Checking if Exchange organization script completed on $($ExchangeServer)."
            $EndTime = Get-Date
            $TimeSpanMinutes = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Minutes
            $TimeSpanHours = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Hours
            $TimeSpan = ($TimeSpanHours*60) + $TimeSpanMinutes
            $orgCompleted = Invoke-ScriptBlockHandler -ScriptBlock {param($NumberOfMinutes);Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1007 -After (Get-Date -Date (Get-Date).AddMinutes($NumberOfMinutes) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $ExchangeServer -Credential $creds -ArgumentList $TimeSpan -IsExchangeServer:$true
            if($orgCompleted -notlike $null) {
                Write-Verbose "Exchange organization script completed on $($ExchangeServer)."
                Write-Verbose "Checking for Exchange organization results on $($ExchangeServer)."
                if(Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip" -ErrorAction Ignore) {
                    Write-Verbose "Exchange organization results found on $($ExchangeServer)."
                    Write-Verbose "Attempting to copy Exchange org results to output location."
                    Copy-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip" -Destination $OutputPath -Force -ErrorAction Ignore
                    Write-Host "FOUND" -ForegroundColor White
                    $OrgResultsFound = $true
                }
                else{
                    Write-Verbose "Exchange organization results not found on $($ExchangeServer)."
                }
            }
            else {
                Write-Verbose "Exchange organization script has not completed on $($ExchangeServer)."
            }
        }
        else {
            #Check the event log to see if data collection completed
            Write-Verbose "Checking if Exchange organization script completed on $($ExchangeServer)."
            $EndTime = Get-Date
            $TimeSpanMinutes = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Minutes
            $TimeSpanHours = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Hours
            $TimeSpan = ($TimeSpanHours*60) + $TimeSpanMinutes
            #$TimeSpan = (New-TimeSpan -Start (Get-Date) -End $ServerStart).Minutes
            $orgCompleted = Invoke-ScriptBlockHandler -ScriptBlock {param($NumberOfMinutes);Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1007 -After (Get-Date -Date (Get-Date).AddMinutes($NumberOfMinutes) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $ExchangeServer -Credential $creds -ArgumentList $TimeSpan
            if($orgCompleted -notlike $null) {
                #Check for resulting zip file
                Write-Verbose "Exchange organization script completed on $($ExchangeServer)."
                Write-Verbose "Checking for Exchange organization results on $($ExchangeServer)."
                $orgResult = Invoke-ScriptBlockHandler -ScriptBlock {$orgFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\*OrgSettings*.zip").FullName; return $orgFile} -ComputerName $ExchangeServer -Credential $creds
                if($orgResult -notlike $null ) {
                    $Session = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name OrgResults -SessionOption $SessionOption
                    Write-Verbose "Attempting to copy Exchange organization results from $($ExchangeServer) to output location."
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
                else {
                    Write-Verbose "Exchange organization results were not found on $($ExchangeServer)."
                }
            }
            else {
                Write-Verbose "Exchange organization script did not complete on $($ExchangeServer)."
            }
        }
        if($OrgResultsFound -eq $false) {
            Write-Verbose "Results for the Exchange organization discovery were not found."
            Write-Host "NOT FOUND" -ForegroundColor Red
            Write-Host "Attempting to retrieve Exchange organization settings..." -ForegroundColor Cyan -NoNewline
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
                Write-Verbose "Checking if Exchange server discovery completed on $($serverName)."
                #Check the event log to see if data collection completed
                $EndTime = Get-Date
                $TimeSpanMinutes = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Minutes
                $TimeSpanHours = (New-TimeSpan -Start ($EndTime) -End $ServerStart).Hours
                $TimeSpan = ($TimeSpanHours*60) + $TimeSpanMinutes
                $serverCompleted = Invoke-ScriptBlockHandler -ScriptBlock {param($NumberOfMinutes);Get-EventLog -LogName Application -Source "MSExchange ADAccess" -InstanceId 1376 -After (Get-Date -Date (Get-Date).AddMinutes($NumberOfMinutes) -Format "M/d/yyyy HH:mm") -ErrorAction Ignore} -ComputerName $ServerName -Credential $creds -ArgumentList $TimeSpan
                if($serverCompleted -notlike $null) {
                    #Now look for the results zip file
                    $serverResult = Invoke-ScriptBlockHandler -ScriptBlock {$serverFile = (Get-Item "$env:ExchangeInstallPath\Logging\SfMC Discovery\$env:COMPUTERNAME*.zip").FullName; return $serverFile} -ComputerName $serverName -Credential $creds -IsExchangeServer $isExchangeServer
                    if($serverResult -notlike $null) {
                        Write-Verbose "Attempting to copy results from $ServerName."
                        if($isExchangeServer) {
                            $serverResult = $serverResult.Replace(":","$")
                            $serverResult = "\\$serverName\$serverResult"
                        }
                        $params.Add("Path",$serverResult) | Out-Null
                        Copy-Item @params
                        #Check if the results were downloaded
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
                    else {
                        Write-Verbose "Results not found on $ServerName."
                    }
                }
                ## Add server to array to check again
                else {
                    Write-Verbose "Script has not completed on $ServerName. Adding to retry list."
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
# MIInxAYJKoZIhvcNAQcCoIIntTCCJ7ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDYiYrf1byT+vNk
# syGJpAGaXujeZnPxFVZWnpV6atmSz6CCDXYwggX0MIID3KADAgECAhMzAAADTrU8
# esGEb+srAAAAAANOMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjMwMzE2MTg0MzI5WhcNMjQwMzE0MTg0MzI5WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDdCKiNI6IBFWuvJUmf6WdOJqZmIwYs5G7AJD5UbcL6tsC+EBPDbr36pFGo1bsU
# p53nRyFYnncoMg8FK0d8jLlw0lgexDDr7gicf2zOBFWqfv/nSLwzJFNP5W03DF/1
# 1oZ12rSFqGlm+O46cRjTDFBpMRCZZGddZlRBjivby0eI1VgTD1TvAdfBYQe82fhm
# WQkYR/lWmAK+vW/1+bO7jHaxXTNCxLIBW07F8PBjUcwFxxyfbe2mHB4h1L4U0Ofa
# +HX/aREQ7SqYZz59sXM2ySOfvYyIjnqSO80NGBaz5DvzIG88J0+BNhOu2jl6Dfcq
# jYQs1H/PMSQIK6E7lXDXSpXzAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUnMc7Zn/ukKBsBiWkwdNfsN5pdwAw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzUwMDUxNjAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBAD21v9pHoLdBSNlFAjmk
# mx4XxOZAPsVxxXbDyQv1+kGDe9XpgBnT1lXnx7JDpFMKBwAyIwdInmvhK9pGBa31
# TyeL3p7R2s0L8SABPPRJHAEk4NHpBXxHjm4TKjezAbSqqbgsy10Y7KApy+9UrKa2
# kGmsuASsk95PVm5vem7OmTs42vm0BJUU+JPQLg8Y/sdj3TtSfLYYZAaJwTAIgi7d
# hzn5hatLo7Dhz+4T+MrFd+6LUa2U3zr97QwzDthx+RP9/RZnur4inzSQsG5DCVIM
# pA1l2NWEA3KAca0tI2l6hQNYsaKL1kefdfHCrPxEry8onJjyGGv9YKoLv6AOO7Oh
# JEmbQlz/xksYG2N/JSOJ+QqYpGTEuYFYVWain7He6jgb41JbpOGKDdE/b+V2q/gX
# UgFe2gdwTpCDsvh8SMRoq1/BNXcr7iTAU38Vgr83iVtPYmFhZOVM0ULp/kKTVoir
# IpP2KCxT4OekOctt8grYnhJ16QMjmMv5o53hjNFXOxigkQWYzUO+6w50g0FAeFa8
# 5ugCCB6lXEk21FFB1FdIHpjSQf+LP/W2OV/HfhC3uTPgKbRtXo83TZYEudooyZ/A
# Vu08sibZ3MkGOJORLERNwKm2G7oqdOv4Qj8Z0JrGgMzj46NFKAxkLSpE5oHQYP1H
# tPx1lPfD7iNSbJsP6LiUHXH1MIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
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
# /Xmfwb1tbWrJUnMTDXpQzTGCGaQwghmgAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAANOtTx6wYRv6ysAAAAAA04wDQYJYIZIAWUDBAIB
# BQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGXdD2gOfizUCtiigCYlmrKN
# MjKZNfcFFOyi3exnJadYMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0B
# AQEFAASCAQAzHPYvLrOJYBt8C4BoIqpXcQPg4GSvnXKyNl3MKMGS74EgREPZM6L9
# pdW1eab0GZ2CJIsEr3KQn73cHzmb2oCS0XQICun3WjsZFRiX0n75VisOUbIT643x
# StQCtR/XlmR8vnvdbL3RunV32u6O+h6rmTnUFeOJ5y1xdNciHblSUJCNA713+lbw
# YO68XfJEjliNxZktgZ6DMEFLfjazqday6R/jIkGiUXv/Nx4+t9LH7XMSoO/ZDxZU
# givHI+K2J3gged2gVb4PAiPZrMpKiUNPDWlXt+4x1vuZQlmCvxFP75rJvcUOdQC5
# KlhJtfhznCOPZEaI6uyRIjiqCFl8ooIkoYIXLDCCFygGCisGAQQBgjcDAwExghcY
# MIIXFAYJKoZIhvcNAQcCoIIXBTCCFwECAQMxDzANBglghkgBZQMEAgEFADCCAVkG
# CyqGSIb3DQEJEAEEoIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZI
# AWUDBAIBBQAEIBrI8PN+2fi7rZTu+UcY6Ape4P4WbRa+TfWS+Nlu1+0yAgZkP9Rm
# 8YQYEzIwMjMwNTEwMTUwMDE0Ljg1M1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYT
# AlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYD
# VQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJ
# cmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBF
# U046M0JENC00QjgwLTY5QzMxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFNlcnZpY2WgghF7MIIHJzCCBQ+gAwIBAgITMwAAAbT7gAhEBdIt+gABAAABtDAN
# BgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0y
# MjA5MjAyMDIyMDlaFw0yMzEyMTQyMDIyMDlaMIHSMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBP
# cGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjNCRDQt
# NEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNl
# MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtEemnmUHMkIfvOiu27K8
# 6ZbwWhksGwV72Dl1uGdqr2pKm+mfzoT+Yngkq9aLEf+XDtADyA+2KIZU0iO8WG79
# eJjzz29flZpBKbKg8xl2P3O9drleuQw3TnNfNN4+QIgjMXpE3txPF7M7IRLKZMiO
# t3FfkFWVmiXJAA7E3OIwJgphg09th3Tvzp8MT8+HOtG3bdrRd/y2u8VrQsQTLZiV
# wTZ6qDYKNT8PQZl7xFrSSO3QzXa91LipZnYOl3siGJDCee1Ba7X1i13dQFHxKl5F
# f4JzDduOBZ85e2VrpyFy1a3ayGUzBrIw59jhMbjIw9YVcQt9kUWntyCmNk15WybC
# S+hXpEDDLVj1X5W9snmoW1qu03+unprQjWQaVuO7BfcvQdNVdyKSqAeKy1eT2Hcc
# 5n1aAVeXFm6sbVJmZzPQEQR3Jr7W8YcTjkqC5hT2qrYuIcYGOf3Pj4OqdXm1Qqhu
# wtskxviv7yy3Z+PxJpxKx+2e6zGRaoQmIlLfg/a42XNVHTf6Wzr5k7Q1w7v0uA/s
# FsgyKmI7HzKHX08xDDSmJooXA5btD6B0lx/Lqs6Qb4KthnA7N2IEdJ5sjMIhyHZw
# Br7fzDskU/+Sgp2UnfqrN1Vda/gb+pmlbJwi8MphvElYzjT7PZK2Dm4eorcjx7T2
# QVe3EIelLuGbxzybblZoRTkCAwEAAaOCAUkwggFFMB0GA1UdDgQWBBTLRIXl8ZS4
# Opy7Eii3Tt44zDLZfjAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBf
# BgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmww
# bAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsGAQUF
# BwMIMA4GA1UdDwEB/wQEAwIHgDANBgkqhkiG9w0BAQsFAAOCAgEAEtEPBYwpt4Ji
# oSq0joGzwqYX6SoNH7YbqpgArdlnrdt6u3ukKREluKEVqS2XajXxx0UkXGc4Xi9d
# p2bSxpuyQnTkq+IQwkg7p1dKrwAa2vdmaNzz3mrSaeUEu40yCThHwquQkweoG4eq
# RRZe19OtVSmDDNC3ZQ6Ig0qz79vivXgy5dFWk4npxA5LxSGR4wBaXaIuVhoEa06v
# d/9/2YsQ99bCiR7SxJRt1XrQ5kJGHUi0Fhgz158qvXgfmq7qNqfqfTSmsQRrtbe4
# Zv/X+qPo/l6ae+SrLkcjRfr0ONV0vFVuNKx6Cb90D5LgNpc9x8V/qIHEr+JXbWXW
# 6mARVVqNQCmXlVHjTBjhcXwSmadR1OotcN/sKp2EOM9JPYr86O9Y/JAZC9zug9ql
# jKTroZTfYA7LIdcmPr69u1FSD/6ivL6HRHZd/k2EL7FtZwzNcRRdFF/VgpkOxHIf
# qvjXambwoMoT+vtGTtqgoruhhSk0bM1F/pBpi/nPZtVNLGTNaK8Wt6kscbC9G6f0
# 9gz/wBBJOBmvTLPOOT/3taCGSoJoDABWnK+De5pie4KX8BxxKQbJvxz7vRsVJ5R6
# mGx+Bvav5AjsxvZZw6eQmkI0vPRckxL9TCVCfWS0uyIKmyo6TdosnbBO/osre7r0
# jS9AH8spEqVlhFcpQNfOg/CvdS2xNVMwggdxMIIFWaADAgECAhMzAAAAFcXna54C
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
# ahC0HVUzWLOhcGbyoYIC1zCCAkACAQEwggEAoYHYpIHVMIHSMQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJl
# bGFuZCBPcGVyYXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjNCRDQtNEI4MC02OUMzMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQBlnNiQ85uX9nN4KRJt/gHkJx4JCKCBgzCB
# gKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUA
# AgUA6AYAgDAiGA8yMDIzMDUxMDE5MzczNloYDzIwMjMwNTExMTkzNzM2WjB3MD0G
# CisGAQQBhFkKBAExLzAtMAoCBQDoBgCAAgEAMAoCAQACAg8yAgH/MAcCAQACAhU8
# MAoCBQDoB1IAAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAI
# AgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAVmrhJeu5F3jl
# i36h9I3s6XSfN6q5Nrcl3SDVhgxvtuouUx5d4LnYTHo5dg8ITm7YnOmxRD5THoGp
# plnPYw9RrJtA/vmGc5ahuBIFv1Ucn5EJUbN2JnU904QwR2Y4wi2LPrJl7600wQJn
# cBBrGE0hWoDluC7fT5bJcHOsDLQxCosxggQNMIIECQIBATCBkzB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAbT7gAhEBdIt+gABAAABtDANBglghkgB
# ZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3
# DQEJBDEiBCBVZYt34RCtlJj1paET9+8RCfCaEZv8Q5xamhRkf96huTCB+gYLKoZI
# hvcNAQkQAi8xgeowgecwgeQwgb0EINPI93vmozBwBlFxvfr/rElreFPR4ux7vXKx
# 2ni3AfcGMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAG0+4AIRAXSLfoAAQAAAbQwIgQgdID9UoKqlj5lZ7wGBx+EI7yy2WHrRv8KJ7Gt
# GU13+KwwDQYJKoZIhvcNAQELBQAEggIAUza97aYVWCYm5GqEcS/3Ire2nzV1vi1P
# 52w73NyHflAyobbNQuB5uzXpcjWwg44ODW5l4JauT4OMQWFrWuJalqianNJ8uHyb
# EWLMcUYGcDddHhcrND9iNV+dXTjy57IdUL4zhIC4Eh3LHzBmpcZXcednMDIIW3VR
# T4r7MuYqv6ZXrW9IG57BFHMBfg6iK8isC6FfX4js5Ry4o4nB625uTMsqldNTnvJg
# RVEoNKsE7s1WJfePSnyANHn8kyzfFgRQjsHe3rltsQJmV5ej6gUCh2rF2M2u2Hy0
# 1ZtaocIDCwU/lNTJqDmRCvEAnMkDa3iRG3aXJiR4dk6jNt/PFiGhs66EQFzPKJ0s
# ZR8jeM+5O/lD5QVw7YqMiYUCeE6oHXtVs131BQuoTr4FKNcvoo/xaMiBT0Ybbeei
# mX4wpKIXdR3PhnMvrnR2hCCYRuf5Ym3uZhSbbpOHSEef7LKqE1OcAb/HqN2tYAVl
# Y7U2UX0buvGwZt5lhYXErmZuTyepxc8ig3irTrieop6q5Jn6f5Ad94vUEKeTIq4F
# vST1WkHqdbC7T9+E0BNEFg/4QIA1WvRJwqtkww9vu/9XcmEwjvBEfJ7oeg6nR7II
# pAW906+K1XFOyDQtpETyB0KjbPpheh987c0WCQKgsiG7CrhS8Wm37b1VdWwJgKqa
# 2/7UZhJO60c=
# SIG # End signature block
