
<#//***********************************************************************
//
// SfMC-Discovery.ps1
// Modified 02 November 2022
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// .VERSION 20221102.0949
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
        $exchInstallPath = (Get-ADObject -Filter "name -eq '$($s.Name)' -and ObjectClass -eq 'msExchExchangeServer'" -SearchBase $s.DistinguishedName -Properties msExchInstallPath -Server $s.OriginatingServer).msExchInstallPath
        $orgResultPath = $exchInstallPath
        $OrgSession = New-PSSession -ComputerName $ExchangeServer -Credential $creds -Name SfMCOrgDiscovery -SessionOption $SessionOption
        Copy-Item "$ScriptPath\Get-ExchangeOrgDiscovery.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $OrgSession
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
            $exchInstallPath = (Get-ADObject -Filter "name -eq '$($s.Name)' -and ObjectClass -eq 'msExchExchangeServer'" -SearchBase $s.DistinguishedName -Properties msExchInstallPath -Server $s.OriginatingServer).msExchInstallPath
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
                            Copy-Item "$ScriptPath\HealthChecker.ps1" -Destination "$exchInstallPath\Scripts" -Force 
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
                        if($HealthChecker) { Copy-Item "$ScriptPath\HealthChecker.ps1" -Destination "$exchInstallPath\Scripts" -Force -ToSession $ServerSession }
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
        $CustomObject = New-Object -TypeName psobject
        ## Check for results and retrieve if missing
        [int]$sAttempted = 0
        Write-Verbose "Attempting to retrieve Exchange server setting results."
        Write-Host "Attempting to retrieve Exchange server settings..." -ForegroundColor Cyan -NoNewline
        foreach($s in $ExchangeServers) {
            $serverName = $s.ServerName#.Substring(0, $s.ServerName.IndexOf("."))
            $NetBIOSName= $ServerName.Substring(0, $ServerName.IndexOf("."))
            ## Check if server results have been received
            $PercentComplete = (($sAttempted/$ExchangeServers.Count)*100)
            $PercentComplete = [math]::Round($PercentComplete)
            Write-Progress -Activity "Exchange Discovery Assessment" -Status "Retrieving data from $serverName.....$PercentComplete% complete" -PercentComplete $PercentComplete # (($foundCount/$totalServerCount)*100)
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
                    Copy-Item @params #$serverResult -Destination $OutputPath -Force -FromSession $Session -ErrorAction Ignore 
                    ## Check if the results were found
                    if(Get-Item $OutputPath\$NetBIOSName* -ErrorAction Ignore) {
                        Write-Verbose "Results from $ServerName were received."
                        $foundCount++
                        Write-Verbose "Attempting to remove scheduled task from $($serverName)."
                        Invoke-ScriptBlockHandler -ScriptBlock {Unregister-ScheduledTask -TaskName ExchangeServerDiscovery -Confirm:$False} -ComputerName $serverName -Credential $creds -IsExchangeServer $isExchangeServer
                        Remove-PSSession -Name ServerResults -ErrorAction Ignore -Confirm:$False
                    }
                    else {Write-Verbose "Failed to copy results from $ServerName."}
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
        $ExchangeServers = $ServersNotFound
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
# MIInowYJKoZIhvcNAQcCoIInlDCCJ5ACAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDwbff3LpMZQC9E
# fq/4PuUTPtX7/9xLIdHHwsQ3eJ+TOaCCDYEwggX/MIID56ADAgECAhMzAAACzI61
# lqa90clOAAAAAALMMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjIwNTEyMjA0NjAxWhcNMjMwNTExMjA0NjAxWjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCiTbHs68bADvNud97NzcdP0zh0mRr4VpDv68KobjQFybVAuVgiINf9aG2zQtWK
# No6+2X2Ix65KGcBXuZyEi0oBUAAGnIe5O5q/Y0Ij0WwDyMWaVad2Te4r1Eic3HWH
# UfiiNjF0ETHKg3qa7DCyUqwsR9q5SaXuHlYCwM+m59Nl3jKnYnKLLfzhl13wImV9
# DF8N76ANkRyK6BYoc9I6hHF2MCTQYWbQ4fXgzKhgzj4zeabWgfu+ZJCiFLkogvc0
# RVb0x3DtyxMbl/3e45Eu+sn/x6EVwbJZVvtQYcmdGF1yAYht+JnNmWwAxL8MgHMz
# xEcoY1Q1JtstiY3+u3ulGMvhAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUiLhHjTKWzIqVIp+sM2rOHH11rfQw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDcwNTI5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAeA8D
# sOAHS53MTIHYu8bbXrO6yQtRD6JfyMWeXaLu3Nc8PDnFc1efYq/F3MGx/aiwNbcs
# J2MU7BKNWTP5JQVBA2GNIeR3mScXqnOsv1XqXPvZeISDVWLaBQzceItdIwgo6B13
# vxlkkSYMvB0Dr3Yw7/W9U4Wk5K/RDOnIGvmKqKi3AwyxlV1mpefy729FKaWT7edB
# d3I4+hldMY8sdfDPjWRtJzjMjXZs41OUOwtHccPazjjC7KndzvZHx/0VWL8n0NT/
# 404vftnXKifMZkS4p2sB3oK+6kCcsyWsgS/3eYGw1Fe4MOnin1RhgrW1rHPODJTG
# AUOmW4wc3Q6KKr2zve7sMDZe9tfylonPwhk971rX8qGw6LkrGFv31IJeJSe/aUbG
# dUDPkbrABbVvPElgoj5eP3REqx5jdfkQw7tOdWkhn0jDUh2uQen9Atj3RkJyHuR0
# GUsJVMWFJdkIO/gFwzoOGlHNsmxvpANV86/1qgb1oZXdrURpzJp53MsDaBY/pxOc
# J0Cvg6uWs3kQWgKk5aBzvsX95BzdItHTpVMtVPW4q41XEvbFmUP1n6oL5rdNdrTM
# j/HXMRk1KCksax1Vxo3qv+13cCsZAaQNaIAvt5LvkshZkDZIP//0Hnq7NnWeYR3z
# 4oFiw9N2n3bb9baQWuWPswG0Dq9YT9kb+Cs4qIIwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIZeDCCGXQCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAsyOtZamvdHJTgAAAAACzDAN
# BglghkgBZQMEAgEFAKCBsDAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQg226gw5Np
# xOCPquGoWtuXhTPH+Mvz4l6eWxOLbhXtQMAwRAYKKwYBBAGCNwIBDDE2MDSgFIAS
# AE0AaQBjAHIAbwBzAG8AZgB0oRyAGmh0dHBzOi8vd3d3Lm1pY3Jvc29mdC5jb20g
# MA0GCSqGSIb3DQEBAQUABIIBADKtsFN1JXDKZ6bcrEhGcLolI6IrQ/FUUwIqK0Ew
# jb9oQUMafvMhzzcvTxVnWGaKQKTGMbA2ir04EMvnZ08N3KnS7DAZBPTPiCYqMP7P
# TrLW+5nj+A5vFPAvJUdUkeTScQacYYhaq2oaMzWXhyufMHBNoHOB6J93di1U0BK8
# 7vLdopZJ6V9gLxEbceNYdM/u9hBTXXNuxlxC0CWcL0XKh7Xli3wXwY7DOEftIUdv
# IvBO52+GTc8NQzkZsGDKgAGDnJudCWG97Bc83SpYQbWBBGNicA8XX7kJYYHTrkUn
# jJj1mSukOEMRZHrhaniHWr5F6/UY8OKORaE2x37pdPVP0vChghcAMIIW/AYKKwYB
# BAGCNwMDATGCFuwwghboBgkqhkiG9w0BBwKgghbZMIIW1QIBAzEPMA0GCWCGSAFl
# AwQCAQUAMIIBUQYLKoZIhvcNAQkQAQSgggFABIIBPDCCATgCAQEGCisGAQQBhFkK
# AwEwMTANBglghkgBZQMEAgEFAAQg/Rjg/XEVoc0hmCx12Q9MKzueDLt6xWWiwSUi
# dWh4WDACBmNIIky36BgTMjAyMjExMDIxNDE1MDguNjk3WjAEgAIB9KCB0KSBzTCB
# yjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMc
# TWljcm9zb2Z0IEFtZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRT
# UyBFU046MTJCQy1FM0FFLTc0RUIxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFNlcnZpY2WgghFXMIIHDDCCBPSgAwIBAgITMwAAAaEBhVWZuVRdigABAAAB
# oTANBgkqhkiG9w0BAQsFADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAe
# Fw0yMTEyMDIxOTA1MjRaFw0yMzAyMjgxOTA1MjRaMIHKMQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmlj
# YSBPcGVyYXRpb25zMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoxMkJDLUUzQUUt
# NzRFQjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANrJPF7la6SStjHFW4cthb0ERYIP
# 2SSOecew4rAZ10g9tmUtj6Xmi8sM1/4EQxAoBlAjcNf3WXXIIO4/1fu048LjxlEZ
# cD9t/2qXQUrnjfyAiXtxXnbxd4Q4XBz8D5RshR9bb3o6aDxnrbFpC/eOsbhT+muI
# CsX96vVQDUc24gZTKqOXKCJI/ArY2cUCmLUkP5R5/lzjuSHulbUqPtGdyGkV5j0x
# 6Q9BGJrtwRpRhTiyoKIlV0Mml58u89P0R22GVDHvmV3H4DBl/Zr1Pu5BFIGHy2nE
# 90gMOQqJYzCMpOsBjT0Dcj+OJ2o+5zw+9f6yrGrJkQ3aHgYDQR2OaTrieQi6QArX
# wrmcAsMs71IxPGkDBAgdEO1l5MKW8A8ISjLW+08Pt/56oepK2675cKR9GNcSlf36
# H1+uwHT8GAPkIF/cQssBrxN58x8dlYQlFM82ttcwqLNKtRKRW//cc/9mwmnBrPkz
# LZFvJzcCH1tPvp4EmTJ9PkU32/8pDQefGFEyzoceFOY3H4vO1hyL68d/QPdAfV4K
# NlZlGOnWY7LGk9TaYMwbqB6W8mx7UnNEAOjtgiiT8ncJxubwxsFubzmKiAWW0Ud5
# wcUQXCuwMYEWc1gcyFxtqtA0D6BjZ7aX18CRfcyMjtSSWSjPvj8/ooip7mNx30U8
# JttJtgf04uy155g5AgMBAAGjggE2MIIBMjAdBgNVHQ4EFgQUFr8gMttjjvlVDIqJ
# lLDjuXT9zKkwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0f
# BFgwVjBUoFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwv
# TWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsG
# AQUFBwEBBGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAx
# MCgxKS5jcnQwDAYDVR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCDANBgkq
# hkiG9w0BAQsFAAOCAgEAIMMjESV9eUblgpwqss9JL5/clZmmvAoSIBK+K9odMFGV
# e0Cz5ORp1ywR6L73Dm+YXm0JTNMfhzScIjttnGewv5LpeyI6zdnVXhZf4jChdQnj
# Mu+zT6ZPi+MYO1h8pD9uyYkpqvZz32b98e/VabYJNzJp4++LzomHdTIuN1EgtZu3
# OzigiYUzDApvMd0+inGsGGCL4LVhmyGixYuWDPK7GNSX6o2DWbnYwmZ/XWWgjsP0
# cmhpDN36t/3bxjyu9QuaDaH8bnSj4PRQnUVr9wklod8Hex8rD1foau1dgaOYzf6D
# 4CFpWx+6kpc204W7m2csq8Afk4iMQNhXVgqaVe4G6FthqyzKA8UyY2AbYCeTd2sR
# wNxmEJdeqlGzM2jUXoa7kkKlBlds4kz1R7k+Ukq2YiYBggazD6mcfL+vmCBJg6ni
# DlnWhT0aFUIzdXRP1p157o5RcGTWsTh1lz9Sw+WPSqiKWMv6U3UDmCSabPuTm0g5
# tUYHt0l3PwnQXBdETmpi7UB29q5VtnAZCQvXHxor+y+MRBbQ1TInb3OcMeJeXm8u
# hFOOMWmyFQGLb4hj6Y2psuaPbiPl5P5uMOUTceY20s+ktwwNipnUf7pTpiZqI2Zp
# zaNFcMBp4QT+6gMy3Z0Ct8k/sz4wO/fPM01Mg1640S0NWCb3PB+AhQJecNm5W2Iw
# ggdxMIIFWaADAgECAhMzAAAAFcXna54Cm0mZAAAAAAAVMA0GCSqGSIb3DQEBCwUA
# MIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMTIwMAYDVQQD
# EylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxMDAeFw0y
# MTA5MzAxODIyMjVaFw0zMDA5MzAxODMyMjVaMHwxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1w
# IFBDQSAyMDEwMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA5OGmTOe0
# ciELeaLL1yR5vQ7VgtP97pwHB9KpbE51yMo1V/YBf2xK4OK9uT4XYDP/XE/HZveV
# U3Fa4n5KWv64NmeFRiMMtY0Tz3cywBAY6GB9alKDRLemjkZrBxTzxXb1hlDcwUTI
# cVxRMTegCjhuje3XD9gmU3w5YQJ6xKr9cmmvHaus9ja+NSZk2pg7uhp7M62AW36M
# EBydUv626GIl3GoPz130/o5Tz9bshVZN7928jaTjkY+yOSxRnOlwaQ3KNi1wjjHI
# NSi947SHJMPgyY9+tVSP3PoFVZhtaDuaRr3tpK56KTesy+uDRedGbsoy1cCGMFxP
# LOJiss254o2I5JasAUq7vnGpF1tnYN74kpEeHT39IM9zfUGaRnXNxF803RKJ1v2l
# IH1+/NmeRd+2ci/bfV+AutuqfjbsNkz2K26oElHovwUDo9Fzpk03dJQcNIIP8BDy
# t0cY7afomXw/TNuvXsLz1dhzPUNOwTM5TI4CvEJoLhDqhFFG4tG9ahhaYQFzymei
# XtcodgLiMxhy16cg8ML6EgrXY28MyTZki1ugpoMhXV8wdJGUlNi5UPkLiWHzNgY1
# GIRH29wb0f2y1BzFa/ZcUlFdEtsluq9QBXpsxREdcu+N+VLEhReTwDwV2xo3xwgV
# GD94q0W29R6HXtqPnhZyacaue7e3PmriLq0CAwEAAaOCAd0wggHZMBIGCSsGAQQB
# gjcVAQQFAgMBAAEwIwYJKwYBBAGCNxUCBBYEFCqnUv5kxJq+gpE8RjUpzxD/LwTu
# MB0GA1UdDgQWBBSfpxVdAF5iXYP05dJlpxtTNRnpcjBcBgNVHSAEVTBTMFEGDCsG
# AQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wEwYDVR0lBAwwCgYIKwYBBQUH
# AwgwGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwCwYDVR0PBAQDAgGGMA8GA1Ud
# EwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAU1fZWy4/oolxiaNE9lJBb186aGMQwVgYD
# VR0fBE8wTTBLoEmgR4ZFaHR0cDovL2NybC5taWNyb3NvZnQuY29tL3BraS9jcmwv
# cHJvZHVjdHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3JsMFoGCCsGAQUFBwEB
# BE4wTDBKBggrBgEFBQcwAoY+aHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9j
# ZXJ0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcnQwDQYJKoZIhvcNAQELBQAD
# ggIBAJ1VffwqreEsH2cBMSRb4Z5yS/ypb+pcFLY+TkdkeLEGk5c9MTO1OdfCcTY/
# 2mRsfNB1OW27DzHkwo/7bNGhlBgi7ulmZzpTTd2YurYeeNg2LpypglYAA7AFvono
# aeC6Ce5732pvvinLbtg/SHUB2RjebYIM9W0jVOR4U3UkV7ndn/OOPcbzaN9l9qRW
# qveVtihVJ9AkvUCgvxm2EhIRXT0n4ECWOKz3+SmJw7wXsFSFQrP8DJ6LGYnn8Atq
# gcKBGUIZUnWKNsIdw2FzLixre24/LAl4FOmRsqlb30mjdAy87JGA0j3mSj5mO0+7
# hvoyGtmW9I/2kQH2zsZ0/fZMcm8Qq3UwxTSwethQ/gpY3UA8x1RtnWN0SCyxTkct
# wRQEcb9k+SS+c23Kjgm9swFXSVRk2XPXfx5bRAGOWhmRaw2fpCjcZxkoJLo4S5pu
# +yFUa2pFEUep8beuyOiJXk+d0tBMdrVXVAmxaQFEfnyhYWxz/gq77EFmPWn9y8FB
# SX5+k77L+DvktxW/tM4+pTFRhLy/AsGConsXHRWJjXD+57XQKBqJC4822rpM+Zv/
# Cuk0+CQ1ZyvgDbjmjJnW4SLq8CdCPSWU5nR0W2rRnj7tfqAxM328y+l7vzhwRNGQ
# 8cirOoo6CGJ/2XBjU02N7oJtpQUQwXEGahC0HVUzWLOhcGbyoYICzjCCAjcCAQEw
# gfihgdCkgc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# JTAjBgNVBAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsT
# HVRoYWxlcyBUU1MgRVNOOjEyQkMtRTNBRS03NEVCMSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQAbcXaM7gsQxUvC
# AoZd1gw3gUGA4KCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MA0GCSqGSIb3DQEBBQUAAgUA5wxUQzAiGA8yMDIyMTEwMjEwMjgxOVoYDzIwMjIx
# MTAzMTAyODE5WjB3MD0GCisGAQQBhFkKBAExLzAtMAoCBQDnDFRDAgEAMAoCAQAC
# AgchAgH/MAcCAQACAhN2MAoCBQDnDaXDAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwG
# CisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQEF
# BQADgYEAoL8ZB828185mB2wZ3PA2Ju0pZtyiNts7qn/QkmA5wZLD7iItM0IG324l
# i7UlHdmFGkvbsTZtpgQDXftONZ5sdvbw6S03XIxQNKViYipSJvkRZq2s5qATO4G7
# 0/+aCpBeKsDLhVQni2Vu8d6rA5xWnR7zPZS3nqoRL/akcFudQ9UxggQNMIIECQIB
# ATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE
# BxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYD
# VQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAaEBhVWZuVRd
# igABAAABoTANBglghkgBZQMEAgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3
# DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCAgtujhsoG103c2VKJ7Qe1DqtC4lF0w3a4o
# zj8K4I0hjDCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQwgb0EIOsIVPE6gYJoIIKO
# hHIF7UlJCswl4IJPISvOKInfjtCEMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzAR
# BgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1p
# Y3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3Rh
# bXAgUENBIDIwMTACEzMAAAGhAYVVmblUXYoAAQAAAaEwIgQgLXLg4iAhEGYcyWws
# cxCogIYQgieNPBgvUEFEvGbKLqMwDQYJKoZIhvcNAQELBQAEggIAYZMbi5xOJgiN
# o24C7ck56dQ0VBylfECt5AMRzpT/bXzoH1kCrUFARYKuG2R0uifYWcb5JRO4pWFz
# iDrSu0Uoz7PIo1wvBW/SJV/SUb04ocoIOEpsK9a2jiEmLU5RsjTo8BjlMnmXNbOI
# uMFN5r+8yPeTG2A0K1LbtIJsLNM3Dc3RAHOA9vi4xr+5xqE4gsLJ1MPF94aXJ8FU
# 3reLQ5oQ77r+vLtMWSGU/wgF3TWjk883dzFgFrGClthgEvJlczlUF30UYqo4dPLN
# Kpu0UYluNDkR/+j+wHVMHCdOsNUVERh9nklj9aVeK50tNCuJWhG8+qyVwjHiUXMm
# /W0cMFkD9oIBehfIExTFv+9jGJZrpK1Cw2OmlPy+xV0pgLCatab6VFUe5M6/QemF
# gQ3m0rn9YPSJLTSiik0TMa/yItxEp6yVRqTRKHLBeNkM6+AxXy1qX12CXTPbNoMz
# PsNIcs3nXnLz/y/se3HQWVfSCP9mSYL9SNgi5SdKdaptoKlmx/Ajln5P03phlvPN
# BVT+ImgE3dXGWHKVlc93KfA5LjvEE1eQ19nzqswwMsKqFe0y5G+rWcGK6nhPmzbw
# PAOYfIEOSWESD5R4pvuKj/5YeGtO1IdEjK7VldPpyeAIIScmdtLlttvi3mdB0ZBX
# P5OxayNMUW1tJRdZOwgLredxcX2Dk6s=
# SIG # End signature block
