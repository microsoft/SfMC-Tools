<#
//***********************************************************************
//
// Get-EwsSignIns.ps1
// Modified 10 October 2023
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin and Dempsey Dunkin
// .VERSION 20231010.1600
//
// .SYNOPSIS
//  Query Azure AD sign-in logs for EWS applications
// 
// .DESCRIPTION
//  This script will determine which Azure AD applications have EWS permissions assigned and then query the Azure AD sign-in logs
//  for any activity within a specified number of days.
//
// .PARAMETERS
//    ResultsPath - The ResultsPath parameter specifies The path for the results file.
//    StartDate - The start date for your sign-in log query.
//
//.EXAMPLES
// .\Get-EwsSignIns.ps1 -ResultsPath c:\Temp\Results
// This example collects the app registrations using EWS permissions and queries for sign-in for the last seven days.
//
// .\Get-EwsSignIns.ps1 -ResultsPath c:\Temp\Results -StartDate (Get-Date).AddDays(-3)
// This example collects the app registrations using EWS permissions and queries for sign-in for the last three days.
//
//.NOTES
// 20231010.1600 - Initial release
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
    [Parameter(Mandatory=$true,HelpMessage="The ResultsPath parameter specifies The path for the results file")][string]$ResultsPath="C:\Temp\",
    [Parameter(Mandatory = $false, HelpMessage="The start date for your signin log query.")] [datetime] $StartDate=(Get-Date).AddDays(-7)
    
)
$script:ScriptVersion = "20231010.1600"

function LogToFile([string]$Details) {
	if ( [String]::IsNullOrEmpty($LogFile) ) { return }
	"$([DateTime]::Now.ToShortDateString()) $([DateTime]::Now.ToLongTimeString())   $Details" | Out-File $LogFile -Append
}

function Log([string]$Details, [ConsoleColor]$Colour) {
    if ($Colour -like $null)
    {
        $Colour = [ConsoleColor]::White
    }
    Write-Host $Details -ForegroundColor $Colour
    LogToFile $Details
}

function LogVerbose([string]$Details) {
    Write-Verbose $Details
    LogToFile $Details
}
LogVerbose "$($MyInvocation.MyCommand.Name) version $($script:ScriptVersion) starting"

function LogDebug([string]$Details) {
    Write-Debug $Details
    LogToFile $Details
}

$script:LastError = $Error[0]
function ErrorReported($Context) {
    # Check for any error, and return the result ($true means a new error has been detected)

    # We check for errors using $Error variable, as try...catch isn't reliable when remoting
    if ([String]::IsNullOrEmpty($Error[0])) { return } #$false }

    # We have an error, have we already reported it?
    if ($Error[0] -eq $script:LastError) { return  } #$false }

    # New error, so log it and return $true
    $script:LastError = $Error[0]
    if ($Context)
    {
        Log "Error ($Context): $($Error[0])" Red
    }
    else
    {
        Log "Error: $($Error[0])" Red
    }
    return #$true
}

function ReportError($Context) {
    # Reports error without returning the result
    ErrorReported $Context | Out-Null
}

#region Dislaimer
$ScriptDisclaimer = @"
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
//***********************************************************************
"@
Write-Host $ScriptDisclaimer -ForegroundColor Yellow
#endregion

#region Determine the location for the results
$timeStamp = Get-Date -Format yyyyMMddHHmmss
if($ResultsPath.Substring($ResultsPath.Length-1,1) -eq "\") {
    $ResultsPath = $ResultsPath.Substring(0,$ResultsPath.Length-1)
}
if(!(Test-Path -Path $ResultsPath -ErrorAction Ignore)) {
    $FullPath = $ResultsPath.Split("\")
    $StartPath = $FullPath[0]+"\"
    for($x=1; $x -lt $FullPath.Count; $x++) {
        $TestPath = $StartPath+"\"+$FullPath[$x]
        if(!(Test-Path $TestPath)) { 
            New-Item -Path $StartPath -Name $FullPath[$x] -Type Directory
        }
            $StartPath = $TestPath
    }
}
$AppPermissionFile = "$ResultsPath\Ews-ApplicationPermissions-$timeStamp.csv"
$ResultsFile = "$ResultsPath\Ews-SignIn-Results-$timeStamp.csv"
$LogFile = "$ResultsPath\Ews-SignIns-$timeStamp.log"

if(Get-InstalledModule -Name Microsoft.Graph.Beta -ErrorAction Ignore){
    try {
        Install-Module Microsoft.Graph.Beta
    }
    catch{
        Write-Host "Failed to install Graph beta module. Please install the module and try again." -ForegroundColor Red
        exit
    }
}

Log([string]::Format("Connecting to Microsoft Graph.")) Gray
Connect-Graph -Scopes AuditLog.Read.All, Application.Read.All -NoWelcome

#Log([string]::Format("Getting a list of Azure AD Applications.")) Cyan
#$Apps = Get-MgBetaApplication -All
Log([string]::Format("Getting a list of Azure AD service principals.")) Cyan
$ServicePrincipals = Get-MgBetaServicePrincipal -All

$AppPermissions = New-Object System.Collections.ArrayList

Log([string]::Format("Checking for EWS application permissions.")) Cyan
foreach($sp in $ServicePrincipals) {
    if((Get-MgBetaServicePrincipalOauth2PermissionGrant -ServicePrincipalId $sp.Id).Scope -match "EWS.AccessAsUser.All"){
       Log([string]::Format("Found {0} with delegated permissions.",$sp.DisplayName)) Green
       $AppPermissions.Add([PSCustomObject]@{
                'ApplicationDisplayName' = $sp.DisplayName
                'ApplicationID'           = $sp.AppId
                'ServicePrincipalId'      = $sp.Id
                'PermissionType'          = "Delegate"
                'PermissionValue'         = "EWS.AccessAsUser.All"
                }) | Out-Null
    }
if((Get-MgBetaServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id).AppRoleId -match 'dc890d15-9560-4a4c-9b7f-a736ec74ec40') {
    Log([string]::Format("Found {0} with application permissions.",$sp.DisplayName)) Green
    $AppPermissions.Add([PSCustomObject]@{
        'ApplicationDisplayName' = $sp.DisplayName
        'ApplicationID'           = $sp.AppId
        'ServicePrincipalId'      = $sp.Id
        'PermissionType'          = $sp.ServicePrincipalType
        'PermissionValue'         = "full_access_as_app"
        }) | Out-Null
    }
}

#Connect to Exchange Online to obtain list of RBAC permissions
Log([string]::Format("Connecting to Exchange Online.")) Gray
Connect-ExchangeOnline -ShowBanner:$false -ShowProgress:$false
Log([string]::Format("Getting a list of RBAC management role assignments for EWS.")) Gray
$RbacAssignments = Get-ManagementRoleAssignment -Role "Application EWS.AccessAsApp"
foreach($Rbac in $RbacAssignments){
    LogVerbose([string]::Format("Checking the role assignee type for the RBAC management role assignment: {0}.", $Rbac.Name))
    if($Rbac.RoleAssigneeType -eq 'ServicePrincipal'){
        LogVerbose([string]::Format("{0} has a service principal {1}.", $Rbac.Name, $Rbac.RoleAssignee))
        #Verify there is an app registration that matches the service principal name
        $PermissionName = ($ServicePrincipals | Where-Object Id -eq $Rbac.RoleAssignee)
        if ($PermissionName) { 
            $AppPermissions.Add([PSCustomObject]@{
                'ApplicationDisplayName' = $PermissionName.AppDisplayName
                'ApplicationID'           = $PermissionName.AppId
                'ServicePrincipalId'      = $Rbac.RoleAssignee
                'PermissionType'          = "RBAC"
                'PermissionValue'         = "Application EWS.AccessAsApp"
            }) | Out-Null
        }
    }
}

$AppPermissions | Format-Table -AutoSize
$AppPermissions | Export-Csv $AppPermissionFile -NoTypeInformation

$AppPermissions = $AppPermissions | Sort-Object -Property ApplicationID -Unique

$TempDate = [datetime]$StartDate
$TempDate = $TempDate.ToUniversalTime()
$SearchStartDate = '{0:yyyy-MM-ddTHH:mm:ssZ}' -f $TempDate
Log([string]::Format("Checking the sign-in logs for each application.")) Green
foreach($App in $AppPermissions) {
    Log([string]::Format("Checking the sign-in logs for {0}.", $App.ApplicationDisplayName)) Gray
    Get-MgBetaAuditLogSignIn -Filter "appid eq '$($app.ApplicationID)' and signInEventTypes/any(t: t eq 'interactiveUser' or t eq 'nonInteractiveUser' or t eq 'servicePrincipal' or t eq 'managedIdentity') and CreatedDateTime ge $SearchStartDate" | Select-Object AppDisplayName, AppId, CreatedDateTime, UserDisplayName, UserPrincipalName, @{Name='SignInEventTypes';Expression={$_.SignInEventTypes -join '; '}} | Export-Csv -Path $ResultsFile -NoTypeInformation -NoClobber -Append
}
Log([string]::Format("Script complete.")) Yellow