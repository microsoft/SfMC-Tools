<#//***********************************************************************
//
// SfMC-EXODiscovery.ps1
// Modified 2021/07/22
// Last Modifier:  Jim Martin
// Project Owner:  Jim Martin
// Version: v1.2
//Syntax for running this script:
//
// .\SfMC-EXODiscovery.ps1 -UserPrincipalName admin@contoso.com -OutputPath C:\Temp\Results
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
    [Parameter(Mandatory=$true)] [string]$UserPrincipalName,
    [Parameter(Mandatory=$false)] [string]$OutputPath,
    [Parameter(Mandatory=$false)] $SessionOptions
)
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
function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    if($currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        return $true
    }
    else {
        return $false
    }
}
if(-not (Is-Admin)) {
	Write-host;Write-Warning "The SfMC-Exchange-Discovery-1.ps1 script needs to be executed in elevated mode. Please start PowerShell 'as Administrator' and try again." 
	Write-host;Start-Sleep -Seconds 2;
	exit
}
Write-host " "
Write-host " "
Write-host -ForegroundColor Cyan "==============================================================================="
Write-host " "
Write-Host -ForegroundColor Cyan " The SfMC EXO Discovery process is about to begin gathering data. "
Write-host -ForegroundColor Cyan " It may take some time to complete depending on the environment. "
Write-host " "
Write-host -ForegroundColor Cyan "==============================================================================="
Write-host " "
Start-Sleep -Seconds 2
## Set a timer
$stopWatch = New-Object -TypeName System.Diagnostics.Stopwatch
$stopWatch.Start()
Write-Host "Connecting to Exchange Online..." -ForegroundColor Yellow -NoNewline
try { Connect-ExchangeOnline -UserPrincipalName $UserPrincipalName -PSSessionOption $SessionOptions -ShowBanner:$False}
catch { Write-Host "FAILED"
    Write-Warning "The ExchangeOnlineManagement module is required to run this script."
    Start-Sleep -Seconds 3
    Write-Host " "
    write-host "Please install the module using 'Install-Module -Name ExchangeOnlineManagement'." -ForegroundColor Cyan
    Write-Host "Then add the module using 'Import-Module ExchangeOnlineManagement'." -ForegroundColor Cyan
    Write-Host " "
    Write-host " "
    Write-Host "For more information about the Exchange Online PowerShell V2 Module go to:" -ForegroundColor Cyan
    Write-Host "https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2" -ForegroundColor Cyan
    break
}
Write-Host "COMPLETE"
if($OutputPath -like $null) {
    Add-Type -AssemblyName System.Windows.Forms
    Write-Host "Select the location where to save the data." -ForegroundColor Yellow
    $folderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog
    $folderBrowser.Description = "Select the location where to save the data"
    $folderBrowser.SelectedPath = "C:\"
    $folderPath = $folderBrowser.ShowDialog()
    [string]$OutputPath = $folderBrowser.SelectedPath
}
else {
    if($OutputPath.Substring($OutputPath.Length-1,1) -eq "\") {$OutputPath = $OutputPath.Substring(0,$OutputPath.Length-1)}
}
[string]$orgName = (Get-OrganizationConfig).Name
$orgName = $orgName.Substring(0, $orgName.IndexOf("."))
$wAction = $WarningPreference
$eAction = $ErrorActionPreference
$WarningPreference = "Ignore"
$ErrorActionPreference = "Ignore"
## Connect to Exchange Online and collect data
Write-Host "Collecting data from Exchange Online..." -ForegroundColor Yellow -NoNewline
Get-AcceptedDomain | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AcceptedDomain.csv -NoTypeInformation
Get-ActiveSyncDeviceAccessRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ActiveSyncDeviceAccessRule.csv -NoTypeInformation
Get-ActiveSyncOrganizationSettings | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ActiveSyncOrganizationSettings.csv -NoTypeInformation
Get-AddressBookPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AddressBookPolicy.csv -NoTypeInformation
Get-AdminAuditLogConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AdminAuditLogConfig.csv -NoTypeInformation
Get-App | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-App.csv -NoTypeInformation
Get-AuthenticationPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuthenticationPolicy.csv -NoTypeInformation
Get-AuthServer | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuthServer.csv -NoTypeInformation
Get-AvailabilityAddressSpace | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AvailabilityAddressSpace.csv -NoTypeInformation
Get-AvailabilityConfig -WarningVariable Ignore | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AvailabilityConfig.csv -NoTypeInformation
Get-CASMailboxPlan | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-CASMailboxPlan.csv -NoTypeInformation
Get-ClientAccessRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ClientAccessRule.csv -NoTypeInformation
Get-EmailAddressPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-EmailAddressPolicy.csv -NoTypeInformation
Get-FederatedOrganizationIdentifier | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-FederatedOrganizationIdentifier.csv -NoTypeInformation
Get-HybridMailflow | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HybridMailflow.csv -NoTypeInformation
Get-HybridMailflowDatacenterIPs | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HybridMailflowDatacenterIPs.csv -NoTypeInformation
#Get-ImapSubscription | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ImapSubscription.csv -NoTypeInformation
Get-InboundConnector | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-InboundConnector.csv -NoTypeInformation
Get-OnPremisesOrganization | Get-IntraOrganizationConfiguration -ErrorAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-IntraOrganizationConfiguration.csv -NoTypeInformation
Get-IntraOrganizationConnector | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-IntraOrganizationConnector.csv -NoTypeInformation
Get-IRMConfiguration | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-IRMConfiguration.csv -NoTypeInformation
Get-JournalRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-JournalRule.csv -NoTypeInformation
Get-MailboxPlan | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-MailboxPlan.csv -NoTypeInformation
Get-ManagementRole | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementRole.csv -NoTypeInformation
Get-ManagementRoleAssignment | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementRoleAssignment.csv -NoTypeInformation
Get-ManagementRoleEntry *\* | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementRoleEntry.csv -NoTypeInformation
Get-ManagementScope | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ManagementScope.csv -NoTypeInformation
Get-MigrationEndpoint | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-MigrationEndpoint.csv -NoTypeInformation
Get-MobileDeviceMailboxPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-MobileDeviceMailboxPolicy.csv -NoTypeInformation
Get-OMEConfiguration | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OMEConfiguration.csv -NoTypeInformation
Get-OnPremisesOrganization | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OnPremisesOrganization.csv -NoTypeInformation
Get-OrganizationConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OrganizationConfig.csv -NoTypeInformation
Get-OrganizationRelationship | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OrganizationRelationship.csv -NoTypeInformation
Get-OutboundConnector | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OutboundConnector.csv -NoTypeInformation
Get-OutlookProtectionRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OutlookProtectionRule.csv -NoTypeInformation
Get-OwaMailboxPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-OwaMailboxPolicy.csv -NoTypeInformation
Get-PartnerApplication | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PartnerApplication.csv -NoTypeInformation
Get-PerimeterConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PerimeterConfig.csv -NoTypeInformation
#Get-PopSubscription | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PopSubscription.csv -NoTypeInformation
Get-RemoteDomain | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RemoteDomain.csv -NoTypeInformation
Get-ResourceConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ResourceConfig.csv -NoTypeInformation
Get-RetentionPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RetentionPolicy.csv -NoTypeInformation
Get-RetentionPolicyTag | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RetentionPolicyTag.csv -NoTypeInformation
Get-RoleAssignmentPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RoleAssignmentPolicy.csv -NoTypeInformation
Get-RoleGroup | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RoleGroup.csv -NoTypeInformation
Get-SharingPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SharingPolicy.csv -NoTypeInformation
Get-SmimeConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SmimeConfig.csv -NoTypeInformation
Get-TransportConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportConfig.csv -NoTypeInformation
Get-TransportRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportRule.csv -NoTypeInformation
Get-TransportRuleAction | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportRuleAction.csv -NoTypeInformation
Get-TransportRulePredicate | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-TransportRulePredicate.csv -NoTypeInformation
Get-AntiPhishPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AntiPhishPolicy.csv -NoTypeInformation
Get-AntiPhishRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AntiPhishRule.csv -NoTypeInformation
Get-AtpPolicyForO365 | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AtpPolicyForO365.csv -NoTypeInformation
Get-ATPProtectionPolicyRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ATPProtectionPolicyRule.csv -NoTypeInformation
Get-AuditConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuditConfig.csv -NoTypeInformation
Get-AuditConfigurationPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuditConfigurationPolicy.csv -NoTypeInformation
Get-AuditConfigurationRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-AuditConfigurationRule.csv -NoTypeInformation
Get-BlockedSenderAddress | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-BlockedSenderAddress.csv -NoTypeInformation
Get-ClassificationRuleCollection | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ClassificationRuleCollection.csv -NoTypeInformation
Get-CompliancePolicyFileSyncNotification | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-CompliancePolicyFileSyncNotification.csv -NoTypeInformation
Get-CompliancePolicySyncNotification | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-CompliancePolicySyncNotification.csv -NoTypeInformation
Get-ComplianceTag | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ComplianceTag.csv -NoTypeInformation
Get-ComplianceTagStorage | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ComplianceTagStorage.csv -NoTypeInformation
Get-CustomizedUserSubmission | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-CustomizedUserSubmission.csv -NoTypeInformation
Get-DataClassification | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DataClassification.csv -NoTypeInformation
Get-DataClassificationConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DataClassificationConfig.csv -NoTypeInformation
Get-DataEncryptionPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DataEncryptionPolicy.csv -NoTypeInformation
Get-DkimSigningConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DkimSigningConfig.csv -NoTypeInformation
Get-DlpPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpPolicy.csv -NoTypeInformation
Get-DlpPolicyTemplate | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpPolicyTemplate.csv -NoTypeInformation
Get-ElevatedAccessApprovalPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ElevatedAccessApprovalPolicy.csv -NoTypeInformation
Get-ElevatedAccessAuthorization | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ElevatedAccessAuthorization.csv -NoTypeInformation
Get-EOPProtectionPolicyRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-EOPProtectionPolicyRule.csv -NoTypeInformation
Get-HostedConnectionFilterPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HostedConnectionFilterPolicy.csv -NoTypeInformation
Get-HostedContentFilterPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HostedContentFilterPolicy.csv -NoTypeInformation
Get-HostedContentFilterRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HostedContentFilterRule.csv -NoTypeInformation
Get-HostedOutboundSpamFilterPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HostedOutboundSpamFilterPolicy.csv -NoTypeInformation
Get-HostedOutboundSpamFilterRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-HostedOutboundSpamFilterRule.csv -NoTypeInformation
Get-MalwareFilterPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-MalwareFilterPolicy.csv -NoTypeInformation
Get-MalwareFilterRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-MalwareFilterRule.csv -NoTypeInformation
Get-PhishFilterPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PhishFilterPolicy.csv -NoTypeInformation
Get-PolicyConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PolicyConfig.csv -NoTypeInformation
Get-PolicyTipConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-PolicyTipConfig.csv -NoTypeInformation
Get-RMSTemplate | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-RMSTemplate.csv -NoTypeInformation
Get-ReportSubmissionPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-ReportSubmissionPolicy.csv -NoTypeInformation
Get-SafeAttachmentPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SafeAttachmentPolicy.csv -NoTypeInformation
Get-SafeAttachmentRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SafeAttachmentRule.csv -NoTypeInformation
Get-SafeLinksPolicy | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SafeLinksPolicy.csv -NoTypeInformation
Get-SafeLinksRule | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-SafeLinksRule.csv -NoTypeInformation
Disconnect-ExchangeOnline -Confirm:$false -InformationAction Ignore | Out-Null
## Connect to Exchange Online Protection
try { Connect-IPPSSession -Credential -UserPrincipalName $UserPrincipalName -PSSessionOption $SessionOptions -ShowBanner:$False}
catch { Write-Warning "Failed to connect to Exchange Online Protection PowerShell." }
Get-DlpKeywordDictionary | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpKeywordDictionary.csv -NoTypeInformation
Get-DlpSensitiveInformationTypeConfig | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpSensitiveInformationTypeConfig.csv -NoTypeInformation
Get-DlpSensitiveInformationTypeRulePackage | Select-Object * -ExcludeProperty SerializationData | Export-Csv $outputPath\$orgName-DlpSensitiveInformationTypeRulePackage.csv -NoTypeInformation
Disconnect-ExchangeOnline -Confirm:$false -InformationAction Ignore | Out-Null
Write-Host "COMPLETE"
$WarningPreference = $wAction
$ErrorActionPreference = $eAction
$stopWatch.Stop()
$totalTime = $stopWatch.Elapsed.TotalSeconds
if(Test-Path "$OutputPath\$orgName.zip") {Remove-Item -Path "$OutputPath\$orgName.zip" -Force}
Write-Host "Creating zip file with the results..." -ForegroundColor Yellow -NoNewline
Get-ChildItem -Path $OutputPath -Filter "$orgName*.csv" | Select-Object FullName | ForEach-Object { Compress-Archive -DestinationPath "$OutputPath\$orgName.zip" -Path $_.FullName -Update }
Get-ChildItem -Path $OutputPath -Filter "$orgName*.csv" | Remove-Item -Confirm:$False -Force
Write-Host "COMPLETE"
Write-host " "
Write-host -ForegroundColor Cyan  "==================================================="
Write-Host -ForegroundColor Cyan " SfMC EXO Discovery data collection has finished!"
Write-Host -ForegroundColor Cyan "          Total collection time: $($totalTime) seconds"
Write-Host -ForegroundColor Cyan "    Please upload results to SfMC. - Thank you!!!"
Write-host -ForegroundColor Cyan "==================================================="
Write-host " "

# SIG # Begin signature block
# MIInpwYJKoZIhvcNAQcCoIInmDCCJ5QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA92Hk1wwC+zKeq
# LOWwBOVkQbnm8i0YscI1xtzuB/hfCaCCDYUwggYDMIID66ADAgECAhMzAAACU+OD
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGXgwghl0AgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAJT44Pelt7FbswAAAAA
# AlMwDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIFrq
# LQ2oog+U1MNUp/LRYLTnltq1ZbOSp1ou7CFH7Fh3MEQGCisGAQQBgjcCAQwxNjA0
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQu
# Y29tIDANBgkqhkiG9w0BAQEFAASCAQC0bcac0dRxYV7eUOjTZ82SpQv0OogO+2pz
# iQdmHhJGqKVnOPP0QCeqMaNPmBUv0QuGtFPpFW4Ufso/keHBLV0rflRCEmWDqfOc
# uKoxvXhgBsLEELI45ju/unYbQRfU5FM+gD/wUyQthA3vGanNfEPlCuxMmi9Qqh5f
# 0FBvft+TXiQ1ALf8l2J6U2VhWQbAcUxz9yVBME6buPzLVU6wQ4qTTMxGWbmuINRG
# rDylFe1ceWRPkspZHoPBedat/xQuwQr/pRAeUyvJjp0TTGeBp5s/MKKb0ybWrVdX
# zbUxxsi4w49RZwIk8UMSYJUs1wg4kQ7TJw+Droaz635s5I8x7grcoYIXADCCFvwG
# CisGAQQBgjcDAwExghbsMIIW6AYJKoZIhvcNAQcCoIIW2TCCFtUCAQMxDzANBglg
# hkgBZQMEAgEFADCCAVEGCyqGSIb3DQEJEAEEoIIBQASCATwwggE4AgEBBgorBgEE
# AYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIMs1PfG2cowpv7PHyfQwX+5lXjlO3s6V
# uDGjKiHXcaKeAgZignxFfw0YEzIwMjIwNTI1MjAyMDEzLjcwOVowBIACAfSggdCk
# gc0wgcoxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJTAjBgNV
# BAsTHE1pY3Jvc29mdCBBbWVyaWNhIE9wZXJhdGlvbnMxJjAkBgNVBAsTHVRoYWxl
# cyBUU1MgRVNOOkU1QTYtRTI3Qy01OTJFMSUwIwYDVQQDExxNaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBTZXJ2aWNloIIRVzCCBwwwggT0oAMCAQICEzMAAAGVt/wN1uM3MSUA
# AQAAAZUwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwHhcNMjExMjAyMTkwNTEyWhcNMjMwMjI4MTkwNTEyWjCByjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjElMCMGA1UECxMcTWljcm9zb2Z0IEFt
# ZXJpY2EgT3BlcmF0aW9uczEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RTVBNi1F
# MjdDLTU5MkUxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Uw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCfbUEMZ7ZLOz9aoRCeJL4h
# hT9Q8JZB2xaVlMNCt3bwhcTI5GLPrt2e93DAsmlqOzw1cFiPPg6S5sLCXz7LbbUQ
# pLha8S4v2qccMtTokEaDQS+QJErnAsl6VSmRvAy0nlj+C/PaZuLb3OzY0ARw7UeC
# ZLpyWPPH+k5MdYj6NUDTNoXqbzQHCuPs+fgIoro5y3DHoO077g6Ir2THIx1yfVFE
# t5zDcFPOYMg4yBi4A6Xc3hm9tZ6w849nBvVKwm5YALfH3y/f3n4LnN61b1wzAx3Z
# CZjf13UKbpE7p6DYJrHRB/+pwFjG99TwHH6uXzDeZT6/r6qH7AABwn8fpYc1Tmle
# FY8YRuVzzjp9VkPHV8VzvzLL7QK2kteeXLL/Y4lvjL6hzyOmE+1LVD3lEbYho1zC
# t+F7bU+FpjyBfTC4i/wHsptb218YlbkQt1i1B6llmJwVFwCLX7gxQ48QIGUacMy8
# kp1+zczY+SxlpaEgNmQkfc1raPh9y5sMa6X48+x0K7B8OqDoXcTiECIjJetxwtuB
# lQseJ05HRfisfgFm09kG7vdHEo3NbUuMMBFikc4boN9Ufm0iUhq/JtqV0Kwrv9Cv
# 3ayDgdNwEWiL2a65InEWSpRTYfsCQ03eqEh5A3rwV/KfUFcit+DrP+9VcDpjWRsC
# okZv4tgn5qAXNMtHa8NiqQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFKuX02ICFFdX
# grcCBmDJfH5v/KkXMB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8G
# A1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBs
# BggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0
# LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUy
# MDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgw
# DQYJKoZIhvcNAQELBQADggIBAOCzNt4fJ+jOvQuq0Itn37IZrYNBGswAi+IAFM3Y
# GK/wGQlEncgjmNBuac95W2fAL6xtFVfMfkeqSLMLqoidVsU9Bm4DEBjaWNOT9uX/
# tcYiJSfFQM0rDbrl8V4nM88RZF56G/qJW9g5dIqOSoimzKUt/Q7WH6VByW0sar5w
# GvgovK3qFadwKShzRYcEqTkHH2zip5e73jezPHx2+taYqJG5xJzdDErZ1nMixRja
# Hs3KpcsmZYuxsIRfBYOJvAFGymTGRv5PuwsNps9Ech1Aasq84H/Y/8xN3GQj4P3M
# iDn8izUBDCuXIfHYk39bqnaAmFbUiCby+WWpuzdk4oDKz/sWwrnsoQ72uEGVEN7+
# kyw9+HSo5i8l8Zg1Ymj9tUgDpVUGjAduoLyHQ7XqknKmS9kJSBKk4okEDg0Id6Le
# KLQwH1e4aVeTyUYwcBX3wg7pLJQWvR7na2SGrtl/23YGQTudmWOryhx9lnU7KBGV
# /aNvz0tTpcsucsK+cZFKDEkWB/oUFVrtyun6ND5pYZNj0CgRup5grVACq/Agb+EO
# GLCD+zEtGNop4tfKvsYb64257NJ9XrMHgpCib76WT34RPmCBByxLUkHxHq5zCyYN
# u0IFXAt1AVicw14M+czLYIVM7NOyVpFdcB1B9MiJik7peSii0XTRdl5/V/KscTaC
# BFz3MIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0B
# AQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAG
# A1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAw
# HhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzET
# MBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMV
# TWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1T
# dGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOTh
# pkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xP
# x2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ
# 3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOt
# gFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYt
# cI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXA
# hjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0S
# idb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSC
# D/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEB
# c8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh
# 8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8Fdsa
# N8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkr
# BgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q
# /y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBR
# BgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3Nv
# ZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAP
# BgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjE
# MFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kv
# Y3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEF
# BQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9w
# a2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEB
# CwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnX
# wnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOw
# Bb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jf
# ZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ
# 5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+
# ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgs
# sU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6
# OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p
# /cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6
# TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784
# cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAs4wggI3
# AgEBMIH4oYHQpIHNMIHKMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMSUwIwYDVQQLExxNaWNyb3NvZnQgQW1lcmljYSBPcGVyYXRpb25zMSYwJAYD
# VQQLEx1UaGFsZXMgVFNTIEVTTjpFNUE2LUUyN0MtNTkyRTElMCMGA1UEAxMcTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA0Y+CyLez
# GgVHWFNmKI1LuE/hY6uggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMDANBgkqhkiG9w0BAQUFAAIFAOY417QwIhgPMjAyMjA1MjYwMDI4MzZaGA8y
# MDIyMDUyNzAwMjgzNlowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5jjXtAIBADAK
# AgEAAgJEwAIB/zAHAgEAAgIR1TAKAgUA5jopNAIBADA2BgorBgEEAYRZCgQCMSgw
# JjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3
# DQEBBQUAA4GBAMhMYpgUYcE6CDP090j/ufuDU2rsP6ug2TefbQ/2mILwZTv0x4Ul
# bZi5UD/cqGXuOvD7SLBWfcNBSssm9LzW30VmjO0Z0RxHyMh4ZuwTC249U024nmca
# OO/oYpvt4t6t3hcovm4/TW3rhYJtWWbvHwpDf8rpoMOVbvytd6OhYxnwMYIEDTCC
# BAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAO
# BgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEm
# MCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGVt/wN
# 1uM3MSUAAQAAAZUwDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsq
# hkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQghKBHRCMYmANmMldbDhRNLAD+ZK1D
# AdHXS1BqZ4Q60q8wgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCBc5kvhjZAL
# e2mhIz/Qd7keVOmA/cC1dzKZT4ybLEkCxzCBmDCBgKR+MHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwAhMzAAABlbf8DdbjNzElAAEAAAGVMCIEIFqHVG9a3UD+
# QbYRoVxizR9Jnvek/Wj9P3xnEx6m6pGPMA0GCSqGSIb3DQEBCwUABIICAFl3wGqN
# D41+JFLllqrpWyZIsiEAWJbzXu+5YV5hRcGV1/gU8irBFkdUn2YrPQGytg2wK1Q+
# oslKMhx16DbPnoyvPDst+uSUxWWOO3SooOVwZ/ovQ6zpXk5OJEC0vJzmjQgc1NV8
# C71qbCrZwtgwh8HPM+Gt3gtJ4fn4qauFlEMUTpg8eLcjhSbclbYdkDMmV9Cw34/v
# fkn6xI2BgIYzMXdPzSGRvv/4Jl6QsIukMn5PBgrjwPPrMQ1zFXp+5hldIPbJpC6K
# BkpnkrxIM+llCAIwGbYa8lYzrRYpnrmV01r1HoAO5RrY+63m4zhnZG8H46tMB95f
# gGef3sP0Eyk112k93l7cu/rBjnCmAMdX3zOsuPqafKeVShx/Ih9M6k2ExbEgiQ2b
# 8/fzD9+hb1ewEk5+4KLHl/xZSsbFl8Mok8jNRTT8mWjC+Je8EgtHuxDNy3ifhPlZ
# oej8HcuaM3PgADMve/hn6QrAMefeWb6tWCisPek7FmlM6rZWoYNEE9tZmUDhAsPq
# EkKQgsbn01CT342KQfjNqjq0+fQJ4jUCU8yvkCOImACi3XREBRtKwzlxBdDttdUx
# d9ym1OMSReYkzeOhwj27cdoiZNEI7ArRvIob0G0+zo0XeegNk0iCNoRzRYIaufTL
# 8aFUNbIn5QMojd5Qa0zZbn6q1hTvaYTvAk7D
# SIG # End signature block
