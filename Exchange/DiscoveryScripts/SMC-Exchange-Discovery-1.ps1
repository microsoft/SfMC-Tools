<#
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

//**********************************************************************?
.SYNOPSIS
  Collect Exchange configuration via PowerShell
 
.DESCRIPTION
  This script will run Get commands in your Exchange Management Shell to collect configuration data via PowerShell

.NOTES
  Should be run from Exchange Management Shell on Exchange 2010 CAS or 2013/2016/2019 MBX, but could be run from mgmt remote powershell connected workstation
#>
param
(
	$ScriptPath = $(split-path $SCRIPT:MyInvocation.MyCommand.Path -parent)
)
Function Is-Admin {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal( [Security.Principal.WindowsIdentity]::GetCurrent() )
    If( $currentPrincipal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )) {
        return $true
    }
    else {
        return $false
    }
}
Function zipAllIt {
	#Change to the Script Location 
	cd $Location
	Add-Type -AssemblyName System.IO.Compression.Filesystem 
	    $date1 = Get-Date -UFormat "%d%b%Y"
	    $zipFolder = "$Location-$date1.zip"
		$i = 1
		while((Test-Path $zipFolder) -eq $True){
			$zipFolder = "$Location-$date1-$i.zip"
			$i++
		}
	    $wData = "Almost done, attempting to zip the [SMC-Email-Discovery] folder on the desktop for you..."
		Write-Host -ForegroundColor yellow $wData
	#zip the file 
	[system.io.compression.zipfile]::CreateFromDirectory($Location, $zipFolder)
	sleep 5		
	$wData2 = "Zip attempt finished."
        Write-Host -ForegroundColor Green $wData2
	Write-host " "
	Write-host -ForegroundColor Cyan  "==================================================="
	Write-Host -ForegroundColor Cyan " SMC Email Discovery data collection has finished!"
	Write-Host -ForegroundColor Cyan "          Total collection time: $($totalTime) minutes"
	Write-Host -ForegroundColor Cyan "    Please upload results to SMC. - Thank you!!!"
	Write-host -ForegroundColor Cyan "==================================================="
	Write-host " "
   }
If(-not (Is-Admin)) {
	Write-host;Write-Warning "The SMC-Exchange-Discovery-1.ps1 script needs to be executed in elevated mode. Please start the Exchange Mangement Shell 'as Administrator'. and try again" 
	Write-host;sleep 2;
	Exit
}
$old_ErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
$execpol = get-executionpolicy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
If (-not (Get-Command ExSetup)) {
    $exver = (Get-ExchangeServer (Get-PSSession).computername).admindisplayversion
}
Else {
    $exver = (Get-Command ExSetup | ForEach {$_.FileVersionInfo}).productversion
}
$starttime = get-date
IF (test-path "$home\desktop\SMC-Email-Discovery"){
    Write-host -ForegroundColor red "======================="
    Write-host -ForegroundColor red " "
    Write-host -ForegroundColor red "The SMC-Email-Discovery folder already exists on your desktop."
    Write-host -ForegroundColor red "Please rename or delete the existing one and run the script again."
    Write-host -ForegroundColor red " "
    Write-host -ForegroundColor red "======================="
    Break;
}
Else {
    Write-host " "
    Write-host " "
    Write-host -ForegroundColor cyan "==============================================================================="
    Write-host " "
    Write-Host -ForegroundColor cyan " The SMC Email Discovery process is about to begin gathering data. "
    Write-host -ForegroundColor cyan " It will take some time to complete depending on the size of your environment. "
    Write-host " "
    Write-host -ForegroundColor cyan "==============================================================================="
    Write-host " "
    Write-host -ForegroundColor Magenta "The configuration files will be stored on the Desktop in \SMC-Email-Discovery"
    $OrigLocation = Get-Location
    $makefolder = New-Item -ItemType directory -Path "$home\desktop\SMC-Email-Discovery"
    sleep 2
    Set-Location -Path "$home\desktop\SMC-Email-Discovery"
	$Location = Get-Location
    Set-ADServerSettings -ViewEntireForest $true
    Write-host " "
    Write-host -ForegroundColor Yellow "Set ViewEntireForest to true successful."
    Write-host " "
    Write-host -ForegroundColor Yellow "Collecting data now, please be patient. This will take some time to complete."
    # TRANSPORT XML
	Write-host -ForegroundColor White "...collecting Transport configuration (1 of 10). ActiveSync next..."
	    Get-AcceptedDomain -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "AcceptedDomains.xml"
	    Get-EdgeSubscription -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "EdgeSubscriptions.xml"
	    If ($exver -like "*15.*") {Get-MailboxTransportService -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "MailboxTransportService.xml"}
	    Get-TransportAgent -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "TransportAgent.xml"
	    Get-TransportConfig -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "TransportConfig.xml"
	    Get-TransportRule -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "TransportRules.xml"
	    If ($exver -like "*15.*") {Get-TransportService -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "TransportService.xml"}
	    Get-JournalRule -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "JournalRules.xml"
	    Get-DeliveryAgentConnector -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "DeliveryAgentConnector.xml"
	    Get-EmailAddressPolicy -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "EmailAddressPolicies.xml"
	    Get-ReceiveConnector -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ReceiveConnectors.xml"
	    Get-SendConnector -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "SendConnectors.xml"
	    Get-RemoteDomain -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "RemoteDomains.xml"
	    Test-EdgeSynchronization -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "TestEdgeSync.xml"
    # ACTIVESYNC XML
	Write-host -ForegroundColor White "...collecting ActiveSync configuration (2 of 10). Virtual Directories next..."
	    Get-ActiveSyncOrganizationSettings -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ActiveSyncOrganizationSettings.xml"
	    Get-MobileDeviceMailboxPolicy -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "MobileDeviceMailboxPolicy.xml"
    # VIRTUAL DIRECTORIES XML
	Write-host -ForegroundColor White "...collecting Virtual Directory configuration (3 of 10). Active Directory next..."
	    Get-AutodiscoverVirtualDirectory -ADPropertiesOnly -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "AutoDiscoverVirtualDirectories.xml"
	    Get-EcpVirtualDirectory -ADPropertiesOnly -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ECPVirtualDirectories.xml"
	    Get-MapiVirtualDirectory -ADPropertiesOnly -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "MapiVirtualDirectories.xml"
	    Get-OabVirtualDirectory -ADPropertiesOnly -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "OABVirtualDirectories.xml"
	    Get-OwaVirtualDirectory -ADPropertiesOnly -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "OWAVirtualDirectories.xml"
	    Get-PowerShellVirtualDirectory -ADPropertiesOnly -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "PowerShellVirtualDirectories.xml"
	    Get-WebServicesVirtualDirectory -ADPropertiesOnly -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "WebServicesVirtualDirectories.xml"
	    Get-ActiveSyncVirtualDirectory -ADPropertiesOnly -WarningAction SilentlyContinue | Select-Object * | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ActiveSyncVirtualDirectories.xml"
    # AD XML
	Write-host -ForegroundColor White "...collecting AD configuration (4 of 10). Mailbox next..."
	    Get-ADSite -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ADSites.xml"
	    Get-ADSiteLink -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ADSiteLinks.xml"
	    Get-DomainController -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "DomainControllers.xml"
    #MAILBOX XML
	Write-host -ForegroundColor White "...collecting Mailbox configuration (5 of 10). Client Access next..."
	    Get-DatabaseAvailabilityGroup -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "DAGInfo.xml"
	    Get-DatabaseAvailabilityGroupNetwork -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "DAGNetworkInfo.xml"
	    Get-MailboxDatabase -status -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml  "MailboxDBInfo.xml"
	    Get-MailboxServer -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "MailboxServers.xml"  
	    Get-SiteMailbox -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "SiteMailbox.xml"
	    Get-RetentionPolicy -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "RetentionPolicies.xml"
	    Get-RetentionPolicyTag -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "RetentionPolicyTags.xml"
	    Get-PublicFolderDatabase -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "PublicFolderDatabases.xml"
	    If ($exver -like "*15.*") {Get-Mailbox -PublicFolder -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "PublicFolderMailboxes.xml"}
	    Get-Mailbox -Arbitration -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ArbitrationMailboxes.xml"
	    #(Get-Mailbox).count | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "MailboxCount.xml"
	    #(Get-DistributionGroup).count | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "DistributionGroupCount.xml"
    #CLIENTACCESS XML
	Write-host -ForegroundColor White "...collecting Client Access configuration (6 of 10). Administration next..."
	    Get-ClientAccessArray -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "CASArrayInfo.xml"
	    Get-ClientAccessServer -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ClientAccessServers.xml"
	    Get-RpcClientAccess -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "RPCClientAccess.xml"
	    Get-OutlookAnywhere -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "OutlookAnywhere.xml"
	    Get-PopSettings -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "PopSettings.xml"
	    Get-ImapSettings -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ImapSettings.xml"
	    Get-ThrottlingPolicy -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ThrottlingPolicy.xml"
    #ADMINISTRATION XML
	Write-host -ForegroundColor White "...collecting Administration configuration (7 of 10). Address Book/List next..."
	    Get-AdminAuditLogConfig -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "AdminAuditLogConfig.xml"
	    Get-ManagementRole -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ManagementRoles.xml"
	    #Get-ManagementRoleEntry "*\*" -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ManagementRoleEntries.xml"
	    Get-ManagementRoleAssignment -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ManagementRoleAssignments.xml"
	    Get-RoleGroup -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "RoleGroups.xml"
	    Get-ManagementScope -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ManagementScopes.xml"
    #ADDRESS BOOK/LIST XML
	Write-host -ForegroundColor White "...collecting Address Book/List configuration (8 of 10). Availability next..."
	    Get-AddressBookPolicy -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "AddressBookPolicies.xml"
	    Get-GlobalAddressList -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "GlobalAddressList.xml"
    #AVAILABILITY XML
	Write-host -ForegroundColor White "...collecting Availability configuration (9 of 10). General next..."
	    Get-FederationTrust -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "FederationTrust.xml"
	    Get-AvailabilityConfig -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "AvailabilityConfig.xml"
	    Get-AvailabilityAddressSpace -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "AvailabilityAddressSpace.xml"
	    Get-IntraOrganizationConfiguration -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "IntraOrganizationalConfig.xml"
	    Get-FederatedOrganizationIdentifier -IncludeExtendedDomainInfo: $false -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "FederationOrgIdentifier.xml"
	    Get-OrganizationRelationship -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "OrganizationRelationships.xml"
    #GENERAL XML
	Write-host -ForegroundColor White "...collecting General configuration (10 of 10)."
	    Get-ExchangeServer -status -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ExchangeServers.xml"
	    Get-ExchangeCertificate -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "ExchangeCertificates.xml"
	    Get-OrganizationConfig -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "OrganizationConfig.xml"
	    If ($exver -like "*15.*") {Get-SmimeConfig| Select-Object * -ExcludeProperty SerializationData | Export-Clixml "SmimeConfig.xml"}
	    If ($exver -like "*15.*") {Get-AuthConfig -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml  "AuthConfig.xml"}
	    Get-HybridConfiguration -WarningAction SilentlyContinue | Select-Object * -ExcludeProperty SerializationData | Export-Clixml "HybridConfig.xml"
	Write-Host -ForegroundColor Green "Exchange On-Premises configuration collection complete."
}
#Prompt for EXO collection if SMC-EXO-Hybrid-Discovery-2.ps1 file exists:
$ErrorActionPreference = �Stop�
If (Test-Path "$ScriptPath\SMC-EXO-Hybrid-Discovery-2.ps1") {
	if(test-path variable:psversiontable) # test if powershell V2
		{
		    add-type -assemblyname 'System.windows.Forms'
		}
	else
		{
		    [void] [Reflection.Assembly]::LoadWithPartialName('System.windows.Forms')
		}
	$result = [System.Windows.Forms.MessageBox]::Show('Would you like to collect Exchange Online (EXO) configuration?', 'Hybrid EXO Discovery:', [System.Windows.Forms.MessageBoxButtons]::YesNo)
	$ErrorActionPreference = 'SilentlyContinue'
	if($result -eq [System.Windows.Forms.DialogResult]::Yes) {
		Write-host " "
		Write-host -ForegroundColor Yellow "Connecting to EXO..."
		$env:payload = "$ScriptPath\SMC-EXO-Hybrid-Discovery-2.ps1 '$ScriptPath'"
		start-process -wait powershell.exe -argumentlist $env:payload
		Write-host -ForegroundColor Green "EXO Config Collection script exited."
		Write-host " "
	}
}
$endtime = get-date
$totaltime = ($endtime - $starttime).Minutes
zipAllIt
#reset
Set-Location $OrigLocation
$ErrorActionPreference = $old_ErrorActionPreference
write-host ""
#End

# SIG # Begin signature block
# MIIjrQYJKoZIhvcNAQcCoIIjnjCCI5oCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCA0O7SJMjJcnkV7
# kjX2XJfbp0sux2H63D6TeM9EZHvTBaCCDZowggYYMIIEAKADAgECAhMzAAACRKv5
# FGhmd6OiAAAAAAJEMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjEwODEyMTczODM1WhcNMjIwOTE1MTczODM1WjCBiDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWlj
# cm9zb2Z0IDNyZCBQYXJ0eSBBcHBsaWNhdGlvbiBDb21wb25lbnQwggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQCwzUai/r+FNF5K1JNkRMJxSz6JIvIfH9Ib
# NR8/3Q1/JIClI8sdX//mpKbiDRIn3BQ/q7lHoGYR6qjCXVxHbO1COlBo2YreHpVb
# Kf8AYkDmSOiA3jx7lJnKRxNDJDAM8j7MkanUHHlbChZFFVW6mnBW0HKVdM2W2p1c
# saCT8HjGvJKlfFBGj/cZbVC1n+fav/yrRK1sucxueSki0DTuiS/NLXbWQI2BnAo/
# iSUvQhOhVihZ0Q0PuCuwrQxUTxiS5g8Tp8v/rwkCBumlnuHfblLD6Gs3U78loWVN
# 9bZlh1W/qU2r86kHSBk3lIGCEk9QfHy4pQMvkNkIyGs6TVdsgmyrAgMBAAGjggGC
# MIIBfjAfBgNVHSUEGDAWBgorBgEEAYI3TBEBBggrBgEFBQcDAzAdBgNVHQ4EFgQU
# m8lV9bB/iidqnKSW6jWBahbwQ74wVAYDVR0RBE0wS6RJMEcxLTArBgNVBAsTJE1p
# Y3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEWMBQGA1UEBRMNMjMx
# NTIyKzQ2NjQxMzAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzcitW2oynUClTBUBgNV
# HR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2Ny
# bC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEGCCsGAQUFBwEBBFUw
# UzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9j
# ZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0MAwGA1UdEwEB/wQC
# MAAwDQYJKoZIhvcNAQELBQADggIBABDZCjHgdc3BNnV5L6eF7q2DieAoO76mgccC
# 1To5CRkkAxKZURF5KlPLZibjqmfnMZ2aVDzrSW5zxg8faWVlOOJ2Zh9moVhvIVSv
# vRDfL9E3eCkjVOk1LP3LSomITDZV/GdQ4cgNOueGGFRFoWG+RY5zLAkacpa1BxEx
# k/RA4qbBbwG9CbI+9E2g7ZTL/oK4Fm5TldW5zzXFQ9AoKpFp3miHRLwBKQEtptXf
# Ko1bJWB/uA0M87sWnKfpl8dgomi1ZhbnSS1cfG3eiz+4A91MRtQ4qqgqegsdrqMa
# 0xGxDefnMs2EutksEKQR9wtyuXZyG0HGAkmkuG36w0K1zxcdJLmMqHucnzQh5mCw
# od7JTVQtomeI6x/aWLTQ6d0PEhS3RkspTGJQW2nH6gI5R4U/Qr4vRqjPUK3dCf8r
# mpt2zTrvXZKYG5IOZ6LJJdCSIVQF8c6KkND6/X1MaAdan4oEZATgwrVFE9lhY1jv
# LAfi8YfRoebg5895jqg6924GCa7JzxkWiy9h5U5cIFLfoeLi6aLZ3m7EFyIxCpWU
# J4M9f2Rf7r9HLsBEe8VdStRTQPfnOBY5pR941DzxuwLs0w2yrPc3wVip0PXtl9qB
# z83IOl2ndypwNulkElMMhab9ju7Y+cRhGod8txO9AcNMjvL2Jxs3rtb6Z2LhO17U
# FqrtAEWnMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkqhkiG9w0BAQsFADCB
# iDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMp
# TWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTEwHhcNMTEw
# NzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQgQ29kZSBTaWduaW5n
# IFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAq/D6chAc
# Lq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03a8YS2AvwOMKZBrDI
# OdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akrrnoJr9eWWcpgGgXp
# ZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0RrrgOGSsbmQ1eKagYw8t
# 00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy4BI6t0le2O3tQ5GD
# 2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9sbKvkjh+0p2ALPVO
# VpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAhdCVfGCi2zCcoOCWY
# OUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8kA/DRelsv1SPjcF0P
# UUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTBw3J64HLnJN+/RpnF
# 78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmnEyimp31ngOaKYnhf
# si+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90lfdu+HggWCwTXWCV
# mj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0wggHpMBAGCSsGAQQB
# gjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2oynUClTAZBgkrBgEE
# AYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB
# /zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNVHR8EUzBRME+g
# TaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9N
# aWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUFBwEBBFIwUDBO
# BggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9jZXJ0cy9N
# aWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNVHSAEgZcwgZQwgZEG
# CSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsGAQUFBwICMDQeMiAd
# AEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABlAG0AZQBuAHQALiAd
# MA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKbC5YR4WOSmUKWfdJ5
# DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11lhJB9i0ZQVdgMknzS
# Gksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6I/MTfaaQdION9Msm
# AkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0wI/zRive/DvQvTXv
# biWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560STkKxgrCxq2u5bLZ
# 2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQamASooPoI/E01mC8Cz
# TfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGaJ+HNpZfQ7l1jQeNb
# B5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ahXJbYANahRr1Z85el
# CUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA9Z74v2u3S5fi63V4
# GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33VtY5E90Z1WTk+/gFci
# oXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMT
# DXpQzTGCFWkwghVlAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIw
# MTECEzMAAAJEq/kUaGZ3o6IAAAAAAkQwDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIHL0NmIAvr6o8sGU4Ec+HdLNKcoYOyIt7SbRDEz4
# En1iMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpo
# dHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0BAQEFAASCAQCcVDxT
# F2BVu4YDz3R9WPAOr15WjZS4LmKKDbMVuRUPi7vXavLaD81EqSrSxWX+BkSuLwP3
# 0KO74TCB4k4/D98NQ6AXDI1xTsOfkgHysLbwrZjfu4ppERgu7V7ZLQVnGLkQSZCL
# aM0A/Ep1HrpgSN5JevMaCUDeGCPkm01eGNE+vnC92RlKjZ1orTBlsiKdfNu7RfLE
# zs3Y8M3aTclTJ8ds20Nra/vtrQ6Mlc3Gx6Z777nqJA0Sb7L+rQuVtB8Zhm+91KuF
# ttBcfpiSzELY0c2SgHfBNeEPdVnguejYcpYC5qJfSn45ZkZgez4rXOGcyNjaQMXN
# xWzuPkZ9m3MLU9vVoYIS8TCCEu0GCisGAQQBgjcDAwExghLdMIIS2QYJKoZIhvcN
# AQcCoIISyjCCEsYCAQMxDzANBglghkgBZQMEAgEFADCCAVUGCyqGSIb3DQEJEAEE
# oIIBRASCAUAwggE8AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIKzx
# Yw7X/jfK7nxZyqTwTJvlMFgyQQeKEnfOOk+JEFV0AgZiD/Zx6dMYEzIwMjIwMzA0
# MjIzNTM5LjM5OVowBIACAfSggdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGNzdGLUUzNTYtNUJB
# RTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCDkQwggT1
# MIID3aADAgECAhMzAAABXp0px1+HBaHqAAAAAAFeMA0GCSqGSIb3DQEBCwUAMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIxMDExNDE5MDIxOVoXDTIy
# MDQxMTE5MDIxOVowgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNvMSYw
# JAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGNzdGLUUzNTYtNUJBRTElMCMGA1UEAxMc
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCASIwDQYJKoZIhvcNAQEBBQAD
# ggEPADCCAQoCggEBAJrTI4OQehn3oKp2zuh6WP2Zib/Dxw/srLeeyTb9ed7PX+fL
# g7zBA0yl6ivF2n6lauGH8W7EBwRPEv7ZCSXwXgYZ6GGaH8aU+OrDXAbc4BXTO5Xn
# LGwSbaye9R2+uQHdCJmaMtz/lEBWUK5xvHoj0TUrXOZdZ/vv7TqMWA4h1AT1w/JB
# R4kHtV1i8KWdlQ+dZX/gNHpA72IoLoOmpImbGRzcGQ4Z2Kzq4eMB9wjaFRV1JF/w
# z1hLFIjGtlU3eGjRBiBEEVI7UEMMSvI4rK+CfLAIZnULu7SzlIfqSU3R0pSNUahw
# pWdCiB6fKzIq94Z+9888moQuo95RAPmzHQW1MI0CAwEAAaOCARswggEXMB0GA1Ud
# DgQWBBSqcny6Dd1L5VTCEACezlR41fgfKzAfBgNVHSMEGDAWgBTVYzpcijGQ80N7
# fEYbxTNoWoVtVTBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29m
# dC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNUaW1TdGFQQ0FfMjAxMC0wNy0wMS5j
# cmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpL2NlcnRzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAxLmNydDAM
# BgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEBCwUA
# A4IBAQB/IfxZhMYkBMqRmXnh/Vit4bfxyioAlr7HJ1XDSHTIvRwDD1PGr0upZE/v
# rrI/QN/1Wi6vDcKmnJ2r7Xj6pWZOZqc9Bp+uBvpPaulue4stu3TqKTc9Fu2K5ibc
# tpF4oHPfZ+IKeChop+Mk9g7N5llHzv0aCDiaM0w2aAT3rj3QHQS8ijnQ5/qhtzwo
# 1AoUnV1y2urWwX5aHdUzaoeAJrvnf2ee89Kf4ycjjyafNJSUp/qaXBlbjMu90vNu
# bJstdSxOtvwcxeeHP6ZaYbTl2cOla4cokiPU+BUjIZA/t/IZfYoazMGmBtLWFJZd
# C9LYWWmLLsNJ2W21qkeSSpEAw4pmMIIGcTCCBFmgAwIBAgIKYQmBKgAAAAAAAjAN
# BgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9y
# aXR5IDIwMTAwHhcNMTAwNzAxMjEzNjU1WhcNMjUwNzAxMjE0NjU1WjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBAKkdDbx3EYo6IOz8E5f1+n9plGt0VBDVpQoAgoX77XxoSyxfxcPlYcJ2
# tz5mK1vwFVMnBDEfQRsalR3OCROOfGEwWbEwRA/xYIiEVEMM1024OAizQt2TrNZz
# MFcmgqNFDdDq9UeBzb8kYDJYYEbyWEeGMoQedGFnkV+BVLHPk0ySwcSmXdFhE24o
# xhr5hoC732H8RsEnHSRnEnIaIYqvS2SJUGKxXf13Hz3wV3WsvYpCTUBR0Q+cBj5n
# f/VmwAOWRH7v0Ev9buWayrGo8noqCjHw2k4GkbaICDXoeByw6ZnNPOcvRLqn9Nxk
# vaQBwSAJk3jN/LzAyURdXhacAQVPIk0CAwEAAaOCAeYwggHiMBAGCSsGAQQBgjcV
# AQQDAgEAMB0GA1UdDgQWBBTVYzpcijGQ80N7fEYbxTNoWoVtVTAZBgkrBgEEAYI3
# FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAf
# BgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEugSaBH
# hkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNS
# b29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsGAQUF
# BzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0Nl
# ckF1dF8yMDEwLTA2LTIzLmNydDCBoAYDVR0gAQH/BIGVMIGSMIGPBgkrBgEEAYI3
# LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9QS0kv
# ZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBs
# AF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcN
# AQELBQADggIBAAfmiFEN4sbgmD+BcQM9naOhIW+z66bM9TG+zwXiqf76V20ZMLPC
# xWbJat/15/B4vceoniXj+bzta1RXCCtRgkQS+7lTjMz0YBKKdsxAQEGb3FwX/1z5
# Xhc1mCRWS3TvQhDIr79/xn/yN31aPxzymXlKkVIArzgPF/UveYFl2am1a+THzvbK
# egBvSzBEJCI8z+0DpZaPWSm8tv0E4XCfMkon/VWvL/625Y4zu2JfmttXQOnxzplm
# kIz/amJ/3cVKC5Em4jnsGUpxY517IW3DnKOiPPp/fZZqkHimbdLhnPkd/DjYlPTG
# pQqWhqS9nhquBEKDuLWAmyI4ILUl5WTs9/S/fmNZJQ96LjlXdqJxqgaKD4kWumGn
# Ecua2A5HmoDF0M2n0O99g/DhO3EJ3110mCIIYdqwUB5vvfHhAN/nMQekkzr3ZUd4
# 6PioSKv33nJ+YWtvd6mBy6cJrDm77MbL2IK0cs0d9LiFAR6A+xuJKlQ5slvayA1V
# mXqHczsI5pgt6o3gMy4SKfXAL1QnIffIrE7aKLixqduWsqdCosnPGUFN4Ib5Kpqj
# EWYw07t0MkvfY3v1mYovG8chr1m1rtxEPJdQcdeh0sVV42neV8HR3jDA/czmTfsN
# v11P6Z0eGTgvvM9YBS7vDaBQNdrvCScc1bN+NR4Iuto229Nfj950iEkSoYIC0jCC
# AjsCAQEwgfyhgdSkgdEwgc4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1ZXJ0byBSaWNv
# MSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGNzdGLUUzNTYtNUJBRTElMCMGA1UE
# AxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUA
# VkmPV/8hZVS9FzbtoX2x3Z2xYyqggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOXM6VwwIhgPMjAyMjAzMDQyMzM5
# MDhaGA8yMDIyMDMwNTIzMzkwOFowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5czp
# XAIBADAKAgEAAgIhcgIB/zAHAgEAAgIRszAKAgUA5c463AIBADA2BgorBgEEAYRZ
# CgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0G
# CSqGSIb3DQEBBQUAA4GBAJWE+kHcKovEtMTBp7+S3U2r4fXZvkrv49txTmnz8RaT
# wKQMV8HB6JQPBVFzkKOUbUGy/mpg432qw+40N2sfI+1qz5/XeyJppAhAClaBSlel
# w+KXyNv30CsqRZ285oMQ8U+/NArRtqco7yIH/KO1hkvvrxTyeijHlvATxbmXCUJ6
# MYIDDTCCAwkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMA
# AAFenSnHX4cFoeoAAAAAAV4wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJ
# AzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgqRdFLOzSChNRi8PcCWY1
# 9+El6tmzW9NzLqdzM4rypPMwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCB+
# 5YTslNSXjuB+5mQDTKRkM7prkewhXnevXpLv8RLT4jCBmDCBgKR+MHwxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29m
# dCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABXp0px1+HBaHqAAAAAAFeMCIEIDsN
# e/pZpc0cWUTkW97iAied2wyRiZRzQbB8iAFazoTmMA0GCSqGSIb3DQEBCwUABIIB
# ABndCbs9OWSvSpN2hMMzrnpyvqAKVFWz3NENwb5nlEbPpA96AxhxJQpbb6r5DuWO
# DPFYERIgwbeuLffhJ4ilOaFImzMGO3dtxa50tigMADfIImSevpQ/ylWa1KjHSCUo
# aJ6DeMlg02u5ET4hxgHHkHij9mIqIHiDAY7IquMuhyPW1UDmYZnlxdK7N6sAQpDY
# oh7EClnPAhdqJgvIXfo/hA4RnEszuufvScdWVc+hkw1wZSqf9eFEl1lxGdkgqZof
# uCLQen/xnFgNyOxeO3a/5ftmrOVWwjhUYiMwuooB4r/Fd72WjWm6gWCmiZ72C/IB
# w95v0MERFb9cggrW32qBp/Q=
# SIG # End signature block
