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

//**********************************************************************​
.SYNOPSIS
  Connect to Exchange Online or MSOnline via PowerShell
 
.DESCRIPTION
  This script will prompt for your Office 365 tenant credentials and connect you to Exchange Online and MSOnline via remote PowerShell
#>

[CmdletBinding()]
param(
	[Parameter(Mandatory=$false)]
	[string]$ScriptLocationPath
)
#Make sure this script is NOT running in Exchange shell
	$modules = get-module
	Foreach ($module in $modules) {
		If (($module.ModuleType -eq "Script") -and ($module.Version -eq "1.0")) {
			$commands = $module.ExportedCommands
		}
	}
	If ($commands.count -gt 0) { 
		If ($commands.containsKey("Get-Mailbox")) {
			Write-host;Write-Host -ForegroundColor Magenta "The SMC-EXO-Discovery-2.ps1 script should NOT be executed from within the Exchange Mangement Shell (EMS)."
			Write-Host -ForegroundColor Red " -> Run SMC-EXO-Discovery-2.ps1 separately from a generic PowerShell session without EMS module loaded. <- "
			Write-Host -ForegroundColor Yellow "      Standby...opening a new PowerShell session for you....."
			Write-host;sleep 7;
			start-process powershell.exe
			Exit
		}
	}

#Variables
$old_ErrorActionPreference = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
$execpol = get-executionpolicy
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
$ConnectMSO="false"
$ConnectEXO="true"
$starttime = get-date
$OrigLocation = Get-Location
Set-Location -Path "$home\desktop\SMC-Email-Discovery"
$Location = Get-Location
$result1 = $null
$result2 = $null
#Temporary workaround for DE keyboard locale error 
	If ($PSculture -eq "de-AT" -or $PSculture -eq "de-DE") {
		$CopyKey = "Strg+C"
		$PasteKey = "Strg+V"}
	Else {
		$CopyKey = "Ctrl+C"
		$PasteKey = "Ctrl+V"}

#Ensure EXOv2 Module is installed
If ($ConnectEXO -eq "true") {
	Import-Module ExchangeOnlineManagement
	$ErrorActionPreference = ‘Stop’
	If (!(Get-Module ExchangeOnlineManagement)) {
			write-host "";write-host "";Write-Host -ForegroundColor Red "ERROR: Unable to retrieve EXO configuration!";write-host ""
            Write-Host -ForegroundColor Yellow "This EXO discovery script requires the EXOv2 Module, please visit: https://www.powershellgallery.com/packages/ExchangeOnlineManagement"
            sleep 30
            Exit
		}
	Else {
		#Login to EXO and collect info
		Write-Host "";Write-Host -ForegroundColor CYAN "Ready to collect EXO configuration, please logon to EXO..."; Write-host " "
		Connect-ExchangeOnline
		Write-host " "
		Write-Host -ForegroundColor Green "Successfully connected to Exchange Online"; Write-host " "
		Write-Host -ForegroundColor Yellow "Collecting EXO configuration...please wait..."; Write-host " "

		#EXO XML
		Get-OnPremisesOrganization -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_OnPremOrg.xml"
		Get-FederatedOrganizationIdentifier -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -IncludeExtendedDomainInfo: $false | Export-Clixml "O365_FederationOrgIdentifier.xml"
		Get-FederationTrust -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_FedTrust.xml"
		Get-OrganizationRelationship -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_OrgRelationships.xml"
		Get-OrganizationConfig -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_OrganizationConfig.xml"
		Get-InboundConnector -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_InBoundConnector.xml"
		Get-OutboundConnector -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_OutboundConnector.xml"
		Get-AcceptedDomain -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_AcceptedDomains.xml"
		Get-RemoteDomain -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_RemoteDomains.xml"
		Get-TransportConfig -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_TransportConfig.xml"
		Get-TransportRule -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_TransportRules.xml"
		Get-JournalRule -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_JournalRules.xml"
		Get-MigrationConfig -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_MigrationConfig.xml"
		Get-MigrationEndpoint -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_MigrationEndpoint.xml"
		Get-OMEConfiguration -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_OMEConfiguration.xml"
		Get-MailboxPlan -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_MailboxPlan.xml"
		Get-CASMailboxPlan -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_CASMailboxPlan.xml"
		Get-AddressList -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_AddressList.xml"
		Get-ActiveSyncDeviceAccessRule -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_ActiveSyncDeviceAccessRule.xml"
		Get-ActiveSyncMailboxPolicy -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_ActiveSyncMailboxPolicy.xml"
		Get-ActiveSyncOrganizationSettings -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_ActiveSyncOrganizationSettings.xml"
		Get-AdminAuditLogConfig -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_AdminAuditLogConfig.xml"
		Get-AntiPhishPolicy -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_AntiPhishPolicy.xml"
		Get-AtpPolicyForO365 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_AtpPolicyForO365.xml"
		Get-AuthServer -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_AuthServer.xml"
		Get-ClientAccessRule -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_ClientAccessRule.xml"
		Get-DlpPolicy -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_DlpPolicy.xml"
		Get-IRMConfiguration -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_IRMConfiguration.xml"
		Get-RetentionPolicy -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_RetentionPolicy.xml"
		Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_SafeAttachmentsPolicy.xml"
		Get-SafeLinksPolicy -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_SafeLinksPolicy.xml"
		Get-SmimeConfig -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_SmimeConfig.xml"
		Get-SharingPolicy -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_SharingPolicy.xml"
		Get-SyncConfig -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Export-Clixml "O365_SyncConfig.xml"
	}
}
#Optional MSOL Config
#Check modules and connect
If ($ConnectMSO-eq "true"){
	$ErrorActionPreference = ‘Stop’
	If (!(Get-Module -Name MSOnline)) {
		Try {
			Import-Module -Name MSOnline
		}
		Catch {
			Write-Host "This EXO discovery script requires the MSOnline to collect MSOL config...cancelling MSOL onfig collection."
		}
	}
	Else {
		#Login to MSO
		Write-Host -ForegroundColor CYAN "Ready to collect MSOL configuration, please logon to MSOL..."; Write-host " "
		Connect-MsolService
		Write-Host -ForegroundColor Green "Successfully connected to MSOL"; Write-host " "
		Write-Host -ForegroundColor Yellow "Collecting MSOL configuration...please wait..."; Write-host " "

		#Get MSOL Config XML
		Get-MsolDomain -ErrorAction Ignore -WarningAction Ignore | Export-Clixml "O365_MsolDomains.xml"
		Get-MsolSubscription -ErrorAction Ignore -WarningAction Ignore | Export-Clixml "O365_MsolSubscriptions.xml"
		Get-MsolAccountSku -ErrorAction Ignore -WarningAction Ignore | Export-Clixml "O365_MsolAccountSku.xml"
		Get-MsolCompanyInformation -ErrorAction Ignore -WarningAction Ignore | Export-Clixml "O365_MsolCompanyInformation.xml"
		Get-MsolDirSyncConfiguration -ErrorAction Ignore -WarningAction Ignore | Export-Clixml "O365_MsolDirSyncConfigurationu.xml"
		Get-MsolDirSyncFeatures -ErrorAction Ignore -WarningAction Ignore | Export-Clixml "O365_MsolDirSyncFeatures.xml"
		Get-AzureADDomain -ErrorAction Ignore -WarningAction Ignore | Export-Clixml "O365_AzureADDomains.xml"
		Get-AzureADSubscribedSku -ErrorAction Ignore -WarningAction Ignore | Export-Clixml "O365_AzureADSubscribedSku.xml"
		Get-AzureADTenantDetail -ErrorAction Ignore -WarningAction Ignore | Export-Clixml "O365_AzureADTenantDetail.xml"
	}
}

Write-Host -ForegroundColor Green "Collecting EXO and/or MSOL configuration is complete!"
start-sleep 8
#reset
Set-Location $OrigLocation
$ErrorActionPreference = $old_ErrorActionPreference
write-host ""
#End

# SIG # Begin signature block
# MIIn1AYJKoZIhvcNAQcCoIInxTCCJ8ECAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDzY6Go/85PLaDu
# BEl1XZ7wILaPyRZgiIHLGydBduVgA6CCDZowggYYMIIEAKADAgECAhMzAAACRKv5
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
# DXpQzTGCGZAwghmMAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIw
# MTECEzMAAAJEq/kUaGZ3o6IAAAAAAkQwDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEICE3L3OvIHDBdHSsjmutOUTzMlZaQXdd2hhJ48gA
# ZmD+MEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpo
# dHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0BAQEFAASCAQAuHsN7
# wr9vBN2225JAQ7d/BT+l3Up/J7LlfPQr5+o0CGWDz8l/XJDjEM4xn89AjMEm3K+2
# S2bqWPGAsXrMpJFrfGRwb3C6L9bCB9a4QpaOFrU8VzqnFA1bv30D/Xps9QEEQUId
# CI2aIHBvT4RHjqOKSL6PsuUtaqOZzfqPmBv7epLTBKz91wHeA/KhqEITT1vXSVhz
# 6hqOIMXUQ7PXHcNPwIDDIdxcvUeEPnrAOS7MvVv5sBGuAVmL/5ywuSoz+nVdjOdf
# n29An68MvLSJrHIy3URi8AqPIJaGKuJ2yos2QGSalv7PjbFJfSBi7ENLwbfLjI8D
# vkDzVuaMhY8G4dYOoYIXGDCCFxQGCisGAQQBgjcDAwExghcEMIIXAAYJKoZIhvcN
# AQcCoIIW8TCCFu0CAQMxDzANBglghkgBZQMEAgEFADCCAVgGCyqGSIb3DQEJEAEE
# oIIBRwSCAUMwggE/AgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIF7e
# zqiv9j7j7gBQip9BdYwsVYgOhRvGaQGVMcsttzaUAgZiF5a3ZUkYEjIwMjIwMzA0
# MjIzNTExLjQ2WjAEgAIB9KCB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0
# aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpGQzQxLTRCRDQt
# RDIyMDElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaCCEWgw
# ggcUMIIE/KADAgECAhMzAAABjlnbRgCoEJTMAAEAAAGOMA0GCSqGSIb3DQEBCwUA
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTIxMTAyODE5Mjc0NVoX
# DTIzMDEyNjE5Mjc0NVowgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5n
# dG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9y
# YXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RkM0MS00QkQ0LUQyMjAxJTAj
# BgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3
# DQEBAQUAA4ICDwAwggIKAoICAQCqIwKro4zMtrnCu1x/sF/1/VZdb2Smps4HOA8m
# 9oYutkbu3CDCpNFZ/UWSOkkoE4blA8hHLtrogVUDLRb60FoVfgifgNsF/a0a5vJj
# 36FFT6FF7A8kfkJg6+k+HvsV8Yzrf46XBFenlgRHq0LRZEqfeavJam3gLAAO4a/Q
# sPZCOeGGC1FWJ2yIOef35ouMy41qlSGy0aoKvslxBm3Rms9Qdb9OpMnKZ5TV6qA2
# isRtN53pRDItpNUCaFc1BcMKF9rnbqdbtFDsvi1df0tzSiC6IJKQ+W7l2s0Do0zz
# P5RdA4AfFV8hBeaL5jdJXaGvZ1zFvL2eVPNi9/hkOvlalzC3u1N1EgmJtcexdYwq
# uY7OKWIYNOgvHfhr9y1kTg04ueWspBY31kb47HnNFqsrUSFKFqEzS5A2FvoEmOnf
# 5zR43MwUnaotmoOnb/diXlD7iT4wMctOKk/pUF3Fx1V93iaCtVPHdp87ko1+AyeA
# YZ+FJrAatpFbbwSGss6ymYjGKL3YTu+Odwna1yOEsKMECtWk+HdxkbmDdlXLmKIB
# qgNqzCk2CcwUArlSfWt4r4wWE+L2Iye9Q/C1MMMm3lgQPkMBPeYFTGnlAfe3tGFn
# AAk0tYu2lN4YXu5vzWxIpi/Zqt1rMB71ctLXS1Xag4+tyeIYnOVdbtU+/GpA3F7y
# UIMDbQIDAQABo4IBNjCCATIwHQYDVR0OBBYEFOxB+TP2BPjg3/kby80drJ6n5pXk
# MB8GA1UdIwQYMBaAFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBS
# oFCGTmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29m
# dCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRg
# MF4wXAYIKwYBBQUHMAKGUGh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# Y2VydHMvTWljcm9zb2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0
# MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQEL
# BQADggIBADVQr3HMh5OUqFJsufRt6RHmBiHpsHVdCmW4KoIDXmyRnftSKVoUnDz4
# aSUMvOU2FI/aY6I7NXIKrySSmqd9RzTVloF7NDGDvup6+PaIzKDf1gl96IIiHFg4
# W6DB6lis87wyUH+i579WEiINvV41hOU9Ka/elqWyC2StvSijQXS5aZfgRBUYpGjR
# QQ21l61UjFrQn0OlR2NBY94SH1wQz5GATbrnDlYBVv5Y3HSJaIXiJNsKatZpUQ5f
# 3Z02oGb1tPVTucbA3kLKCk0CARpietMzHU3gCPE5sAIM3kN28aW787QN8xZVzqqT
# qIoMULpaldBKQyWuVcgj82Gn7T6ehTq18Skcou3t9ib2h/mL9CiZwLCj96SI4KNi
# S2nf3ei+gLU7a4u1sucxWUTmtoEsE1Jsg1npAvGIDjWVedVUsjMOKFQvwxT0Iy8b
# ix1uGTYVfzO+uw/k94EjDV9p6cxm7PRXdRcK1Tk6THl+aKhaKItlIKLWWNrFf4ET
# BCKKcKL68Tn1tNgjkVu5Hy0O4YuJW78lKlUVevNYw/YqfXWwIsAYSOolhSY7W1Fj
# b0p3sdwiPaeJIHQ9A4KNiWcKfLCcOKepLUJe9GyKyNWVLVGnhOa6Sz6kbGIwbMXn
# zNxv6GgUrI424vdv62DFMDPewXcFVf26T0zkX44Sh7IvIZ8t6Q0CMIIHcTCCBVmg
# AwIBAgITMwAAABXF52ueAptJmQAAAAAAFTANBgkqhkiG9w0BAQsFADCBiDELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9z
# b2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMjEwOTMwMTgy
# MjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOThpkzntHIhC3miy9ck
# eb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDivbk+F2Az/1xPx2b3lVNxWuJ+Slr+
# uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5GawcU88V29YZQ3MFEyHFcUTE3oAo4
# bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUmZNqYO7oaezOtgFt+jBAcnVL+tuhi
# JdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjksUZzpcGkNyjYtcI4xyDUoveO0hyTD
# 4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvrg0XnRm7KMtXAhjBcTyziYrLNueKN
# iOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31BmkZ1zcRfNN0Sidb9pSB9fvzZnkXf
# tnIv231fgLrbqn427DZM9ituqBJR6L8FA6PRc6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8
# P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRRRuLRvWoYWmEBc8pnol7XKHYC4jMY
# ctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSRlJTYuVD5C4lh8zYGNRiER9vcG9H9
# stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflSxIUXk8A8FdsaN8cIFRg/eKtFtvUe
# h17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHdMIIB2TASBgkrBgEEAYI3FQEEBQID
# AQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSavoKRPEY1Kc8Q/y8E7jAdBgNVHQ4E
# FgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYDVR0gBFUwUzBRBgwrBgEEAYI3TIN9
# AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1UdJQQMMAoGCCsGAQUFBwMIMBkGCSsG
# AQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
# AQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0w
# S6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYI
# KwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCdVX38
# Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHixBpOXPTEztTnXwnE2P9pkbHzQdTlt
# uw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjYNi6cqYJWAAOwBb6J6Gngugnue99q
# b74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe53Z/zjj3G82jfZfakVqr3lbYoVSfQ
# JL1AoL8ZthISEV09J+BAljis9/kpicO8F7BUhUKz/AyeixmJ5/ALaoHCgRlCGVJ1
# ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QMvOyRgNI95ko+ZjtPu4b6MhrZlvSP
# 9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1APMdUbZ1jdEgssU5HLcEUBHG/ZPkk
# vnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsNn6Qo3GcZKCS6OEuabvshVGtqRRFH
# qfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFsc/4Ku+xBZj1p/cvBQUl+fpO+y/g7
# 5LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue10CgaiQuPNtq6TPmb/wrpNPgkNWcr
# 4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6gMTN9vMvpe784cETRkPHIqzqKOghi
# f9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm8qGCAtcwggJAAgEBMIIBAKGB2KSB
# 1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UE
# CxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQL
# Ex1UaGFsZXMgVFNTIEVTTjpGQzQxLTRCRDQtRDIyMDElMCMGA1UEAxMcTWljcm9z
# b2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEBMAcGBSsOAwIaAxUAPWIr6k9OEeqC
# lrnGw+aJiu5ZW4yggYMwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MDANBgkqhkiG9w0BAQUFAAIFAOXMoE4wIhgPMjAyMjAzMDQyMjI3MjZaGA8yMDIy
# MDMwNTIyMjcyNlowdzA9BgorBgEEAYRZCgQBMS8wLTAKAgUA5cygTgIBADAKAgEA
# AgILYgIB/zAHAgEAAgIRRzAKAgUA5c3xzgIBADA2BgorBgEEAYRZCgQCMSgwJjAM
# BgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIBAAIDAYagMA0GCSqGSIb3DQEB
# BQUAA4GBACyEA4HmdZuWmyR5yovrceaSl4RBcBVY3IehyjooM+qRC/wMYj3964e5
# gaZ5P6Whc5zXkGHRYJq5MS9nGYKJLatNy3cQAd3M1rftA0jrlHK2F1URauUoP0gF
# dR8YSYFj3vhyUKacgcJa5sUama1IN83ksuQgr8a+rBtkpHI7PWtAMYIEDTCCBAkC
# AQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQG
# A1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGOWdtGAKgQ
# lMwAAQAAAY4wDQYJYIZIAWUDBAIBBQCgggFKMBoGCSqGSIb3DQEJAzENBgsqhkiG
# 9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgECU91RmQQZ5XZHCvG8x9JR0OiA2bqhKS
# SD8d3atj9WYwgfoGCyqGSIb3DQEJEAIvMYHqMIHnMIHkMIG9BCC9BY8hO+KBpS5X
# n5/+VazcFdnAn+XWZ/7J6W7mdebEJTCBmDCBgKR+MHwxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0
# YW1wIFBDQSAyMDEwAhMzAAABjlnbRgCoEJTMAAEAAAGOMCIEIKwHnD5DEWMRQgWv
# cLSgIx2voS4CqnPLo7J3TWBfYJnKMA0GCSqGSIb3DQEBCwUABIICAJvGqmoCSJ2T
# Ydn5BaINLk2G3IjF3EMn/gKLqzKG4jF6ulbDaA0l35hkBiL593FoPAZXtdV1uGKx
# 1fovWchH0/NqcCL3CCXRYmsAqoJ60JoR27D8ijDl7ZjMedb9w+Kh3pTszRwHnvKb
# GMTkEvFJw9osx28a17d7aLNmsOVmne3FRhLqmy0K5/aPRQQtllXHzMKPNy0p6olO
# YoiUFHD+jZNV+fziIHHPlOSf1Kkl+AkNYbCjDcq6XRpgWq+fxOPKG2SVeUSrChS2
# oZWDyXD+y+ORNHYNqgv3ymJep/nsKjKOdtc1/eooiCD4bHVxipybj7Jk31/stSgt
# iyDoqOkGtYNQcZF3B/5CmS8Zxi+8k6mB9Wrk1SV+yKwk3jNT4QsgXbZLmKl0bYj4
# C2olL0aag6dy2mMeNVyQ48LPVY2XK+GKCSsGeZsb11me9vg22PYzp0GO+tNRoWT7
# pS6JreRWz3ziY+GntvUrlQ+gxApjxO9Qrbvi9P6FCwUGnxd89esC+A6/NGYKwxb0
# GuPs2dsY5TgCBd+8Q8ggOhOFeI79/sF3Bf7pUcj6ZRyhYHof/ut8c2rz198A3Oet
# 7Oh3CK16lJ3l/1B5H0VdCaaNCElsnZyP2G4b6cA06x17oSzq2DaPpAmnNXv2db0F
# ewnArAUDTwV81qs7sqa9qEnA5sj3+yAK
# SIG # End signature block
