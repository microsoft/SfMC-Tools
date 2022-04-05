#***********************************************************************
#
# Copyright (c) 2018 Microsoft Corporation. All rights reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#**********************************************************************​

<#  
.SYNOPSIS  
    This script collects various datasets useful in troubleshooting MRM policy issues.

.DESCRIPTION  
    Data collection script that will then collect mailbox information, MRM policy and tag information, and Managed Folder Assistant log events.
    The output will include an easy to read summary report as well as the full verbose output.

.NOTES  
    File Name  : MRMReport.ps1  
    Author     : Minh Nguyen - minhng@microsoft.com
    Requires   : run client as admin and on powershell v3 or higher

.PARAMETER user
    Require paramater
    Mailbox used to collect data

.PARAMETER mfa
    Optional parameter
    Used when you only want to collect managed folder assisant event logs and none of the other logs

.PARAMETER all
    Optional parameter
    Used when you want to collect all retention policy and tags in the organization
    This is normally left out and the script only collects data for the user

.OUTPUTS
    Various output files that can be found in c:\temp\MRM Report\<user>

    '<user>-Mailbox.txt' - Format listed output for Get-Mailbox of user
    '<user>-MailboxDiagnosticLogs-ExtendedProperties.txt' - Output of MailboxLog from 'Export-MailboxDiagnosticlogs -ExtendedProperties' cmdlet
    '<user>-MailboxDiagnosticLogs-MRMComponentLogs.txt' - Output of MailboxLog from 'Export-MailboxDiagnosticlogs -Component MRM' cmdlet
    '<user>-MailboxFolderStatisticsFULL.txt - Output of MailboxFolderStatistics logs for every folder in mailbox
    '<user>-MailboxFolderStatistics_Sizes_ItemCounts.txt - Filtered output of MailboxFolderStatistics logs for every folder to clearly display folder sizes and item counts
    '<user>-ArchiveMailbox.txt' - Format listed output for archive mailbox
    '<user>-ArchiveMailboxDiagnosticLogs-ExtendedProperties.txt' - Output of MailboxLog from 'Export-MailboxDiagnosticlogs -ExtendedProperties' cmdlet
    '<user>-ArchiveMailboxDiagnosticLogs-MRMComponentLogs.txt' - Output of MailboxLog from 'Export-MailboxDiagnosticlogs -Component MRM' cmdlet
    '<user>-ArchiveMailboxFolderStatisticsFULL.txt - Output of MailboxFolderStatistics logs for every folder in mailbox
    '<user>-ArchiveMailboxFolderStatistics_Sizes_ItemCounts.txt - Filtered output of MailboxFolderStatistics logs for every folder to clearly display folder sizes and item counts
    '<user>-MFAReport.txt' - Easy to read output of email lifecyle (Elc*) events when managed folder assistant processes a mailbox
    '<user>-RetentionPolicy.txt' - Format listed output of MRM policy that is assigned to user
    '<user>-RetentionPolicyTag.txt' - Easy to read format table and verbose format listed output of only retention tags on the MRM policy assigned to user, not all retention tags
    '<user>-SummaryReport.txt' - Easy to read output that compiles all relevant data needed to troubleshoot MRM issues for a user
    'All-RetentionPolicies.txt - Format listed output of all retention policies in the organization
    'All-RetentionPolicyTags.txt - Format table and format listed output of every retention tag in the organization

.SYNTAX EXAMPLES
    .\mrmreport.ps1 john.doe@contoso.com
    .\mrmreport.ps1 john.doe -mfa
    .\mrmreport.ps1 "john doe" -all

.LINKS  
    https://technet.microsoft.com/en-us/library/dd298086(v=exchg.160).aspx
    https://technet.microsoft.com/en-us/library/dd298009(v=exchg.160).aspx
    https://technet.microsoft.com/en-us/library/ff459236(v=exchg.160).aspx

.CHANGELOG

    04.18.2018 - Added archive mailbox logs (mailboxfolderstatistics/export-mailboxdiagnosticlogs)
                 Updated body to look cleaner and fixed several formatting errors in the summary report
    09.20.2016 - Added width adjustment for mailboxfolderstatistics log output to look cleaner
    09.02.2016 - Removed unneeded lines that didn't impact script
    08.23.2016 - Added export-mailboxdiagnosticlog for mrm component
    08.19.2016 - Added mailbox folder statistics log to include all folders
    08.03.2016 - Trimmed code and added Recoverable Items Stats to report
    07.20.2016 - Added formatting to MFA events report to make it compact and neater
#>
#requires -runasadministrator
#requires -version 3

[CmdletBinding(DefaultParameterSetName='user')]
Param(
    [Parameter(Mandatory=$True,Position=1)]
    [string]$user,
    [Parameter(Mandatory=$False,Position=2,ParameterSetName='-mfa')]
    [switch]$mfa = $false,
    [Parameter(Mandatory=$False,Position=2,ParameterSetName='-all')]
    [switch]$all = $false
)
$EAP = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
$global:FormatEnumerationLimit=-1
#check if user is valid, if not, get-mailbox will return user not found
if (Get-Mailbox $user)
{
    #create folder for files if it doesn't exist
    if (!(Test-Path -Path "c:\temp\MRM Report\$user" -ErrorAction SilentlyContinue )) {New-Item "c:\temp\MRM Report\$user" -Type Directory -ErrorAction SilentlyContinue | Out-Null}
    [string]$path = 'c:\temp\MRM Report\'+$user+'\'

    if ($mfa.IsPresent) #if switch is called, run export-mailboxdiagnosticlog to get latest managed folder assistant events only
    {
        if (Test-Path $path"$user-MailboxDiagnosticLogs-ExtendedProperties.txt") #if file exists, create new file labeled as 'Updated' and don't overwrite existing so they can be compared for differences
        {
            #pull mailboxdiagnosticlogs extended properties and check for mrm component logs
            (Export-MailboxDiagnosticLogs $user -ExtendedProperties).mailboxlog | FL > $path"UPDATED-$user-MailboxDiagnosticLogs-ExtendedProperties.txt"
            $error.Clear()
            Export-MailboxDiagnosticLogs $user -ComponentName MRM | FL > $path"UPDATED-$user-MailboxDiagnosticLogs-MRMComponentLogs.txt"
            if ($error) {$error | FT -Autosize -Wrap | Out-File $path"UPDATED-$user-MailboxDiagnosticLogs-MRMComponentLogs.txt" -Append}
            if (!(Select-String -Path $path"UPDATED-$user-MailboxDiagnosticLogs-ExtendedProperties.txt" -Pattern '(ElcLast)')) #check to see if MFA has ever processed mailbox. if not, make suggestion to run start-mfa
            {
                Set-Content $path"UPDATED-$user-MFAReport.txt" -Value "No email lifecycle (Elc*) events were found for '$user'`r`nManaged Folder Assistant has never been ran against '$user'`r`n`r`nRun 'Start-ManagedFolderAssistant $user' to scan/process the mailbox and rerun script to retrieve log events`r`n"
            } 
            else
            {
                Select-String -Path $path"UPDATED-$user-MailboxDiagnosticLogs-ExtendedProperties.txt" -Pattern '(ElcLast)' -Context 0,1 | Select @{n="Elc Property";e={($_.Line).Split('<>')[2]}}, @{n="Value";e={($_.Context.PostContext).split('<>')[2]}} | FT -Autosize -Wrap > $path"UPDATED-$user-MFAReport.txt"
            }
        }
        else
        {
            #pull mailboxdiagnosticlogs extended properties and check for mrm component logs
            (Export-MailboxDiagnosticLogs $user -ExtendedProperties).mailboxlog | FL > $path"$user-MailboxDiagnosticLogs-ExtendedProperties.txt"
            $error.Clear()
            Export-MailboxDiagnosticLogs $user -ComponentName MRM | FL > $path"$user-MailboxDiagnosticLogs-MRMComponentLogs.txt"
            if ($error) {$error | FT -Autosize -Wrap | Out-File $path"$user-MailboxDiagnosticLogs-MRMComponentLogs.txt" -Append}
            if (!(Select-String -Path $path"$user-MailboxDiagnosticLogs-ExtendedProperties.txt" -Pattern '(ElcLast)')) #check to see if MFA has ever processed mailbox. if not, make suggestion to run start-mfa
            {
                Set-Content $path"$user-MFAReport.txt" -Value "No email lifecycle (Elc*) events were found for '$user'`r`nManaged Folder Assistant has never been ran against '$user'`r`n`r`nRun 'Start-ManagedFolderAssistant $user' to scan/process the mailbox and rerun script to retrieve log events`r`n"
            } 
            else
            {
                Select-String -Path $path"$user-MailboxDiagnosticLogs-ExtendedProperties.txt" -Pattern '(ElcLast)' -Context 0,1 | Select @{n="Elc Property";e={($_.Line).Split('<>')[2]}}, @{n="Value";e={($_.Context.PostContext).split('<>')[2]}} | FT -Autosize -Wrap > $path"$user-MFAReport.txt"
            }
        }
    }
    else
    {
        #collect mailbox, retention policy, retention tags, managed folder assistant logs
        Remove-Item $path"*" -Recurse
        $mailbox = Get-Mailbox $user
        $mailbox | FL > $path"$user-Mailbox.txt"
        $folderstats = Get-MailboxFolderStatistics $user
        $folderstats | FL > $path"$user-MailboxFolderStatisticsFULL.txt"
        $folderstats | FT -AutoSize -Wrap FolderPath,ItemsInFolder,ItemsInFolderAndSubfolders,FolderAndSubFolderSize | Out-File $path"$user-MailboxFolderStatistics_Sizes_ItemCounts.txt" -Width 4096
        $retentionpolicy = Get-RetentionPolicy $mailbox.RetentionPolicy
        $retentionpolicy | FL > $path"$user-RetentionPolicy.txt"
        $taglinks = $retentionpolicy.RetentionPolicyTagLinks
        $tags = $taglinks | % {Get-RetentionPolicyTag $_}
        $tags | FT -Autosize -Wrap Identity,Type,RetentionAction,AgeLimitForRetention,@{n="RetentionEnabled";e={$_.RetentionEnabled};align="Left"},RetentionId | Out-File $path"$user-RetentionPolicyTag.txt" -Width 4096
        $tags | FL >> $path"$user-RetentionPolicyTag.txt"
        (Export-MailboxDiagnosticLogs $user -ExtendedProperties).mailboxlog | FL > $path"$user-MailboxDiagnosticLogs-ExtendedProperties.txt"
        $error.Clear()
        Export-MailboxDiagnosticLogs $user -ComponentName MRM | FL > $path"$user-MailboxDiagnosticLogs-MRMComponentLogs.txt"
        if ($error) {$error | FT -Autosize -Wrap | Out-File $path"$user-MailboxDiagnosticLogs-MRMComponentLogs.txt" -Append}
        if (!(Select-String -Path $path"$user-MailboxDiagnosticLogs-ExtendedProperties.txt" -Pattern '(ElcLast)')) #check to see if MFA has ever processed mailbox. if not, make suggestion to run start-mfa
        {
            Set-Content $path"$user-MFAReport.txt" -Value "No email lifecycle (Elc*) events were found for '$user'`r`nManaged Folder Assistant has never been ran against '$user'`r`n`r`nRun 'Start-ManagedFolderAssistant $user' to scan/process the mailbox and rerun script to retrieve log events`r`n"
        } 
        else
        {
            Select-String -Path $path"$user-MailboxDiagnosticLogs-ExtendedProperties.txt" -Pattern '(ElcLast)' -Context 0,1 | Select @{n="Elc Property";e={($_.Line).Split('<>')[2]}}, @{n="Value";e={($_.Context.PostContext).split('<>')[2]}} | FT -Autosize -Wrap > $path"$user-MFAReport.txt"
        }
        #checking for archive mailbox and collect logs on it
        if ($mailbox.ArchiveStatus -eq 'Active')
        {
            $mailbox | FL *archive* > $path"$user-ArchiveMailbox.txt"
            $archivefolderstats = Get-MailboxFolderStatistics $user -Archive
            $archivefolderstats | FL > $path"$user-ArchiveMailboxFolderStatisticsFULL.txt"
            $archivefolderstats | FT -AutoSize -Wrap FolderPath,ItemsInFolder,ItemsInFolderAndSubfolders,FolderAndSubFolderSize | Out-File $path"$user-ArchiveMailboxFolderStatistics_Sizes_ItemCounts.txt" -Width 4096
            (Export-MailboxDiagnosticLogs $user -ExtendedProperties).mailboxlog | FL > $path"$user-ArchiveMailboxDiagnosticLogs-ExtendedProperties.txt"
            $error.Clear()
            Export-MailboxDiagnosticLogs $user -ComponentName MRM | FL > $path"$user-ArchiveMailboxDiagnosticLogs-MRMComponentLogs.txt"
            if ($error) {$error | FT -Autosize -Wrap | Out-File $path"$user-ArchiveMailboxDiagnosticLogs-MRMComponentLogs.txt" -Append}
            if (!(Select-String -Path $path"$user-ArchiveMailboxDiagnosticLogs-ExtendedProperties.txt" -Pattern '(ElcLast)')) #check to see if MFA has ever processed mailbox. if not, make suggestion to run start-mfa
            {
                Set-Content $path"$user-ArchiveMFAReport.txt" -Value "No email lifecycle (Elc*) events were found for '$user'`r`nManaged Folder Assistant has never been ran against '$user'`r`n`r`nRun 'Start-ManagedFolderAssistant $user' to scan/process the mailbox and rerun script to retrieve log events`r`n"
            } 
            else
            {
                Select-String -Path $path"$user-ArchiveMailboxDiagnosticLogs-ExtendedProperties.txt" -Pattern '(ElcLast)' -Context 0,1 | Select @{n="Elc Property";e={($_.Line).Split('<>')[2]}}, @{n="Value";e={($_.Context.PostContext).split('<>')[2]}} | FT -Autosize -Wrap > $path"$user-MFAReport.txt"
            }
        }
        #create summary report of relevant data
        $separator = "`r`n=============================`r`n"
        $content = $null
        Set-Content -Path $path"$user-SummaryReport.txt" -Value $null
        [string]$summarypath = $path+"$user-SummaryReport.txt"
        $text = ($mailbox | select PrimarySMTPAddress,UserPrincipalName,RecipientTypeDetails,ExchangeGuid,*ObjectId,AdminDisplayVersion,isDirSynced,LitigationHold*,InPlaceHolds,ElcProcessingDisabled,*Retention*,RetainDeletedItemsFor,*Archive*,When* | Out-String).trim()
        $content += $separator+"Mailbox Info"+$separator+"`r`n$text`r`n"
        if ($mailbox.ArchiveStatus -eq 'Active'){$content += "`r`nTo see archive mailbox data, please view the archive logs in the log directory`r`n"}
        $text = ($folderstats |? {$_.RecoverableItemsFolder -eq $true} | select FolderPath,ItemsInFolder,ItemsInFolderAndSubfolders,FolderAndSubFolderSize | Out-String -Width 4096).trim()
        $content += $separator+"Recoverable Items Statistiscs"+$separator+"`r`n$text`r`n`r`nTo see mailbox folder statistics for other folders, please view the mailboxfolderstatistics log in the log directory`r`n"
        $text = ($retentionpolicy | select Identity,isDefault,RetentionID,Guid,RetentionPolicyTagLinks | Out-String -Width 4096).trim()
        $content += $separator+"Retention Policy"+$separator+"`r`n$text`r`n"
        $text = ($tags | Sort Identity | FT -AutoSize -Wrap Identity,Type,RetentionAction,AgeLimitForRetention,@{n="RetentionEnabled";e={$_.RetentionEnabled};align="Left"},RetentionId | Out-String -Width 4096).trim()
        $content += $separator+"Retention Tags"+$separator+"`r`n$text`r`n"
        $content += $separator+"ManagedFolderAssistant Events"+$separator
        $content += Get-Content $path"$user-MFAReport.txt" -Raw
        
        if (Select-String -Path $path"$user-MailboxDiagnosticLogs-MRMComponentLogs.txt" -Pattern "Logs for component 'MRM'")
        {
            $content += "No results were found for the cmdlet 'Export-MailboxDiagnosticlogs $user -ComponentName MRM'`r`nThis means there are no errors for this user in the MRM component logs"
        }
        else
        {
            $content += $separator+"MRM Component Logs"+$separator
            $content += Get-Content $path"$user-MailboxDiagnosticLogs-MRMComponentLogs.txt" -Raw
        }
        if ($all.IsPresent) #if switch is called, run cmdlets to see every retention policy and tag
        {
            Get-RetentionPolicy | FL > $path"All-RetentionPolicies.txt"
            Get-RetentionPolicyTag | Sort Identity | FT -Autosize -Wrap Identity,Type,RetentionAction,AgeLimitForRetention,@{n="RetentionEnabled";e={$_.RetentionEnabled};align="Left"},RetentionId | Out-File $path"All-RetentionPolicyTags.txt" -Width 4096
            Get-RetentionPolicyTag | Select * | Out-File $path"All-RetentionPolicyTags.txt" -Append
        }
        Add-Content $summarypath -Value $content
    }
    #display path to retrieve results
    Write-Host -ForegroundColor Yellow "`nCheck the following log path to see results: $path"
}
else {Write-Error "The user entered is either invalid or cannot be found. Confirm that the account used is valid and retry the script." -ErrorAction Stop}
$ErrorActionPreference = $EAP
# SIG # Begin signature block
# MIIn0gYJKoZIhvcNAQcCoIInwzCCJ78CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC2VDgEgR5HGulX
# QcyBCahxkrKxKm4391LNicRLBsRi16CCDZowggYYMIIEAKADAgECAhMzAAACRKv5
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
# DXpQzTGCGY4wghmKAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIw
# MTECEzMAAAJEq/kUaGZ3o6IAAAAAAkQwDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZI
# hvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcC
# ARUwLwYJKoZIhvcNAQkEMSIEIPvHnGhDE70+GW/UhmsnETRAopilIfH0RN1Ybt/E
# rsRpMEQGCisGAQQBgjcCAQwxNjA0oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpo
# dHRwczovL3d3dy5taWNyb3NvZnQuY29tIDANBgkqhkiG9w0BAQEFAASCAQAzB+5+
# CCGMqMN27QvfyzAGv/ZziNbT1YHbCoL8PJzsgk3UUp3nQHDoChiTKKz260P6UK/0
# WVSP0OVZbtOQywe881afm8IiH0Zs+hEbEVLMmimpyYROQ6WjD3LftvnmPs7Xicx6
# 70xX6PXBLH+LXcOqhQDtfo6u4dcU7cZBns4HV9xDgXNKnKF1tj12IeICQ1QITBfe
# iSq4aXpdcI2e3MZm9WERgcdHH/HjGW9GXGciGbSxHVE9TKHsK/6dJH4OS/wH6+cU
# j5a9wHuKRQeo0PZA35l39ZwQ/36mpV6wThXzyYzTuBoA0aC7q2HUjADR3F7vYqGu
# qiSgYM6FTA7gnPLpoYIXFjCCFxIGCisGAQQBgjcDAwExghcCMIIW/gYJKoZIhvcN
# AQcCoIIW7zCCFusCAQMxDzANBglghkgBZQMEAgEFADCCAVkGCyqGSIb3DQEJEAEE
# oIIBSASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIHbL
# YCpqILgrtsSEYm84UaPnIuIBAPkgCSyXcegCj3F9AgZiF7dpHCgYEzIwMjIwNDA1
# MDAyMzQ1LjI2N1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJh
# dGlvbnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046MDg0Mi00QkU2
# LUMyOUExJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WgghFl
# MIIHFDCCBPygAwIBAgITMwAAAYdCFmYEXPP0jQABAAABhzANBgkqhkiG9w0BAQsF
# ADB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMTEwMjgxOTI3Mzla
# Fw0yMzAxMjYxOTI3MzlaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExp
# bWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjA4NDItNEJFNi1DMjlBMSUw
# IwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAvml4GWM9A6PREQiHgZAAPK6n+Th6m+LYwKYL
# aQFlZXbTqrodhsni7HVIRkqBFuG8og1KZry02xEmmbdp89O40xCIQfW8FKW7oO/l
# YYtUAQW2kp0uMuYEJ1XkZ6eHjcMuqEJwC47UakZx3AekakP+GfGuDDO9kZGQRe8I
# piiJ4Qkn6mbDhbRpgcUOdsDzmNz6kXG7gfIfgcs5kzuKIP6nN4tsjPhyF58VU0Zf
# I0PSC+n5OX0hsU8heWe3pUiDr5gqP16a6kIjFJHkgNPYgMivGTQKcjNxNcXnnymT
# /JVuNs7Zvk1P5KWf8G1XG/MtZZ5/juqsg0QoUmQZjVh0XRku7YpMpktW7XfFA3y+
# YJOG1pVzizB3PzJXUC8Ma8AUywtUuULWjYT5y7/EwwHWmn1RT0PhYp9kmpfS6HIY
# fEBboYUvULW2HnGNfx65f4Ukc7kgNSQbeAH6yjO5dg6MUwPfzo/rBdNaZfJxZ7Rs
# cTByTtlxblfUT46yPHCXACiX/BhaHEY4edFgp/cIb7XHFJbu4mNDAPzRlAkIj1SG
# uO9G4sbkjM9XpNMWglj2dC9QLN/0geBFXoNI8F+HfHw4Jo+p6iSP8hn43mkkWKSG
# OiT4hLJzocErFntK5i9PebXSq2BvMgzVc+BBvCN35DfD0mokRKxam2tQM060SORy
# 3S7ucesCAwEAAaOCATYwggEyMB0GA1UdDgQWBBQiUcAWukEtYYF+3WFzmZA/DaWN
# IDAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtTNRnpcjBfBgNVHR8EWDBWMFSg
# UqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3Nv
# ZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5jcmwwbAYIKwYBBQUHAQEE
# YDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3Bz
# L2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0ElMjAyMDEwKDEpLmNy
# dDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMIMA0GCSqGSIb3DQEB
# CwUAA4ICAQC5q35T2RKjAFRN/3cYjnPFztPa7KeqJKJnKgviUj9IMfC8/FQ2ox6U
# wyd40TS7zKvtuMl11FFlfWkEncN3lqihiSAqIDPOdVvr1oJY4NFQBOHzLpetepHn
# Mg0UL2UXHzvjKg24VOIzb0dtdP69+QIy7SDpcVh9KI0EXKG2bolpBypqRttGTDd0
# JQkOtMdiSpaDpOHwgCMNXE8xIu48hiuT075oIqnHJha378/DpugI0DZjYcZH1cG8
# 4J06ucq5ygrod9szr19ObCZJdJLpyvJWCy8PRDAkRjPJglSmfn2UR0KvnoyCOzjs
# zAwNCp/JJnkRp20weItzm97iNg+FZF1J9E16eWIB1sCr7Vj9QD6Kt+z81rOcLRfx
# hlO2/sK09Uw+DiQkPbu6OZ3TsDvLsr8yG9W2A8yXcggNqd4XpLtdEkf52OIN0GgR
# LSY1LNDB4IKY+Zj34IwMbDbs2sCig5Li2ILWEMV/6gyL37J71NbW7Vzo7fcGrNne
# 9OqxgFC2WX5degxyJ3Sx2bKw6lbf04KaXnTBOSz0QC+RfJuz8nOpIf28+WmMPicX
# 2l7gs/MrC5anmyK/nbeKkaOx+AXhwYLzETNg+1IcygjdwnbqWKafLdCNKfhsb/gM
# 5SFbgD5ATEX1bAxwUFVxKvQv0dIRAm5aDjF3DZpgvy3mSojSrBN/8zCCB3EwggVZ
# oAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jv
# c29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4
# MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvX
# JHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa
# /rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AK
# OG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rbo
# YiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIck
# w+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbni
# jYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F
# 37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZ
# fD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIz
# GHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR
# /bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1
# Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUC
# AwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0O
# BBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yD
# fQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lv
# cHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkr
# BgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw
# AwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBN
# MEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0
# cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoG
# CCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9
# /Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5
# bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvf
# am++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn
# 0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlS
# dYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0
# j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5
# JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakUR
# R6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4
# O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVn
# K+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoI
# Yn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggLUMIICPQIBATCCAQChgdik
# gdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNV
# BAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEmMCQGA1UE
# CxMdVGhhbGVzIFRTUyBFU046MDg0Mi00QkU2LUMyOUExJTAjBgNVBAMTHE1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAHh3k1QEKAZE
# hsLGYGHtf/6DG4PzoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIw
# MTAwDQYJKoZIhvcNAQEFBQACBQDl9Z5TMCIYDzIwMjIwNDA1MDA0MTU1WhgPMjAy
# MjA0MDYwMDQxNTVaMHQwOgYKKwYBBAGEWQoEATEsMCowCgIFAOX1nlMCAQAwBwIB
# AAICEJkwBwIBAAICETcwCgIFAOX279MCAQAwNgYKKwYBBAGEWQoEAjEoMCYwDAYK
# KwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkqhkiG9w0BAQUF
# AAOBgQAN1ctvC+dJamlgfiDrfbA5YzQsl8reuPRmek/FQHXjl46jMbyVQnG/+l/x
# tw2OKN0TRT6nYhvT4nxMgL612kvnwaVHO0hix1xS7KpN8yf+vBC6ZKRlEDJtmkJz
# bt8LAwO3icdXT2eZzdzPuFPnOpC/IumQ01yH7hEOh6htqSDx3DGCBA0wggQJAgEB
# MIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAABh0IWZgRc8/SN
# AAEAAAGHMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMxDQYLKoZIhvcN
# AQkQAQQwLwYJKoZIhvcNAQkEMSIEILKaF6tn8MjgGCxBqY2ggQDi/m4zVQPnEU8D
# 9DyNcz0wMIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgxCzwoBNuoB92wsC2
# SxZhz4HVGyvCZnwYNuczpGyam1gwgZgwgYCkfjB8MQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFt
# cCBQQ0EgMjAxMAITMwAAAYdCFmYEXPP0jQABAAABhzAiBCATN7FihZbUo04x5O6+
# YZjgQdKjfvapfciBK2NaWrZVezANBgkqhkiG9w0BAQsFAASCAgAVSnfzJ3jDawYr
# aE7lV10NvHY0syqk4B+dRDTn++7+2QJAKKgIl4ojXQy29Uo6Zcn18EV8B4rLD43c
# iaFTQQ5/Y1ONqL323yXJP6OSVoq6+IlWXerTwtpwUv73SYkleOD1qTGVvJgHgbDc
# msg5+2n2W/WesC3KaGE1ncGd8GcrVphGnoYuXWIGyUsKaiCmjRxBmYth09xcy+E9
# dBhBw8Al/zH+PyNHtc6xaAyC9GBrzmuvH6NuGT0ZmOItTLHYjm4w1k6ijHbxFHpL
# Pqi17/1nTOp9vQrTGy8PXj/xBhGp8VvllPSpdeaPfQk54BQEsdGul21kyFh45A3J
# 5iaVSvqYB2XAJapsoYZeGtSzlyAOXuO+/j52yXu0Z6apeKHefp8ZNZ16MR++zcyv
# SAFitAEaf16CBWVXn1+6tXMVcLVhTc3l8bZrXK0z81GyaO2v/yAojRpfHLgoB/N+
# C4FmafyME5C1QS93u+1/RuANySv8Xtr67huwYsmS7BX4+EcVCjKfupTdoOv/G4uY
# WJv/g55yWV0Rw9DQXfUsPBS9UcJPfYnNInJDq10nT+EBiCJ4thXgu2IUlfAYnBgV
# ZL8BavJJM6Bl0YZO461bDrBpVNnwZv56uClfZLZuhzIOVWdCZ1FzGPLF1aDOUFIu
# K9ptBOxAsEQGO0wLP9+NRVEAHa9C2A==
# SIG # End signature block
