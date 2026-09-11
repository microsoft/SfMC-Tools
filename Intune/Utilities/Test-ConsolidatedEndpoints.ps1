<#
.SYNOPSIS
    High-performance connectivity testing for Microsoft Intune Consolidated Endpoint List.

.DESCRIPTION
    This script tests connectivity to all endpoints listed in the Intune Consolidated Endpoint List.
    Automatically fetches the latest endpoint list from Microsoft Learn and caches it locally.
    
    Features:
    - Automatic endpoint list updates from Microsoft Learn documentation
    - Smart caching with configurable validity period
    - Change detection between endpoint list versions
    - Separate testing for FQDNs and IP subnets
    - Smart sampling for wildcard domains and IP ranges
    - SSL certificate validation for endpoints requiring no SSL inspection
    - Concurrent job execution for maximum speed
    - Real-time progress tracking
    - Comprehensive reporting (HTML with charts, JSON, logs, transcript)

.PARAMETER FqdnSamplePercent
    Percentage of IPs to sample from wildcard domain resolutions (1-100). Default is 20%.

.PARAMETER IpSamplePercent
    Percentage of IPs to sample from each subnet (1-100). Default is 10%.

.PARAMETER MaxConcurrentJobs
    Maximum number of concurrent testing jobs. Default is 50.

.PARAMETER TimeoutSeconds
    Connection timeout in seconds. Default is 1 second for fast failure detection.

.PARAMETER OutputFolder
    Custom output folder name. Default is "ConsolidatedEndpointResults".

.PARAMETER CacheValidityDays
    Number of days to consider cached endpoint list valid. Default is 7 days.

.PARAMETER ForceFreshData
    Force fetching fresh endpoint data from Microsoft Learn, bypassing cache.

.EXAMPLE
    .\Test-ConsolidatedEndpoints.ps1

.EXAMPLE
    .\Test-ConsolidatedEndpoints.ps1 -ForceFreshData

.EXAMPLE
    .\Test-ConsolidatedEndpoints.ps1 -FqdnSamplePercent 30 -IpSamplePercent 15 -MaxConcurrentJobs 100

.NOTES
    Version: 1.0
    Author: Microsoft Intune Support Tools
    Date: 2025-11-21
    
    Source: https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints#consolidated-endpoint-list
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 100)]
    [int]$FqdnSamplePercent = 20,
    
    [ValidateRange(1, 100)]
    [int]$IpSamplePercent = 10,
    
    [ValidateRange(1, 200)]
    [int]$MaxConcurrentJobs = 50,
    
    [ValidateRange(1, 10)]
    [int]$TimeoutSeconds = 1,
    
    [string]$OutputFolder = "ConsolidatedEndpointResults",
    
    [ValidateRange(1, 30)]
    [int]$CacheValidityDays = 7,
    
    [switch]$ForceFreshData,
    
    [switch]$DetailedDiagnostics
)

#Requires -Version 5.1


#region Information

$disclaimer = @"
###########################################################################################
#                                                                                         #
# The sample scripts are not supported under any Microsoft standard support               #
# program or service. The sample scripts are provided AS IS without warranty              #
# of any kind. Microsoft further disclaims all implied warranties including, without      #
# limitation, any implied warranties of merchantability or of fitness for a particular    #
# purpose. The entire risk arising out of the use or performance of the sample scripts    #
# and documentation remains with you. In no event shall Microsoft, its authors, or        #
# anyone else involved in the creation, production, or delivery of the scripts be liable  #
# for any damages whatsoever (including, without limitation, damages for loss of business #
# profits, business interruption, loss of business information, or other pecuniary loss   #
# arising out of the use of or inability to use the sample scripts or documentation,      #
# even if Microsoft has been advised of the possibility of such damages.                  #
#                                                                                         #
###########################################################################################
"@

Write-Host
Write-Host
Write-Host $disclaimer -foregroundColor Yellow
Write-Host 
Start-Sleep -Seconds 3 


#endregion Information

####################################################

#region Confirmation

    Write-Host
    Write-Host "─────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host " Do you acknowledge the above and want to continue?" -ForegroundColor White
    Write-Host "─────────────────────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host " [" -NoNewline -ForegroundColor DarkGray
    Write-Host "Y" -NoNewline -ForegroundColor Green
    Write-Host "] Yes   [" -NoNewline -ForegroundColor DarkGray
    Write-Host "N" -NoNewline -ForegroundColor Red
    Write-Host "] No" -ForegroundColor DarkGray
    Write-Host
    $Confirmation = Read-Host "   Your choice"

    If ($Confirmation -notmatch '^[Yy]$')
        {
            Write-Host
            Write-Host " Script cancelled by the user." -ForegroundColor Yellow
            Write-Host
            exit
        }

#endregion Confirmation

# Define SSL certificate validation callback helper (must be before any use)
if (-not ([System.Management.Automation.PSTypeName]'SSLHelper').Type) {
    Add-Type -TypeDefinition @"
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;
    public class SSLHelper {
        public static bool AlwaysAcceptCallback(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
"@
}

# Script constants
$script:TIMEOUT_MS = $TimeoutSeconds * 1000
$script:TEST_PORTS = @(443, 80)
$script:SSL_NO_INSPECTION_PATTERNS = @(
    '*.manage.microsoft.com',
    'manage.microsoft.com',
    '*.dm.microsoft.com',
    '*attest.azure.net',
    'displaycatalog.mp.microsoft.com',
    'purchase.md.mp.microsoft.com',
    'licensing.mp.microsoft.com',
    'storeedgefd.dsx.mp.microsoft.com'
)

# Source URL for consolidated endpoint lists
$script:ENDPOINT_SOURCE_URL = "https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints"

# Dynamic endpoint lists (populated from cache or web)
$script:CONSOLIDATED_FQDNS = @()
$script:CONSOLIDATED_IP_SUBNETS = @()

# Default fallback endpoint lists (used if fetching fails)
$script:FALLBACK_FQDNS = @(
    '*.manage.microsoft.com',
    'manage.microsoft.com',
    '*.dl.delivery.mp.microsoft.com',
    '*.do.dsp.mp.microsoft.com',
    '*.update.microsoft.com',
    '*.windowsupdate.com',
    'adl.windows.com',
    'dl.delivery.mp.microsoft.com',
    'tsfe.trafficshaping.dsp.mp.microsoft.com',
    'time.windows.com',
    '*.s-microsoft.com',
    'clientconfig.passport.net',
    'windowsphone.com',
    'approdimedatahotfix.azureedge.net',
    'approdimedatapri.azureedge.net',
    'approdimedatasec.azureedge.net',
    'euprodimedatahotfix.azureedge.net',
    'euprodimedatapri.azureedge.net',
    'euprodimedatasec.azureedge.net',
    'naprodimedatahotfix.azureedge.net',
    'naprodimedatapri.azureedge.net',
    'naprodimedatasec.azureedge.net',
    'swda01-mscdn.azureedge.net',
    'swda02-mscdn.azureedge.net',
    'swdb01-mscdn.azureedge.net',
    'swdb02-mscdn.azureedge.net',
    'swdc01-mscdn.azureedge.net',
    'swdc02-mscdn.azureedge.net',
    'swdd01-mscdn.azureedge.net',
    'swdd02-mscdn.azureedge.net',
    'swdin01-mscdn.azureedge.net',
    'swdin02-mscdn.azureedge.net',
    '*.notify.windows.com',
    '*.wns.windows.com',
    'ekcert.spserv.microsoft.com',
    'ekop.intel.com',
    'ftpm.amd.com',
    'intunecdnpeasd.azureedge.net',
    '*.monitor.azure.com',
    '*.support.services.microsoft.com',
    '*.trouter.communication.microsoft.com',
    '*.trouter.skype.com',
    '*.trouter.teams.microsoft.com',
    'api.flightproxy.skype.com',
    'ecs.communication.microsoft.com',
    'edge.microsoft.com',
    'edge.skype.com',
    'remoteassistanceprodacs.communication.azure.com',
    'remoteassistanceprodacseu.communication.azure.com',
    'remotehelp.microsoft.com',
    'wcpstatic.microsoft.com',
    'lgmsapeweu.blob.core.windows.net',
    'intunemaape1.eus.attest.azure.net',
    'intunemaape10.weu.attest.azure.net',
    'intunemaape11.weu.attest.azure.net',
    'intunemaape12.weu.attest.azure.net',
    'intunemaape13.jpe.attest.azure.net',
    'intunemaape17.jpe.attest.azure.net',
    'intunemaape18.jpe.attest.azure.net',
    'intunemaape19.jpe.attest.azure.net',
    'intunemaape2.eus2.attest.azure.net',
    'intunemaape3.cus.attest.azure.net',
    'intunemaape4.wus.attest.azure.net',
    'intunemaape5.scus.attest.azure.net',
    'intunemaape7.neu.attest.azure.net',
    'intunemaape8.neu.attest.azure.net',
    'intunemaape9.neu.attest.azure.net',
    '*.webpubsub.azure.com',
    '*.gov.teams.microsoft.us',
    'remoteassistanceweb.usgov.communication.azure.us',
    'config.edge.skype.com',
    'contentauthassetscdn-prod.azureedge.net',
    'contentauthassetscdn-prodeur.azureedge.net',
    'contentauthrafcontentcdn-prod.azureedge.net',
    'contentauthrafcontentcdn-prodeur.azureedge.net',
    'fd.api.orgmsg.microsoft.com',
    'ris.prod.api.personalization.ideas.microsoft.com'
)

$script:FALLBACK_IP_SUBNETS = @(
    '4.145.74.224/27',
    '4.150.254.64/27',
    '4.154.145.224/27',
    '4.200.254.32/27',
    '4.207.244.0/27',
    '4.213.25.64/27',
    '4.213.86.128/25',
    '4.216.205.32/27',
    '4.237.143.128/25',
    '13.67.13.176/28',
    '13.67.15.128/27',
    '13.69.67.224/28',
    '13.69.231.128/28',
    '13.70.78.128/28',
    '13.70.79.128/27',
    '13.74.111.192/27',
    '13.77.53.176/28',
    '13.86.221.176/28',
    '13.89.174.240/28',
    '13.89.175.192/28',
    '20.37.153.0/24',
    '20.37.192.128/25',
    '20.38.81.0/24',
    '20.41.1.0/24',
    '20.42.1.0/24',
    '20.42.130.0/24',
    '20.42.224.128/25',
    '20.43.129.0/24',
    '20.44.19.224/27',
    '20.91.147.72/29',
    '20.168.189.128/27',
    '20.189.172.160/27',
    '20.189.229.0/25',
    '20.191.167.0/25',
    '20.192.159.40/29',
    '20.192.174.216/29',
    '20.199.207.192/28',
    '20.204.193.10/31',
    '20.204.193.12/30',
    '20.204.194.128/31',
    '20.208.149.192/27',
    '20.208.157.128/27',
    '20.214.131.176/29',
    '40.67.121.224/27',
    '40.70.151.32/28',
    '40.71.14.96/28',
    '40.74.25.0/24',
    '40.78.245.240/28',
    '40.78.247.128/27',
    '40.79.197.64/27',
    '40.79.197.96/28',
    '40.80.180.208/28',
    '40.80.180.224/27',
    '40.80.184.128/25',
    '40.82.248.224/28',
    '40.82.249.128/25',
    '40.84.70.128/25',
    '40.119.8.128/25',
    '48.218.252.128/25',
    '52.150.137.0/25',
    '52.162.111.96/28',
    '52.168.116.128/27',
    '52.182.141.192/27',
    '52.236.189.96/27',
    '52.240.244.160/27',
    '57.151.0.192/27',
    '57.153.235.0/25',
    '57.154.140.128/25',
    '57.154.195.0/25',
    '57.155.45.128/25',
    '68.218.134.96/27',
    '74.224.214.64/27',
    '74.242.35.0/25',
    '104.46.162.96/27',
    '104.208.197.64/27',
    '172.160.217.160/27',
    '172.201.237.160/27',
    '172.202.86.192/27',
    '172.205.63.0/25',
    '172.212.214.0/25',
    '172.215.131.0/27',
    '13.107.219.0/24',
    '13.107.227.0/24',
    '13.107.228.0/23',
    '150.171.97.0/24',
    '2620:1ec:40::/48',
    '2620:1ec:49::/48',
    '2620:1ec:4a::/47'
)

# Global variables for tracking
$script:StartTime = Get-Date
$script:Results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$script:TranscriptLog = [System.Collections.ArrayList]::Synchronized([System.Collections.ArrayList]::new())

#region Helper Functions

function Write-TranscriptLog {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
    $logEntry = "[$timestamp] $Message"
    [void]$script:TranscriptLog.Add($logEntry)
}

function Get-ConsolidatedEndpointList {
    <#
    .SYNOPSIS
        Fetches the consolidated endpoint list from Microsoft Learn documentation.
    #>
    param(
        [string]$CachePath
    )
    
    Write-Host "  Fetching consolidated endpoint list from Microsoft Learn..." -ForegroundColor Cyan
    Write-TranscriptLog "Fetching endpoints from: $script:ENDPOINT_SOURCE_URL"
    
    try {
        $response = Invoke-WebRequest -Uri $script:ENDPOINT_SOURCE_URL -UseBasicParsing -TimeoutSec 30
        $content = $response.Content
        
        # Find the "Consolidated Endpoint List" section and extract code blocks
        # Structure: <h2>Consolidated Endpoint List</h2>...<p>FQDNs</p><pre><code>...list...</code></pre>...<p>IP Subnets</p><pre><code>...list...</code></pre>
        
        # Find section start
        $consolidatedIndex = $content.IndexOf('Consolidated Endpoint List')
        if ($consolidatedIndex -eq -1) {
            throw "Could not find 'Consolidated Endpoint List' in page"
        }
        
        # Extract from section onwards (next 50KB should contain both lists)
        $sectionContent = $content.Substring($consolidatedIndex, [Math]::Min(50000, $content.Length - $consolidatedIndex))
        
        # Find FQDN block: <p>FQDNs</p> followed by <pre><code>...content...</code></pre>
        if ($sectionContent -notmatch '(?s)<p>FQDNs</p>\s*<pre><code>(.*?)</code></pre>') {
            throw "Could not find FQDN code block"
        }
        $fqdnBlock = $matches[1]
        
        # Find IP Subnets block: <p>IP Subnets</p> followed by <pre><code>...content...</code></pre>
        if ($sectionContent -notmatch '(?s)<p>IP Subnets</p>\s*(?:<p>.*?</p>\s*)?<pre><code>(.*?)</code></pre>') {
            throw "Could not find IP Subnets code block"
        }
        $ipBlock = $matches[1]
        
        # Decode HTML entities (like &ast; for asterisks)
        $fqdnBlock = $fqdnBlock -replace '&ast;', '*' -replace '&gt;', '>' -replace '&lt;', '<' -replace '&amp;', '&' -replace '&quot;', '"'
        $ipBlock = $ipBlock -replace '&ast;', '*' -replace '&gt;', '>' -replace '&lt;', '<' -replace '&amp;', '&' -replace '&quot;', '"'
        
        # Parse FQDNs
        $fqdns = @()
        $fqdnLines = $fqdnBlock -split "[\r\n]+"
        foreach ($line in $fqdnLines) {
            $line = $line.Trim()
            if ($line -and $line -match '^[\*\w][\*\w\-\.]*\.[a-zA-Z]{2,}$') {
                $fqdns += $line
            }
        }
        
        # Parse IP Subnets
        $ipSubnets = @()
        $ipLines = $ipBlock -split "[\r\n]+"
        foreach ($line in $ipLines) {
            $line = $line.Trim()
            # Match both IPv4 and IPv6 CIDR notation
            if ($line -match '^\d+\.\d+\.\d+\.\d+/\d+$' -or $line -match '^[0-9a-fA-F:]+/\d+$') {
                $ipSubnets += $line
            }
        }
        
        if ($fqdns.Count -eq 0 -or $ipSubnets.Count -eq 0) {
            throw "Parsed endpoint list appears incomplete (FQDNs: $($fqdns.Count), IPs: $($ipSubnets.Count))"
        }
        
        Write-Host "  [OK] Successfully fetched $($fqdns.Count) FQDNs and $($ipSubnets.Count) IP subnets" -ForegroundColor Green
        Write-TranscriptLog "Fetched $($fqdns.Count) FQDNs and $($ipSubnets.Count) IP subnets from Microsoft Learn"
        
        # Save to cache
        $cacheData = @{
            FQDNs           = $fqdns
            IPSubnets       = $ipSubnets
            FetchedDate     = (Get-Date).ToString("o")
            SourceURL       = $script:ENDPOINT_SOURCE_URL
            FQDNCount       = $fqdns.Count
            IPSubnetCount   = $ipSubnets.Count
        }
        
        try {
            $cacheData | ConvertTo-Json -Depth 5 | Out-File $CachePath -Encoding UTF8 -Force
            Write-TranscriptLog "Cached endpoint list to: $CachePath"
        }
        catch {
            Write-TranscriptLog "WARNING: Failed to save cache: $($_.Exception.Message)"
        }
        
        return $cacheData
    }
    catch {
        Write-Host "  [X] Failed to fetch from Microsoft Learn: $($_.Exception.Message)" -ForegroundColor Red
        Write-TranscriptLog "ERROR: Failed to fetch endpoints: $($_.Exception.Message)"
        return $null
    }
}

function Get-CachedEndpointList {
    <#
    .SYNOPSIS
        Loads endpoint list from cache if valid.
    #>
    param(
        [string]$CachePath,
        [int]$ValidityDays
    )
    
    if (-not (Test-Path $CachePath)) {
        Write-TranscriptLog "No cache file found at: $CachePath"
        return $null
    }
    
    try {
        $cacheData = Get-Content $CachePath -Raw | ConvertFrom-Json
        $fetchedDate = [DateTime]::Parse($cacheData.FetchedDate)
        $cacheAge = (Get-Date) - $fetchedDate
        
        if ($cacheAge.TotalDays -gt $ValidityDays) {
            $ageInDays = [Math]::Round($cacheAge.TotalDays, 1)
            Write-Host "  [!] Cache expired ($ageInDays days old)" -ForegroundColor Yellow
            Write-TranscriptLog "Cache expired: $ageInDays days old (validity: $ValidityDays days)"
            return $null
        }
        
        $ageInDays = [Math]::Round($cacheAge.TotalDays, 1)
        Write-Host "  [OK] Using cached endpoint list (age: $ageInDays days)" -ForegroundColor Green
        Write-TranscriptLog "Loaded valid cache: $($cacheData.FQDNCount) FQDNs, $($cacheData.IPSubnetCount) IPs"
        
        return $cacheData
    }
    catch {
        Write-Host "  [X] Failed to load cache: $($_.Exception.Message)" -ForegroundColor Red
        Write-TranscriptLog "ERROR: Cache load failed: $($_.Exception.Message)"
        return $null
    }
}

function Compare-EndpointLists {
    <#
    .SYNOPSIS
        Compares current and previous endpoint lists to detect changes.
    #>
    param(
        [array]$NewFQDNs,
        [array]$OldFQDNs,
        [array]$NewIPs,
        [array]$OldIPs
    )
    
    $changes = @{
        FQDNsAdded      = @()
        FQDNsRemoved    = @()
        IPsAdded        = @()
        IPsRemoved      = @()
        HasChanges      = $false
    }
    
    # Compare FQDNs
    $changes.FQDNsAdded = $NewFQDNs | Where-Object { $_ -notin $OldFQDNs }
    $changes.FQDNsRemoved = $OldFQDNs | Where-Object { $_ -notin $NewFQDNs }
    
    # Compare IPs
    $changes.IPsAdded = $NewIPs | Where-Object { $_ -notin $OldIPs }
    $changes.IPsRemoved = $OldIPs | Where-Object { $_ -notin $NewIPs }
    
    $changes.HasChanges = ($changes.FQDNsAdded.Count -gt 0 -or $changes.FQDNsRemoved.Count -gt 0 -or 
                          $changes.IPsAdded.Count -gt 0 -or $changes.IPsRemoved.Count -gt 0)
    
    return $changes
}

function Test-FastTcpConnection {
    <#
    .SYNOPSIS
        Enhanced TCP connectivity test with network path validation.
        Distinguishes between local blocks, remote timeouts, and successful connections.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Target,
        
        [Parameter(Mandatory)]
        [int]$Port,
        
        [int]$TimeoutMs = $script:TIMEOUT_MS
    )
    
    $tcpClient = $null
    $connected = $false
    $errorMsg = $null
    $resolvedIP = $null
    $pathStatus = 'Unknown'  # LocalBlock, PathAvailable, Connected
    $errorType = $null  # Immediate, Timeout, None
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $startTime = Get-Date
        $connectTask = $tcpClient.ConnectAsync($Target, $Port)
        
        if ($connectTask.Wait($TimeoutMs)) {
            $elapsed = ((Get-Date) - $startTime).TotalMilliseconds
            $connected = $tcpClient.Connected
            
            if ($connected) {
                $resolvedIP = $tcpClient.Client.RemoteEndPoint.Address.ToString()
                $pathStatus = 'Connected'
                $errorType = 'None'
            }
            else {
                # Connection attempt completed but failed
                # This means packet was sent but rejected (path available, remote refused)
                $pathStatus = 'PathAvailable'
                $errorType = 'RemoteRefused'
                $errorMsg = "Connection refused by remote host (path available)"
            }
        }
        else {
            # Timeout - packet was likely sent but no response
            # This is NORMAL for many Azure IPs (load balancing, unallocated)
            $pathStatus = 'PathAvailable'
            $errorType = 'RemoteTimeout'
            $errorMsg = "Remote timeout (${TimeoutMs}ms) - path available, no response"
        }
    }
    catch {
        $elapsed = ((Get-Date) - $startTime).TotalMilliseconds
        $errorMsg = $_.Exception.Message
        
        # Analyze exception to determine if local block or network path available
        if ($_.Exception.InnerException) {
            $innerMsg = $_.Exception.InnerException.Message
            
            # Immediate failures (< 50ms) often indicate local firewall/proxy blocks
            if ($elapsed -lt 50) {
                if ($innerMsg -match 'actively refused|connection refused|access denied|no connection could be made') {
                    $pathStatus = 'LocalBlock'
                    $errorType = 'LocalRefused'
                    $errorMsg = "BLOCKED: Local firewall/proxy refused connection (${elapsed}ms)"
                }
                elseif ($innerMsg -match 'host not found|no such host|name resolution') {
                    $pathStatus = 'LocalBlock'
                    $errorType = 'DNSFailure'
                    $errorMsg = "BLOCKED: DNS resolution failed"
                }
                else {
                    $pathStatus = 'LocalBlock'
                    $errorType = 'ImmediateFailure'
                    $errorMsg = "BLOCKED: Immediate failure (${elapsed}ms) - $innerMsg"
                }
            }
            else {
                # Slower failures usually mean packet left network but failed remotely
                $pathStatus = 'PathAvailable'
                $errorType = 'RemoteFailure'
                $errorMsg = "Remote failure after ${elapsed}ms (path available) - $innerMsg"
            }
        }
        else {
            # Generic error - assume path available unless proven otherwise
            if ($elapsed -lt 50) {
                $pathStatus = 'LocalBlock'
                $errorType = 'ImmediateFailure'
            }
            else {
                $pathStatus = 'PathAvailable'
                $errorType = 'RemoteFailure'
            }
        }
    }
    finally {
        if ($tcpClient) { $tcpClient.Dispose() }
    }
    
    return [PSCustomObject]@{
        Target      = $Target
        Port        = $Port
        Connected   = $connected
        PathStatus  = $pathStatus  # LocalBlock, PathAvailable, Connected
        ErrorType   = $errorType   # Immediate, Timeout, RemoteRefused, RemoteFailure, None
        ResolvedIP  = $resolvedIP
        Error       = $errorMsg
        Timestamp   = Get-Date
    }
}

function Test-SSLCertificate {
    <#
    .SYNOPSIS
        Validates SSL certificate for endpoints requiring no SSL inspection.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Hostname
    )
    
    $result = [PSCustomObject]@{
        Hostname           = $Hostname
        CertificateValid   = $false
        Issuer             = $null
        Subject            = $null
        NotBefore          = $null
        NotAfter           = $null
        DaysUntilExpiry    = $null
        IsPublicCA         = $false
        ValidationMessages = @()
        Error              = $null
    }
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync($Hostname, 443)
        
        if (-not $connectTask.Wait($script:TIMEOUT_MS)) {
            $result.Error = "Connection timeout"
            return $result
        }
        
        if (-not $tcpClient.Connected) {
            $result.Error = "Connection failed"
            return $result
        }
        
        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(),
            $false,
            { param($sender, $cert, $chain, $sslPolicyErrors) return $true }
        )
        
        $authTask = $sslStream.AuthenticateAsClientAsync($Hostname)
        
        if (-not $authTask.Wait($script:TIMEOUT_MS)) {
            $result.Error = "SSL handshake timeout"
            return $result
        }
        
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$sslStream.RemoteCertificate
        
        if ($cert) {
            $result.Issuer = $cert.Issuer
            $result.Subject = $cert.Subject
            $result.NotBefore = $cert.NotBefore
            $result.NotAfter = $cert.NotAfter
            $result.DaysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
            
            # Check if issued by known public CA
            $publicCAIssuers = @(
                'DigiCert', 'Microsoft', 'GlobalSign', 'Let''s Encrypt', 'GeoTrust',
                'Thawte', 'Comodo', 'Sectigo', 'GoDaddy', 'Entrust', 'Baltimore'
            )
            $result.IsPublicCA = $publicCAIssuers | Where-Object { $cert.Issuer -match $_ } | Select-Object -First 1
            
            # Validation checks
            $now = Get-Date
            if ($now -lt $cert.NotBefore) {
                $result.ValidationMessages += "Certificate not yet valid"
            }
            if ($now -gt $cert.NotAfter) {
                $result.ValidationMessages += "Certificate expired"
                $result.CertificateValid = $false
            }
            elseif ($result.DaysUntilExpiry -lt 30) {
                $result.ValidationMessages += "Certificate expires in $($result.DaysUntilExpiry) days"
                $result.CertificateValid = $true
            }
            else {
                $result.CertificateValid = $true
                $result.ValidationMessages += "Certificate valid"
            }
            
            if (-not $result.IsPublicCA) {
                $result.ValidationMessages += "WARNING: Certificate not from known public CA"
            }
        }
        
        $sslStream.Dispose()
        $tcpClient.Dispose()
    }
    catch {
        $result.Error = $_.Exception.Message
    }
    
    return $result
}

function Invoke-TcpTraceroute {
    <#
    .SYNOPSIS
        Performs TCP-based traceroute to identify where connectivity fails.
        Uses SYN packets to specified port to trace network path.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$Target,
        
        [Parameter(Mandatory)]
        [int]$Port,
        
        [int]$MaxHops = 30,
        
        [int]$TimeoutMs = 2000
    )
    
    $hops = @()
    
    try {
        # Try to resolve target first
        $resolvedIP = $null
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($Target)
            $resolvedIP = $resolved[0].IPAddressToString
        }
        catch {
            return [PSCustomObject]@{
                Target = $Target
                Port = $Port
                Success = $false
                Error = "DNS resolution failed: $($_.Exception.Message)"
                Hops = @()
                FailurePoint = "DNS"
            }
        }
        
        Write-TranscriptLog "TCP Traceroute to ${Target}:${Port} ($resolvedIP) - Max $MaxHops hops"
        
        # Use Test-NetConnection with TraceRoute (requires PowerShell 5.1+)
        # Note: This uses ICMP, but we'll combine with TCP test at each hop
        try {
            $traceResult = Test-NetConnection -ComputerName $Target -Port $Port -TraceRoute -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            
            if ($traceResult.TraceRoute) {
                $hopNumber = 1
                foreach ($hop in $traceResult.TraceRoute) {
                    $hopInfo = [PSCustomObject]@{
                        Hop = $hopNumber
                        Address = $hop
                        RTT = $null
                        Reached = ($hop -eq $resolvedIP)
                    }
                    $hops += $hopInfo
                    $hopNumber++
                    
                    if ($hopInfo.Reached) {
                        break
                    }
                }
            }
            
            $finalTcpTest = Test-FastTcpConnection -Target $Target -Port $Port -TimeoutMs $TimeoutMs
            
            $failurePoint = 'None'
            if ($hops.Count -eq 0) {
                $failurePoint = 'LocalNetwork'
            }
            elseif ($hops.Count -eq 1) {
                $failurePoint = 'FirstHop'
            }
            elseif ($hops.Count -lt 5) {
                $failurePoint = 'ISP'
            }
            elseif (-not $finalTcpTest.Connected -and $finalTcpTest.PathStatus -eq 'LocalBlock') {
                $failurePoint = 'LocalFirewall'
            }
            else {
                $failurePoint = 'RemoteNetwork'
            }
            
            return [PSCustomObject]@{
                Target = $Target
                Port = $Port
                ResolvedIP = $resolvedIP
                Success = $traceResult.TcpTestSucceeded
                PathAvailable = ($finalTcpTest.PathStatus -ne 'LocalBlock')
                Hops = $hops
                HopCount = $hops.Count
                FailurePoint = $failurePoint
                FinalTest = $finalTcpTest
                Error = if (-not $traceResult.TcpTestSucceeded) { "TCP connection failed" } else { $null }
            }
        }
        catch {
            return [PSCustomObject]@{
                Target = $Target
                Port = $Port
                ResolvedIP = $resolvedIP
                Success = $false
                PathAvailable = $false
                Hops = @()
                HopCount = 0
                FailurePoint = 'TraceRouteFailed'
                Error = $_.Exception.Message
            }
        }
    }
    catch {
        return [PSCustomObject]@{
            Target = $Target
            Port = $Port
            Success = $false
            PathAvailable = $false
            Hops = @()
            HopCount = 0
            FailurePoint = 'Exception'
            Error = $_.Exception.Message
        }
    }
}

function Expand-IPSubnet {
    <#
    .SYNOPSIS
        Expands CIDR notation to individual IP addresses with smart sampling.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$CIDR,
        
        [int]$SamplePercent = 10
    )
    
    try {
        # Check for IPv6
        if ($CIDR -match ':') {
            Write-TranscriptLog "Skipping IPv6 subnet: $CIDR (not implemented)"
            return @()
        }
        
        $parts = $CIDR -split '/'
        $ip = $parts[0]
        $maskBits = [int]$parts[1]
        
        # Convert IP to integer
        $ipBytes = [System.Net.IPAddress]::Parse($ip).GetAddressBytes()
        [Array]::Reverse($ipBytes)
        $ipInt = [System.BitConverter]::ToUInt32($ipBytes, 0)
        
        # Calculate range
        $mask = [Convert]::ToUInt32(('1' * $maskBits + '0' * (32 - $maskBits)), 2)
        $networkInt = $ipInt -band $mask
        $broadcastInt = $networkInt -bor (-bnot $mask -band 0xFFFFFFFF)
        $totalIPs = $broadcastInt - $networkInt + 1
        
        # Smart sampling strategy: prioritize IPs most likely to be active
        $ips = @()
        $usableIPs = $totalIPs - 2  # Exclude network and broadcast addresses
        
        # Helper function to convert integer to IP
        $ConvertToIP = {
            param($intValue)
            $bytes = [System.BitConverter]::GetBytes([uint32]$intValue)
            [Array]::Reverse($bytes)
            return [System.Net.IPAddress]::new($bytes).ToString()
        }
        
        if ($totalIPs -le 10 -or $SamplePercent -ge 100) {
            # Small subnet or 100% sampling - test all usable IPs (skip network/broadcast)
            for ($i = 1; $i -lt ($totalIPs - 1); $i++) {
                $currentInt = $networkInt + $i
                $ipAddress = & $ConvertToIP $currentInt
                $ips += [PSCustomObject]@{
                    IP = $ipAddress
                    Subnet = $CIDR
                    Priority = 'Full'
                }
            }
        }
        else {
            # TIER 1: High-priority IPs (most likely to be active)
            $tier1IPs = @()
            
            # Common service IPs at start of range (.1, .2, .3, .4, .5)
            for ($i = 1; $i -le [Math]::Min(5, $usableIPs); $i++) {
                $tier1IPs += @{ Index = $i; Priority = 'Start' }
            }
            
            # Common service IPs at end of range (last 5 before broadcast)
            $endStart = [Math]::Max(6, $totalIPs - 6)
            for ($i = $endStart; $i -lt ($totalIPs - 1); $i++) {
                if ($i -gt 5) {  # Avoid duplicates if subnet is tiny
                    $tier1IPs += @{ Index = $i; Priority = 'End' }
                }
            }
            
            # Common gateway/service positions (.254, .253, .252 for /24 and larger)
            if ($totalIPs -gt 50) {
                $commonOffsets = @(254, 253, 252, 10, 20, 50, 100)
                foreach ($offset in $commonOffsets) {
                    if ($offset -lt ($totalIPs - 1) -and $offset -notin $tier1IPs.Index) {
                        $tier1IPs += @{ Index = $offset; Priority = 'Common' }
                    }
                }
            }
            
            # Add Tier 1 IPs
            foreach ($ipInfo in $tier1IPs) {
                $currentInt = $networkInt + $ipInfo.Index
                $ipAddress = & $ConvertToIP $currentInt
                $ips += [PSCustomObject]@{
                    IP = $ipAddress
                    Subnet = $CIDR
                    Priority = $ipInfo.Priority
                }
            }
            
            # TIER 2: Fill remaining sample with evenly distributed IPs
            $tier1Count = $tier1IPs.Count
            $targetSampleSize = [Math]::Max($tier1Count, [Math]::Ceiling($totalIPs * $SamplePercent / 100))
            $targetSampleSize = [Math]::Min($targetSampleSize, $usableIPs)
            $remainingSamples = $targetSampleSize - $tier1Count
            
            if ($remainingSamples -gt 0) {
                $tier1Indices = $tier1IPs.Index
                $step = $usableIPs / $remainingSamples
                $addedCount = 0
                
                for ($i = 0; $i -lt $remainingSamples -and $addedCount -lt $remainingSamples; $i++) {
                    $index = [Math]::Floor($i * $step) + 1  # +1 to skip network address
                    
                    # Skip if already in tier1
                    if ($index -notin $tier1Indices) {
                        $currentInt = $networkInt + $index
                        $ipAddress = & $ConvertToIP $currentInt
                        $ips += [PSCustomObject]@{
                            IP = $ipAddress
                            Subnet = $CIDR
                            Priority = 'Even'
                        }
                        $addedCount++
                    }
                }
            }
        }
        
        # Count by priority
        $startCount = ($ips | Where-Object { $_.Priority -eq 'Start' }).Count
        $endCount = ($ips | Where-Object { $_.Priority -eq 'End' }).Count
        $commonCount = ($ips | Where-Object { $_.Priority -eq 'Common' }).Count
        $evenCount = ($ips | Where-Object { $_.Priority -eq 'Even' }).Count
        $fullCount = ($ips | Where-Object { $_.Priority -eq 'Full' }).Count
        
        if ($fullCount -gt 0) {
            Write-TranscriptLog "Subnet ${CIDR}: Testing all $($ips.Count) usable IPs (full scan)"
        }
        else {
            Write-TranscriptLog "Subnet ${CIDR}: Smart sample $($ips.Count)/$totalIPs IPs (Start=$startCount End=$endCount Common=$commonCount Even=$evenCount)"
        }
        return $ips
    }
    catch {
        Write-TranscriptLog "ERROR: Failed to expand subnet $CIDR - $($_.Exception.Message)"
        return @()
    }
}

function Resolve-WildcardDomain {
    <#
    .SYNOPSIS
        Resolves wildcard domains by testing common subdomains and sampling results.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$WildcardDomain,
        
        [int]$SamplePercent = 20
    )
    
    # Remove wildcard prefix
    $baseDomain = $WildcardDomain -replace '^\*\.', ''
    
    # Common subdomain prefixes for Microsoft services
    $commonPrefixes = @(
        'www', 'portal', 'api', 'login', 'graph', 'admin', 'outlook',
        'teams', 'endpoint', 'manage', 'config', 'prod', 'us', 'eu', 'ap'
    )
    
    $resolvedHosts = @()
    $resolvedHosts += $baseDomain  # Always include base domain
    
    foreach ($prefix in $commonPrefixes) {
        $testHost = "$prefix.$baseDomain"
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses($testHost)
            if ($resolved.Count -gt 0) {
                $resolvedHosts += $testHost
                Write-TranscriptLog "Wildcard resolution: $testHost resolved successfully"
            }
        }
        catch {
            # Silent fail - subdomain doesn't exist
        }
    }
    
    # Apply sampling
    $sampleSize = [Math]::Max(1, [Math]::Ceiling($resolvedHosts.Count * $SamplePercent / 100))
    $sampled = $resolvedHosts | Select-Object -First $sampleSize
    
    Write-TranscriptLog "Wildcard ${WildcardDomain}: found $($resolvedHosts.Count) hosts, sampled $sampleSize"
    return $sampled
}

function Show-ProgressBar {
    <#
    .SYNOPSIS
        Displays real-time progress with ETA calculation.
    #>
    param(
        [int]$Current,
        [int]$Total,
        [string]$Activity,
        [datetime]$StartTime
    )
    
    $percentComplete = [Math]::Round(($Current / $Total) * 100, 1)
    $elapsed = (Get-Date) - $StartTime
    
    if ($Current -gt 0) {
        $avgTimePerItem = $elapsed.TotalSeconds / $Current
        $remaining = ($Total - $Current) * $avgTimePerItem
        $eta = [TimeSpan]::FromSeconds($remaining)
        $status = "Completed: $Current/$Total ($percentComplete%) | Elapsed: $($elapsed.ToString('mm\:ss')) | ETA: $($eta.ToString('mm\:ss'))"
    }
    else {
        $status = "Starting..."
    }
    
    Write-Progress -Activity $Activity -Status $status -PercentComplete $percentComplete
}

function Test-EndpointBatch {
    <#
    .SYNOPSIS
        Tests a batch of endpoints concurrently (runs in separate job).
    #>
    param(
        [Parameter(Mandatory)]
        [array]$Endpoints,
        
        [Parameter(Mandatory)]
        [string]$Type,  # 'FQDN' or 'IP'
        
        [Parameter(Mandatory)]
        [int]$TimeoutMs,
        
        [array]$Ports = @(443, 80),
        
        [bool]$CheckSSL = $false,
        
        [array]$SSLPatterns = @()
    )
    
    $results = @()
    
    foreach ($endpoint in $Endpoints) {
        foreach ($port in $Ports) {
            # Use enhanced TCP connection test with path validation
            $tcpClient = $null
            $connected = $false
            $errorMsg = $null
            $resolvedIP = $null
            $pathStatus = 'Unknown'
            $errorType = $null
            $startTime = Get-Date
            
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $connectTask = $tcpClient.ConnectAsync($endpoint, $port)
                
                if ($connectTask.Wait($TimeoutMs)) {
                    $elapsed = ((Get-Date) - $startTime).TotalMilliseconds
                    $connected = $tcpClient.Connected
                    
                    if ($connected) {
                        $resolvedIP = $tcpClient.Client.RemoteEndPoint.Address.ToString()
                        $pathStatus = 'Connected'
                        $errorType = 'None'
                    }
                    else {
                        $pathStatus = 'PathAvailable'
                        $errorType = 'RemoteRefused'
                        $errorMsg = "Remote refused (path OK)"
                    }
                }
                else {
                    # Timeout - packet sent but no response (NORMAL for many Azure IPs)
                    $pathStatus = 'PathAvailable'
                    $errorType = 'RemoteTimeout'
                    $errorMsg = "Timeout (${TimeoutMs}ms) - path OK"
                }
            }
            catch {
                $elapsed = ((Get-Date) - $startTime).TotalMilliseconds
                $errorMsg = $_.Exception.Message
                
                # Analyze error to detect local blocks vs remote failures
                if ($_.Exception.InnerException) {
                    $innerMsg = $_.Exception.InnerException.Message
                    
                    if ($elapsed -lt 50) {
                        if ($innerMsg -match 'actively refused|connection refused|access denied|no connection') {
                            $pathStatus = 'LocalBlock'
                            $errorType = 'LocalRefused'
                            $errorMsg = "BLOCKED locally (${elapsed}ms)"
                        }
                        elseif ($innerMsg -match 'host not found|no such host|name resolution') {
                            $pathStatus = 'LocalBlock'
                            $errorType = 'DNSFailure'
                            $errorMsg = "DNS failed"
                        }
                        else {
                            $pathStatus = 'LocalBlock'
                            $errorType = 'ImmediateFailure'
                            $errorMsg = "Blocked (${elapsed}ms)"
                        }
                    }
                    else {
                        $pathStatus = 'PathAvailable'
                        $errorType = 'RemoteFailure'
                        $errorMsg = "Remote error (${elapsed}ms) - path OK"
                    }
                }
                else {
                    if ($elapsed -lt 50) {
                        $pathStatus = 'LocalBlock'
                        $errorType = 'ImmediateFailure'
                    }
                    else {
                        $pathStatus = 'PathAvailable'
                        $errorType = 'RemoteFailure'
                    }
                }
            }
            finally {
                if ($tcpClient) { $tcpClient.Dispose() }
            }
            
            $testResult = [PSCustomObject]@{
                Type       = $Type
                Target     = $endpoint
                Port       = $port
                Connected  = $connected
                PathStatus = $pathStatus  # LocalBlock, PathAvailable, Connected
                ErrorType  = $errorType
                ResolvedIP = $resolvedIP
                Error      = $errorMsg
                Timestamp  = Get-Date
                SSLChecked = $false
                SSLValid   = $null
                SSLIssuer  = $null
                Subnet     = $null  # Will be populated for IP tests
            }
            
            # SSL certificate check for all port 443 connections
            if ($CheckSSL -and $port -eq 443 -and $connected) {
                # Check SSL for all HTTPS endpoints to verify certificates
                # Pattern matching determines if strict validation is required (no SSL inspection)
                $needsStrictValidation = $false
                foreach ($pattern in $SSLPatterns) {
                    if ($endpoint -like $pattern) {
                        $needsStrictValidation = $true
                        break
                    }
                }
                
                # Always check SSL for port 443, but only flag as issue if strict validation required
                if ($true) {
                    Write-Verbose "[SSL] Checking certificate for $endpoint"
                    try {
                        $tcpClient = New-Object System.Net.Sockets.TcpClient
                        $connectTask = $tcpClient.ConnectAsync($endpoint, 443)
                        
                        # Wait for connection with proper error handling
                        $connected = $false
                        try {
                            $connected = $connectTask.Wait($TimeoutMs) -and $tcpClient.Connected
                        }
                        catch {
                            # Task may have faulted, check status
                            $connected = $false
                        }
                        
                        if ($connected) {
                            Write-Verbose "[SSL] TCP connected to $endpoint`:443"
                            
                            # Use static C# method for certificate validation callback
                            # PowerShell scriptblocks don't work in background jobs (no runspace)
                            $method = [SSLHelper].GetMethod('AlwaysAcceptCallback')
                            $callback = [System.Net.Security.RemoteCertificateValidationCallback]::CreateDelegate([System.Net.Security.RemoteCertificateValidationCallback], $method)
                            
                            $sslStream = New-Object System.Net.Security.SslStream(
                                $tcpClient.GetStream(),
                                $false,
                                $callback
                            )
                            
                            $authTask = $sslStream.AuthenticateAsClientAsync($endpoint)
                            
                            # Wait for authentication with proper error handling
                            # SSL handshakes need more time than regular TCP connections
                            $sslTimeoutMs = [Math]::Max($TimeoutMs * 3, 3000)  # At least 3 seconds
                            $authenticated = $false
                            try {
                                $authenticated = $authTask.Wait($sslTimeoutMs)
                            }
                            catch {
                                # Authentication may have faulted
                                $authenticated = $false
                            }
                            
                            if ($authenticated) {
                                Write-Verbose "[SSL] SSL handshake completed for $endpoint"
                                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]$sslStream.RemoteCertificate
                                
                                if ($cert) {
                                    $testResult.SSLChecked = $true
                                    # Explicitly convert to string to avoid serialization issues
                                    $issuerString = if ($cert.Issuer) { [string]$cert.Issuer } else { "" }
                                    $testResult.SSLIssuer = $issuerString
                                    
                                    Write-Verbose "[SSL] Certificate Details:"
                                    Write-Verbose "[SSL]   Issuer: $issuerString"
                                    Write-Verbose "[SSL]   Subject: $($cert.Subject)"
                                    Write-Verbose "[SSL]   NotBefore: $($cert.NotBefore)"
                                    Write-Verbose "[SSL]   NotAfter: $($cert.NotAfter)"
                                    
                                    # Check if from public CA
                                    $publicCAIssuers = @('DigiCert', 'Microsoft', 'GlobalSign', 'Let''s Encrypt', 'GeoTrust', 'Entrust', 'Baltimore', 'Sectigo', 'Comodo', 'Thawte')
                                    $isPublicCA = $null
                                    if ($issuerString) {
                                        $isPublicCA = $publicCAIssuers | Where-Object { $issuerString -match $_ } | Select-Object -First 1
                                    }
                                    
                                    Write-Verbose "[SSL]   Public CA Match: $($isPublicCA -ne $null) (Matched: $isPublicCA)"
                                    
                                    $now = Get-Date
                                    $dateValid = ($now -ge $cert.NotBefore -and $now -le $cert.NotAfter)
                                    Write-Verbose "[SSL]   Date Valid: $dateValid"
                                    
                                    $testResult.SSLValid = ($dateValid -and ($isPublicCA -ne $null))
                                    Write-Verbose "[SSL]   Final Result: $($testResult.SSLValid) (Date:$dateValid, PublicCA:$($isPublicCA -ne $null))"
                                }
                                else {
                                    Write-Verbose "[SSL] No certificate returned"
                                    $testResult.SSLChecked = $true
                                    $testResult.SSLValid = $false
                                    $testResult.SSLIssuer = "ERROR: No certificate returned"
                                }
                            }
                            else {
                                Write-Verbose "[SSL] SSL handshake timeout for $endpoint"
                                $testResult.SSLChecked = $true
                                $testResult.SSLValid = $false
                                $testResult.SSLIssuer = "ERROR: SSL handshake timeout"
                            }
                            
                            $sslStream.Dispose()
                        }
                        else {
                            Write-Verbose "[SSL] TCP connection failed/timeout for $endpoint"
                        }
                        
                        $tcpClient.Dispose()
                    }
                    catch {
                        $errMsg = $_.Exception.Message
                        Write-Verbose "[SSL] Exception during SSL check for $endpoint`: $errMsg"
                        $testResult.SSLChecked = $true
                        $testResult.SSLValid = $false
                        $testResult.SSLIssuer = "ERROR: $errMsg"
                    }
                }
            }
            
            $results += $testResult
        }
    }
    
    return $results
}

#endregion

#region Main Execution

# Initialize
Clear-Host
Write-Host "`n╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║   MICROSOFT INTUNE CONSOLIDATED ENDPOINT CONNECTIVITY TEST             ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

Write-TranscriptLog "=== Test Session Started ==="
Write-TranscriptLog "FQDN Sample Percent: $FqdnSamplePercent%"
Write-TranscriptLog "IP Sample Percent: $IpSamplePercent%"
Write-TranscriptLog "Max Concurrent Jobs: $MaxConcurrentJobs"
Write-TranscriptLog "Timeout: $TimeoutSeconds second(s)"

# Create output folder
$outputPath = Join-Path $PSScriptRoot $OutputFolder
if (-not (Test-Path $outputPath)) {
    New-Item -Path $outputPath -ItemType Directory -Force | Out-Null
    Write-Host "[OK] Created output folder: $outputPath" -ForegroundColor Green
}
else {
    Write-Host "[OK] Using output folder: $outputPath" -ForegroundColor Green
}

Write-TranscriptLog "Output folder: $outputPath"

# Initialize endpoint lists from cache or web
Write-Host "`n┌─────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Magenta
Write-Host "│ LOADING ENDPOINT LISTS                                                  │" -ForegroundColor Magenta
Write-Host "└─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Magenta
Write-Host ""

$cachePath = Join-Path $outputPath "EndpointCache.json"
$endpointData = $null
$usedCache = $false

# Try to use cache first (unless forced refresh)
if (-not $ForceFreshData) {
    $endpointData = Get-CachedEndpointList -CachePath $cachePath -ValidityDays $CacheValidityDays
    if ($endpointData) {
        $usedCache = $true
    }
}
else {
    Write-Host "  [!] Force refresh requested, bypassing cache" -ForegroundColor Yellow
    Write-TranscriptLog "Force fresh data requested"
}

# Fetch fresh data if no valid cache
if (-not $endpointData) {
    $endpointData = Get-ConsolidatedEndpointList -CachePath $cachePath
    
    # If fetch fails, use fallback lists
    if (-not $endpointData) {
        Write-Host "  [!] Using fallback endpoint list (hardcoded in script)" -ForegroundColor Yellow
        Write-TranscriptLog "WARNING: Using fallback endpoint lists"
        
        $endpointData = @{
            FQDNs           = $script:FALLBACK_FQDNS
            IPSubnets       = $script:FALLBACK_IP_SUBNETS
            FetchedDate     = (Get-Date).ToString("o")
            SourceURL       = "Fallback (hardcoded)"
            FQDNCount       = $script:FALLBACK_FQDNS.Count
            IPSubnetCount   = $script:FALLBACK_IP_SUBNETS.Count
        }
    }
}

# Check for changes if we fetched fresh data and had previous cache
if (-not $usedCache -and (Test-Path $cachePath)) {
    try {
        $oldCache = Get-Content $cachePath -Raw | ConvertFrom-Json
        $changes = Compare-EndpointLists -NewFQDNs $endpointData.FQDNs -OldFQDNs $oldCache.FQDNs -NewIPs $endpointData.IPSubnets -OldIPs $oldCache.IPSubnets
        
        if ($changes.HasChanges) {
            Write-Host ""
            Write-Host "  [CHANGES] ENDPOINT LIST CHANGES DETECTED:" -ForegroundColor Yellow
            
            if ($changes.FQDNsAdded.Count -gt 0) {
                Write-Host "    [+] FQDNs Added: $($changes.FQDNsAdded.Count)" -ForegroundColor Green
                $changes.FQDNsAdded | Select-Object -First 5 | ForEach-Object { Write-Host "       • $_" -ForegroundColor Gray }
                if ($changes.FQDNsAdded.Count -gt 5) { Write-Host "       ... and $($changes.FQDNsAdded.Count - 5) more" -ForegroundColor Gray }
            }
            
            if ($changes.FQDNsRemoved.Count -gt 0) {
                Write-Host "    [-] FQDNs Removed: $($changes.FQDNsRemoved.Count)" -ForegroundColor Red
                $changes.FQDNsRemoved | Select-Object -First 5 | ForEach-Object { Write-Host "       • $_" -ForegroundColor Gray }
                if ($changes.FQDNsRemoved.Count -gt 5) { Write-Host "       ... and $($changes.FQDNsRemoved.Count - 5) more" -ForegroundColor Gray }
            }
            
            if ($changes.IPsAdded.Count -gt 0) {
                Write-Host "    [+] IP Subnets Added: $($changes.IPsAdded.Count)" -ForegroundColor Green
                $changes.IPsAdded | Select-Object -First 5 | ForEach-Object { Write-Host "       • $_" -ForegroundColor Gray }
                if ($changes.IPsAdded.Count -gt 5) { Write-Host "       ... and $($changes.IPsAdded.Count - 5) more" -ForegroundColor Gray }
            }
            
            if ($changes.IPsRemoved.Count -gt 0) {
                Write-Host "    [-] IP Subnets Removed: $($changes.IPsRemoved.Count)" -ForegroundColor Red
                $changes.IPsRemoved | Select-Object -First 5 | ForEach-Object { Write-Host "       • $_" -ForegroundColor Gray }
                if ($changes.IPsRemoved.Count -gt 5) { Write-Host "       ... and $($changes.IPsRemoved.Count - 5) more" -ForegroundColor Gray }
            }
            
            Write-TranscriptLog "Changes detected: +$($changes.FQDNsAdded.Count)/-$($changes.FQDNsRemoved.Count) FQDNs, +$($changes.IPsAdded.Count)/-$($changes.IPsRemoved.Count) IPs"
            Write-Host ""
        }
        else {
            Write-Host "  [OK] No changes detected from previous version" -ForegroundColor Green
            Write-TranscriptLog "No endpoint changes detected"
        }
    }
    catch {
        Write-TranscriptLog "Could not compare with previous cache: $($_.Exception.Message)"
    }
}

# Populate script variables
$script:CONSOLIDATED_FQDNS = $endpointData.FQDNs
$script:CONSOLIDATED_IP_SUBNETS = $endpointData.IPSubnets

Write-Host ""
Write-Host "  [INFO] Loaded Endpoints:" -ForegroundColor Cyan
Write-Host "     FQDNs: $($script:CONSOLIDATED_FQDNS.Count)" -ForegroundColor White
Write-Host "     IP Subnets: $($script:CONSOLIDATED_IP_SUBNETS.Count)" -ForegroundColor White
Write-Host "     Source: $($endpointData.SourceURL)" -ForegroundColor Gray
Write-Host ""

# Export current endpoint list to JSON
$consolidatedData = @{
    FQDNs           = $script:CONSOLIDATED_FQDNS
    IPSubnets       = $script:CONSOLIDATED_IP_SUBNETS
    SourceURL       = $endpointData.SourceURL
    ExportDate      = (Get-Date).ToString("o")
    FetchedDate     = $endpointData.FetchedDate
    FQDNCount       = $script:CONSOLIDATED_FQDNS.Count
    IPSubnetCount   = $script:CONSOLIDATED_IP_SUBNETS.Count
}

$jsonPath = Join-Path $outputPath "ConsolidatedEndpointList.json"
$consolidatedData | ConvertTo-Json -Depth 5 | Out-File $jsonPath -Encoding UTF8 -Force
Write-Host "[OK] Exported current endpoint list to JSON" -ForegroundColor Green
Write-TranscriptLog "Exported consolidated list to: $jsonPath"

#region SECTION 1: FQDN Testing

Write-Host "`n┌─────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
Write-Host "│ SECTION 1: FQDN CONNECTIVITY TESTING                                    │" -ForegroundColor Yellow
Write-Host "└─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
Write-Host ""

Write-TranscriptLog "=== FQDN Testing Section Started ==="

# Prepare FQDN test targets
$fqdnTargets = @()
$wildcardCount = 0
$directCount = 0

foreach ($fqdn in $script:CONSOLIDATED_FQDNS) {
    if ($fqdn -like '**') {
        $wildcardCount++
        $resolved = Resolve-WildcardDomain -WildcardDomain $fqdn -SamplePercent $FqdnSamplePercent
        $fqdnTargets += $resolved
    }
    else {
        $directCount++
        $fqdnTargets += $fqdn
    }
}

$fqdnTargets = $fqdnTargets | Select-Object -Unique

Write-Host "  Original FQDNs: $($script:CONSOLIDATED_FQDNS.Count) (Wildcards: $wildcardCount, Direct: $directCount)" -ForegroundColor Gray
Write-Host "  Test Targets: $($fqdnTargets.Count) unique hosts" -ForegroundColor Cyan
Write-Host "  Ports: $($script:TEST_PORTS -join ', ')" -ForegroundColor Gray
Write-Host "  SSL Certificate Validation: Enabled for no-inspection endpoints" -ForegroundColor Gray
Write-Host ""

Write-TranscriptLog "FQDN test targets prepared: $($fqdnTargets.Count) hosts"

# Concurrent FQDN testing
$fqdnStartTime = Get-Date
$fqdnJobs = @()
$fqdnCompleted = 0
$fqdnTotal = $fqdnTargets.Count

# Batch targets for concurrent processing
$batchSize = 5
$batches = @()
for ($i = 0; $i -lt $fqdnTargets.Count; $i += $batchSize) {
    $end = [Math]::Min($i + $batchSize - 1, $fqdnTargets.Count - 1)
    $batches += ,@($fqdnTargets[$i..$end])
}

Write-Host "  Starting concurrent testing with $MaxConcurrentJobs parallel jobs..." -ForegroundColor Cyan
Write-TranscriptLog "Created $($batches.Count) batches for FQDN testing"

$scriptBlock = ${function:Test-EndpointBatch}

foreach ($batch in $batches) {
    # Wait if we've hit the concurrent job limit
    while ((Get-Job -State Running).Count -ge $MaxConcurrentJobs) {
        Start-Sleep -Milliseconds 100
        
        # Collect completed jobs
        $completed = Get-Job -State Completed
        foreach ($job in $completed) {
            $jobResults = Receive-Job -Job $job
            foreach ($result in $jobResults) {
                $script:Results.Add($result)
            }
            Remove-Job -Job $job -Force
            $fqdnCompleted++
        }
        
        Show-ProgressBar -Current $fqdnCompleted -Total $fqdnTotal -Activity "Testing FQDNs" -StartTime $fqdnStartTime
    }
    
    # Start new job
    $job = Start-Job -ScriptBlock {
        param($batch, $timeoutMs, $ports, $sslPatterns, $funcDef)
        
        # Add SSL Helper type in job scope
        if (-not ([System.Management.Automation.PSTypeName]'SSLHelper').Type) {
            Add-Type -TypeDefinition @"
            using System.Net.Security;
            using System.Security.Cryptography.X509Certificates;
            public class SSLHelper {
                public static bool AlwaysAcceptCallback(
                    object sender,
                    X509Certificate certificate,
                    X509Chain chain,
                    SslPolicyErrors sslPolicyErrors)
                {
                    return true;
                }
            }
"@
        }
        
        # Recreate function in job scope
        Invoke-Expression "function Test-EndpointBatch { $funcDef }"
        
        Test-EndpointBatch -Endpoints $batch -Type 'FQDN' -TimeoutMs $timeoutMs -Ports $ports -CheckSSL $true -SSLPatterns $sslPatterns
    } -ArgumentList $batch, $script:TIMEOUT_MS, $script:TEST_PORTS, $script:SSL_NO_INSPECTION_PATTERNS, $scriptBlock.ToString()
    
    $fqdnJobs += $job
}

# Wait for remaining jobs
Write-Host "`n  Waiting for remaining FQDN tests to complete..." -ForegroundColor Cyan

while ((Get-Job -State Running).Count -gt 0) {
    Start-Sleep -Milliseconds 200
    
    $completed = Get-Job -State Completed
    foreach ($job in $completed) {
        $jobResults = Receive-Job -Job $job
        foreach ($result in $jobResults) {
            $script:Results.Add($result)
        }
        Remove-Job -Job $job -Force
        $fqdnCompleted++
    }
    
    Show-ProgressBar -Current $fqdnCompleted -Total $fqdnTotal -Activity "Testing FQDNs" -StartTime $fqdnStartTime
}

Write-Progress -Activity "Testing FQDNs" -Completed

$fqdnDuration = (Get-Date) - $fqdnStartTime
Write-Host "`n[OK] FQDN testing completed in $($fqdnDuration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Green
Write-TranscriptLog "FQDN testing completed: $fqdnCompleted targets in $($fqdnDuration.TotalSeconds)s"

#endregion

#region SECTION 2: IP Subnet Testing

Write-Host "`n┌─────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
Write-Host "│ SECTION 2: IP SUBNET CONNECTIVITY TESTING                               │" -ForegroundColor Yellow
Write-Host "└─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
Write-Host ""

Write-TranscriptLog "=== IP Subnet Testing Section Started ==="

# Expand IP subnets
$ipTargets = @()
$totalIPsInSubnets = 0

Write-Host "  Expanding IP subnets with $IpSamplePercent% sampling..." -ForegroundColor Cyan

foreach ($subnet in $script:CONSOLIDATED_IP_SUBNETS) {
    $ips = Expand-IPSubnet -CIDR $subnet -SamplePercent $IpSamplePercent
    if ($ips.Count -gt 0) {
        $ipTargets += $ips
    }
}

# Deduplicate by IP address (keep first occurrence with subnet info)
$uniqueTargets = @{}
foreach ($target in $ipTargets) {
    if (-not $uniqueTargets.ContainsKey($target.IP)) {
        $uniqueTargets[$target.IP] = $target
    }
}
$ipTargets = $uniqueTargets.Values

# Build SubnetMap and extract IP strings for testing
$script:SubnetMap = @{}
$ipStrings = @()
foreach ($target in $ipTargets) {
    $script:SubnetMap[$target.IP] = $target.Subnet
    $ipStrings += $target.IP
}

Write-Host "  Original Subnets: $($script:CONSOLIDATED_IP_SUBNETS.Count)" -ForegroundColor Gray
Write-Host "  Test Targets: $($ipStrings.Count) sampled IPs" -ForegroundColor Cyan
Write-Host "  Ports: $($script:TEST_PORTS -join ', ')" -ForegroundColor Gray
Write-Host ""

Write-TranscriptLog "IP test targets prepared: $($ipStrings.Count) IPs from $($script:CONSOLIDATED_IP_SUBNETS.Count) subnets"

# Concurrent IP testing
$ipStartTime = Get-Date
$ipJobs = @()
$ipCompleted = 0
$ipTotal = $ipStrings.Count

# Batch IPs
$batchSize = 10
$batches = @()
for ($i = 0; $i -lt $ipStrings.Count; $i += $batchSize) {
    $end = [Math]::Min($i + $batchSize - 1, $ipStrings.Count - 1)
    $batches += ,@($ipStrings[$i..$end])
}

Write-Host "  Starting concurrent testing with $MaxConcurrentJobs parallel jobs..." -ForegroundColor Cyan
Write-TranscriptLog "Created $($batches.Count) batches for IP testing"

foreach ($batch in $batches) {
    # Wait if we've hit the concurrent job limit
    while ((Get-Job -State Running).Count -ge $MaxConcurrentJobs) {
        Start-Sleep -Milliseconds 100
        
        # Collect completed jobs
        $completed = Get-Job -State Completed
        foreach ($job in $completed) {
            $jobResults = Receive-Job -Job $job
            foreach ($result in $jobResults) {
                $script:Results.Add($result)
            }
            Remove-Job -Job $job -Force
            $ipCompleted++
        }
        
        Show-ProgressBar -Current $ipCompleted -Total $ipTotal -Activity "Testing IP Addresses" -StartTime $ipStartTime
    }
    
    # Start new job
    $job = Start-Job -ScriptBlock {
        param($batch, $timeoutMs, $ports, $funcDef)
        
        # Recreate function in job scope
        Invoke-Expression "function Test-EndpointBatch { $funcDef }"
        
        Test-EndpointBatch -Endpoints $batch -Type 'IP' -TimeoutMs $timeoutMs -Ports $ports -CheckSSL $false
    } -ArgumentList $batch, $script:TIMEOUT_MS, $script:TEST_PORTS, $scriptBlock.ToString()
    
    $ipJobs += $job
}

# Wait for remaining jobs
Write-Host "`n  Waiting for remaining IP tests to complete..." -ForegroundColor Cyan

while ((Get-Job -State Running).Count -gt 0) {
    Start-Sleep -Milliseconds 200
    
    $completed = Get-Job -State Completed
    foreach ($job in $completed) {
        $jobResults = Receive-Job -Job $job
        foreach ($result in $jobResults) {
            $script:Results.Add($result)
        }
        Remove-Job -Job $job -Force
        $ipCompleted++
    }
    
    Show-ProgressBar -Current $ipCompleted -Total $ipTotal -Activity "Testing IP Addresses" -StartTime $ipStartTime
}

Write-Progress -Activity "Testing IP Addresses" -Completed

$ipDuration = (Get-Date) - $ipStartTime
Write-Host "`n[OK] IP testing completed in $($ipDuration.TotalSeconds.ToString('F2')) seconds" -ForegroundColor Green
Write-TranscriptLog "IP testing completed: $ipCompleted targets in $($ipDuration.TotalSeconds)s"

#endregion

#region Results Processing and Reporting

Write-Host "`n┌─────────────────────────────────────────────────────────────────────────┐" -ForegroundColor Magenta
Write-Host "│ GENERATING REPORTS                                                       │" -ForegroundColor Magenta
Write-Host "└─────────────────────────────────────────────────────────────────────────┘" -ForegroundColor Magenta
Write-Host ""

Write-TranscriptLog "=== Report Generation Started ==="

# Convert ConcurrentBag to array
$allResults = @($script:Results)

# Calculate statistics
$totalTests = $allResults.Count
$fqdnResults = $allResults | Where-Object { $_.Type -eq 'FQDN' }
$ipResults = $allResults | Where-Object { $_.Type -eq 'IP' }

# FQDN statistics with path-aware metrics
$fqdnConnected = ($fqdnResults | Where-Object { $_.Connected }).Count
$fqdnPathAvailable = ($fqdnResults | Where-Object { $_.PathStatus -in @('Connected', 'PathAvailable') }).Count
# Only count truly blocked FQDNs (not wildcards or expected DNS failures)
$fqdnLocalBlock = ($fqdnResults | Where-Object { $_.PathStatus -eq 'LocalBlock' -and $_.Target -notlike '*`**' -and $_.Error -notlike '*DNS*' }).Count
$fqdnConnectionRate = if ($fqdnResults.Count -gt 0) { [Math]::Round(($fqdnConnected / $fqdnResults.Count) * 100, 2) } else { 0 }
$fqdnPathRate = if ($fqdnResults.Count -gt 0) { [Math]::Round(($fqdnPathAvailable / $fqdnResults.Count) * 100, 2) } else { 0 }

# Legacy variables for backward compatibility
$fqdnSuccess = $fqdnConnected
$fqdnFailed = $fqdnResults.Count - $fqdnConnected
$fqdnSuccessRate = $fqdnConnectionRate

# Add subnet information to IP results
foreach ($result in $ipResults) {
    if ($script:SubnetMap.ContainsKey($result.Target)) {
        $result | Add-Member -NotePropertyName 'Subnet' -NotePropertyValue $script:SubnetMap[$result.Target] -Force
    }
}

# Aggregate results by subnet - NETWORK PATH focus
# SUCCESS = At least 1 IP shows network path is available (PathAvailable or Connected)
$subnetResults = @{}
foreach ($result in $ipResults) {
    if ($result.Subnet) {
        if (-not $subnetResults.ContainsKey($result.Subnet)) {
            $subnetResults[$result.Subnet] = @{
                Subnet = $result.Subnet
                TotalTests = 0
                ConnectedTests = 0
                PathAvailableTests = 0
                LocalBlockTests = 0
                TestedIPs = @()
                HasPath = $false  # Network path available (primary metric)
                HasConnection = $false  # Actual connection (secondary metric)
            }
        }
        
        $subnetResults[$result.Subnet].TotalTests++
        $subnetResults[$result.Subnet].TestedIPs += "$($result.Target):$($result.Port)"
        
        # Count by path status
        if ($result.PathStatus -eq 'Connected') {
            $subnetResults[$result.Subnet].ConnectedTests++
            $subnetResults[$result.Subnet].HasConnection = $true
            $subnetResults[$result.Subnet].HasPath = $true
        }
        elseif ($result.PathStatus -eq 'PathAvailable') {
            $subnetResults[$result.Subnet].PathAvailableTests++
            $subnetResults[$result.Subnet].HasPath = $true
        }
        elseif ($result.PathStatus -eq 'LocalBlock') {
            $subnetResults[$result.Subnet].LocalBlockTests++
        }
    }
}

# Mark subnets with only 1 test as successful if path available
foreach ($subnet in $subnetResults.Values) {
    if ($subnet.TotalTests -eq 1 -and ($subnet.PathAvailableTests -gt 0 -or $subnet.ConnectedTests -gt 0)) {
        $subnet.HasPath = $true
    }
}

# IP-level statistics (secondary metrics)
$ipConnected = ($ipResults | Where-Object { $_.Connected }).Count
$ipPathAvailable = ($ipResults | Where-Object { $_.PathStatus -in @('Connected', 'PathAvailable') }).Count
$ipLocalBlock = ($ipResults | Where-Object { $_.PathStatus -eq 'LocalBlock' }).Count
$ipBlocked = $ipLocalBlock  # Alias for HTML report
$ipConnectionRate = if ($ipResults.Count -gt 0) { [Math]::Round(($ipConnected / $ipResults.Count) * 100, 2) } else { 0 }
$ipPathRate = if ($ipResults.Count -gt 0) { [Math]::Round(($ipPathAvailable / $ipResults.Count) * 100, 2) } else { 0 }
$ipBlockedRate = if ($ipResults.Count -gt 0) { [Math]::Round(($ipBlocked / $ipResults.Count) * 100, 2) } else { 0 }

# Subnet-level statistics (PRIMARY METRIC: Network Path Availability)
$subnetStats = $subnetResults.Values
$totalSubnets = $subnetStats.Count
$subnetsWithPath = ($subnetStats | Where-Object { $_.HasPath }).Count
$subnetsBlocked = $totalSubnets - $subnetsWithPath
$subnetPathRate = if ($totalSubnets -gt 0) { [Math]::Round(($subnetsWithPath / $totalSubnets) * 100, 2) } else { 0 }

# Secondary subnet metric: actual connections
$subnetsConnected = ($subnetStats | Where-Object { $_.HasConnection }).Count
$subnetConnectionRate = if ($totalSubnets -gt 0) { [Math]::Round(($subnetsConnected / $totalSubnets) * 100, 2) } else { 0 }

# SSL validation statistics (critical for detecting MITM/inspection)
$sslChecked = @($allResults.Where({ $_.SSLChecked })).Count
$sslValid = @($allResults.Where({ $_.SSLValid -eq $true })).Count
$invalidResults = @($allResults.Where({ $_.SSLChecked -and ($_.SSLValid -eq $false) }))
$sslMITMSuspected = $invalidResults.Count
if (-not $sslMITMSuspected) { $sslMITMSuspected = 0 }

$totalDuration = (Get-Date) - $script:StartTime

# Console Summary Report
Write-Host "╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                        TEST SUMMARY REPORT                             ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Execution Time: $($totalDuration.ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host "  Total Tests: $totalTests" -ForegroundColor White
Write-Host ""
Write-Host "  ┌─ FQDN Results ────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
Write-Host "  │  Tests: $($fqdnResults.Count)" -ForegroundColor White
Write-Host "  │  Path Available: $fqdnPathAvailable ($fqdnPathRate%)" -ForegroundColor Green
Write-Host "  │  Connected: $fqdnConnected ($fqdnConnectionRate%)" -ForegroundColor Cyan
Write-Host "  │  Blocked: $fqdnLocalBlock" -ForegroundColor Red
Write-Host "  │  " -ForegroundColor Yellow
$sslColor = if ($sslMITMSuspected -gt 0) { 'Red' } elseif ($sslInvalid -gt 0) { 'Yellow' } else { 'Green' }
Write-Host "  │  SSL Validation: $sslChecked checked" -ForegroundColor White
Write-Host "  │    Valid (Public CA): $sslValid" -ForegroundColor Green
Write-Host "  │    Invalid/MITM Suspected: $sslMITMSuspected" -ForegroundColor $sslColor
if ($sslMITMSuspected -gt 0) {
    Write-Host "  │    [!] WARNING: SSL inspection may be interfering" -ForegroundColor Red
}
Write-Host "  └───────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ┌─ IP Subnet Network Path Results ──────────────────────────────────────┐" -ForegroundColor Yellow
Write-Host "  │  PRIMARY: Network Path Availability" -ForegroundColor Cyan
Write-Host "  │  Subnets Tested: $totalSubnets" -ForegroundColor White
Write-Host "  │  Path Available: $subnetsWithPath ($subnetPathRate%)" -ForegroundColor Green
Write-Host "  │  Blocked: $subnetsBlocked" -ForegroundColor Red
Write-Host "  └───────────────────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
Write-Host ""
Write-Host "  ┌─ Individual IP Test Details ──────────────────────────────────────────┐" -ForegroundColor Gray
Write-Host "  │  Total IP Tests: $($ipResults.Count)" -ForegroundColor White
Write-Host "  │  " -ForegroundColor Gray
Write-Host "  │  Status Breakdown:" -ForegroundColor White
Write-Host "  │    Connected: $ipConnected ($ipConnectionRate%)" -ForegroundColor Green
Write-Host "  │    Path OK (no response): $($ipPathAvailable - $ipConnected)" -ForegroundColor Cyan
Write-Host "  │    Blocked: $ipLocalBlock" -ForegroundColor Red
Write-Host "  │  " -ForegroundColor Gray
Write-Host "  │  Subnet Connections: $subnetsConnected / $totalSubnets ($subnetConnectionRate%)" -ForegroundColor Gray
Write-Host "  └───────────────────────────────────────────────────────────────────────┘" -ForegroundColor Gray
Write-Host ""

Write-TranscriptLog "Summary: FQDN $fqdnSuccessRate% ($fqdnSuccess/$($fqdnResults.Count)), Subnet Path Availability $subnetPathRate% ($subnetsWithPath/$totalSubnets), Subnet Connections $subnetConnectionRate% ($subnetsConnected/$totalSubnets), IP Path $ipPathRate% ($ipPathAvailable/$($ipResults.Count))"

# Save detailed FQDN log
$fqdnLogPath = Join-Path $outputPath "FQDN-TestResults.log"
$fqdnLogContent = @()
$fqdnLogContent += "=" * 80
$fqdnLogContent += "FQDN CONNECTIVITY TEST RESULTS"
$fqdnLogContent += "=" * 80
$fqdnLogContent += "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$fqdnLogContent += "Total Tests: $($fqdnResults.Count)"
$fqdnLogContent += "Success: $fqdnSuccess ($fqdnSuccessRate%)"
$fqdnLogContent += "Failed: $fqdnFailed"
$fqdnLogContent += "=" * 80
$fqdnLogContent += ""

foreach ($result in ($fqdnResults | Sort-Object Target, Port)) {
    $status = if ($result.Connected) { "[OK]" } else { "[X]" }
    $fqdnLogContent += "$status $($result.Target):$($result.Port) - $(if ($result.Connected) { "SUCCESS" } else { "FAILED: $($result.Error)" })"
    
    if ($result.SSLChecked) {
        $sslStatus = if ($result.SSLValid) { "[OK] SSL Valid" } else { "[!] SSL Issue" }
        $fqdnLogContent += "    $sslStatus - Issuer: $($result.SSLIssuer)"
    }
    
    if ($result.ResolvedIP) {
        $fqdnLogContent += "    Resolved IP: $($result.ResolvedIP)"
    }
}

$fqdnLogContent | Out-File $fqdnLogPath -Encoding UTF8 -Force
Write-Host "[OK] FQDN detailed log: $fqdnLogPath" -ForegroundColor Green

# Save detailed IP log with subnet aggregation
$ipLogPath = Join-Path $outputPath "IP-TestResults.log"
$ipLogContent = @()
$ipLogContent += "=" * 80
$ipLogContent += "IP SUBNET NETWORK PATH TEST RESULTS"
$ipLogContent += "=" * 80
$ipLogContent += "Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
$ipLogContent += ""
$ipLogContent += "PRIMARY METRIC: Network Path Availability (Can traffic reach ISP/WAN?)"
$ipLogContent += "Subnets Tested: $totalSubnets"
$ipLogContent += "Path Available: $subnetsWithPath ($subnetPathRate%)"
$ipLogContent += "Blocked: $subnetsBlocked"
$ipLogContent += ""
$ipLogContent += "SECONDARY METRICS: Actual Connections"
$ipLogContent += "Subnets with Connection: $subnetsConnected ($subnetConnectionRate%)"
$ipLogContent += "Individual IPs Connected: $ipConnected / $($ipResults.Count) ($ipConnectionRate%)"
$ipLogContent += "Individual IPs Path OK: $ipPathAvailable / $($ipResults.Count) ($ipPathRate%)"
$ipLogContent += "=" * 80
$ipLogContent += ""
$ipLogContent += "SUBNET-LEVEL RESULTS (Path Available = Traffic can leave network)"
$ipLogContent += "=" * 80
$ipLogContent += ""

foreach ($subnet in ($subnetResults.Values | Sort-Object Subnet)) {
    $status = if ($subnet.HasPath) { "[PATH OK]" } else { "[BLOCKED]" }
    $description = if ($subnet.HasPath) { 'NETWORK PATH AVAILABLE' } else { 'LOCALLY BLOCKED' }
    $ipLogContent += "$status $($subnet.Subnet) - $description"
    $ipLogContent += "    Connected: $($subnet.ConnectedTests) | Path Available: $($subnet.PathAvailableTests) | Blocked: $($subnet.LocalBlockTests) | Total: $($subnet.TotalTests)"
    $ipLogContent += ""
}

$ipLogContent += "=" * 80
$ipLogContent += "DETAILED IP-LEVEL RESULTS (PathStatus: Connected / PathAvailable / LocalBlock)"
$ipLogContent += "=" * 80
$ipLogContent += ""

foreach ($result in ($ipResults | Sort-Object Subnet, Target, Port)) {
    $status = if ($result.PathStatus -eq 'Connected') { "[CONN]" } elseif ($result.PathStatus -eq 'PathAvailable') { "[PATH]" } else { "[BLOCK]" }
    $subnetInfo = if ($result.Subnet) { " [$($result.Subnet)]" } else { "" }
    $ipLogContent += "$status $($result.Target):$($result.Port)$subnetInfo - $($result.PathStatus): $($result.Error)"
}

$ipLogContent | Out-File $ipLogPath -Encoding UTF8 -Force
Write-Host "[OK] IP detailed log: $ipLogPath" -ForegroundColor Green

# Save transcript log
$transcriptPath = Join-Path $outputPath "TestSession-Transcript.log"
$script:TranscriptLog | Out-File $transcriptPath -Encoding UTF8 -Force
Write-Host "[OK] Session transcript: $transcriptPath" -ForegroundColor Green

# Generate HTML Overview Report (Primary Page)
$htmlOverviewPath = Join-Path $outputPath "index.html"
$htmlDetailedPath = Join-Path $outputPath "detailed-report.html"

$htmlOverviewContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Intune Connectivity - Network Path Overview</title>
    <meta charset="utf-8">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; text-align: center; font-size: 32px; }
        .overview-header { text-align: center; margin: 30px 0; padding: 20px; background: #f0f0f0; border-radius: 8px; }
        .overview-header h2 { margin: 0; color: #323130; font-size: 24px; }
        .overview-header p { color: #666; font-size: 16px; margin: 10px 0 0 0; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 30px; margin: 40px 0; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 12px; text-align: center; box-shadow: 0 4px 15px rgba(0,0,0,0.2); }
        .stat-card.success { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .stat-card.failed { background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); }
        .stat-card.warning { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .stat-value { font-size: 48px; font-weight: bold; margin: 15px 0; }
        .stat-label { font-size: 16px; opacity: 0.9; text-transform: uppercase; letter-spacing: 1px; }
        .stat-sublabel { font-size: 14px; opacity: 0.8; margin-top: 10px; }
        .details-link { display: inline-block; margin: 30px auto; padding: 15px 40px; background: #0078d4; color: white; text-decoration: none; border-radius: 8px; font-size: 18px; font-weight: bold; box-shadow: 0 4px 10px rgba(0,0,0,0.2); transition: background 0.3s; }
        .details-link:hover { background: #005a9e; }
        .download-link { display: inline-block; margin: 10px; padding: 12px 30px; background: #6264a7; color: white; text-decoration: none; border-radius: 6px; font-size: 16px; font-weight: 600; box-shadow: 0 2px 8px rgba(0,0,0,0.15); transition: background 0.3s; }
        .download-link:hover { background: #464775; }
        .info-box { background: #e6f2ff; border-left: 5px solid #0078d4; padding: 20px; margin: 20px 0; border-radius: 8px; }
        .info-box h3 { margin: 0 0 10px 0; color: #0078d4; font-size: 18px; }
        .info-box p { margin: 5px 0; color: #323130; font-size: 14px; line-height: 1.6; }
        .info-box ul { margin: 10px 0; padding-left: 20px; }
        .info-box li { margin: 5px 0; color: #323130; }
        .info-box.notes { background: #fff8e6; border-left: 5px solid #f59e0b; }
        .info-box.notes h3 { color: #d97706; }
        .alert { padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 5px solid; }
        .alert.success { background: #dff6dd; border-color: #107c10; color: #107c10; }
        .alert.warning { background: #fff4ce; border-color: #f7630c; color: #f7630c; }
        .alert.error { background: #fde7e9; border-color: #d13438; color: #d13438; }
        .alert h3 { margin: 0 0 10px 0; font-size: 20px; }
        .footer { margin-top: 50px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 12px; }
        .detail-button-container { text-align: center; margin: 40px 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 14px; }
        th { background: #0078d4; color: white; padding: 12px; text-align: left; }
        td { padding: 10px 12px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .success-cell { color: #107c10; font-weight: bold; }
        .failed-cell { color: #d13438; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Microsoft Intune Endpoint - Network Path Availability Report</h1>
        
        <div class="overview-header">
            <h2>PRIMARY GOAL: Verify Network Path to ISP/WAN</h2>
            <p>Testing if traffic can successfully leave the local network and reach Microsoft Intune services</p>
            <p><strong>Tested:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | <strong>Duration:</strong> $($totalDuration.ToString('mm\:ss'))</p>
        </div>
        
        <div class="summary">
            <div class="stat-card info">
                <div class="stat-label">FQDN Network Path</div>
                <div class="stat-value">$fqdnPathRate%</div>
                <div class="stat-sublabel">$fqdnPathAvailable / $($fqdnResults.Count) FQDNs can reach network</div>
            </div>
            
            <div class="stat-card $(if ($subnetPathRate -eq 100) { 'success' } elseif ($subnetPathRate -ge 80) { 'warning' } else { 'failed' })">
                <div class="stat-label">IP Subnet Network Path</div>
                <div class="stat-value">$subnetPathRate%</div>
                <div class="stat-sublabel">$subnetsWithPath / $totalSubnets subnets accessible</div>
            </div>
            
            <div class="stat-card $(if ($sslMITMSuspected -eq 0) { 'success' } else { 'warning' })">
                <div class="stat-label">SSL Certificate Validation</div>
                <div class="stat-value">$(if ($sslMITMSuspected -eq 0) { '✅' } else { '⚠️' })</div>
                <div class="stat-sublabel">$sslValid valid / $sslChecked checked$(if ($sslMITMSuspected -gt 0) { " | $sslMITMSuspected invalid" })</div>
            </div>
        </div>
        
        $(if ($fqdnPathRate -ge 90 -and $subnetPathRate -ge 90) {
            "<div class='alert success'><h3>✅ Excellent Network Path Availability</h3><p>Your network configuration allows traffic to successfully reach Microsoft Intune endpoints. No significant firewall or routing blocks detected.</p></div>"
        } elseif ($fqdnPathRate -ge 70 -or $subnetPathRate -ge 70) {
            "<div class='alert warning'><h3>⚠️ Partial Network Path Issues</h3><p>Some endpoints are experiencing connectivity issues. Review the detailed report to identify blocked endpoints.</p></div>"
        } else {
            "<div class='alert error'><h3>❌ Critical Network Path Issues</h3><p>Significant number of endpoints are blocked. Firewall rules or proxy configuration may need adjustment.</p></div>"
        })
        
        $(if ($sslMITMSuspected -gt 0) {
            "<div class='alert warning'><h3>🔒 SSL Inspection Detected</h3><p><strong>$sslMITMSuspected endpoints</strong> show invalid SSL certificates, indicating SSL inspection/MITM is active. Microsoft Intune requires certain endpoints to have no SSL inspection. Review the detailed report for affected endpoints.</p></div>"
        })
        
        <div class="detail-button-container">
            <a href="ip-details.html" class="details-link" style="background: #107c10; margin: 10px;">🌐 View IP Subnet Details</a>
            <a href="fqdn-details.html" class="details-link" style="background: #0078d4; margin: 10px;">🔗 View FQDN Details</a>
        </div>
        
        <h2>📋 Quick Summary</h2>
        <table>
            <tr><th>Metric</th><th>Value</th><th>Status</th></tr>
            <tr>
                <td>FQDN Path Availability</td>
                <td>$fqdnPathAvailable / $($fqdnResults.Count) ($fqdnPathRate%)</td>
                <td class="$(if ($fqdnPathRate -ge 90) { 'success-cell' } else { 'failed-cell' })">$(if ($fqdnPathRate -ge 90) { 'GOOD' } else { 'NEEDS ATTENTION' })</td>
            </tr>
            <tr>
                <td>IP Subnet Path Availability</td>
                <td>$subnetsWithPath / $totalSubnets ($subnetPathRate%)</td>
                <td class="$(if ($subnetPathRate -eq 100) { 'success-cell' } else { 'failed-cell' })">$(if ($subnetPathRate -eq 100) { 'EXCELLENT' } elseif ($subnetPathRate -ge 90) { 'GOOD' } else { 'NEEDS ATTENTION' })</td>
            </tr>
            <tr>
                <td>SSL Certificate Validation</td>
                <td>$sslValid valid / $sslChecked checked</td>
                <td class="$(if ($sslMITMSuspected -eq 0) { 'success-cell' } else { 'failed-cell' })">$(if ($sslMITMSuspected -eq 0) { 'PASS' } else { 'SSL INSPECTION ACTIVE' })</td>
            </tr>
        </table>
        
        <div class="info-box">
            <h3>📦 Download Endpoint Data</h3>
            <p>Access the raw endpoint list for automation, scripting, or further analysis:</p>
            <div style="text-align: center; margin-top: 15px;">
                <a href="ConsolidatedEndpointList.json" class="download-link" download>📄 Download JSON Endpoint List</a>
            </div>
            <p style="margin-top: 15px; font-size: 13px; color: #666;"><strong>Contents:</strong> Complete list of FQDNs, IP subnets, ports, and required/optional flags from Microsoft's official Intune endpoint documentation.</p>
        </div>
        
        <div class="info-box notes">
            <h3>ℹ️ Important Notes from Microsoft</h3>
            <ul>
                <li><strong>Wildcard FQDNs:</strong> Many Intune endpoints use wildcards (e.g., *.manage.microsoft.com). These represent dynamic cloud services and cannot be tested directly.</li>
                <li><strong>SSL Inspection:</strong> Microsoft requires that certain endpoints bypass SSL inspection/decryption. Invalid certificates indicate your network may be performing MITM inspection.</li>
                <li><strong>Network Path vs Connection:</strong> "Path Available" means traffic can reach the ISP/WAN but the endpoint may not respond. This is expected behavior for many cloud services.</li>
                <li><strong>Ports:</strong> Intune primarily uses HTTPS (443) and HTTP (80). Ensure both ports are accessible for all endpoints listed in the detailed reports.</li>
            </ul>
        </div>
        
        <div class="footer">
            <p>Generated by Intune Connectivity Tool | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p>Source: <a href="https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints">Microsoft Learn - Intune Endpoints</a></p>
        </div>
    </div>
</body>
</html>
"@

$htmlOverviewContent | Out-File $htmlOverviewPath -Encoding UTF8 -Force
Write-Host "[OK] HTML overview report: $htmlOverviewPath" -ForegroundColor Green

# Generate IP Subnet Details HTML Report
$htmlIpDetailsPath = Join-Path $outputPath "ip-details.html"
$htmlIpContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>IP Subnet Details - Intune Connectivity</title>
    <meta charset="utf-8">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #107c10; border-bottom: 3px solid #107c10; padding-bottom: 10px; }
        h2 { color: #323130; margin-top: 30px; border-left: 4px solid #107c10; padding-left: 10px; }
        h3 { color: #505050; margin-top: 20px; }
        .back-link { display: inline-block; margin: 20px 0; padding: 10px 20px; background: #107c10; color: white; text-decoration: none; border-radius: 5px; }
        .back-link:hover { background: #0e6b0e; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-card.success { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .stat-card.failed { background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); }
        .stat-card.info { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
        .stat-card.info-dark { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); }
        .stat-card.blocked-danger { background: linear-gradient(135deg, #ffafbd 0%, #ffc3a0 100%); color: #8b0000; font-weight: 600; }
        .summary-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 15px 0; }
        .stat-value { font-size: 32px; font-weight: bold; margin: 10px 0; }
        .stat-label { font-size: 13px; opacity: 0.9; }
        .stat-sublabel { font-size: 11px; opacity: 0.8; margin-top: 5px; }
        .chart-container { margin: 30px 0; text-align: center; }
        canvas { max-width: 500px; margin: 0 auto; display: block; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 13px; }
        th { background: #107c10; color: white; padding: 10px; text-align: left; position: sticky; top: 0; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .success-cell { color: #107c10; font-weight: bold; }
        .failed-cell { color: #d13438; font-weight: bold; }
        .info-box { background: #f0f7ff; border-left: 4px solid #0078d4; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .log-section { background: #f9f9f9; padding: 15px; margin: 20px 0; border-radius: 8px; border: 1px solid #ddd; }
        .log-link { color: #0078d4; text-decoration: none; font-weight: bold; }
        .log-link:hover { text-decoration: underline; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 12px; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
    <div class="container">
        <a href="index.html" class="back-link">← Back to Overview</a>
        
        <h1>🌐 IP Subnet Network Path Details</h1>
        
        <div class="info-box">
            <strong>PRIMARY GOAL:</strong> Verify that network traffic can successfully leave the local network and reach Microsoft Intune IP endpoints via ISP/WAN.<br>
            <strong>Path Available</strong> means packets can be routed out (firewall/routing OK), even if the remote endpoint doesn't respond.<br>
            <strong>Connected</strong> means full TCP handshake completed successfully.
        </div>
        
        <h2>📊 Network Path Summary</h2>
        
        <!-- Row 1: Totals -->
        <div class="summary-row">
            <div class="stat-card info-dark">
                <div class="stat-label">Total Subnets</div>
                <div class="stat-value">$totalSubnets</div>
                <div class="stat-sublabel">Tested from Microsoft endpoints</div>
            </div>
            <div class="stat-card info-dark">
                <div class="stat-label">Total IP Tests</div>
                <div class="stat-value">$($ipResults.Count)</div>
                <div class="stat-sublabel">Individual IP samples tested</div>
            </div>
        </div>
        
        <!-- Row 2: Path & Subnet Connectivity -->
        <div class="summary-row">
            <div class="stat-card success">
                <div class="stat-label">Path Available</div>
                <div class="stat-value">$subnetsWithPath</div>
                <div class="stat-sublabel">$subnetPathRate% of subnets</div>
            </div>
            <div class="stat-card success">
                <div class="stat-label">Subnets w/ Connection</div>
                <div class="stat-value">$subnetsConnected</div>
                <div class="stat-sublabel">$subnetConnectionRate% with TCP response</div>
            </div>
        </div>
        
        <!-- Row 3: IP Connection & Blocks -->
        <div class="summary-row">
            <div class="stat-card success">
                <div class="stat-label">IPs Connected</div>
                <div class="stat-value">$ipConnected</div>
                <div class="stat-sublabel">$ipConnectionRate% of tested IPs</div>
            </div>
            <div class="stat-card $(if ($subnetsBlocked -eq 0) { 'success' } else { 'blocked-danger' })">
                <div class="stat-label">Blocked Subnets</div>
                <div class="stat-value">$subnetsBlocked</div>
                <div class="stat-sublabel">$(if ($subnetsBlocked -eq 0) { 'No blocks detected ✓' } else { 'Network blocks detected!' })</div>
            </div>
        </div>
        
        <div class="chart-container">
            <canvas id="subnetPathChart"></canvas>
        </div>
        
        <h2>🔍 Individual IP Test Breakdown</h2>
        <div class="summary">
            <div class="stat-card success">
                <div class="stat-label">Connected (Full TCP)</div>
                <div class="stat-value">$ipConnected</div>
                <div class="stat-sublabel">$ipConnectionRate%</div>
            </div>
            <div class="stat-card info">
                <div class="stat-label">Path OK (No Response)</div>
                <div class="stat-value">$ipPathAvailable</div>
                <div class="stat-sublabel">$ipPathRate%</div>
            </div>
            <div class="stat-card $(if ($ipBlocked -eq 0) { 'success' } else { 'failed' })">
                <div class="stat-label">Locally Blocked</div>
                <div class="stat-value" style="color: white;">$ipBlocked</div>
                <div class="stat-sublabel">$ipBlockedRate%</div>
            </div>
        </div>
        
        <div class="chart-container">
            <canvas id="ipStatusChart"></canvas>
        </div>
        
        <h2>📋 Complete Subnet Test Results</h2>
        <p>Detailed breakdown of all $totalSubnets subnets tested with connection statistics per subnet.</p>
        <table>
            <tr><th>Status</th><th>Subnet (CIDR)</th><th>Connected</th><th>Path OK</th><th>Blocked</th><th>Total Tests</th><th>Path Rate</th></tr>
"@

$sortedSubnets = $subnetResults.Values | Sort-Object @{Expression={$_.HasPath}; Descending=$true}, Subnet
foreach ($subnet in $sortedSubnets) {
    $status = if ($subnet.HasPath) { "✅ PATH OK" } else { "❌ BLOCKED" }
    $statusClass = if ($subnet.HasPath) { "success-cell" } else { "failed-cell" }
    $pathRate = if ($subnet.TotalTests -gt 0) { [Math]::Round((($subnet.ConnectedTests + $subnet.PathAvailableTests) / $subnet.TotalTests) * 100, 1) } else { 0 }
    $htmlIpContent += "<tr><td class='$statusClass'>$status</td><td><code>$($subnet.Subnet)</code></td><td>$($subnet.ConnectedTests)</td><td>$($subnet.PathAvailableTests)</td><td>$($subnet.LocalBlockTests)</td><td>$($subnet.TotalTests)</td><td>$pathRate%</td></tr>`n"
}

$htmlIpContent += @"
        </table>
        
        <h2>📝 Test Configuration</h2>
        <table>
            <tr><th>Parameter</th><th>Value</th></tr>
            <tr><td>IP Sample Percent</td><td>$IpSamplePercent%</td></tr>
            <tr><td>Max Concurrent Jobs</td><td>$MaxConcurrentJobs</td></tr>
            <tr><td>Connection Timeout</td><td>$TimeoutSeconds second(s)</td></tr>
            <tr><td>Test Ports</td><td>$($script:TEST_PORTS -join ', ')</td></tr>
            <tr><td>Smart Sampling</td><td>Enabled (Priority: Start/End IPs, Common offsets)</td></tr>
        </table>
        
        <h2>📄 Generated Log Files</h2>
        <div class="log-section">
            <h3>📊 IP-TestResults.log</h3>
            <p><strong>Description:</strong> Comprehensive log containing detailed IP-level test results with PathStatus for each IP tested.</p>
            <p><strong>Content:</strong> Includes subnet aggregation summary, individual IP test results with connection status (Connected/PathAvailable/LocalBlock), error details, and subnet groupings.</p>
            <p><strong>Use Case:</strong> Troubleshooting specific IP connectivity issues, identifying blocked IPs, analyzing subnet patterns.</p>
            <p><a href="IP-TestResults.log" class="log-link">📥 Download IP-TestResults.log</a></p>
        </div>
        
        <div class="log-section">
            <h3>📝 TestSession-Transcript.log</h3>
            <p><strong>Description:</strong> Complete execution transcript of the test session including all operations performed.</p>
            <p><strong>Content:</strong> Timestamps, cache operations, endpoint loading, test execution phases, and report generation steps.</p>
            <p><strong>Use Case:</strong> Debugging script execution, verifying test sequence, audit trail.</p>
            <p><a href="TestSession-Transcript.log" class="log-link">📥 Download TestSession-Transcript.log</a></p>
        </div>
        
        <div class="footer">
            <p>Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Execution Time: $($totalDuration.ToString('mm\:ss'))</p>
            <p>Source: <a href="https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints#consolidated-endpoint-list">Microsoft Learn - Intune Endpoints</a></p>
        </div>
    </div>
    
    <script>
        // Subnet Path Availability Chart
        new Chart(document.getElementById('subnetPathChart'), {
            type: 'doughnut',
            data: {
                labels: ['Path Available', 'Blocked'],
                datasets: [{
                    data: [$subnetsWithPath, $subnetsBlocked],
                    backgroundColor: ['#38ef7d', '#f45c43']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: { display: true, text: 'Subnet Network Path Availability', font: { size: 18 } },
                    legend: { position: 'bottom' }
                }
            }
        });
        
        // Individual IP Status Chart
        new Chart(document.getElementById('ipStatusChart'), {
            type: 'doughnut',
            data: {
                labels: ['Connected', 'Path OK (No Response)', 'Blocked'],
                datasets: [{
                    data: [$ipConnected, $ipPathAvailable, $ipBlocked],
                    backgroundColor: ['#38ef7d', '#00f2fe', '#f45c43']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: { display: true, text: 'Individual IP Test Status Distribution', font: { size: 18 } },
                    legend: { position: 'bottom' }
                }
            }
        });
    </script>
</body>
</html>
"@

$htmlIpContent | Out-File $htmlIpDetailsPath -Encoding UTF8 -Force
Write-Host "[OK] HTML IP details report: $htmlIpDetailsPath" -ForegroundColor Green

# Generate FQDN Details HTML Report
$htmlFqdnDetailsPath = Join-Path $outputPath "fqdn-details.html"
$htmlFqdnContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>FQDN Details - Intune Connectivity</title>
    <meta charset="utf-8">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; border-bottom: 3px solid #0078d4; padding-bottom: 10px; }
        h2 { color: #323130; margin-top: 30px; border-left: 4px solid #0078d4; padding-left: 10px; }
        h3 { color: #505050; margin-top: 20px; }
        .back-link { display: inline-block; margin: 20px 0; padding: 10px 20px; background: #0078d4; color: white; text-decoration: none; border-radius: 5px; }
        .back-link:hover { background: #005a9e; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-card.success { background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%); }
        .stat-card.failed { background: linear-gradient(135deg, #eb3349 0%, #f45c43 100%); }
        .stat-card.warning { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }
        .stat-card.info { background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); }
        .stat-value { font-size: 32px; font-weight: bold; margin: 10px 0; }
        .stat-label { font-size: 13px; opacity: 0.9; }
        .stat-sublabel { font-size: 11px; opacity: 0.8; margin-top: 5px; }
        .chart-container { margin: 30px 0; text-align: center; }
        canvas { max-width: 500px; margin: 0 auto; display: block; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 13px; }
        th { background: #0078d4; color: white; padding: 10px; text-align: left; position: sticky; top: 0; }
        td { padding: 8px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .success-cell { color: #107c10; font-weight: bold; }
        .failed-cell { color: #d13438; font-weight: bold; }
        .warning-cell { color: #f7630c; font-weight: bold; }
        .info-box { background: #f0f7ff; border-left: 4px solid #0078d4; padding: 15px; margin: 20px 0; border-radius: 4px; }
        .alert { padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 5px solid; }
        .alert.warning { background: #fff4ce; border-color: #f7630c; color: #f7630c; }
        .alert.error { background: #fde7e9; border-color: #d13438; color: #d13438; }
        .alert h3 { margin: 0 0 10px 0; font-size: 20px; }
        .log-section { background: #f9f9f9; padding: 15px; margin: 20px 0; border-radius: 8px; border: 1px solid #ddd; }
        .log-link { color: #0078d4; text-decoration: none; font-weight: bold; }
        .log-link:hover { text-decoration: underline; }
        .json-section { background: #f0f0f0; padding: 15px; margin: 20px 0; border-radius: 8px; border: 1px solid #ccc; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 12px; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
    <div class="container">
        <a href="index.html" class="back-link">← Back to Overview</a>
        
        <h1>🔗 FQDN Network Path Details</h1>
        
        <div class="info-box">
            <strong>PRIMARY GOAL:</strong> Verify that network traffic can successfully reach Microsoft Intune FQDN endpoints.<br>
            <strong>Path Available</strong> means DNS resolution succeeded and packets can be routed out (firewall/routing OK).<br>
            <strong>Connected</strong> means full TCP handshake completed successfully.<br>
            <strong>SSL Validation</strong> checks for corporate SSL inspection/MITM on endpoints requiring direct certificate trust.
        </div>
        
        <h2>📊 Network Path Summary</h2>
        <div class="summary">
            <div class="stat-card info">
                <div class="stat-label">Total FQDNs</div>
                <div class="stat-value">$($fqdnResults.Count)</div>
            </div>
            <div class="stat-card success">
                <div class="stat-label">Path Available</div>
                <div class="stat-value">$fqdnPathAvailable</div>
                <div class="stat-sublabel">$fqdnPathRate%</div>
            </div>
            <div class="stat-card success">
                <div class="stat-label">Connected</div>
                <div class="stat-value">$fqdnConnected</div>
                <div class="stat-sublabel">$fqdnConnectionRate%</div>
            </div>
        </div>
        
        <div class="chart-container">
            <canvas id="fqdnPathChart"></canvas>
        </div>
        
        <h2>🔒 SSL Certificate Validation Analysis</h2>
        <div class="info-box">
            <h3>How SSL Validation Works:</h3>
            <p><strong>Method:</strong> The script validates SSL certificates by checking if they are signed by a trusted public Certificate Authority (CA). This is done using .NET's <code>System.Net.Security.SslStream</code> with <code>RemoteCertificateValidationCallback</code>.</p>
            <p><strong>What we check:</strong></p>
            <ul>
                <li>Certificate is issued by a public CA (not corporate/internal CA)</li>
                <li>Certificate chain validation passes</li>
                <li>Certificate is not expired or revoked</li>
                <li>Certificate matches the hostname</li>
            </ul>
            <p><strong>Why this matters:</strong> If your corporate firewall/proxy is performing SSL inspection (MITM), it replaces Microsoft's certificate with one signed by your corporate CA. This is detected as invalid because it's not from a public CA.</p>
            <p><strong>Test Scope:</strong> Only endpoints marked as requiring "no SSL inspection" in Microsoft documentation are tested (typically *.manage.microsoft.com, *.infra.windows.net, etc.).</p>
        </div>
        $(if ($sslMITMSuspected -gt 0) {
            "<div class='alert warning'><h3>⚠️ SSL Inspection Detected</h3><p><strong>$sslMITMSuspected of $sslChecked endpoints</strong> show invalid SSL certificates. This indicates corporate SSL inspection/MITM is active on your network. Microsoft Intune documentation specifically lists endpoints that require <strong>no SSL inspection</strong> to function correctly.</p><p><strong>Impact:</strong> SSL inspection can break Intune enrollment, policy delivery, and app management.</p><p><strong>Recommendation:</strong> Configure your firewall/proxy to bypass SSL inspection for Microsoft Intune endpoints.</p></div>"
        } else {
            "<div class='info-box'><strong>Status:</strong> No SSL inspection detected on tested endpoints requiring direct certificate trust.</div>"
        })
        
        <div class="summary">
            <div class="stat-card info">
                <div class="stat-label">SSL Checks Performed</div>
                <div class="stat-value">$sslChecked</div>
            </div>
            <div class="stat-card $(if ($sslValid -gt 0) { 'success' } else { 'info' })">
                <div class="stat-label">Valid Certificates</div>
                <div class="stat-value">$sslValid</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-label">Invalid/MITM Suspected</div>
                <div class="stat-value">$sslMITMSuspected</div>
            </div>
        </div>
        
        <div class="chart-container">
            <canvas id="sslChart"></canvas>
        </div>
        
        <h2>📋 Testable FQDN Results (Direct Hostnames)</h2>
        <p>Direct FQDNs that can be tested for connectivity and SSL validation.</p>
        <table>
            <tr><th>Status</th><th>FQDN</th><th>Resolved IP</th><th>Port</th><th>Path Status</th><th>SSL Valid</th><th>Error</th></tr>
"@

# Separate wildcard and non-wildcard FQDNs
$testableFqdns = $fqdnResults | Where-Object { $_.Target -notlike '*`**' -and $_.PathStatus -ne 'LocalBlock' }
$wildcardFqdns = $fqdnResults | Where-Object { $_.Target -like '*`**' -or ($_.PathStatus -eq 'LocalBlock' -and $_.Error -like '*DNS*') }

$sortedTestable = $testableFqdns | Sort-Object @{Expression={$_.PathStatus -eq 'Connected'}; Descending=$true}, @{Expression={$_.PathStatus -eq 'PathAvailable'}; Descending=$true}, Target
foreach ($fqdn in $sortedTestable) {
    $statusIcon = switch ($fqdn.PathStatus) {
        'Connected' { '✅' }
        'PathAvailable' { '🟡' }
        default { '❌' }
    }
    $statusClass = switch ($fqdn.PathStatus) {
        'Connected' { 'success-cell' }
        'PathAvailable' { 'warning-cell' }
        default { 'failed-cell' }
    }
    $sslStatus = if ($fqdn.SSLChecked) { 
        if ($fqdn.SSLValid) { '✅ Valid' } else { '⚠️ Invalid/MITM' }
    } else { 
        'N/A' 
    }
    $sslClass = if ($fqdn.SSLChecked -and -not $fqdn.SSLValid) { 'warning-cell' } else { '' }
    $resolvedIp = if ($fqdn.ResolvedIP) { $fqdn.ResolvedIP } else { '-' }
    $error = if ($fqdn.Error) { $fqdn.Error } else { 'None' }
    
    $htmlFqdnContent += "<tr><td class='$statusClass'>$statusIcon $($fqdn.PathStatus)</td><td><code>$($fqdn.Target)</code></td><td>$resolvedIp</td><td>$($fqdn.Port)</td><td class='$statusClass'>$($fqdn.PathStatus)</td><td class='$sslClass'>$sslStatus</td><td>$error</td></tr>`n"
}

$htmlFqdnContent += @"
        </table>
        
        <h2>🔀 Wildcard FQDNs (Expected DNS Failures)</h2>
        <div class="info-box">
            <p><strong>Note:</strong> The following endpoints contain wildcards (e.g., *.manage.microsoft.com) and cannot be directly tested. DNS resolution failures are <strong>expected and normal</strong> for these entries.</p>
            <p><strong>Purpose:</strong> These wildcard entries are used in firewall/proxy configurations to allow entire domains. Your firewall should be configured to allow these patterns.</p>
            <p><strong>DNS Status:</strong> The table below shows the original wildcard FQDN from Microsoft documentation. When tested directly, these patterns fail DNS resolution as expected because wildcards are not valid DNS names.</p>
        </div>
        <table>
            <tr><th>Wildcard FQDN</th><th>Ports Required</th><th>DNS Result</th><th>Category</th><th>Purpose</th></tr>
"@

# Get wildcard FQDNs from original source data
$wildcardPatterns = $script:CONSOLIDATED_FQDNS | Where-Object { $_ -like '*`**' } | Sort-Object
foreach ($pattern in $wildcardPatterns) {
    $category = if ($pattern -like '*.manage.*' -or $pattern -like '*.infra.*') { 'Core Management' } 
                elseif ($pattern -like '*.delivery.*' -or $pattern -like '*.windowsupdate.*' -or $pattern -like '*.do.dsp.*') { 'Update/Delivery' }
                elseif ($pattern -like '*.dm.microsoft.com') { 'Device Management' }
                elseif ($pattern -like '*attest.azure.net') { 'Attestation' }
                elseif ($pattern -like '*.microsoft.com' -or $pattern -like '*.windows.*') { 'Microsoft Services' }
                else { 'General' }
    
    $purpose = if ($pattern -like '*.manage.*') { 'Intune service management' }
               elseif ($pattern -like '*attest*') { 'Device attestation/TPM validation' }
               elseif ($pattern -like '*.delivery.*' -or $pattern -like '*.windowsupdate.*') { 'Windows Update and app delivery' }
               elseif ($pattern -like '*.dm.microsoft.com') { 'Device enrollment and check-in' }
               else { 'Supporting services' }
    
    $htmlFqdnContent += "<tr><td><code>$pattern</code></td><td>443, 80</td><td class='warning-cell'>Cannot resolve (wildcard)</td><td>$category</td><td>$purpose</td></tr>`n"
}

$htmlFqdnContent += @"
        </table>
        
        <h2>📝 Test Configuration</h2>
        <table>
            <tr><th>Parameter</th><th>Value</th></tr>
            <tr><td>FQDN Sample Percent</td><td>$FqdnSamplePercent%</td></tr>
            <tr><td>Max Concurrent Jobs</td><td>$MaxConcurrentJobs</td></tr>
            <tr><td>Connection Timeout</td><td>$TimeoutSeconds second(s)</td></tr>
            <tr><td>Test Ports</td><td>$($script:TEST_PORTS -join ', ')</td></tr>
            <tr><td>SSL Validation</td><td>Enabled (Public CA verification)</td></tr>
        </table>
        
        <h2>📄 Generated Files</h2>
        <div class="log-section">
            <h3>📊 FQDN-TestResults.log</h3>
            <p><strong>Description:</strong> Detailed FQDN test results log with connection status, SSL validation, and error details.</p>
            <p><strong>Content:</strong> Lists all FQDN endpoints tested with success/failure status, PathStatus (Connected/PathAvailable/LocalBlock), SSL certificate validation results, and detailed error messages.</p>
            <p><strong>Use Case:</strong> Troubleshooting specific FQDN connectivity issues, identifying DNS failures, SSL inspection problems, and firewall blocks.</p>
            <p><a href="FQDN-TestResults.log" class="log-link">📥 Download FQDN-TestResults.log</a></p>
        </div>
        
        <div class="json-section">
            <h3>📦 ConsolidatedEndpointList.json</h3>
            <p><strong>Description:</strong> Complete list of Microsoft Intune consolidated endpoints in JSON format.</p>
            <p><strong>Content:</strong> All FQDN and IP subnet endpoints extracted from <a href="https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints#consolidated-endpoint-list" target="_blank">Microsoft Learn documentation</a>. Includes wildcard FQDNs expanded to testable hostnames, IP subnets in CIDR notation, port requirements, and SSL inspection bypass requirements.</p>
            <p><strong>Use Case:</strong> Firewall rule configuration, proxy bypass list creation, network planning, and automation scripts.</p>
            <p><strong>Cache:</strong> Updated every $CacheValidityDays days to ensure latest endpoint list from Microsoft.</p>
            <p><a href="ConsolidatedEndpointList.json" class="log-link">📥 Download ConsolidatedEndpointList.json</a></p>
        </div>
        
        <div class="log-section">
            <h3>📝 TestSession-Transcript.log</h3>
            <p><strong>Description:</strong> Complete execution transcript of the test session.</p>
            <p><strong>Content:</strong> Timestamps, cache operations, endpoint loading, test execution phases, and report generation steps.</p>
            <p><strong>Use Case:</strong> Debugging script execution, verifying test sequence, audit trail.</p>
            <p><a href="TestSession-Transcript.log" class="log-link">📥 Download TestSession-Transcript.log</a></p>
        </div>
        
        <div class="footer">
            <p>Report Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') | Execution Time: $($totalDuration.ToString('mm\:ss'))</p>
            <p>Source: <a href="https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/intune-endpoints#consolidated-endpoint-list">Microsoft Learn - Intune Endpoints</a></p>
        </div>
    </div>
    
    <script>
        // FQDN Path Status Chart (excluding blocked endpoints)
        new Chart(document.getElementById('fqdnPathChart'), {
            type: 'doughnut',
            data: {
                labels: ['Connected', 'Path Available'],
                datasets: [{
                    data: [$fqdnConnected, $($fqdnPathAvailable - $fqdnConnected)],
                    backgroundColor: ['#38ef7d', '#00f2fe']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: { display: true, text: 'FQDN Network Path Status Distribution', font: { size: 18 } },
                    legend: { position: 'bottom' }
                }
            }
        });
        
        // SSL Validation Chart
        new Chart(document.getElementById('sslChart'), {
            type: 'doughnut',
            data: {
                labels: ['Valid (Public CA)', 'Invalid/MITM Suspected'],
                datasets: [{
                    data: [$sslValid, $sslMITMSuspected],
                    backgroundColor: ['#38ef7d', '#f5576c']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    title: { display: true, text: 'SSL Certificate Validation Results', font: { size: 18 } },
                    legend: { position: 'bottom' }
                }
            }
        });
    </script>
</body>
</html>
"@

$htmlFqdnContent | Out-File $htmlFqdnDetailsPath -Encoding UTF8 -Force
Write-Host "[OK] HTML FQDN details report: $htmlFqdnDetailsPath" -ForegroundColor Green

Write-TranscriptLog "All reports generated successfully"

#endregion

# Final summary
Write-Host "`n╔════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║                    TEST COMPLETED SUCCESSFULLY                         ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "📁 Output Location: $outputPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Generated Files:" -ForegroundColor White
Write-Host "  HTML Reports:" -ForegroundColor Cyan
Write-Host "    • index.html - Overview report (Network Path Availability)" -ForegroundColor Cyan
Write-Host "    • ip-details.html - Complete IP subnet analysis" -ForegroundColor Cyan
Write-Host "    • fqdn-details.html - Complete FQDN analysis with SSL inspection details" -ForegroundColor Cyan
Write-Host "  Log Files:" -ForegroundColor Gray
Write-Host "    • FQDN-TestResults.log - Detailed FQDN test log" -ForegroundColor Gray
Write-Host "    • IP-TestResults.log - Detailed IP test log" -ForegroundColor Gray
Write-Host "    • TestSession-Transcript.log - Complete session transcript" -ForegroundColor Gray
Write-Host "  Data Files:" -ForegroundColor Gray
Write-Host "    • ConsolidatedEndpointList.json - Microsoft Intune endpoint list" -ForegroundColor Gray
Write-Host ""
Write-Host "💡 Open index.html in your browser for quick overview!" -ForegroundColor Yellow
Write-Host ""

Write-TranscriptLog "=== Test Session Completed Successfully ==="
Write-TranscriptLog "Total execution time: $($totalDuration.TotalSeconds)s"

# Open HTML overview report in default browser
if ($PSVersionTable.PSVersion.Major -ge 6) {
    Start-Process $htmlOverviewPath
}
else {
    Invoke-Item $htmlOverviewPath
}

#endregion
