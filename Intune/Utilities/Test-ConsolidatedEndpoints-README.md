# Microsoft Intune Consolidated Endpoint Connectivity Test

PowerShell utility for testing connectivity from a Windows computer to the FQDNs and IP subnets in the Microsoft Intune consolidated endpoint list.

> [!IMPORTANT]
> The script performs outbound DNS, TCP, HTTPS certificate, and web requests. It does not modify Intune, sign in to Microsoft Graph, or require access to an Intune tenant.

## Overview

`Test-ConsolidatedEndpoints.ps1` retrieves the current Intune consolidated endpoint list from Microsoft Learn and tests representative FQDN and IPv4 targets over TCP ports 443 and 80.

The script provides:

- Automatic endpoint-list retrieval from Microsoft Learn.
- Configurable local caching and an embedded fallback list.
- Separate FQDN and IP subnet testing.
- Sampling of wildcard domains and IPv4 subnet addresses.
- Concurrent background jobs for faster execution.
- HTTPS certificate issuer and validity checks.
- Path-oriented classification of connection results.
- Console progress, HTML reports, JSON endpoint data, and detailed logs.

> [!NOTE]
> Results are diagnostic indicators, not an exhaustive firewall certification. Wildcard domains and larger subnets are sampled, and outcomes can vary by DNS response, geography, load balancing, proxy behavior, and service availability.

## How It Works

### 1. Load the endpoint list

The script checks `EndpointCache.json` in the output folder. If the cache is missing, expired, or bypassed with `-ForceFreshData`, it downloads the Microsoft Learn endpoint page and extracts the consolidated FQDN and IP subnet lists.

If downloading or parsing fails, the script continues with its embedded fallback list. The active list is exported to `ConsolidatedEndpointList.json`.

### 2. Prepare targets

- Direct FQDNs are tested as listed.
- Wildcard FQDNs are expanded using common subdomain names and sampled according to `-FqdnSamplePercent`.
- IPv4 CIDR ranges use prioritized and evenly distributed samples according to `-IpSamplePercent`.
- Very small IPv4 ranges are tested across all usable addresses.
- Duplicate targets are removed.

### 3. Test connectivity

Each target is tested on TCP ports 443 and 80. FQDN connections that succeed on port 443 also undergo certificate inspection for validity dates and recognition of the issuing public certificate authority.

Tests run in PowerShell background jobs limited by `-MaxConcurrentJobs`.

### 4. Generate reports

The script prints a summary, writes detailed log and data files, generates three linked HTML reports, and opens `index.html` in the default browser.

## Result Classification

| Status | Meaning |
|---|---|
| `Connected` | A TCP connection to the target and port completed successfully. |
| `PathAvailable` | The connection timed out, was refused remotely, or failed after the immediate-failure threshold. The script treats this as evidence that traffic likely left the local computer. |
| `LocalBlock` | The connection failed immediately or DNS resolution failed, suggesting a local DNS, firewall, proxy, or network restriction. |

> [!CAUTION]
> `PathAvailable` is a heuristic, not proof of end-to-end reachability. A timeout is classified as path available because many cloud IP addresses do not answer direct probes. Confirm unexpected results with firewall, proxy, DNS, and packet-capture data.

For subnet reporting, a subnet is considered to have a network path when at least one sampled test is classified as `Connected` or `PathAvailable`.

## Requirements

- Windows PowerShell 5.1 or later.
- Windows 10, Windows 11, or a compatible Windows Server version.
- DNS resolution and outbound TCP access for the endpoints being tested.
- HTTPS access to Microsoft Learn.
- Write access to the script directory.
- Permission to run PowerShell background jobs and open local HTML files.

Local administrator rights are not normally required. The script uses built-in PowerShell and .NET functionality and does not install modules.

The detailed reports load Chart.js from `cdn.jsdelivr.net`. If that CDN is blocked, report tables remain available, but charts may not render.

## Parameters

| Parameter | Type | Default | Allowed values | Description |
|---|---|---:|---|---|
| `FqdnSamplePercent` | Integer | `20` | 1-100 | Percentage used to sample hosts discovered for wildcard FQDNs. |
| `IpSamplePercent` | Integer | `10` | 1-100 | Percentage of addresses sampled from each IPv4 subnet. |
| `MaxConcurrentJobs` | Integer | `50` | 1-200 | Maximum number of concurrently running PowerShell jobs. |
| `TimeoutSeconds` | Integer | `1` | 1-10 | TCP connection timeout for each target and port. |
| `OutputFolder` | String | `ConsolidatedEndpointResults` | Valid folder name or path | Output folder joined to the script directory. |
| `CacheValidityDays` | Integer | `7` | 1-30 | Maximum cache age before a refresh is attempted. |
| `ForceFreshData` | Switch | Off | On or off | Bypasses a valid cache and retrieves the endpoint list again. |
| `DetailedDiagnostics` | Switch | Off | On or off | Reserved; the current version accepts it but does not run additional diagnostics. |

Higher sampling, timeout, and concurrency values can increase execution time, local resource use, and firewall, proxy, or DNS load.

## Run the Test

1. Place `Test-ConsolidatedEndpoints.ps1` on the Windows computer whose network path you want to test.
2. Open Windows PowerShell in the script folder.
3. Run one of the examples below.
4. Review the disclaimer and enter `Y` to continue.
5. Wait for FQDN and IP subnet testing to finish.
6. Review the console summary and the automatically opened `index.html` report.

### Default test

```powershell
.\Test-ConsolidatedEndpoints.ps1
```

### Force a fresh endpoint list

```powershell
.\Test-ConsolidatedEndpoints.ps1 -ForceFreshData
```

### Increase sampling and concurrency

```powershell
.\Test-ConsolidatedEndpoints.ps1 `
    -FqdnSamplePercent 30 `
    -IpSamplePercent 15 `
    -MaxConcurrentJobs 100
```

### Set a longer timeout and custom output folder

```powershell
.\Test-ConsolidatedEndpoints.ps1 `
    -TimeoutSeconds 3 `
    -OutputFolder 'EndpointConnectivityResults'
```

If execution policy blocks the script, follow your organization's approved process for running trusted scripts. Do not weaken organization-managed security controls.

## Output

By default, the script creates `ConsolidatedEndpointResults` beside the script:

```text
ConsolidatedEndpointResults\
|-- index.html
|-- ip-details.html
|-- fqdn-details.html
|-- FQDN-TestResults.log
|-- IP-TestResults.log
|-- TestSession-Transcript.log
|-- ConsolidatedEndpointList.json
`-- EndpointCache.json
```

| File | Contents |
|---|---|
| `index.html` | High-level network path, FQDN, subnet, and SSL summary. |
| `ip-details.html` | Subnet aggregation and individual sampled IP test details. |
| `fqdn-details.html` | FQDN connectivity, resolved addresses, errors, and certificate results. |
| `FQDN-TestResults.log` | Text log of each FQDN and port test. |
| `IP-TestResults.log` | Text log of subnet summaries and individual IP and port tests. |
| `TestSession-Transcript.log` | Internal session events, settings, timing, and errors. |
| `ConsolidatedEndpointList.json` | FQDNs and subnets used for the run, with source and retrieval metadata. |
| `EndpointCache.json` | Cached endpoint list from a successful Microsoft Learn retrieval. It may be absent when only fallback data is available. |

Existing files with these names are overwritten. The output folder is not compressed automatically.

## SSL Results

For a successful FQDN connection on port 443, the script checks:

- Whether the current date is within the certificate validity period.
- Whether the issuer text matches a built-in list of recognized public certificate authorities.

An invalid result can indicate TLS inspection, an unexpected issuer, an expired or not-yet-valid certificate, or an incomplete handshake. The check does not perform complete operating-system chain and hostname validation. Confirm findings with approved browser, certificate, proxy, or packet-capture tools before changing network policy.

## Current Limitations

- IPv6 subnets are loaded but skipped during subnet expansion and testing.
- Wildcard testing uses generated candidate names and does not enumerate every matching hostname.
- IPv4 subnet testing is sampled by default.
- TCP tests do not validate a complete application transaction.
- Immediate-failure timing is used to infer local blocking and can vary by environment.
- `-DetailedDiagnostics` and the traceroute helper are not connected to the main execution flow.
- Endpoint-list changes are displayed in the console/session log; no separate change report is generated.

## Troubleshooting

### The endpoint list cannot be downloaded

- Confirm HTTPS access to `learn.microsoft.com`.
- Check proxy and TLS inspection requirements for PowerShell web requests.
- Review `TestSession-Transcript.log` for download or parsing errors.
- Confirm the reported source before relying on fallback-list results.

### Many FQDNs show `LocalBlock`

- Confirm DNS resolution from the test computer.
- Review local and perimeter firewall rules for TCP 443 and 80.
- Check whether an authenticated proxy prevents direct TCP connections.
- Retry with a longer `-TimeoutSeconds` value.

### Many IP tests show `PathAvailable` but not `Connected`

This can be expected. Cloud subnets can contain addresses that do not accept direct connections even when a route exists. Correlate the subnet metric with FQDN results and network telemetry.

### SSL results indicate inspection

- Compare the reported issuer with the certificate shown in a browser on the same computer.
- Check proxy and firewall TLS inspection policies.
- Confirm whether the endpoint requires an SSL inspection bypass.
- Retry with a longer timeout if the handshake did not complete.

### HTML charts do not appear

Allow access to `cdn.jsdelivr.net` or review the report tables and logs without charts. A web server is not required.

## Security and Data Handling

Reports contain tested endpoint names, IP addresses, certificate issuer information, timestamps, errors, and network-path observations. They do not intentionally collect tenant configuration or credentials.

Review logs before sharing them and handle the output according to your organization's diagnostic-data policy.

## Disclaimer

This sample script is not supported under any Microsoft standard support program or service. It is provided as-is, without warranty of any kind. Use of the script and interpretation of its results are at your own risk.

## Related Resources

- [Network endpoints for Microsoft Intune](https://learn.microsoft.com/intune/intune-service/fundamentals/intune-endpoints)
- [PowerShell background jobs](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_jobs)
- [Test-NetConnection documentation](https://learn.microsoft.com/powershell/module/nettcpip/test-netconnection)
