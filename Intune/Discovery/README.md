# SfMC Intune Discovery Assessment

PowerShell-based, read-only discovery of Microsoft Intune configuration for a Support for Mission Critical (SfMC) assessment.

> [!IMPORTANT]
> This script does not change Intune policies, applications, assignments, or service configuration. It does install or update local PowerShell dependencies when required and writes discovery data to the selected output folder.

## Overview

The script connects interactively to Microsoft Graph, collects Intune configuration and assignment information, and exports the results in human-readable and JSON formats. Where applicable, Microsoft Entra group IDs in assignments are resolved to group display names.

At the end of the run, the script:

- Displays a collection summary with policy and assignment counts.
- Saves a PowerShell transcript for troubleshooting.
- Compresses the collected category folders into `SMCIntuneDiscoveryAssessment.zip`.

The ZIP file is intended to be transferred to the SfMC team through an approved secure workspace or other approved secure method.

## What's New

### Version 2.2

- Corrects assignment collection for Android and Windows app protection policies.
- Corrects JSON export for the Apple Push Notification certificate.
- Corrects naming and variable issues affecting Apple User Enrollment and Autopilot exports.
- Corrects module version comparison and module update validation.
- Adds the missing JSON export for Apple DEP profiles.
- Increases Administrative Templates JSON depth to preserve nested presentation values.
- Corrects Administrative Templates and Windows Driver Update status messages.

### Version 2.1

- Exports all Windows Settings Catalog policy settings in JSON format.

### Version 2.0

- Replaces the deprecated AzureAD and MSGraph dependencies with Microsoft Graph PowerShell modules.
- Uses modern, interactive browser authentication.
- Adds automatic handling of paged Microsoft Graph responses.
- Adds Settings Catalog policy collection.
- Updates all collection areas to use Microsoft Graph.

## Data Collected

The script collects the following 27 configuration areas:

| # | Configuration area | Additional data |
|---:|---|---|
| 1 | Client applications | Assignments |
| 2 | App configuration policies | Settings and assignments |
| 3 | App protection policies | Android, iOS, MDM WIP, Windows, and assignments |
| 4 | Compliance policies | Additional properties and assignments |
| 5 | Device configuration policies | Additional properties and assignments |
| 6 | Settings Catalog policies | Expanded settings, complete settings JSON, and assignments |
| 7 | Windows scripts | Script metadata, decoded `.ps1` content, and assignments |
| 8 | Device management intents | Template settings and assignments |
| 9 | Administrative Templates | Definition and presentation values, and assignments |
| 10 | Windows Autopilot deployment profiles | Out-of-box experience settings and assignments |
| 11 | Device enrollment configurations | Restrictions, limits, Enrollment Status Page, Windows Hello for Business, and assignments |
| 12 | Apple Push Notification certificate | Certificate configuration |
| 13 | Apple User Enrollment profiles | Profile configuration |
| 14 | Apple DEP profiles | DEP settings and enrollment profiles |
| 15 | Apple VPP tokens | Token configuration |
| 16 | Android managed store account enterprise | Enterprise settings |
| 17 | Android corporate-owned profiles | Device owner enrollment profiles |
| 18 | Android for Work profiles | Enrollment profiles |
| 19 | Android for Work settings | Tenant settings |
| 20 | Assignment filters | Filter configuration |
| 21 | Device categories | Category configuration |
| 22 | Domain Join connectors | Connector configuration |
| 23 | Microsoft Tunnel | Configurations and sites |
| 24 | NDES connectors | Connector configuration |
| 25 | Windows Feature Update profiles | Assignments |
| 26 | Windows Driver Update profiles | Assignments |
| 27 | Windows Quality Update profiles | Assignments |

Microsoft Graph beta endpoints are used for parts of the collection. Beta API schemas and behavior can change.

## Requirements

### Workstation

- Windows 10 or Windows 11.
- Windows PowerShell 5.1 or a compatible PowerShell environment with PowerShellGet and PackageManagement.
- Internet access to Microsoft Graph, Microsoft identity sign-in endpoints, and PowerShell Gallery.
- Permission to install PowerShell modules for the current user.
- Sufficient free disk space for the uncompressed exports and ZIP archive.

The computer does not need to be domain joined, Microsoft Entra joined, or Intune enrolled. Local administrator rights are not normally required because modules are installed with `-Scope CurrentUser`; managed workstation policies may impose additional requirements.

### Microsoft Graph PowerShell Modules

The script checks for and installs these modules when they are missing:

- `Microsoft.Graph.Authentication`
- `Microsoft.Graph.DeviceManagement`
- `Microsoft.Graph.Beta.DeviceManagement`
- `Microsoft.Graph.Devices.CorporateManagement`
- `Microsoft.Graph.Beta.Groups`

The NuGet package provider is also installed if required. Depending on the workstation configuration, PowerShell may ask for confirmation before installing from PowerShell Gallery.

### Account and Consent

Use a Microsoft Entra account that has sufficient Intune read permissions for the data being collected. The script requests these delegated Microsoft Graph scopes during sign-in:

| Scope | Purpose in this script |
|---|---|
| `DeviceManagementApps.Read.All` | Read managed applications, app configuration, app protection policies, and related assignments. |
| `DeviceManagementServiceConfig.Read.All` | Read enrollment and Intune service configuration. |
| `DeviceManagementConfiguration.Read.All` | Read device configuration, compliance, update, and related policy data. |
| `DeviceManagementManagedDevices.Read.All` | Read managed-device-related Intune properties required by the discovery process. |
| `DeviceManagementScripts.Read.All` | Read Intune device management scripts and script content. |
| `Directory.Read.All` | Resolve Microsoft Entra group IDs to display names. |

Your tenant's consent policy determines whether the signed-in user can consent or an administrator must grant consent. A Global Administrator does not need to perform the entire collection; an appropriately authorized administrator can grant the required consent, after which an account with suitable Intune read access can run the script.

For more information, see [Microsoft identity platform permissions and consent](https://learn.microsoft.com/entra/identity-platform/permissions-consent-overview).

## Run the Assessment

1. Download the script to a Windows computer.
2. Open PowerShell in the folder containing the script.
3. Run the script:

   ```powershell
   & '.\SfMC_Intune_DiscoveryAssessment V 2.2.ps1'
   ```

4. Review the disclaimer and enter `Y` to continue.
5. Complete the browser-based Microsoft sign-in and consent flow.
6. Enter the parent output folder when prompted. Press Enter to use the current folder.
7. Allow the collection and compression process to complete.

> [!WARNING]
> If `SfMC - Intune Discovery Assessment` already exists below the selected path, the script waits 10 seconds before continuing and may overwrite files in its Intune subfolders. Press `Ctrl+C` during the countdown to cancel and preserve the existing collection.

If PowerShell execution policy blocks the script, follow your organization's approved process for running trusted scripts. Do not weaken organization-managed security controls.

## Output

The script creates this root folder under the selected parent path:

```text
SfMC - Intune Discovery Assessment\
|-- <configuration category folders>\
|   |-- <policy>.txt
|   |-- <policy>.json
|   `-- Assignments\
|       `-- <assignment>.json
|-- DiscoveryAssesment_Transcript.txt
`-- SMCIntuneDiscoveryAssessment.zip
```

Output varies by configuration area:

- `.txt` files provide a readable representation of collected objects.
- `.json` files preserve structured configuration data.
- `Assignments` folders contain assignment details and, where available, resolved Microsoft Entra group names.
- `Windows Scripts\PS1 Files` contains decoded PowerShell script content collected from Intune.
- `DiscoveryAssesment_Transcript.txt` records console activity and errors.
- `SMCIntuneDiscoveryAssessment.zip` contains the collected configuration category folders. The transcript remains beside the ZIP and is not included automatically.

## Security and Data Handling

The output can contain sensitive tenant configuration, application metadata, assignment targets, group names and IDs, connector information, and script content. Treat the output as confidential:

- Review and store it according to your organization's data-handling requirements.
- Transfer it only through an approved secure method or workspace.
- Restrict access to the assessment team and other authorized personnel.
- Remove local copies when they are no longer required, in accordance with retention policy.

## Troubleshooting

### Module installation fails

Confirm that PowerShell Gallery is reachable and that current-user module installation is permitted. The modules can be installed manually with:

```powershell
$modules = @(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.DeviceManagement'
    'Microsoft.Graph.Beta.DeviceManagement'
    'Microsoft.Graph.Devices.CorporateManagement'
    'Microsoft.Graph.Beta.Groups'
)

$modules | ForEach-Object {
    Install-Module -Name $_ -Scope CurrentUser -Force
}
```

### Sign-in or consent fails

- Confirm that browser sign-in is allowed from the workstation.
- Verify that the account is permitted to request the listed delegated scopes.
- Ask an authorized Microsoft Entra administrator to grant consent if required by tenant policy.
- Confirm that Conditional Access requirements are satisfied.

### Some categories or group names are empty

- Verify that the account has access to the relevant Intune configuration area.
- Confirm that `Directory.Read.All` consent is available for group-name resolution.
- Check `DiscoveryAssesment_Transcript.txt` for Microsoft Graph authorization or endpoint errors.
- A category folder can be empty when the tenant has no configuration of that type.

### The ZIP file is not created

Check the completion message and available disk space. If all category folders were created successfully, compress those folders manually and transfer the resulting archive through the approved secure channel.

## Disclaimer

This sample script is not supported under any Microsoft standard support program or service. It is provided as-is, without warranty of any kind. Use of the script and its output is at your own risk.

## Related Resources

- [Microsoft Graph PowerShell documentation](https://learn.microsoft.com/powershell/microsoftgraph/overview)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/graph/permissions-reference)
- [Microsoft Intune documentation](https://learn.microsoft.com/mem/intune/)
- [SfMC-Tools repository](https://github.com/microsoft/SfMC-Tools)
