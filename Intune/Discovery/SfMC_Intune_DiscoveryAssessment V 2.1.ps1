<#

VERSION HISTORY
===================

V 1.1  
----------------
- Add more information for each section. 
- Install modules for Intune and AzureAD are being forced to minimized user interaction. 
- Was evaluated the -Adminconcent for connect MS-Graph but won't work witih -Credential. If cred is not required, a double authentication is prompt. 
- Intune module installation failure have an additional commnets for the installation status and on the catch section.
- Nuget Package provider detection and validation was included. 
- MsGraph connection display status and for the failure have an additional commnet on the catch section.
- AzureAD module dectection module improved.

V 1.2
----------------
- Set for all the output files the format JSON to be able to provide a baseline/backup files from the current configuration 

V 1.3
----------------
- Transcript collected.
- Add 9 new sections. 
        #region 19. Assignment Filters
        #region 20. Device Categories
        #region 21. Domain Join Connectors
        #region 22. Microsoft Tunnel Configurations
        #region 23. Microsoft Tunnel Sites
        #region 24. NDES Connectors
        #region 25. Windows Feature Update Profiles
        #region 26. Windows Drive Update Profiles - UNDER CONSTRUCTION
        #region 27. Windows Quality Update Profiles

V 2.0
----------------
- The information section is reviewed and the SMC was updated to SfMC and some minor changes.
- The MsGraph is depreciated and all the instructions are upgrated to use the MgGraph. 
- The Get-Credential is removed to allow the Modern Authentication to be used. 
- Add Function to get All Pages Get-MgGraphAllPages
- Region AzureAD Module and connection removed due to depreciation and use instead the Get-MgBetaGroup. 
- Connect to AzureAD region removed.
- Replace the Intune module for Microsoft.Graph.Beta.Groups.
- Add the module Microsoft.Graph.Devices.CorporateManagement
- Add the module Microsoft.Graph.Authentication
- Replace MsGraph connection to MgGraph.
- Update All data collection sections. 
- Included the Settings Catalog Policies. 

V 2.1
-----------------
- Windows Settings Catalog policies now export all the policy settings in JSON format.
 

#>
####################################################


#region Function Countdown

<# 
 This function will start a 10 seconds countdown timer to cancel the data collection 
 if the output folder exists and want to prevent data overwrite. 
#>

Function Start-Countdown 
{

    Param(
        [Int32]$Seconds = 10,
        [string]$Message = "Pausing for 10 seconds..."
    )
    ForEach ($Count in (1..$Seconds))
    {   Write-Progress -Id 1 -Activity $Message -Status "Waiting for $Seconds seconds, $($Seconds - $Count) left" -PercentComplete (($Count / $Seconds) * 100)
        Start-Sleep -Seconds 1
    }
    Write-Progress -Id 1 -Activity $Message -Status "Continuing!" -PercentComplete 100 -Completed
}

#endregion                                    

####################################################

#region Function to get All Pages

    <# 
    The MgGraphAllPages is not a CMDLET incuded in the new modules. 
    This funtion is created based on the original MSGraphAllPages.
    #>

function Get-MgGraphAllPages {
    [CmdletBinding(
        ConfirmImpact = 'Medium',
        DefaultParameterSetName = 'SearchResult'
    )]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'NextLink', ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('@odata.nextLink')]
        [string]$NextLink
        ,
        [Parameter(Mandatory = $true, ParameterSetName = 'SearchResult', ValueFromPipeline = $true)]
        [ValidateNotNull()]
        [PSObject]$SearchResult
        ,
        [Parameter(Mandatory = $false)]
        [switch]$ToPSCustomObject
    )

    begin {}

    process 
    {
        if ($PSCmdlet.ParameterSetName -eq 'SearchResult') 
            {
                # Set the current page to the search result provided
                $page = $SearchResult

                # Extract the NextLink
                $currentNextLink = $page.'@odata.nextLink'


                if ($page.ContainsKey('@odata.count')) 
                    {
                        Write-Verbose "First page value count: $($Page.'@odata.count')"    
                    }

                if ($page.ContainsKey('@odata.nextLink') -or $page.ContainsKey('value')) 
                    {
                        $values = $page.value
                    } 
                
                else 
                    { 
                        $values = $page
                    }

                # Output the values

                if ($values) 
                    {
                
                    if ($ToPSCustomObject) 
                        {
                            $values | ForEach-Object {[pscustomobject]$_}   
                        } 
                
                    else 
                        {
                            $values | Write-Output
                        }
                    }
            }

        while (-Not ([string]::IsNullOrWhiteSpace($currentNextLink)))
            {
                # Make the call to get the next page
                try 
                    {
                        $page = Invoke-MgGraphRequest -Uri $currentNextLink -Method GET
                    } 
                
                catch 
                    {
                        throw $_
                    }

                # Extract the NextLink
                $currentNextLink = $page.'@odata.nextLink'

                # Output the items in the page
                $values = $page.value

                if ($page.ContainsKey('@odata.count')) 
                    {
                        Write-Verbose "Current page value count: $($Page.'@odata.count')"    
                    }


                if ($ToPSCustomObject) 
                    {
                        $values | ForEach-Object {[pscustomobject]$_}   
                    } 
                    
                else 
                    {
                        $values | Write-Output
                    }
            }
    }

    end {}
}        
#endregion Function to get All Pages

####################################################

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

$Purpose = @"
###########################################################################################
#                                                                                         #
# This script DO NOT perform changes in the Intune policies, applications                 #
# nor services of any kind.                                                               #
#                                                                                         #
# Data will be collected as part of the Support for Mission Critical (SfMC) Discovery     #
# Assessment.                                                                             #
#                                                                                         #
# Please ensure to share the ZIP file: SMCIntuneDiscoveryAssessment.zip created at the    #
# of the process using a secure method or workspace, as instructed by the SfMC team       #
#                                                                                         #
###########################################################################################
"@

Write-Host
Write-Host
Write-Host $disclaimer -foregroundColor Yellow
Write-Host 
Start-Sleep -Seconds 3 
Write-Host $Purpose -ForegroundColor Cyan
Write-Host 
Start-Sleep -Seconds 3 

#endregion Information

####################################################

#region Prerequisites

<# 
Will be verified if the modules DeviceManagement and Groups required are being installed already. 
Valudate the NuGet package version and install if required. 
If the modules are not present it will be attempt to install automatically. 
Connetions to Mggraph is stablished.

#>


    #region NuGet Provider

        Try 
            {
                Write-Host
                Write-Host "Validating NuGet Package provider status..." -NoNewline
                $NuGetPackProv = Get-PackageProvider -name nuget
                    If (-not $NuGetPackProv)
                        {
                            Write-Host " Installing" -foregroundColor Green
                            Install-PackageProvider -Name NuGet -Force -Confirm:$false -ForceBootstrap | Out-Null     
                    
                        }
                    Else
                        {
                            $NuGetPackProvVer = $NuGetPackProv.version.ToString()
                            $LatestNuGetProv = Find-PackageProvider -Name Nuget
                            $LatestNuGetProvVer = $LatestNuGetProv.version.ToString()
                            
                            if ($NuGetPackProvVer -eq $LatestNuGetProvVer)
                                {
                                    Write-Host " Installed" -foregroundColor Green        
                                }
        
                            if ($NuGetPackProvVer -lt $LatestNuGetProvVer)
                                {
                                    Write-Host " Updating" -foregroundColor Green
                                    Install-PackageProvider -Name NuGet -Force -Confirm:$false -ForceBootstrap | Out-Null
                                }
                        }
             }
    
        Catch 
            {
                Write-host "Error!" -ForegroundColor Red
                Write-host "Nuget Package provider could not be installed" -foregroundColor Red
                $_
                exit
            }
    #endregion NuGet Provider
            
    #region Microsoft.Graph.DeviceManagement
        Write-Host
        Write-Host "Validating Microsoft Graph Device Management module status..." -NoNewline
        $Module = get-module -ListAvailable | ?{$_.name -eq "Microsoft.Graph.DeviceManagement"}
        If (-not $Module)
            {
                Write-Host " Installing" -ForegroundColor Green
                    try {
                            Install-Module -Name Microsoft.Graph.DeviceManagement -Force -ErrorAction Stop | Out-Null
                            if (Get-Module -ListAvailable -Name "Microsoft.Graph.DeviceManagement") 
                                {
                                    Write-Host "Microsoft.Graph.DeviceManagement module is installed" -ForegroundColor Green
                                } 
                            else 
                                {
                                    Write-Host "Microsoft.Graph.DeviceManagement module could not be installed" -ForegroundColor Yellow
                                    Write-Host "Try a manual installation running 'Install-Module Microsoft.Graph.DeviceManagement' from an elevated PowerShell prompt"
                                    Write-Host
                                    Write-Host "NOTE:" -ForegroundColor Yellow
                                    Write-Host "-----" -ForegroundColor Yellow
                                    Write-Host "The script cannot continue until the Graph Device Management module is installed"
                                    exit
                                }
                        }
         
				    catch 
					    {
						    Write-Host "Error!" -ForegroundColor Red
						    Write-Host "The module Microsoft.Graph.DeviceManagement could not be installed" -ForegroundColor Red
						    $_
						    exit
					    }
			}
                
        Else
           {
                $ModuleVer = $Module.version.ToString()
                $LatestModule = find-module Microsoft.Graph.DeviceManagement
                $LatestModuleVer = $LatestModule.version.ToString()

                If ($ModuleVer -lt $LatestModuleVer)
                    {
                        Write-Host " Updating" -foregroundColor Green
                      
                        try {

                                $updateModule = Update-Module -Name Microsoft.Graph.DeviceManagement -Force | Out-Null
                                if (Get-Module -ListAvailable -Name "Microsoft.Graph.DeviceManagement") 
                                    {
                                        Write-Host "Microsoft.Graph.DeviceManagement module is updated" -ForegroundColor Green
                                    } 
                                If (!($updateModule))
                                    {
                                        Write-Host "Microsoft.Graph.DeviceManagement module could not be Updated" -ForegroundColor Yellow
                                        Write-Host "Try a manual installation running 'Install-Module Microsoft.Graph.DeviceManagement' from an elevated PowerShell prompt"
                                        Write-Host
                                        Write-Host "NOTE:" -ForegroundColor Yellow
                                        Write-Host "-----" -ForegroundColor Yellow
                                        Write-Host "The script cannot continue until the Graph Device Management module is installed"
                                        Write-Host "If the module was updated run the script again."
                                        exit
                                    }
                            }

                        catch 
					        {
						        Write-Host "Error!" -ForegroundColor Red
						        Write-Host "The module Microsoft.Graph.DeviceManagement could not be installed" -ForegroundColor Red
						        $_
						        exit
					        }
                    }

                If ($Module.name -eq "Microsoft.Graph.DeviceManagement" -and $ModuleVer -ge $LatestModuleVer)
                    {
                        Write-Host " Installed" -foregroundColor Green
                    }
            }

    #endregion Microsoft.Graph.DeviceManagement

    #region Microsoft.Graph.Beta.DeviceManagement
        Write-Host
        Write-Host "Validating Microsoft Graph Beta Device Management module status..." -NoNewline
        $Module = get-module -ListAvailable | ?{$_.name -eq "Microsoft.Graph.Beta.DeviceManagement"}
        If (-not $Module)
            {
                Write-Host " Installing" -ForegroundColor Green
                    try {
                            Install-Module -Name Microsoft.Graph.Beta.DeviceManagement -Force -ErrorAction Stop | Out-Null
                            if (Get-Module -ListAvailable -Name "Microsoft.Graph.Beta.DeviceManagement") 
                                {
                                    Write-Host "Microsoft.Graph.Beta.DeviceManagement module is installed" -ForegroundColor Green
                                } 
                            else 
                                {
                                    Write-Host "Microsoft.Graph.Beta.DeviceManagement module could not be installed" -ForegroundColor Yellow
                                    Write-Host "Try a manual installation running 'Install-Module Microsoft.Graph.Beta.DeviceManagement' from an elevated PowerShell prompt"
                                    Write-Host
                                    Write-Host "NOTE:" -ForegroundColor Yellow
                                    Write-Host "-----" -ForegroundColor Yellow
                                    Write-Host "The script cannot continue until the Graph Beta Device Management module is installed"
                                    exit
                                }
                        }
         
				    catch 
					    {
						    Write-Host "Error!" -ForegroundColor Red
						    Write-Host "The module Microsoft.Graph.Beta.DeviceManagement could not be installed" -ForegroundColor Red
						    $_
						    exit
					    }
			}
                
        Else
           {
                $ModuleVer = $Module.version.ToString()
                $LatestModule = find-module Microsoft.Graph.Beta.DeviceManagement
                $LatestModuleVer = $LatestModule.version.ToString()

                If ($ModuleVer -lt $LatestModuleVer)
                    {
                        Write-Host " Updating" -foregroundColor Green
                      
                        try {

                                $updateModule = Update-Module -Name Microsoft.Graph.Beta.DeviceManagement -Force | Out-Null
                                if (Get-Module -ListAvailable -Name "Microsoft.Graph.Beta.DeviceManagement") 
                                    {
                                        Write-Host "Microsoft.Graph.Beta.DeviceManagement module is updated" -ForegroundColor Green
                                    } 
                                If (!($updateModule))
                                    {
                                        Write-Host "Microsoft.Graph.Beta.DeviceManagement module could not be Updated" -ForegroundColor Yellow
                                        Write-Host "Try a manual installation running 'Install-Module Microsoft.Graph.Beta.DeviceManagement' from an elevated PowerShell prompt"
                                        Write-Host
                                        Write-Host "NOTE:" -ForegroundColor Yellow
                                        Write-Host "-----" -ForegroundColor Yellow
                                        Write-Host "The script cannot continue until the Graph Beta Device Management module is installed"
                                        Write-Host "If the module was updated run the script again."
                                        exit
                                    }
                            }

                        catch 
					        {
						        Write-Host "Error!" -ForegroundColor Red
						        Write-Host "The module Microsoft.Graph.Beta.DeviceManagement could not be installed" -ForegroundColor Red
						        $_
						        exit
					        }
                    }

                If ($Module.name -eq "Microsoft.Graph.Beta.DeviceManagement" -and $ModuleVer -ge $LatestModuleVer)
                    {
                        Write-Host " Installed" -foregroundColor Green
                    }
            }

    #endregion Microsoft.Graph.Beta.DeviceManagement

    #region Microsoft.Graph.Devices.CorporateManagement
        Write-Host
        Write-Host "Validating Microsoft Graph Devices CorporateManagement module status..." -NoNewline
        $Module = get-module -ListAvailable | ?{$_.name -eq "Microsoft.Graph.Devices.CorporateManagement"}
        If (-not $Module)
            {
                Write-Host " Installing" -ForegroundColor Green
                    try {
                            Install-Module -Name Microsoft.Graph.Devices.CorporateManagement -Force -ErrorAction Stop | Out-Null
                            if (Get-Module -ListAvailable -Name "Microsoft.Graph.Devices.CorporateManagement") 
                                {
                                    Write-Host "Microsoft.Graph.Devices.CorporateManagement module is installed" -ForegroundColor Green
                                } 
                            else 
                                {
                                    Write-Host "Microsoft.Graph.Devices.CorporateManagement module could not be installed" -ForegroundColor Yellow
                                    Write-Host "Try a manual installation running 'Install-Module Microsoft.Graph.Devices.CorporateManagement' from an elevated PowerShell prompt"
                                    Write-Host
                                    Write-Host "NOTE:" -ForegroundColor Yellow
                                    Write-Host "-----" -ForegroundColor Yellow
                                    Write-Host "The script cannot continue until the Graph Devices CorporateManagement module is installed"
                                    exit
                                }
                        }
         
				    catch 
					    {
						    Write-Host "Error!" -ForegroundColor Red
						    Write-Host "The module Microsoft.Graph.Devices.CorporateManagement could not be installed" -ForegroundColor Red
						    $_
						    exit
					    }
			}
                
        Else
           {
                $ModuleVer = $Module.version.ToString()
                $LatestModule = find-module Microsoft.Graph.Devices.CorporateManagement
                $LatestModuleVer = $LatestModule.version.ToString()

                If ($ModuleVer -lt $LatestModuleVer)
                    {
                        Write-Host " Updating" -foregroundColor Green
                        
                        try {
                                $updateModule = Update-Module -Name Microsoft.Graph.Devices.CorporateManagement -Force | Out-Null
                                if (Get-Module -ListAvailable -Name "Microsoft.Graph.Devices.CorporateManagement") 
                                    {
                                        Write-Host "Microsoft.Graph.Devices.CorporateManagement module is updated" -ForegroundColor Green
                                    } 
                                If (!($updateModule))
                                    {
                                        Write-Host "Microsoft.Graph.Devices.CorporateManagement module could not be Updated" -ForegroundColor Yellow
                                        Write-Host "Try a manual installation running 'Install-Module Microsoft.Graph.Devices.CorporateManagement' from an elevated PowerShell prompt"
                                        Write-Host
                                        Write-Host "NOTE:" -ForegroundColor Yellow
                                        Write-Host "-----" -ForegroundColor Yellow
                                        Write-Host "The script cannot continue until the Graph Devices CorporateManagement module is installed"
                                        Write-Host "If the module was updated run the script again."
                                        exit
                                    }
                            }

                        catch 
					        {
						        Write-Host "Error!" -ForegroundColor Red
						        Write-Host "The module Microsoft.Graph.Devices.CorporateManagement could not be installed" -ForegroundColor Red
						        $_
						        exit
					        }
                    }

                If ($Module.name -eq "Microsoft.Graph.Devices.CorporateManagement" -and $ModuleVer -ge $LatestModuleVer)
                    {
                        Write-Host " Installed" -foregroundColor Green
                    }
            }

    #endregion Microsoft.Graph.Devices.CorporateManagement

    #region Microsoft.Graph.Beta.Groups
        Write-Host
        Write-Host "Validating Microsoft Graph Beta Groups module status..." -NoNewline
        $Module = get-module -ListAvailable | ?{$_.name -eq "Microsoft.Graph.Beta.Groups"}
        If (-not $Module)
            {
                Write-Host " Installing" -ForegroundColor Green
                    try {
                            Install-Module -Name Microsoft.Graph.Beta.Groups -Force -ErrorAction Stop | Out-Null
                            if (Get-Module -ListAvailable -Name "Microsoft.Graph.Beta.Groups") 
                                {
                                    Write-Host "Microsoft.Graph.Beta.Groups module is installed" -ForegroundColor Green
                                } 
                            else 
                                {
                                    Write-Host "Microsoft.Graph.Beta.Groups module could not be installed" -ForegroundColor Yellow
                                    Write-Host "Try a manual installation running 'Install-Module Microsoft.Graph.Beta.Groups' from an elevated PowerShell prompt"
                                    Write-Host
                                    Write-Host "NOTE:" -ForegroundColor Yellow
                                    Write-Host "-----" -ForegroundColor Yellow
                                    Write-Host "The script cannot continue until the Graph Beta Groups module is installed"
                                    exit
                                }
                        }
         
				    catch 
					    {
						    Write-Host "Error!" -ForegroundColor Red
						    Write-Host "The module Microsoft.Graph.Beta.Groups could not be installed" -ForegroundColor Red
						    $_
						    exit
					    }
			}
                
        Else
           {
                $ModuleVer = $Module.version.ToString()
                $LatestModule = find-module Microsoft.Graph.Beta.Groups
                $LatestModuleVer = $LatestModule.version.ToString()

                If ($ModuleVer -lt $LatestModuleVer)
                    {
                        Write-Host " Updating" -foregroundColor Green
                        
                        try {
                                $updateModule = Update-Module -Name Microsoft.Graph.Beta.Groups -Force | Out-Null
                                if (Get-Module -ListAvailable -Name "Microsoft.Graph.Beta.Groups") 
                                    {
                                        Write-Host "Microsoft.Graph.Beta.Groups module is updated" -ForegroundColor Green
                                    } 
                                If (!($updateModule))
                                    {
                                        Write-Host "Microsoft.Graph.Beta.Groups module could not be Updated" -ForegroundColor Yellow
                                        Write-Host "Try a manual installation running 'Install-Module Microsoft.Graph.Beta.Groups' from an elevated PowerShell prompt"
                                        Write-Host
                                        Write-Host "NOTE:" -ForegroundColor Yellow
                                        Write-Host "-----" -ForegroundColor Yellow
                                        Write-Host "The script cannot continue until the Graph Beta Groups module is installed"
                                        Write-Host "If the module was updated run the script again."
                                        exit
                                    }
                            }

                        catch 
					        {
						        Write-Host "Error!" -ForegroundColor Red
						        Write-Host "The module Microsoft.Graph.Beta.Groups could not be installed" -ForegroundColor Red
						        $_
						        exit
					        }
                    }

                If ($Module.name -eq "Microsoft.Graph.Beta.Groups" -and $ModuleVer -ge $LatestModuleVer)
                    {
                        Write-Host " Installed" -foregroundColor Green
                    }
            }

    #endregion Microsoft.Graph.Beta.Groups

    #region Microsoft.Graph.Authentication
        Write-Host
        Write-Host "Validating Microsoft Graph Authentication module status..." -NoNewline
        $Module = get-module -ListAvailable | ?{$_.name -eq "Microsoft.Graph.Authentication"}
        If (-not $Module)
            {
                Write-Host " Installing" -ForegroundColor Green
                    try {
                            Install-Module -Name Microsoft.Graph.Authentication -Force -ErrorAction Stop | Out-Null
                            if (Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication") 
                                {
                                    Write-Host "Microsoft.Graph.Authentication module is installed" -ForegroundColor Green
                                } 
                            else 
                                {
                                    Write-Host "Microsoft.Graph.Authentication module could not be installed" -ForegroundColor Yellow
                                    Write-Host "Try a manual installation running 'Install-Module Microsoft.Graph.Authentication' from an elevated PowerShell prompt"
                                    Write-Host
                                    Write-Host "NOTE:" -ForegroundColor Yellow
                                    Write-Host "-----" -ForegroundColor Yellow
                                    Write-Host "The script cannot continue until the Graph Authentication module is installed"
                                    exit
                                }
                        }
         
				    catch 
					    {
						    Write-Host "Error!" -ForegroundColor Red
						    Write-Host "The module Microsoft.Graph.Authentication could not be installed" -ForegroundColor Red
						    $_
						    exit
					    }
			}
                
        Else
           {
                $ModuleVer = $Module.version.ToString()
                $LatestModule = find-module Microsoft.Graph.Authentication
                $LatestModuleVer = $LatestModule.version.ToString()

                If ($ModuleVer -lt $LatestModuleVer)
                    {
                        Write-Host " Updating" -foregroundColor Green
                        
                        try {
                                $updateModule = Update-Module -Name Microsoft.Graph.Authentication -Force | Out-Null
                                if (Get-Module -ListAvailable -Name "Microsoft.Graph.Authentication") 
                                    {
                                        Write-Host "Microsoft.Graph.Authentication module is updated" -ForegroundColor Green
                                    } 
                                If (!($updateModule))
                                    {
                                        Write-Host "Microsoft.Graph.Authentication module could not be Updated" -ForegroundColor Yellow
                                        Write-Host "Try a manual installation running 'Install-Module Microsoft.Graph.Authentication' from an elevated PowerShell prompt"
                                        Write-Host
                                        Write-Host "NOTE:" -ForegroundColor Yellow
                                        Write-Host "-----" -ForegroundColor Yellow
                                        Write-Host "The script cannot continue until the Graph Authentication module is installed"
                                        Write-Host "If the module was updated run the script again."
                                        exit
                                    }
                            }

                        catch 
					        {
						        Write-Host "Error!" -ForegroundColor Red
						        Write-Host "The module Microsoft.Graph.Authentication could not be installed" -ForegroundColor Red
						        $_
						        exit
					        }
                    }

                If ($Module.name -eq "Microsoft.Graph.Authentication" -and $ModuleVer -ge $LatestModuleVer)
                    {
                        Write-Host " Installed" -foregroundColor Green
                    }
            }

    #endregion Microsoft.Graph.Authentication
    
    #region Load modules

    $modules = @(
    "Microsoft.Graph.DeviceManagement",
    "Microsoft.Graph.Beta.DeviceManagement",
    "Microsoft.Graph.Devices.CorporateManagement",
    "Microsoft.Graph.Beta.Groups",
    "Microsoft.Graph.Authentication"
    )

    Foreach($module in $modules)
        {
            Import-Module -Name $module | Out-Null
        }

    #endregion Load modules

    #region MgGraph Connect
        Write-Host
        Set-MgEnvironment -Name "Beta" -GraphEndpoint "https://graph.microsoft.com/beta" -AzureADEndpoint "https://login.microsoftonline.com" | Out-Null
        
        Write-Host
        Write-Host "Connecting to MGgraph..." -NoNewline
        
        #If you need to change the scopes, you can edit the list below. The following are the minimum required for the script to collect the data requried. 
        #########################
        $Scopes = @(
        "DeviceManagementApps.Read.All",
        "DeviceManagementServiceConfig.Read.All",
        "DeviceManagementConfiguration.Read.All",
        "DeviceManagementManagedDevices.Read.All",
        "Directory.Read.All",
        "DeviceManagementScript.ReadWrite.All",
        "DeviceManagementScript.Read.All"
        )
        #########################
        Try 
            {
                $ConnectMGgraph = Connect-MGGraph -Scopes $Scopes
                
                If ($ConnectMGgraph)
                    {
                        Write-Host " Connected" -foregroundColor Green 
                    }
                Elseif (!($ConnectMGgraph))
                    {
                        Write-Host " Failed" -foregroundColor Red 
                        Write-host "Connection to MgGraph could not be completed" -foregroundColor Red
                        exit
                    }

            }

        Catch 
            {
                Write-host
                Write-host " Error!" -ForegroundColor Red
                $_
                exit
            }
    #endregion MgGraph Connect  

#endregion Prerequisites

####################################################

#region Output directory  

<# 
An output folder path is requested. 
If the folder exists the timeout funtion is being invoked to cancel the operation. 
#>


        Write-host 
        $Outpath = Read-Host "Provide the output folder path"
        
        try {
            
                if (-not ($Outpath))
                    {
                        $Outpath = Get-Location
                        Write-Host "No output folder was provided. The current folder will be used as parent folder:" -NoNewline -ForegroundColor Yellow
                        Write-host " $Outpath"
                    }
            }
        
        catch 
            {
                Write-host "Error!" -ForegroundColor Red
                $_
                exit
            }

        $Outfolder = "$outpath\SfMC - Intune Discovery Assessment"

        If (Test-Path "$Outfolder") 
            {
                Write-host 
                Write-host "Path already exists, be aware existing data in the SUBFOLDERS related to Intune will be overwriten..." -ForegroundColor Yellow
                Write-host "To cancel or termiante the script use:" -NoNewline -ForegroundColor Yellow
                Write-host " CTRL + C..." -ForegroundColor Magenta
                Start-Countdown -Seconds 10 -Message "Waiting for confirmation"

            }

        elseif (-not (Test-Path "$Outfolder"))        
            {
                Write-Host
                Write-Host "Creating the Output folder in the path provided..."
                New-Item -Path "$Outfolder" -ItemType Directory
                Write-Host

            }

#endregion Output directory  
####################################################
Start-Transcript -Path "$Outfolder\DiscoveryAssesment_Transcript.txt" -append | Out-Null
####################################################

#region Data Collection 


<# 
The data collection from the Intune environment is defined on this section. 
The configurations output data is collected in TXT and JSON files.
The assignments details are exported, if any, are captured as well where the AzureAD group ID is obtained. 
Using the connection to AzureAD, the Group name is obtained based on the Group ID and append to the assignments output file generated.
The Assignemnts output file is on a JSON format.
#>



        #region 1. Client Applications
            
            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Client Apps")) 
                {
                    New-Item -Path "$Outfolder\Client Apps" -ItemType Directory | Out-Null
                }
            
            Write-Host
            Write-host "Collecting Client Apps configurations" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1


            $Applications = Get-MgDeviceAppManagementMobileApp | Get-MgGraphAllPages

            Foreach ($Application in $Applications) 
                {
                    $ApplicationType = $Application.AdditionalProperties.'@odata.type'.split('.')[-1]
                    Write-Output "   Exporting Application: $($Application.displayName) - $ApplicationType"


                    $ApplicationsfileName = ($Application.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $ApplicationDetails = Invoke-MGGraphRequest -Method GET -Uri "beta/deviceAppManagement/mobileApps/$($Application.id)"
                    $ApplicationDetails | Out-File -LiteralPath "$Outfolder\Client Apps\$($ApplicationType)_$($ApplicationsfileName).txt"
                    $ApplicationDetails | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Client Apps\$($ApplicationType)_$($ApplicationsfileName).json"
                }

            # Assignments Export

            if (-not (Test-Path "$Outfolder\Client Apps\Assignments")) 
                {
                    New-Item -Path "$Outfolder\Client Apps\Assignments" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "   Collecting Client Apps assignments" -ForegroundColor Cyan
            
            foreach ($Application in $Applications) 
                {
                    $ApplicationAssignmentname = $Application.displayName
                    $assignments = Get-MgDeviceAppMgtMobileAppAssignment -MobileAppId $Application.id 
                    if ($assignments)
                        {
                            Write-Output "   Exporting Client App Assignment: $($ApplicationAssignmentname)"
                            $ApplicationsAssignmentfileName = ($Application.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\Client Apps\Assignments\$($Application.id) - $ApplicationsAssignmentfileName.txt"
                            $assignments | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroupIDs = $assignments.id
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $EntraIDGroup = $AssignedGroupID.Substring(0, $AssignedGroupID.Length - 4)
                                        $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $EntraIDGroup -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                        $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                        $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                        $Values = @(
                                        "",
                                        "",
                                        "Group Name   Group ID",
                                        "==========   ========",
                                        "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID"
                                        )
                                        foreach ($value in $values)
                                            {
                                                Add-Content -LiteralPath "$assignmentspath" -value $value
                                            }

                                    }
                                }
                        }
                }


        #endregion

        #region 2. App Configuration Policies
            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\App Configuration Policy"))            
                {
                    New-Item -Path "$Outfolder\App Configuration Policy" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting App Configuration Policies" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1


            $AppConfigPolicies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceAppManagement/mobileAppConfigurations" | Get-MgGraphAllPages

            Foreach ($AppConfigPolicy in $AppConfigPolicies) 
                {
                    Write-Output "   Exporting App Configuration Policy: $($AppConfigPolicy.displayName)"
                    $AppConfigPolicyFilename = ($AppConfigPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AppConfigPolicy | Out-File -LiteralPath "$Outfolder\App Configuration Policy\$AppConfigPolicyFilename.txt"
                    $AppConfigPolicy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\App Configuration Policy\$AppConfigPolicyFilename.json"
                    
                    $Policysettings = $AppConfigPolicy.settings | ConvertTo-Json -Depth 3
                    $Values = @(
                    "Configuration Settings",
                    "======================",
                    $Policysettings
                    )
                    foreach ($value in $values)
                        {
                            Add-Content -LiteralPath "$Outfolder\App Configuration Policy\$AppConfigPolicyFilename.txt" -Value $value
                        }
                }

            # Assignments Export

            if (-not (Test-Path "$Outfolder\App Configuration Policy\Assignments")) 
                {
                    New-Item -Path "$Outfolder\App Configuration Policy\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting App Configuration Policy Assignments" -ForegroundColor Cyan
            
            foreach ($AppConfigPolicy in $AppConfigPolicies) 
                {
                    $assignments = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceAppManagement/mobileAppConfigurations/$($AppConfigPolicy.id)/assignments" | Get-MgGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting App Configuration Policy Assignment: $($AppConfigPolicy.displayName)"
                            $AppConfigPolicyAssignFileName = ($AppConfigPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\App Configuration Policy\Assignments\$AppConfigPolicyAssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments.target
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $AssignedGroupID
                                        $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                        $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                        $AssignedFilterID = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterId
                                        $AssignedFilterType = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterType
                                        $Values = @(
                                        "",
                                        "",
                                        "Group Name   Group ID   Assignment   FilterId   FilterType",
                                        "==========   ========   ==========   ========   ==========",
                                        "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID   $AssignedFilterID   $AssignedFilterType"
                                        )
                                        foreach ($value in $values)
                                        {
                                            Add-Content -LiteralPath "$assignmentspath" -value $value
                                        }

                                    }
                                }                    
                        }
                }      

        #endregion

        #region 3. App Protection Policies
         
            #region Android

                # Policy/Data Export
            
                If (-not (Test-Path "$Outfolder\App Protection Policies\Android")) 
                {
                    New-Item -Path "$Outfolder\App Protection Policies\Android" -ItemType Directory | Out-Null
                }

                Write-Host
                Write-host "Collecting Android Apps Protection policies configurations" -ForegroundColor Green
                Write-host "*******************************************************"
                Write-host
                Start-Sleep -Seconds 1


                $AppProtectionPolicies = Get-MgDeviceAppMgtAndroidManagedAppProtection | Get-MgGraphAllPages

                foreach ($AppProtectionPolicy in $AppProtectionPolicies) 
                {
                    Write-Output "   Exporting Android App Protection Policy: $($AppProtectionPolicy.displayName)"
                    $fileName = ($AppProtectionPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AppProtectionPolicy |fl | Out-File -LiteralPath "$Outfolder\App Protection Policies\Android\$fileName.txt"
                    $AppProtectionPolicy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\App Protection Policies\Android\$fileName.json"
                }
           
                # Assignments Export

                if (-not (Test-Path "$Outfolder\App Protection Policies\Android\Assignments")) 
                    {
                        New-Item -Path "$Outfolder\App Protection Policies\Android\Assignments" -ItemType Directory | Out-Null
                    }

                Write-Host
                Write-host "   Collecting Android App Protection Policies assignments" -ForegroundColor Cyan
            
                foreach ($AppProtectionPolicy in $AppProtectionPolicies) 
                    {
                        $assignments = Get-MgDeviceAppMgtAndroidManagedAppProtectionAssignment -AndroidManagedAppProtectionId $AppProtectionPolicy.id | Get-MgGraphAllPages
                        if ($assignments) 
                            {
                                Write-Output "   Exporting Android App Protection Policy assignment: $($AppProtectionPolicy.displayName)"
                                $AppProtecPolAssigfileName = ($AppProtectionPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                                $assignmentspath = "$Outfolder\App Protection Policies\Android\Assignments\$($AppProtectionPolicy.id) - $AppProtecPolAssigfileName.json"
                                $assignments | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$assignmentspath"

                                $AssignedGroupIDs = $assignments.target.AdditionalProperties
                                foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                    {
                                        If($AssignedGroup)
                                        {
                                            $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $AssignedGroupID.groupId
                                            $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                            $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                            $AssignedTypefull = $AssignedGroup.'@odata.type'
                                            $AssignedType = $AssignedTypefull -replace "#microsoft.graph.", ""
                                            $Values = @(
                                            "",
                                            "",
                                            "Group Name   Group ID   FilterType",
                                            "==========   ========   ==========",
                                            "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID   $AssignedType"
                                            )
                                            foreach ($value in $values)
                                            {
                                                Add-Content -LiteralPath "$assignmentspath" -value $value
                                            }
                                        }
                                    }
                             }
                      }
            #endregion Android

            #region iOS

                # Policy/Data Export
            
                If (-not (Test-Path "$Outfolder\App Protection Policies\iOS")) 
                {
                    New-Item -Path "$Outfolder\App Protection Policies\iOS" -ItemType Directory | Out-Null
                }

                Write-Host
                Write-host "Collecting iOS App Protection policies configurations" -ForegroundColor Green
                Write-host "*******************************************************"
                Write-host
                Start-Sleep -Seconds 1


                $AppProtectionPolicies = Get-MgDeviceAppMgtiOSManagedAppProtection | Get-MgGraphAllPages

                foreach ($AppProtectionPolicy in $AppProtectionPolicies) 
                {
                    Write-Output "   Exporting iOS App Protection Policy: $($AppProtectionPolicy.displayName)"
                    $fileName = ($AppProtectionPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AppProtectionPolicy |fl | Out-File -LiteralPath "$Outfolder\App Protection Policies\iOS\$fileName.txt"
                    $AppProtectionPolicy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\App Protection Policies\iOS\$fileName.json"
                }
           
                # Assignments Export

                if (-not (Test-Path "$Outfolder\App Protection Policies\iOS\Assignments")) 
                    {
                        New-Item -Path "$Outfolder\App Protection Policies\iOS\Assignments" -ItemType Directory | Out-Null
                    }

                Write-Host
                Write-host "   Collecting iOS App Protection Policies assignments" -ForegroundColor Cyan
            
                foreach ($AppProtectionPolicy in $AppProtectionPolicies) 
                    {
                        $assignments = Get-MgDeviceAppMgtiOSManagedAppProtectionAssignment -iOSManagedAppProtectionId $AppProtectionPolicy.id | Get-MgGraphAllPages
                        if ($assignments) 
                            {
                                Write-Output "   Exporting iOS App Protection Policy assignment: $($AppProtectionPolicy.displayName)"
                                $AppProtecPolAssigfileName = ($AppProtectionPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                                $assignmentspath = "$Outfolder\App Protection Policies\iOS\Assignments\$($AppProtectionPolicy.id) - $AppProtecPolAssigfileName.json"
                                $assignments | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$assignmentspath"

                                $AssignedGroups = $assignments.target.AdditionalProperties
                                foreach ($AssignedGroup in $AssignedGroups) 
                                    {
                                        If($AssignedGroup)
                                        {
                                            $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $AssignedGroup.groupId
                                            $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                            $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                            $AssignedTypefull = $AssignedGroup.'@odata.type'
                                            $AssignedType = $AssignedTypefull -replace "#microsoft.graph.", ""
                                            $Values = @(
                                            "",
                                            "",
                                            "Group Name   Group ID   FilterType",
                                            "==========   ========   ==========",
                                            "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID   $AssignedType"
                                            )
                                            foreach ($value in $values)
                                            {
                                                Add-Content -LiteralPath "$assignmentspath" -value $value
                                            }
                                        }
                                    }
                             }
                      }
            #endregion iOS

            #region MDM WIP

                # Policy/Data Export
            
                If (-not (Test-Path "$Outfolder\App Protection Policies\MDM WIP")) 
                {
                    New-Item -Path "$Outfolder\App Protection Policies\MDM WIP" -ItemType Directory | Out-Null
                }

                Write-Host
                Write-host "Collecting MDM Windows Information Protection policies configurations" -ForegroundColor Green
                Write-host "*******************************************************"
                Write-host
                Start-Sleep -Seconds 1


                $AppProtectionPolicies = Get-MgDeviceAppMgtMdmWindowInformationProtectionPolicy | Get-MgGraphAllPages

                foreach ($AppProtectionPolicy in $AppProtectionPolicies) 
                {
                    Write-Output "   Exporting MDM Windows Information Protection Policy: $($AppProtectionPolicy.displayName)"
                    $fileName = ($AppProtectionPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AppProtectionPolicy |fl | Out-File -LiteralPath "$Outfolder\App Protection Policies\MDM WIP\$fileName.txt"
                    $AppProtectionPolicy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\App Protection Policies\MDM WIP\$fileName.json"
                }
           
                # Assignments Export

                if (-not (Test-Path "$Outfolder\App Protection Policies\MDM WIP\Assignments")) 
                    {
                        New-Item -Path "$Outfolder\App Protection Policies\MDM WIP\Assignments" -ItemType Directory | Out-Null
                    }

                Write-Host
                Write-host "   Collecting MDM Windows Information Protection Policies assignments" -ForegroundColor Cyan
            
                foreach ($AppProtectionPolicy in $AppProtectionPolicies) 
                    {
                        $assignments = Get-MgDeviceAppMgtMdmWindowInformationProtectionPolicyAssignment -MdmWindowsInformationProtectionPolicyId $AppProtectionPolicy.id | Get-MgGraphAllPages
                        if ($assignments) 
                            {
                                Write-Output "   Exporting MDM Windows Information Protection Policy assignment: $($AppProtectionPolicy.displayName)"
                                $AppProtecPolAssigfileName = ($AppProtectionPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                                $assignmentspath = "$Outfolder\App Protection Policies\MDM WIP\Assignments\$($AppProtectionPolicy.id) - $AppProtecPolAssigfileName.json"
                                $assignments | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$assignmentspath"

                                $AssignedGroups = $assignments.target.AdditionalProperties
                                foreach ($AssignedGroup in $AssignedGroups) 
                                    {
                                        If($AssignedGroup)
                                        {
                                            $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $AssignedGroup.groupId
                                            $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                            $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                            $AssignedTypefull = $AssignedGroup.'@odata.type'
                                            $AssignedType = $AssignedTypefull -replace "#microsoft.graph.", ""
                                            $Values = @(
                                            "",
                                            "",
                                            "Group Name   Group ID   FilterType",
                                            "==========   ========   ==========",
                                            "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID   $AssignedType"
                                            )
                                            foreach ($value in $values)
                                            {
                                                Add-Content -LiteralPath "$assignmentspath" -value $value
                                            }
                                        }
                                    }
                             }
                      }
            #endregion MDM WIP

            #region Windows

                # Policy/Data Export
            
                If (-not (Test-Path "$Outfolder\App Protection Policies\Windows")) 
                {
                    New-Item -Path "$Outfolder\App Protection Policies\Windows" -ItemType Directory | Out-Null
                }

                Write-Host
                Write-host "Collecting Windows App Protection policies configurations" -ForegroundColor Green
                Write-host "*******************************************************"
                Write-host
                Start-Sleep -Seconds 1


                $AppProtectionPolicies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceAppManagement/windowsManagedAppProtections" | Get-MgGraphAllPages

                foreach ($AppProtectionPolicy in $AppProtectionPolicies) 
                {
                    Write-Output "   Exporting Windows App Protection Policy: $($AppProtectionPolicy.displayName)"
                    $fileName = ($AppProtectionPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AppProtectionPolicy |fl | Out-File -LiteralPath "$Outfolder\App Protection Policies\Windows\$fileName.txt"
                    $AppProtectionPolicy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\App Protection Policies\Windows\$fileName.json"
                }
           
                # Assignments Export

                if (-not (Test-Path "$Outfolder\App Protection Policies\Windows\Assignments")) 
                    {
                        New-Item -Path "$Outfolder\App Protection Policies\Windows\Assignments" -ItemType Directory | Out-Null
                    }

                Write-Host
                Write-host "   Collecting Windows App Protection Policies assignments" -ForegroundColor Cyan
            
                foreach ($AppProtectionPolicy in $AppProtectionPolicies) 
                    {
                        $assignments = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceAppManagement/windowsManagedAppProtections/$($AppProtectionPolicies.id)/assignments" | Get-MgGraphAllPages
                        if ($assignments) 
                            {
                                Write-Output "   Exporting Windows App Protection Policy assignment: $($AppProtectionPolicy.displayName)"
                                $AppProtecPolAssigfileName = ($AppProtectionPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                                $assignmentspath = "$Outfolder\App Protection Policies\Windows\Assignments\$($AppProtectionPolicy.id) - $AppProtecPolAssigfileName.json"
                                $assignments | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$assignmentspath"

                                $AssignedGroupIDs = $assignments.id
                                foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                    {
                                        If($AssignedGroupID)
                                        {
                                            $EntraIDGroup = $AssignedGroupID.Substring(0, $AssignedGroupID.Length - 5)
                                            $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $EntraIDGroup -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                            $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                            $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                            $Values = @(
                                            "",
                                            "",
                                            "Group Name   Group ID",
                                            "==========   ========",
                                            "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID"
                                            )
                                        foreach ($value in $values)
                                        {
                                            Add-Content -LiteralPath "$assignmentspath" -value $value
                                        }

                                    }
                                }
                             }
                      }
            #endregion Windows

        #endregion

        #region 4. Compliance Policies

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Compliance Policies")) 
                {
                    New-Item -Path "$Outfolder\Compliance Policies" -ItemType Directory | Out-Null
                }
            
            Write-Host
            Write-host "Collecting Compliance Policies configurations" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1


            $CompliancePolicies = Get-MgDeviceManagementDeviceCompliancePolicy | Get-MgGraphAllPages

            Foreach ($CompliancePolicy in $CompliancePolicies) 
                {
                    Write-Output "   Exporting Compliance Policy: $($CompliancePolicy.displayName)"

                    $fileName = ($CompliancePolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $CompliancePolicy | fl | Out-File -LiteralPath "$Outfolder\Compliance Policies\$fileName.txt"
                    $CompliancePolicy |ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Compliance Policies\$fileName.json"

                    $Policysettings = $CompliancePolicy.AdditionalProperties | ConvertTo-Json -Depth 3
                    $Values = @(
                    "Additional Properties",
                    "======================",
                    $Policysettings
                    )
                    foreach ($value in $values)
                        {
                            Add-Content -LiteralPath "$Outfolder\Compliance Policies\$fileName.txt" -Value $value
                        }
                }

            # Assignments Export

            if (-not (Test-Path "$Outfolder\Compliance Policies\Assignments")) 
                {
                    New-Item -Path "$Outfolder\Compliance Policies\Assignments" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "   Collecting Compliance Policies assignments" -ForegroundColor Cyan

            foreach ($CompliancePolicy in $CompliancePolicies) 
                {
                    $assignments = Get-MgDeviceManagementDeviceCompliancePolicyAssignment -DeviceCompliancePolicyId $CompliancePolicy.id | Get-MgGraphAllPages
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Compliance Policy assignment: $($CompliancePolicy.displayName)"
                            $CompliancePolAssigfileName = ($CompliancePolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\Compliance Policies\Assignments\$($CompliancePolicy.id) - $CompliancePolAssigfileName.json"
                            $assignments | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroupIDs = $assignments.Id
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $CompliancePolicy_id = $CompliancePolicy.id
                                        $EntraIDGroup = $AssignedGroupID -replace "$CompliancePolicy_id`_", ""
                                        $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $EntraIDGroup -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                        $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                        $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                        $Values = @(
                                        "",
                                        "",
                                        "Group Name   Group ID",
                                        "==========   ========",
                                        "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID"
                                        )
                                        foreach ($value in $values)
                                        {
                                            Add-Content -LiteralPath "$assignmentspath" -value $value
                                        }

                                    }
                                }
                        }
                }

        #endregion

        #--------------------------------------------------------------------> Corregir hacia arriba para hacer las politicas mas simples de modificar reusando variables en Region 5 las estandarize lo mas que pude. 
        #region 5. Device Configuration Policies

            # Policy/Data Export

            $path = "$Outfolder\Device Configurations"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Device Configuration Policies configurations" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Get-MgDeviceManagementDeviceConfiguration | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                    Write-Output "   Exporting Device Configuration Policies: $($Policy.displayName)"
                    $FileName = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy |fl | Out-File -LiteralPath "$path\$fileName.txt"
                    $Policy | ConvertTo-JSON -Depth 3 | Out-File -LiteralPath "$path\$fileName.json"

                    $Policysettings = $Policy.AdditionalProperties | ConvertTo-Json -Depth 3
                    $Values = @(
                    "Additional Properties",
                    "======================",
                    $Policysettings
                    )
                    foreach ($value in $values)
                        {
                            Add-Content -LiteralPath "$path\$fileName.txt" -Value $value
                        }

                }

            # Assignments Export

            if (-not (Test-Path "$path\Assignments")) 
                {
                    New-Item -Path "$path\Assignments" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "   Collecting Device Configuration Policies assignments" -ForegroundColor Cyan

            foreach ($Policy in $Policies) 
                {
                    $assignments = Get-MgDeviceManagementDeviceConfigurationAssignment -DeviceConfigurationId $Policy.id | Get-MgGraphAllPages
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Device Configuration Policies Assignment: $($Policy.displayName)"
                            $PolicyConfigAssignfileName = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Path\Assignments\$($Policy.id) - $PolicyConfigAssignfileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroups = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $assignments.target.AdditionalProperties
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $EntraIDGroup = $AssignedGroupID.groupId
                                        If($EntraIDGroup)
                                            {
                                                $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $EntraIDGroup
                                            }
                                        Else
                                            {
                                                $AssignedEntraIDGroup = $null
                                            }
                                        $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                        $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                        $AssignedTypefull = $AssignedGroupID.'@odata.type'
                                        $AssignedType = $AssignedTypefull -replace "#microsoft.graph.", ""
                                        $Values = @(
                                        "",
                                        "",
                                        "Group Name   Group ID   FilterType",
                                        "==========   ========   ==========",
                                        "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID   $AssignedType"
                                        )
                                        foreach ($value in $values)
                                        {
                                            Add-Content -LiteralPath "$assignmentspath" -value $value
                                        }

                                    }
                                }
                        }
                }


        #endregion

        #region 6. Settings Catalog policies.

            # Policy/Data Export
                    $path = "$Outfolder\Settings Catalog Policies"             
                    If (-not (Test-Path "$Path")) 
                        {
                            New-Item -Path "$Path" -ItemType Directory | Out-Null                
                        }

                    Write-Host
                    Write-host "Collecting Settings Catalog Policies" -ForegroundColor Green
                    Write-host "*******************************************************"
                    Write-host
                    Start-Sleep -Seconds 1


                    $sharedParams = @{
                        all    = $true
                        expand = "assignments"
	                    }
		
                    $Params = $sharedParams.clone()
                    $Params.select = $Params.select -replace "displayname", "name"
                    $Params.expand += ",settings,"
                    $SCPolicies = Get-MgBetaDeviceManagementConfigurationPolicy @Params


                      foreach ($SCpolicy in $SCpolicies) 
                        {
                            Write-Output "   Exporting Settings Catalog Policies: $($SCpolicy.Name)"
                            $SCpolicyFileName = ($SCpolicy.Name).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $SCpolicyOutFile = "$Path\$($SCPolicy.Platforms) - $SCpolicyFileName.txt"
                            $SCpolicy | fl | Out-File -LiteralPath $SCpolicyOutFile
                            $SCpolicy | ConvertTo-json -Depth 10 | Out-File -LiteralPath "$Path\$($SCPolicy.Platforms) - $SCpolicyFileName.json"
                


                            # Policy Settings Export

                   
                            #Get the settings configured in the policy and it will calpture any child settings appending in a TXT file.
                    

                             $SCpolicySettings = $SCpolicy.settings.SettingInstance
                             Add-Content -LiteralPath "$SCpolicyOutFile" " Expanding Setings "
                             Add-Content -LiteralPath "$SCpolicyOutFile" "==================="
                             Foreach ($SCpolicySetting in $SCpolicySettings)
                                {
                                      $SCpolicySettingDef = $SCpolicySetting.SettingDefinitionId 
                                      $SCpolicySettingValue = $SCpolicySetting.AdditionalProperties.Values.value
                                      $SCpolicySettingValueA = $SCpolicySetting.AdditionalProperties.simpleSettingValue.Values    
                                      $SCpolicySettingValueChildren = $SCpolicySetting.AdditionalProperties.choiceSettingValue.children

                                        If ($SCpolicySettingValueChildren.count -eq 0)
                                            {
                                                $OutSCpolicySetting = [PSCustomObject]@{
                                                Setting        = $SCpolicySettingDef
                                                Value          = $SCpolicySettingValue
                                                SimpleValue    = $SCpolicySettingValueA
                                                    }
                                
                                                $OutSCpolicySetting | fl | Out-File -LiteralPath $SCpolicyOutFile -Append
                                            }

                        
                                        If ($SCpolicySettingValueChildren.count -ge 1)
                                            {
                                                $SCpolicySettingValueChildrenDef = $SCpolicySetting.AdditionalProperties.choiceSettingValue.children.settingDefinitionId
                                                $SCpolicySettingValueChildrenDefValue = $SCpolicySetting.AdditionalProperties.choiceSettingValue.Values.values.value
                                                $SCpolicySettingValueChildrenDefSetting = $SCpolicySetting.AdditionalProperties.choiceSettingValue.children.simpleSettingValue.Values

                                                $OutSCpolicySetting  = [PSCustomObject]@{
                                                Setting          = $SCpolicySettingDef
                                                Value            = $SCpolicySettingValue
                                                SimpleValue      = $SCpolicySettingValueA
                                                SubSetting       = $SCpolicySettingValueChildrenDef
                                                SubSettingValue  = $SCpolicySettingValueChildrenDefValue
                                                SubsettingChildValue = $SCpolicySettingValueChildrenDefSetting
                                                    }
                                
                                                $OutSCpolicySetting | fl | Out-File -LiteralPath $SCpolicyOutFile -Append
                                            }
                                }
                                
                                #Export all the settings in a single JSON file
                                $SCPolicySettings = Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($SCPolicy.id)/settings?$expand=settingDefinitions&top=1000"
                                $SCpolicySettingsOutFile = "$SCpolicyOutFile`_Settings.json"
                                $SCPolicySettings |ConvertTo-Json -Depth 10 | Out-File -LiteralPath "$SCpolicySettingsOutFile"     
                          }

                            # Assignments Export

                            if (-not (Test-Path "$Path\Assignments")) 
                                {
                                    New-Item -Path "$Path\Assignments" -ItemType Directory | Out-Null
                                }

                            Write-Host
                            Write-host "   Collecting Settings Catalog Policies Assignments" -ForegroundColor Cyan
                    
                            foreach ($SCpolicy in $SCpolicies)
                                {
                                    $Assignments = Get-MgBetaDeviceManagementConfigurationPolicyAssignment -DeviceManagementConfigurationPolicyId $SCPolicy.Id
                                    if ($Assignments) 
                                        {
                                            Write-Output "   Exporting Settings Catalog Policies Assignment: $($SCpolicy.Name)"
                                            $SCpolicyAssignFileName = ($SCpolicy.Name).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                                            $assignmentspath = "$Path\Assignments\$($SCPolicy.id) - $SCpolicyAssignFileName.json"
                                            $Assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"
                            
                                            $AssignedGroupIDs = $assignments                    
                                                Foreach($AssignedGroupID in $AssignedGroupIDs)
                                                    { 
                                                        If($AssignedGroupID)
                                                            {
                                                                $SCPolicy_id = $SCPolicy.id
                                                                $EntraIDGroup = $AssignedGroupID.id -replace "$SCPolicy_id`_", ""
                                                                If($EntraIDGroup -ne "acacacac-9df4-4c7d-9d50-4ef0226f57a9" -and $EntraIDGroup -ne "adadadad-808e-44e2-905a-0b7873a8a531")
                                                                    {
                                                                        $AssignedEntraIDGroup =  Get-MgBetaGroup -GroupId $EntraIDGroup
                                                                    }                                                               
                                                                
                                                                Elseif($EntraIDGroup -eq "adadadad-808e-44e2-905a-0b7873a8a531")
                                                                    {
                                                                        $AssignedEntraIDGroup = New-Object PSObject -Property @{
                                                                        DisplayName = "All Devices"
                                                                        Id = "$EntraIDGroup"
                                                                        }
                                                                    }

                                                                Elseif($EntraIDGroup -eq "acacacac-9df4-4c7d-9d50-4ef0226f57a9")
                                                                    {
                                                                        $AssignedEntraIDGroup = New-Object PSObject -Property @{
                                                                        DisplayName = "All Users"
                                                                        Id = "$EntraIDGroup"
                                                                        }
                                                                    }


                                                                $AssignedEntraIDGroupName = $AssignedEntraIDGroup.DisplayName
                                                                $AssignedEntraIDGroupID = $AssignedEntraIDGroup.id
                                                                $AssignedFilterID = $AssignedGroupID.target.deviceAndAppManagementAssignmentFilterId
                                                                $AssignedFilterType = $AssignedGroupID.target.deviceAndAppManagementAssignmentFilterType
                                                        
                                                                $Values = @(
                                                                "",
                                                                "",
                                                                "Group Name   Group ID   FilterId   FilterType",
                                                                "==========   ========   ========   ==========",
                                                                "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID   $AssignedFilterID   $AssignedFilterType"
                                                                )
                                                                foreach ($value in $values)
                                                                    {
                                                                        Add-Content -LiteralPath "$assignmentspath" -value $value
                                                                    }
                                                            }
                                                    }
                                         }
                                 }

        #endregion

        #region 6. Windows Scripts

            # Policy/Data Export
            
            $path = "$Outfolder\Windows Scripts"
            If (-not (Test-Path "$path\PS1 Files")) 
                {
                    New-Item -Path "$path\PS1 Files" -ItemType Directory | Out-Null                
                }

            Write-Host
            Write-host "Collecting Windows Scripts configurations" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            
            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/deviceManagementScripts" | Get-MgGraphAllPages

            foreach ($Policy in $Policies) 
                {
                    Write-Output "   Exporting Windows Script: $($Policy.displayName)"
                    $Policy = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/deviceManagementScripts/$($Policy.Id)"
                    $PolicyFileName = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$PolicyFileName.txt"
                    $Policy | ConvertTo-json -Depth 3 | Out-File -LiteralPath "$path\$PolicyFileName.json"

                    $PolicyContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Policy.scriptContent))
                    $PolicyContent | Out-File -LiteralPath "$path\PS1 Files\$($Policy.id) - $PolicyFileName.ps1"
                }

            # Assignments Export

            if (-not (Test-Path "$path\Assignments")) 
                {
                    New-Item -Path "$path\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting Windows Scripts Assignments" -ForegroundColor Cyan
            foreach ($Policy in $Policies) 
                {
                    $assignments = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/deviceManagementScripts/$($Policy.id)/assignments" | Get-MgGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Windows Script Assignment: $($Policy.displayName)"
                            $PolicyAssignFileName = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$path\Assignments\$PolicyAssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroupIDs = $assignments.target
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedEntraIDgroup = Get-MgBetaGroup -GroupId $AssignedGroupID.groupId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                        $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                        $AssignedEntraIDgroupID = $AssignedEntraIDgroup.Id
                                        $Values = @(
                                        "",
                                        "",
                                        "Group Name   Group ID",
                                        "==========   ========",
                                        "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID"
                                        )
                                        foreach ($value in $values)
                                        {
                                            Add-Content -LiteralPath "$assignmentspath" -value $value
                                        }
                                    }
                                }
                        }
                 }

        #endregion

        #region 7. Device Management Intents


            # Policy/Data Export
            $path = "$Outfolder\Device Management Intents"
            if (-not (Test-Path "$path")) 
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }
            
            Write-Host
            Write-host "Collecting Device Management Intents" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/intents" | Get-MgGraphAllPages

            foreach ($Policy in $Policies) 
                {
                    $Policytemplate = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/templates/$($Policy.templateId)"
                    $PolicytemplateDisplayName = ($Policytemplate.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'

                    Write-Host "   Exporting Device Management Intent ($($Policytemplate.displayName)): $($Policy.displayName)"

                    if (-not (Test-Path "$path\$PolicytemplateDisplayName")) 
                        {
                            New-Item -Path "$path\$PolicytemplateDisplayName" -ItemType Directory | Out-Null
                        }

                    Write-Host "   Requesting Template Categories..."
                    $PolicytemplateCategories = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/templates/$($Policy.templateId)/categories" | Get-MgGraphAllPages

                    $PolicysettingsDelta = @()
                    foreach ($PolicytemplateCategory in $PolicytemplateCategories) 
                        {
                            Write-Host "   Requesting Intent Setting Values..."
                            $PolicysettingsDelta += (Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/intents/$($Policy.id)/categories/$($PolicytemplateCategory.id)/settings").value
                        }

                    $intentBackupValue = @{
                                            "displayName" = $Policy.displayName
                                            "description" = $Policy.description
                                            "settingsDelta" = $PolicysettingsDelta
                                            "roleScopeTagIds" = $Policy.roleScopeTagIds
                                          }
        
                    $PolicyFileName = ("$($Policytemplate.displayName)_$($Policy.displayName)").Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $intentBackupValue | Out-File -LiteralPath "$path\$PolicytemplateDisplayName\$PolicyFileName.txt"
                    $intentBackupValue | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$PolicytemplateDisplayName\$PolicyFileName.json"

                }

            # Assignments Export

                if (-not (Test-Path "$path\Assignments")) 
                    {
                        New-Item -Path "$path\Assignments" -ItemType Directory | Out-Null
                    }
                    
                Write-Host
                Write-host "   Collecting Device Management Intents Assignments" -ForegroundColor Cyan
                
                foreach ($Policy in $Policies) 
                    {
                        $assignments = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/intents/$($Policy.id)/assignments" | Get-MgGraphAllPages
                
                        if ($assignments) 
                            {
                                Write-Output "   Exporting Device Management Intent Assignment: $($Policy.displayName)"
                                $PolicyAssignFileName = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                                $assignmentspath = "$path\Assignments\$PolicyAssignFileName.json"
                                $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                                $AssignedGroupIDs = $assignments.target
                                foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                    {
                                        If($AssignedGroupID)
                                        {
                                            $EntraIDGroup = $AssignedGroupID.groupId
                                                If($EntraIDGroup)
                                                    {
                                                        $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $EntraIDGroup
                                                    }
                                                Else
                                                    {
                                                        $AssignedEntraIDGroup = $null
                                                    }
                                            $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                            $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                            $AssignedTypefull = $AssignedGroupID.'@odata.type'
                                            $AssignedType = $AssignedTypefull -replace "#microsoft.graph.", ""
                                            $AssignedFilterID = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterId
                                            $AssignedFilterType = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterType
                                            $Values = @(
                                            "",
                                            "",
                                            "Group Name   Group ID   Assignment   FilterId   FilterType",
                                            "==========   ========   ==========   ========   ==========",
                                            "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID   $AssignedType   $AssignedFilterID   $AssignedFilterType"
                                            )
                                            foreach ($value in $values)
                                            {
                                                Add-Content -LiteralPath "$assignmentspath" -value $value
                                            }
                                        }
                                    }
                            }
                    }
        #endregion
        
        #region 8. Administrative Templates / Group Policies Configurations

            # Policy/Data Export
            $path = "$Outfolder\Administrative Templates"
            if (-not (Test-Path "$path")) 
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Administrative templates" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $GroupPolicyConfigs = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/GroupPolicyConfigurations" | Get-MgGraphAllPages

            foreach ($GroupPolicyConfig in $GroupPolicyConfigs) 
                {
                    $GroupPolicyDefinitionValues = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/GroupPolicyConfigurations/$($GroupPolicyConfig.id)/definitionValues" | Get-MgGraphAllPages
                    $GroupPolicyBackupValues = @()

                        foreach ($GroupPolicyDefinitionValue in $GroupPolicyDefinitionValues) 
                            {
                                $GroupPolicyDefinition = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/GroupPolicyConfigurations/$($GroupPolicyConfig.id)/definitionValues/$($GroupPolicyDefinitionValue.id)/definition"
                                $GroupPolicyPresentationValues = (Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/GroupPolicyConfigurations/$($GroupPolicyConfig.id)/definitionValues/$($GroupPolicyDefinitionValue.id)/presentationValues?`$expand=presentation").Value
                                $GroupPolicyBackupValue = @{
                                    "enabled" = $GroupPolicyDefinitionValue.enabled
                                    "definition@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($GroupPolicyDefinition.id)')"
                                }

                                if ($GroupPolicyPresentationValues.value) 
                                    {
                                        $GroupPolicyBackupValue."presentationValues" = @()
                                        foreach ($GroupPolicyPresentationValue in $GroupPolicyPresentationValues) 
                                            {
                                                $GroupPolicyBackupValue."presentationValues" +=
                                                    @{
                                                        "@odata.type" = $GroupPolicyPresentationValue.'@odata.type'
                                                        "value" = $GroupPolicyPresentationValue.value
                                                        "presentation@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($GroupPolicyDefinition.id)')/presentations('$($GroupPolicyPresentationValue.presentation.id)')"
                                                    }
                                            }
                                    } 
                                    elseif ($GroupPolicyPresentationValues.values) 
                                        {
                                            $GroupPolicyBackupValue."presentationValues" = @(
                                                    @{
                                                        "@odata.type" = $GroupPolicyPresentationValues.'@odata.type'
                                                        "values" = @(
                                                            foreach ($GroupPolicyPresentationValue in $GroupPolicyPresentationValues.values) 
                                                                {
                                                                    @{
                                                                        "name" = $GroupPolicyPresentationValue.name
                                                                        "value" = $GroupPolicyPresentationValue.value
                                                                    }
                                                                }
                                                            )
                                                        "presentation@odata.bind" = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($GroupPolicyDefinition.id)')/presentations('$($GroupPolicyPresentationValues.presentation.id)')"
                                                    } 
                                                )
                                        }   

                                        $GroupPolicyBackupValues += $GroupPolicyBackupValue
                            }

                    Write-Host "   Exporting Administrative Template: $($GroupPolicyConfig.displayName)"
                    $GroupPolicyAdmTemplatefileName = ($GroupPolicyConfig.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $GroupPolicyBackupValues | Out-File -LiteralPath "$path\$GroupPolicyAdmTemplatefileName.txt"
                    $GroupPolicyBackupValues | Convertto-Json -Depth 3 | Out-File -LiteralPath "$path\$GroupPolicyAdmTemplatefileName.json"
                }

            # Assignments Export
 
            if (-not (Test-Path "$path\Assignments")) 
                {
                    New-Item -Path "$path\Assignments" -ItemType Directory | Out-Null
                }
                    
            Write-Host
            Write-host "   Collecting Administrative Templates Assignments" -ForegroundColor Cyan
            

            foreach ($GroupPolicyConfig in $GroupPolicyConfigs) 
                {
                    $assignments = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/GroupPolicyConfigurations/$($GroupPolicyConfig.id)/assignments" | Get-MgGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Device Management Intent Assignment: $($GroupPolicyConfig.displayName)"
                            $GroupPolicyConfigAssignFileName = ($GroupPolicyConfig.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$path\Assignments\$GroupPolicyConfigAssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroupIDs = $assignments.target
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                        {
                                            $EntraIDGroup = $AssignedGroupID.groupId
                                                If($EntraIDGroup)
                                                    {
                                                        $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $EntraIDGroup
                                                    }
                                                Else
                                                    {
                                                        $AssignedEntraIDGroup = $null
                                                    }
                                            $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                            $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                            $AssignedTypefull = $AssignedGroupID.'@odata.type'
                                            $AssignedType = $AssignedTypefull -replace "#microsoft.graph.", ""
                                            $AssignedFilterID = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterId
                                            $AssignedFilterType = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterType
                                            $Values = @(
                                            "",
                                            "",
                                            "Group Name   Group ID   Assignment   FilterId   FilterType",
                                            "==========   ========   ==========   ========   ==========",
                                            "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID   $AssignedType   $AssignedFilterID   $AssignedFilterType"
                                            )
                                            foreach ($value in $values)
                                            {
                                                Add-Content -LiteralPath "$assignmentspath" -value $value
                                            }
                                        }
                                    }
                        }
                }            

        #endregion
 
        #region 9. Autopilot Deployment Profiles

            # Policy/Data Export
            $path = "$Outfolder\Autopilot Deployment Profiles"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Autopilot Deployment Profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1


            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/windowsAutopilotDeploymentProfiles" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                    Write-Output "   Exporting Autopilot Deployment Profile: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$PolicyFilename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"

                    $Policysettings = $Policy.outOfBoxExperienceSetting | ConvertTo-Json -Depth 3
                    $Values = @(
                    "outOfBoxExperienceSetting",
                    "=========================",
                    $Policysettings
                    )
                    foreach ($value in $values)
                        {
                            Add-Content -LiteralPath "$Path\$fileName.txt" -Value $value
                        }

                    $Policysettings = $Policy.outOfBoxExperienceSettings | ConvertTo-Json -Depth 3
                    $Values = @(
                    "outOfBoxExperienceSettings",
                    "==========================",
                    $Policysettings
                    )
                    foreach ($value in $values)
                        {
                            Add-Content -LiteralPath "$Path\$fileName.txt" -Value $value
                        }
                }

            # Assignments Export

            if (-not (Test-Path "$path\Assignments")) 
                {
                    New-Item -Path "$path\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting Autopilot Deployment Profiles Assignments" -ForegroundColor Cyan
            

            foreach ($Policy in $Policies) 
                {
                    $assignments = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/windowsAutopilotDeploymentProfiles/$($Policy.id)/assignments" | Get-MgGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Autopilot Deployment Profile Assignment: $($Policy.displayName)"
                            $PolicyAssignFileName = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$path\Assignments\$PolicyAssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroupIDs = $assignments.target
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedEntraIDgroup = Get-MgBetaGroup -GroupId $AssignedGroupID.groupId -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                        $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                        $AssignedEntraIDgroupID = $AssignedEntraIDgroup.Id
                                        $Values = @(
                                        "",
                                        "",
                                        "Group Name   Group ID",
                                        "==========   ========",
                                        "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID"
                                        )
                                        foreach ($value in $values)
                                            {
                                                Add-Content -LiteralPath "$assignmentspath" -value $value
                                            }
                                    }
                                }
                        }
                }       

        #endregion

        #region 10. Device Enrollment Configurations (Device restrictions / Device Limit / Autopilot ESP / WHfB)
            
            # Policy/Data Export
            $path = "$Outfolder\Device Enrollment Configurations"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Device Enrollment Configurations" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host 
            Start-Sleep -Seconds 1

            $Policies =  Get-MgDeviceManagementDeviceEnrollmentConfiguration | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                    Write-Output "   Exporting Device Enrollent Configuration: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$($Policy.id) - $Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$($Policy.id) - $Filename.json"
                }

            # Assignments Export

            if (-not (Test-Path "$path\Assignments")) 
                {
                    New-Item -Path "$path\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting Device Enrollment Configurations Assignments" -ForegroundColor Cyan
           

            Foreach ($Policy in $Policies)  
                {
                    $assignments = Get-MgDeviceManagementDeviceEnrollmentConfigurationAssignment -DeviceEnrollmentConfigurationId $Policy.Id | Get-MgGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Device Enrollment Configuration Assignment: $($Policy.displayName)"
                            $AssignFileName = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$path\Assignments\$($Policy.id) - $AssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroupIDs = $assignments.Id
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                                                                
                                        If($AssignedGroupID.Length -eq "110")
                                            {
                                                $EntraIDGroup = $AssignedGroupID.Substring(37, $AssignedGroupID.Length - 74)
                                                $AssignedEntraIDgroup = Get-MgBetaGroup -GroupId $EntraIDGroup -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                                $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                            }

                                        If($AssignedGroupID.Length -lt "110")
                                            {
                                                $AssignedEntraIDgroup = $null
                                                $AssignedEntraIDgroupName = $Policy.Description
                                            }
                                        
                                        $AssignedEntraIDgroupID = $AssignedEntraIDgroup.Id
                                        $Values = @(
                                        "",
                                        "",
                                        "Group Name   Group ID",
                                        "==========   ========",
                                        "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID"
                                        )
                                        foreach ($value in $values)
                                            {
                                                Add-Content -LiteralPath "$assignmentspath" -value $value
                                            }
                                    }
                                }
                        }
                }  
            
        #endregion                

        #region 11. APN Certificate
 
            # Policy/Data Export
            $path = "$Outfolder\Apple Push Notitication Certificate"         
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Apple Push Notification Certificate " -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1


                $Policies =  Get-MgDeviceManagementApplePushNotificationCertificate | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                    Write-Output "   Exporting Apple Push Notification Certificate: $($Policy.topicIdentifier)"
                    $Filename = ($Policy.topicIdentifier).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.txt"
                }
        #endregion

        #region 12. Apple User Enrollment Profiles.

            # Policy/Data Export
            $path = "$Outfolder\Apple User Enrollment Profile"           
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Apple User Enrollment Profiles " -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1
            $Polices =  Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/appleUserInitiatedEnrollmentProfiles" | Get-MgGraphAllPages

            Foreach ($Policy in $Polices) 
                {
                    Write-Output "   Exporting Apple User Enrollment Profile: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                }
            
        #endregion

        #region 13. Apple DEP Profiles (PEND)

            # Policy/Data Export
            $path = "$Outfolder\Apple DEP"
            if (-not (Test-Path "$path")) 
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Apple DEP Profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/depOnboardingSettings" | Get-MgGraphAllPages

            foreach ($Policy in $Policies) 
                {
                    Write-Host "   Exporting Apple DEP Profile: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $PolicyEnrollmentProfiles = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/depOnboardingSettings/$($Policy.id)/enrollmentProfiles" | Get-MgGraphAllPages

                        foreach ($PolicyEnrollmentProfile in $PolicyEnrollmentProfiles) 
                            {
                            if (-not (Test-Path "$path\Enrollment Profiles")) 
                                {
                                    New-Item -Path "$path\Enrollment Profiles" -ItemType Directory | Out-Null
                                }
                                Write-Host "   Exporting Apple DEP Enrollment Profile: $($PolicyEnrollmentProfile.displayName)"
                                $PolicyEnrollmentProfilefileName = ($PolicyEnrollmentProfile.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                                $PolicyEnrollmentProfile | Out-File -LiteralPath "$path\Enrollment Profiles\$PolicyEnrollmentProfilefileName.txt"
                                $PolicyEnrollmentProfile | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\Enrollment Profiles\$PolicyEnrollmentProfilefileName.json"
                            }
                }
        
        #endregion
    
        #region 14. Apple VPP Token (PEND)

            # Policy/Data Export
            $path = "$Outfolder\Apple VPP Token"            
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Apple VPP Tokens" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $AppleVPPTokens = Get-MgDeviceAppMgtVppToken | Get-MgGraphAllPages

            Foreach ($AppleVPPToken in $AppleVPPTokens) 
                {
                    Write-Output "   Exporting Apple VPP Token: $($AppleVPPToken.displayName)"
                    $AppleVPPTokenFilename = ($AppleVPPToken.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AppleVPPToken | Out-File -LiteralPath "$path\$AppleVPPTokenFilename.txt"
                    $AppleVPPToken | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$AppleVPPTokenFilename.Json"
                }

        #endregion

        #region 15. Android Managed Store Account Enterprise Settings

            # Policy/Data Export
            $path = "$Outfolder\Android Managed Store Account Enterprise"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Android Managed Store Account Enterprise" -ForegroundColor Green
            Write-host "***************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings" #| Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                    Write-Output "   Exporting Android Managed Store Account Enterprise Setting: $($Policy.ownerOrganizationName)"
                    $Filename = ($Policy.ownerOrganizationName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.Json"
                }

        #endregion

        #region 16. Android Corporate-Owned profiles (Corp Owned & AFW)

            # Policy/Data Export
            $path = "$Outfolder\Android Corporate-Owned profiles"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Android Corporate-Owned profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                    Write-Output "   Exporting Android Corporate-Owned profile: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                    
                }

        #endregion

        #region 17. Android for Work profiles

            # Policy/Data Export
            $path = "$Outfolder\Android for Work profiles"
            If (-not (Test-Path "$Path"))            
                {
                    New-Item -Path "$Path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Android for Work profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1


            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/androidForWorkEnrollmentProfiles" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                    Write-Output "   Exporting Android for Work profile: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$Path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Path\$Filename.json"
                }

        #endregion

        #region 18. Android for work settings 
            
            # Policy/Data Export
            $path = "$Outfolder\Android for work settings"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Android for work settings" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/androidForWorkSettings" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                Write-Output "   Exporting Android for work setting: $($Policy.ownerOrganizationName)"
                    $Filename = ($Policy.ownerOrganizationName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                }

        #endregion        

        #region 19. Assignment Filters

            # Policy/Data Export
            $path = "$Outfolder\Filters"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Filters" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/assignmentFilters" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                Write-Output "   Exporting Filter: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                }

        #endregion 

        #region 20. Device Categories

            # Policy/Data Export
            $path = "$Outfolder\Device Categories"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Device Categories" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/deviceCategories" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                Write-Output "   Exporting Device Categorie: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                }

        #endregion 

        #region 21. Domain Join Connectors

            # Policy/Data Export
            $path = "$Outfolder\Domain Join Connectors"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Domain Join Connectors" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/domainJoinConnectors" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                Write-Output "   Exporting Domain Join Connector: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                }

        #endregion

        #region 22. Microsoft Tunnel Sites & Configurations

            # Policy/Data Export
            $path = "$Outfolder\Microsoft Tunnel\Configurations"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Microsoft Tunnel Configurations" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/microsoftTunnelConfigurations" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                Write-Output "   Exporting Microsoft Tunnel Configuration: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                }


            # Policy/Data Export
            $path = "$Outfolder\Microsoft Tunnel\Sites"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Microsoft Tunnel Sites" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/microsoftTunnelSites" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                Write-Output "   Exporting Microsoft Tunnel Site: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                }

        #endregion

        #region 23. NDES Connectors

            # Policy/Data Export
            $path = "$Outfolder\NDESConnectors"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting NDES Connectors" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/NDESConnectors" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                Write-Output "   Exporting NDES Connector: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                }

        #endregion

        #region 25. Windows Feature Update Profiles

            # Policy/Data Export
            $path = "$Outfolder\Windows Update\Feature Update"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Windows Feature Update Profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/windowsFeatureUpdateProfiles" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                    Write-Output "   Exporting Windows Feature Update Profile: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                }

            # Assignments Export

            if (-not (Test-Path "$path\Assignments")) 
                {
                    New-Item -Path "$path\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting Windows Feature Update Profiles Assignments" -ForegroundColor Cyan
            

            foreach ($Policy in $Policies) 
                {
                    $assignments = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/windowsFeatureUpdateProfiles/$($Policy.id)/assignments" | Get-MgGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Windows Feature Update Profile Assignment: $($Policy.displayName)"
                            $AssignFileName = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$path\Assignments\$AssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments.Target
                            $AssignedGroupIDs = $AssignedGroup.GroupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $AssignedGroupID
                                        $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                        $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                        $AssignedFilterID = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterId
                                        $AssignedFilterType = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterType
                                        $Values = @(
                                        "",
                                        "",
                                        "Group Name   Group ID   Assignment   FilterId   FilterType",
                                        "==========   ========   ==========   ========   ==========",
                                        "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID   $AssignedFilterID   $AssignedFilterType"
                                        )
                                        foreach ($value in $values)
                                        {
                                            Add-Content -LiteralPath "$assignmentspath" -value $value
                                        }

                                    }
                                }
                        }
                }       

        #endregion

        #region 26. Windows Driver Update Profiles

            # Policy/Data Export
            $path = "$Outfolder\Windows Update\Driver Update"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Windows Driver Update Profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/windowsDriverUpdateProfiles" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                    Write-Output "   Exporting Windows Driver Update Profile: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                }

            # Assignments Export

            if (-not (Test-Path "$path\Assignments")) 
                {
                    New-Item -Path "$path\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting Windows Quality Update Profiles Assignments" -ForegroundColor Cyan
            

            foreach ($Policy in $Policies) 
                {
                    $assignments = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/windowsDriverUpdateProfiles/$($Policy.id)/assignments" | Get-MgGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Windows Quality Update Profile Assignment: $($Policy.displayName)"
                            $AssignFileName = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$path\Assignments\$AssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments.Target
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $AssignedGroupID
                                        $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                        $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                        $AssignedFilterID = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterId
                                        $AssignedFilterType = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterType
                                        $Values = @(
                                        "",
                                        "",
                                        "Group Name   Group ID   Assignment   FilterId   FilterType",
                                        "==========   ========   ==========   ========   ==========",
                                        "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID   $AssignedFilterID   $AssignedFilterType"
                                        )
                                        foreach ($value in $values)
                                        {
                                            Add-Content -LiteralPath "$assignmentspath" -value $value
                                        }

                                    }
                                }
                        }
                }       


        #endregion

        #region 27. Windows Quality Update Profiles

            # Policy/Data Export
            $path = "$Outfolder\Windows Update\Quality Update"
            If (-not (Test-Path "$path"))            
                {
                    New-Item -Path "$path" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Windows Quality Update Profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $Policies = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/windowsQualityUpdateProfiles" | Get-MgGraphAllPages

            Foreach ($Policy in $Policies) 
                {
                    Write-Output "   Exporting Windows Quality Update Profile: $($Policy.displayName)"
                    $Filename = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Policy | Out-File -LiteralPath "$path\$Filename.txt"
                    $Policy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$path\$Filename.json"
                }

            # Assignments Export

            if (-not (Test-Path "$path\Assignments")) 
                {
                    New-Item -Path "$path\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting Windows Quality Update Profiles Assignments" -ForegroundColor Cyan
            

            foreach ($Policy in $Policies) 
                {
                    $assignments = Invoke-MgGraphRequest -Method GET -Uri "beta/deviceManagement/windowsQualityUpdateProfiles/$($Policy.id)/assignments" | Get-MgGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Windows Quality Update Profile Assignment: $($Policy.displayName)"
                            $AssignFileName = ($Policy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$path\Assignments\$AssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments.Target
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedEntraIDGroup = Get-MgBetaGroup -GroupId $AssignedGroupID
                                        $AssignedEntraIDgroupName = $AssignedEntraIDgroup.DisplayName
                                        $AssignedEntraIDgroupID = $AssignedEntraIDgroup.id
                                        $AssignedFilterID = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterId
                                        $AssignedFilterType = $AssignedEntraIDGroup.deviceAndAppManagementAssignmentFilterType
                                        $Values = @(
                                        "",
                                        "",
                                        "Group Name   Group ID   Assignment   FilterId   FilterType",
                                        "==========   ========   ==========   ========   ==========",
                                        "$AssignedEntraIDgroupName   $AssignedEntraIDgroupID   $AssignedFilterID   $AssignedFilterType"
                                        )
                                        foreach ($value in $values)
                                        {
                                            Add-Content -LiteralPath "$assignmentspath" -value $value
                                        }

                                    }
                                }
                        }
                }       


        #endregion


#endregion Data Collection 

####################################################

#region Add to Zip all data collected
        Write-host 
        Write-host "Compressing data collected..." -ForegroundColor Green
        Write-host "****************************************************"
          
        Get-ChildItem -Path $Outfolder | Where-Object {$_.mode -eq "d-----"} | Compress-Archive -DestinationPath "$Outfolder\SMCIntuneDiscoveryAssessment.zip" -Force

        Try 
            {
            $Zipcreated = Test-Path "$Outfolder\SMCIntuneDiscoveryAssessment.zip"

            If ($Zipcreated)
                {
                Write-host
                Write-host "   Zip file " -NoNewline
                Write-host "SMCIntuneDiscoveryAssessment.zip " -NoNewline -ForegroundColor Cyan
                Write-Host "was created in the folder: " -NoNewline
                Write-Host "$Outfolder" -ForegroundColor Cyan
                Write-host "   Data collection completed!" -ForegroundColor Cyan
                }
            
            Elseif (-not ($Zipcreated))
                {
                Write-host
                Write-host "   Zip file SMCIntuneDiscoveryAssessment.zip was NOT found on the path $Outfolder" -ForegroundColor Yellow
                Write-host "   If the zip file SMCIntuneDiscoveryAssessment.zip is not found, please do the manual compression of the folder $Outfolder with all the data collected"
                Write-host 
                }

            }
        
        Catch 
            {
            Write-host "Error!" -ForegroundColor Red
            $_
            exit
            }
            
        #endregion Add to Zip all data collected

####################################################

Write-host
Start-Sleep -Seconds 3
Write-Host "Script terminated" -ForegroundColor Yellow
Start-Sleep -Seconds 1
Write-Host

Stop-Transcript | Out-Null

exit