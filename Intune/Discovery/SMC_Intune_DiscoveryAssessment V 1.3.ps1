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


#region Informational

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
# This script DO NOT perform changes in the Intune policies, programs                     #
# nor services of any kind.                                                               #
#                                                                                         #
# Data will be collected for the Support Mission Critial (SMC) Discovery Assessment.      #
# Please ensure to share the ZIP file: SMCIntuneDiscoveryAssessment.zip created at the    #
# of the process using a secure method or workspace.                                      #
#                                                                                         #
# If no Workspace has being shared by the SMC team or CSAM please create a support case.  #
# It will be used only to create the url for this assessment data upload.                 #
#                                                                                         #
###########################################################################################
"@

Write-Host
Write-Host
Write-Host $disclaimer -foregroundColor Yellow
Write-Host 
Write-Host $Purpose -ForegroundColor Cyan
Write-Host 

#endregion

####################################################

#region Prerequisites

<# 
The credential variable is captured to be reused on the services connections during the script execution. 
Will be verified if the modules Intune and AzureAD required are being installed already. 
If the modules are not present it will be attempt to install automatically. 
Connetions to MSgraph and AzureAD are being made. 
#>

$cred = Get-Credential

    #region Intune Module and NuGet povider

        #NuGet package provider. 
        Try 
            {
                Write-Host
                Write-Host "Validating NuGet Package provider status..." -NoNewline

                 $NuGetPackProv = Get-PackageProvider -name nuget
        
                
                if (($NuGetPackProv) -and ($NuGetPackProv.version -ge "2.8.5.201"))
                    {
                        Write-Host " Installed" -foregroundColor Green        
                    }
        
                if (($NuGetPackProv) -and ($NuGetPackProv.version -lt "2.8.5.201"))
                    {
                        Write-Host " Updating" -foregroundColor Green
                        Install-PackageProvider -Name NuGet -Force -Confirm:$false -ForceBootstrap       
                    }
                
                if (-not ($NuGetPackProv))
                    {
                        Write-Host " Installing" -foregroundColor Green
                        Install-PackageProvider -Name NuGet -Force -Confirm:$false -ForceBootstrap      
                    }


             }
    
        Catch 
            {
                Write-host "Error!" -ForegroundColor Red
                Write-host "Nuget Package provider could not be installed" -foregroundColor Red
                $_
                exit
            }
        
        #Intune module. 
        Try 
            {
                Write-Host
                Write-Host "Validating Intune Module status..." -NoNewline

                 $IntuneModule = Get-Module -ListAvailable -Name Microsoft.Graph.Intune
        
                If (-not ($IntuneModule))
                    {
                        Write-Host " Installing" -foregroundColor Green 
                        Install-Module -Name Microsoft.Graph.Intune -Force
     
                    }
        
                if (($IntuneModule) -and ($IntuneModule.version -lt "6.1907.1.0"))
                    {
                        Write-Host " Updating" -foregroundColor Green  
                        Install-Module -Name Microsoft.Graph.Intune -Force
       
                    }
                if (($IntuneModule) -and ($IntuneModule.version -eq "6.1907.1.0"))
                    {
                        Write-Host " Installed" -foregroundColor Green        
                    }
             }
    
        Catch 
            {
                Write-host "Error!" -ForegroundColor Red
                Write-host "Intune module could not be installed" -foregroundColor Red
                $_
                exit
            }

    #endregion Intune Module

    #region MsGraph Connect
        Write-Host
        Write-Host "Connecting to MSgraph..." -NoNewline
        Try 
            {
                $ConnectMSgraph = Connect-MSGraph -Credential $Cred
                
                If ($ConnectMSgraph)
                    {
                        Write-Host " Connected" -foregroundColor Green 
                    }
                Elseif (!($ConnectMSgraph))
                    {
                        Write-Host " Failed" -foregroundColor Red 
                        Write-host "Connection to MS-Graph could not be completed" -foregroundColor Red
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
    #endregion MsGraph Connect 
    
    #region AzureAD Module and connection
        Write-Host
        Write-Host "Validating AzureAD Module status..." -NoNewline
        $AadModule = get-module -ListAvailable | where{$_.name -eq "AzureAD" -or $_.Name -eq "AzureADPreview"}
        
        If ($AadModule.name -contains "AzureAD"-and $AadModule -contains "AzureADPreview") 
            {
                Write-Host " Installed" -foregroundColor Green
            }
        if ($AadModule.name -contains "AzureAD"-and $AadModule -notcontains "AzureADPreview") 
            {
                Write-Host " Installed" -foregroundColor Green
            }
        If ($AadModule.name -notcontains "AzureAD"-and $AadModule -contains "AzureADPreview") 
            {
                Write-Host " Preview Installed" -foregroundColor Green
            }
        
        if ($AadModule.count -eq 0) 
            {
                Write-Host " Installing" -foregroundColor Green
                Try 
                    {
                        $AadModule = Install-Module -Name AzureAD | Out-Null
                        If ($AadModule)
                                {
                                    Wirte-host "Azure AD module was installed" -ForegroundColor Green
                                }
                        
                        ElseIf (-not ($AadModule))
                                {
                                    Write-host "Azure AD module could not be installed" -ForegroundColor Yellow
                                    Write-host "Try a manual installation running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt"
                                    write-host
                                    write-host "NOTE:" -ForegroundColor Yellow
                                    write-host "-----" -ForegroundColor Yellow
                                    write-host "The script could continue, but the groups assigned to Intune objects won't be mapped to AzureAD groups"
                                    write-host "Errors will be observed related to AzureAD, but could be safely ignored"
                                    write-host "If the AzureAD groups name resolution is reelevant please terminate the script and resolve the AzureAd module installation problem"
                                }
                    }
   
                Catch 
                    {
                        Write-host "Error!" -ForegroundColor Red
                        $_
                        exit
                    }  
            }
            

        # AzureAD connection attempted
        Try 
            {
                Connect-AzureAD -Credential $cred | Out-Null
            }

        Catch 
            {
                Write-host "Error!" -ForegroundColor Red
                $_
                exit
            }

    #endregion
    

#endregion Prerequisites

####################################################

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

        $Outfolder = "$outpath\SMC - Intune Discovery Assessment"

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

####################################################

Start-Transcript -Path "$Outfolder\DiscoveryAssesment_Transcript.txt" -append | Out-Null

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

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $Applications = Get-DeviceAppManagement_MobileApps | Get-MSGraphAllPages

            Foreach ($Application in $Applications) 
                {
                    $ApplicationType = $Application.'@odata.type'.split('.')[-1]
                    Write-Output "   Exporting Application: $($Application.displayName) - $ApplicationType"


                    $ApplicationsfileName = ($Application.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $ApplicationDetails = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceAppManagement/mobileApps/$($Application.id)"
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
            
            $ApplicationsAssignments = Get-DeviceAppManagement_MobileApps
            foreach ($ApplicationsAssignment in $ApplicationsAssignments) 
                {
                    $ApplicationAssignmentname = $ApplicationsAssignment.displayName
                    $assignments = Get-DeviceAppManagement_MobileApps_Assignments -MobileAppId $ApplicationsAssignment.id 
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Client App Assignment: $($ApplicationAssignmentname)"
                            $ApplicationsAssignmentfileName = ($ApplicationsAssignment.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\Client Apps\Assignments\$($ApplicationsAssignment.id) - $ApplicationsAssignmentfileName.json"
                            $assignments | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                        $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                        $AssignedAADgroupID = $AssignedAADgroup.objectid
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                        Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                        Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
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

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $AppConfigPolicies = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceAppManagement/mobileAppConfigurations" | Get-MSGraphAllPages

            Foreach ($AppConfigPolicy in $AppConfigPolicies) 
                {
                    Write-Output "   Exporting App Configuration Policy: $($AppConfigPolicy.displayName)"
                    $AppConfigPolicyFilename = ($AppConfigPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AppConfigPolicy | Out-File -LiteralPath "$Outfolder\App Configuration Policy\$AppConfigPolicyFilename.txt"
                    $AppConfigPolicy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\App Configuration Policy\$AppConfigPolicyFilename.json"
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
                    $assignments = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceAppManagement/mobileAppConfigurations/$($AppConfigPolicy.id)/assignments" | Get-MSGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting App Configuration Policy Assignment: $($AppConfigPolicy.displayName)"
                            $AppConfigPolicyAssignFileName = ($AppConfigPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\App Configuration Policy\Assignments\$AppConfigPolicyAssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                        $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                        $AssignedAADgroupID = $AssignedAADgroup.objectid
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                        Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                        Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
                                    }
                                }                    
                        }
                }      

        #endregion

        #region 3. App Protection Policies

            # Policy/Data Export
            
            If (-not (Test-Path "$Outfolder\App Protection Policies")) 
            {
                New-Item -Path "$Outfolder\App Protection Policies" -ItemType Directory | Out-Null
            }

            Write-Host
            Write-host "Collecting Apps Protection policies configurations" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }


            $AppProtectionPolicies = Get-IntuneAppProtectionPolicy | Get-MSGraphAllPages

            foreach ($AppProtectionPolicy in $AppProtectionPolicies) 
            {
                Write-Output "   Exporting App Protection Policy: $($AppProtectionPolicy.displayName)"
                $fileName = ($AppProtectionPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                $AppProtectionPolicy | Out-File -LiteralPath "$Outfolder\App Protection Policies\$fileName.txt"
                $AppProtectionPolicy | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\App Protection Policies\$fileName.json"
            }
           
            # Assignments Export

            if (-not (Test-Path "$Outfolder\App Protection Policies\Assignments")) 
                {
                    New-Item -Path "$Outfolder\App Protection Policies\Assignments" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "   Collecting App Protection Policies assignments" -ForegroundColor Cyan
            
            foreach ($AppProtectionPolicy in $AppProtectionPolicies) 
                {
                    $AppProtectionPoliciesdevicetype = $AppProtectionPolicy."@odata.type"
                    Try
                        {
                            if($AppProtectionPoliciesdevicetype -eq "#microsoft.graph.androidManagedAppProtection")
                                {    
                                    $AppProtectionPolicyURL = "deviceAppManagement/androidManagedAppProtections/$($AppProtectionPolicy.id)/assignments" 
                                }
                    
                            elseif($AppProtectionPoliciesdevicetype -eq "#microsoft.graph.iosManagedAppProtection")
                                {    
                                    $AppProtectionPolicyURL = "deviceAppManagement/iosManagedAppProtections/$($AppProtectionPolicy.id)/assignments"
                                }
                
                            elseif($AppProtectionPoliciesdevicetype -eq "#microsoft.graph.mdmWindowsInformationProtectionPolicy" -or $AppProtectionPoliciesdevicetype -eq "#microsoft.graph.windowsInformationProtectionPolicy")
                                {    
                                    $AppProtectionPolicyURL = "deviceAppManagement/windowsInformationProtectionPolicies/$($AppProtectionPolicy.id)/assignments"
                                }
                        }
            
                    catch 
                        {    
                            $ex = $_.Exception
                            $errorResponse = $ex.Response.GetResponseStream()
                            $reader = New-Object System.IO.StreamReader($errorResponse)
                            $reader.BaseStream.Position = 0
                            $reader.DiscardBufferedData()
                            $responseBody = $reader.ReadToEnd();
                            Write-Host "Response content:`n$responseBody" -f Red
                            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                            write-host
                        }

                    $assignments = Invoke-MSGraphRequest -HttpMethod GET -Url $AppProtectionPolicyURL  | Get-MSGraphAllPages
                    if ($assignments) 
                        {
                            Write-Output "   Exporting App Protection Policy assignment: $($AppProtectionPolicy.displayName)"
                            $AppProtecPolAssigfileName = ($AppProtectionPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\App Protection Policies\Assignments\$($AppProtectionPolicy.id) - $AppProtecPolAssigfileName.json"
                            $assignments | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                        $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                        $AssignedAADgroupID = $AssignedAADgroup.objectid
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                        Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                        Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
                                    }
                                }
                        }
                }

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

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $CompliancePolicies = Get-DeviceManagement_DeviceCompliancePolicies | Get-MSGraphAllPages

            Foreach ($CompliancePolicy in $CompliancePolicies) 
                {
                    Write-Output "   Exporting Compliance Policy: $($CompliancePolicy.displayName)"

                    $fileName = ($CompliancePolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $CompliancePolicy | Out-File -LiteralPath "$Outfolder\Compliance Policies\$fileName.txt"
                    $CompliancePolicy |ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Compliance Policies\$fileName.json"
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
                    $assignments = Get-IntuneDeviceCompliancePolicyAssignment -DeviceCompliancePolicyId $CompliancePolicy.id | Get-MSGraphAllPages
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Compliance Policy assignment: $($CompliancePolicy.displayName)"
                            $AppProtecPolsAssigfileName = ($CompliancePolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\Compliance Policies\Assignments\$($CompliancePolicy.id) - $AppProtecPolsAssigfileName.json"
                            $assignments | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                        $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                        $AssignedAADgroupID = $AssignedAADgroup.objectid
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                        Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                        Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
                                    }
                                }
                        }
                }

        #endregion

        #region 5. Device Configuration Policies

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Device Configurations"))            
                {
                    New-Item -Path "$Outfolder\Device Configurations" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Device Configuration Policies configurations" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }


            $DeviceConfigurations = Get-DeviceManagement_DeviceConfigurations | Get-MSGraphAllPages

            Foreach ($DeviceConfiguration in $DeviceConfigurations) 
                {
                    Write-Output "   Exporting Device Configuration: $($DeviceConfiguration.displayName)"
                    $FileName = ($DeviceConfiguration.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $DeviceConfiguration | Out-File -LiteralPath "$Outfolder\Device Configurations\$fileName.txt"
                    $DeviceConfiguration | ConvertTo-JSON -Depth 3 | Out-File -LiteralPath "$Outfolder\Device Configurations\$fileName.json"
                }

            # Assignments Export

            if (-not (Test-Path "$Outfolder\Device Configurations\Assignments")) 
                {
                    New-Item -Path "$Outfolder\Device Configurations\Assignments" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "   Collecting Device Configuration Policies assignments" -ForegroundColor Cyan

            foreach ($DeviceConfiguration in $DeviceConfigurations) 
                {
                    $assignments = Get-DeviceManagement_DeviceConfigurations_Assignments -DeviceConfigurationId $DeviceConfiguration.id | Get-MSGraphAllPages
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Device Configuration Assignment: $($DeviceConfiguration.displayName)"
                            $DeviceConfigAssignfileName = ($DeviceConfiguration.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\Device Configurations\Assignments\$DeviceConfigAssignfileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                        $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                        $AssignedAADgroupID = $AssignedAADgroup.objectid
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                        Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                        Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
                                    }
                                }
                        }
                }


        #endregion

        #region 6. Windows Scripts

            # Policy/Data Export
             
            If (-not (Test-Path "$Outfolder\Windows Scripts\PS1 Files")) 
                {
                    New-Item -Path "$Outfolder\Windows Scripts\PS1 Files" -ItemType Directory | Out-Null                
                }

            Write-Host
            Write-host "Collecting Windows Scripts configurations" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            If (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }
            
            $WindowsScripts = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/deviceManagementScripts" | Get-MSGraphAllPages

            foreach ($WindowsScript in $WindowsScripts) 
                {
                    Write-Output "   Exporting Windows Script: $($WindowsScript.displayName)"
                    $WindowsScriptPolicy = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/deviceManagementScripts/$($WindowsScript.Id)"
                    $WindowsScriptFileName = ($WindowsScriptPolicy.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $WindowsScriptObject | Out-File -LiteralPath "$Outfolder\Windows Scripts\$WindowsScriptFileName.txt"
                    $WindowsScriptObject | ConvertTo-json -Depth 3 | Out-File -LiteralPath "$Outfolder\Windows Scripts\$WindowsScriptFileName.json"

                    $WindowsScriptPolicyContent = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($WindowsScriptPolicy.scriptContent))
                    $WindowsScriptPolicyContent | Out-File -LiteralPath "$Outfolder\Windows Scripts\PS1 Files\$WindowsScriptFileName.ps1"
                }

            # Assignments Export

            if (-not (Test-Path "$Outfolder\Windows Scripts\Assignments")) 
                {
                    New-Item -Path "$Outfolder\Windows Scripts\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting Windows Scripts Assignments" -ForegroundColor Cyan
            foreach ($WindowsScript in $WindowsScripts) 
                {
                    $assignments = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/deviceManagementScripts/$($WindowsScript.id)/assignments" | Get-MSGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Windows Script Assignment: $($WindowsScript.displayName)"
                            $WindowsScriptAssignFileName = ($WindowsScript.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\Windows Scripts\Assignments\$WindowsScriptAssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                        $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                        $AssignedAADgroupID = $AssignedAADgroup.objectid
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                        Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                        Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
                                    }
                                }
                        }
                }

        #endregion

        #region 7. Device Management Intents 

            # Policy/Data Export

            if (-not (Test-Path "$Outfolder\Device Management Intents")) 
                {
                    New-Item -Path "$Outfolder\Device Management Intents" -ItemType Directory | Out-Null
                }
            
            Write-Host
            Write-host "Collecting Device Management Intents" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }


            $DeviceManagementintents = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/intents" | Get-MSGraphAllPages

            foreach ($DeviceManagementintent in $DeviceManagementintents) 
                {
                    $DeviceManagementintentstemplate = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/templates/$($DeviceManagementintent.templateId)"
                    $DeviceManagementintentstemplateDisplayName = ($DeviceManagementintentstemplate.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'

                    Write-Host "   Exporting Device Management Intent ($($DeviceManagementintentstemplate.displayName)): $($DeviceManagementintent.displayName)"

                    if (-not (Test-Path "$Outfolder\Device Management Intents\$DeviceManagementintentstemplateDisplayName")) 
                        {
                            New-Item -Path "$Outfolder\Device Management Intents\$DeviceManagementintentstemplateDisplayName" -ItemType Directory | Out-Null
                        }

                    Write-Host "   Requesting Template Categories..."
                    $DeviceManagementintentstemplateCategories = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/templates/$($DeviceManagementintent.templateId)/categories" | Get-MSGraphAllPages

                    $DeviceManagementintentSettingsDelta = @()
                    foreach ($DeviceManagementintentstemplateCategory in $DeviceManagementintentstemplateCategories) 
                        {
                            Write-Host "   Requesting Intent Setting Values..."
                            $DeviceManagementintentSettingsDelta += (Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/intents/$($DeviceManagementintent.id)/categories/$($DeviceManagementintentstemplateCategory.id)/settings").value
                        }

                    $intentBackupValue = @{
                                            "displayName" = $DeviceManagementintent.displayName
                                            "description" = $DeviceManagementintent.description
                                            "settingsDelta" = $DeviceManagementintentSettingsDelta
                                            "roleScopeTagIds" = $DeviceManagementintent.roleScopeTagIds
                                          }
        
                    $deviceManagementIntentFileName = ("$($DeviceManagementintentstemplate.displayName)_$($DeviceManagementintent.displayName)").Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $intentBackupValue | Out-File -LiteralPath "$Outfolder\Device Management Intents\$DeviceManagementintentstemplateDisplayName\$deviceManagementIntentFileName.txt"
                    $intentBackupValue | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Device Management Intents\$DeviceManagementintentstemplateDisplayName\$deviceManagementIntentFileName.json"

                }

            # Assignments Export

                if (-not (Test-Path "$Outfolder\Device Management Intents\Assignments")) 
                    {
                        New-Item -Path "$Outfolder\Device Management Intents\Assignments" -ItemType Directory | Out-Null
                    }
                    
                Write-Host
                Write-host "   Collecting Device Management Intents Assignments" -ForegroundColor Cyan
                
                foreach ($DeviceManagementintent in $DeviceManagementintents) 
                    {
                        $assignments = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/intents/$($DeviceManagementintent.id)/assignments" | Get-MSGraphAllPages
                
                        if ($assignments) 
                            {
                                Write-Output "   Exporting Device Management Intent Assignment: $($DeviceManagementintent.displayName)"
                                $DeviceManagementintentAssignFileName = ($DeviceManagementintent.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                                $assignmentspath = "$Outfolder\Device Management Intents\Assignments\$DeviceManagementintentAssignFileName.json"
                                $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                                $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                                $AssignedGroupIDs = $AssignedGroup.groupId
                                foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                    {
                                        If($AssignedGroupID)
                                        {
                                            $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                            $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                            $AssignedAADgroupID = $AssignedAADgroup.objectid
                                            Add-Content -LiteralPath "$assignmentspath" " "
                                            Add-Content -LiteralPath "$assignmentspath" " "
                                            Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                            Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                            Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
                                        }
                                    }
                            }
                    }

        #endregion

        #region 8. Administrative Templates / Group Policies Configurations

            # Policy/Data Export

            if (-not (Test-Path "$Outfolder\Administrative Templates")) 
                {
                    New-Item -Path "$Outfolder\Administrative Templates" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Administrative templates" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }
            $GroupPolicyConfigs = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/GroupPolicyConfigurations" | Get-MSGraphAllPages

            foreach ($GroupPolicyConfig in $GroupPolicyConfigs) 
                {
                    $GroupPolicyDefinitionValues = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfig.id)/definitionValues" | Get-MSGraphAllPages
                    $GroupPolicyBackupValues = @()

                        foreach ($GroupPolicyDefinitionValue in $GroupPolicyDefinitionValues) 
                            {
                                $GroupPolicyDefinition = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfig.id)/definitionValues/$($GroupPolicyDefinitionValue.id)/definition"
                                $GroupPolicyPresentationValues = (Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfig.id)/definitionValues/$($GroupPolicyDefinitionValue.id)/presentationValues?`$expand=presentation").Value
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
                    $GroupPolicyBackupValues | Out-File -LiteralPath "$Outfolder\Administrative Templates\$GroupPolicyAdmTemplatefileName.txt"
                    $GroupPolicyBackupValues | Convertto-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Administrative Templates\$GroupPolicyAdmTemplatefileName.json"
                }

            # Assignments Export
 
            if (-not (Test-Path "$Outfolder\Administrative Templates\Assignments")) 
                {
                    New-Item -Path "$Outfolder\Administrative Templates\Assignments" -ItemType Directory | Out-Null
                }
                    
            Write-Host
            Write-host "   Collecting Administrative Templates Assignments" -ForegroundColor Cyan
            

            foreach ($GroupPolicyConfig in $GroupPolicyConfigs) 
                {
                    $assignments = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/GroupPolicyConfigurations/$($GroupPolicyConfig.id)/assignments" | Get-MSGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Device Management Intent Assignment: $($GroupPolicyConfig.displayName)"
                            $GroupPolicyConfigAssignFileName = ($GroupPolicyConfig.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\Administrative Templates\Assignments\$GroupPolicyConfigAssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                        $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                        $AssignedAADgroupID = $AssignedAADgroup.objectid
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                        Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                        Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
                                    }
                                }
                        }
                }            

        #endregion
 
        #region 9. Autopilot Deployment Profiles

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Autopilot Deployment Profiles"))            
                {
                    New-Item -Path "$Outfolder\Autopilot Deployment Profiles" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Autopilot Deployment Profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }


            $APDeploymentProfiles = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/windowsAutopilotDeploymentProfiles" | Get-MSGraphAllPages

            Foreach ($APDeploymentProfile in $APDeploymentProfiles) 
                {
                    Write-Output "   Exporting Autopilot Deployment Profile: $($APDeploymentProfile.displayName)"
                    $APDeploymentProfileFilename = ($APDeploymentProfile.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $APDeploymentProfile | Out-File -LiteralPath "$Outfolder\Autopilot Deployment Profiles\$APDeploymentProfileFilename.txt"
                    $APDeploymentProfile | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Autopilot Deployment Profiles\$APDeploymentProfileFilename.json"
                }

            # Assignments Export

            if (-not (Test-Path "$Outfolder\Autopilot Deployment Profiles\Assignments")) 
                {
                    New-Item -Path "$Outfolder\Autopilot Deployment Profiles\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting Autopilot Deployment Profiles Assignments" -ForegroundColor Cyan
            

            foreach ($APDeploymentProfile in $APDeploymentProfiles) 
                {
                    $assignments = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/windowsAutopilotDeploymentProfiles/$($APDeploymentProfile.id)/assignments" | Get-MSGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Autopilot Deployment Profile Assignment: $($APDeploymentProfile.displayName)"
                            $APDeploymentProfileAssignFileName = ($APDeploymentProfile.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\Autopilot Deployment Profiles\Assignments\$APDeploymentProfileAssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                        $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                        $AssignedAADgroupID = $AssignedAADgroup.objectid
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                        Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                        Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
                                    }
                                }
                        }
                }       

        #endregion

        #region 10. Device Enrollment Configurations (Device restrictions / Device Limit / Autopilot ESP / WHfB)

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Device Enrollment Configurations"))            
                {
                    New-Item -Path "$Outfolder\Device Enrollment Configurations" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Device Enrollment Configurations" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $DeviceEnrollConfigs =  Get-IntuneDeviceEnrollmentConfiguration | Get-MSGraphAllPages

            Foreach ($DeviceEnrollConfig in $DeviceEnrollConfigs) 
                {
                    Write-Output "   Exporting Device Enrollent Configuration: $($DeviceEnrollConfig.displayName)"
                    $DeviceEnrollConfigFilename = ($DeviceEnrollConfig.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $DeviceEnrollConfig | Out-File -LiteralPath "$Outfolder\Device Enrollment Configurations\$DeviceEnrollConfigFilename.txt"
                    $DeviceEnrollConfig | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Device Enrollment Configurations\$DeviceEnrollConfigFilename.json"
                }

            # Assignments Export

            if (-not (Test-Path "$Outfolder\Device Enrollment Configurations\Assignments")) 
                {
                    New-Item -Path "$Outfolder\Device Enrollment Configurations\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting Device Enrollment Configurations Assignments" -ForegroundColor Cyan
           

            Foreach ($DeviceEnrollConfig in $DeviceEnrollConfigs)  
                {
                    $assignments = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/deviceEnrollmentConfigurations/$($DeviceEnrollConfig.id)/assignments" | Get-MSGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Device Enrollment Configuration Assignment: $($DeviceEnrollConfig.displayName)"
                            $APDeploymentProfilesAssignFileName = ($DeviceEnrollConfig.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\Device Enrollment Configurations\Assignments\$APDeploymentProfilesAssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                        $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                        $AssignedAADgroupID = $AssignedAADgroup.objectid
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                        Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                        Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
                                    }
                                }
                        }
                }  
            
        #endregion
                
        #region 11. APN Certificate
 
            # Policy/Data Export
                     
            If (-not (Test-Path "$Outfolder\Apple Push Notitication Certificate"))            
                {
                    New-Item -Path "$Outfolder\Apple Push Notitication Certificate" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Apple Push Notification Certificate " -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

                $APNCerts =  Get-IntuneApplePushNotificationCertificate

            Foreach ($APNCert in $APNCerts) 
                {
                    Write-Output "   Exporting Apple Push Notification Certificate: $($APNCert.topicIdentifier)"
                    $APNCertFilename = ($APNCert.topicIdentifier).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $APNCert | Out-File -LiteralPath "$Outfolder\Apple Push Notitication Certificate\$APNCertFilename.txt"
                    $APNCert | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Apple Push Notitication Certificate\$APNCertFilename.txt"
                }
          
        #endregion

        #region 12. Apple User Enrollment Profiles.

            # Policy/Data Export
                     
            If (-not (Test-Path "$Outfolder\Apple User Enrollment Profile"))            
                {
                    New-Item -Path "$Outfolder\Apple User Enrollment Profile" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Apple User Enrollment Profiles " -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1
            $AppleUsrEnrollProfiles =  Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/appleUserInitiatedEnrollmentProfiles" | Get-MSGraphAllPages

            Foreach ($AppleUsrEnrollProfile in $AppleUsrEnrollProfiles) 
                {
                    Write-Output "   Exporting Apple User Enrollment Profile: $($AppleUsrEnrollProfile.displayName)"
                    $AppleUsrEnrollProfileFilename = ($AppleUsrEnrollProfile.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AppleUsrEnrollProfile | Out-File -LiteralPath "$Outfolder\Apple User Enrollment Profile\$AppleUsrEnrollProfileFilename.txt"
                    $AppleUsrEnrollProfile | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Apple User Enrollment Profile\$AppleUsrEnrollProfileFilename.json"
                }
            
        #endregion

        #region 13. Apple DEP Profiles

            # Policy/Data Export

            if (-not (Test-Path "$Outfolder\Apple DEP")) 
                {
                    New-Item -Path "$Outfolder\Apple DEP" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Apple DEP Profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }
            $AppleDEPs = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/depOnboardingSettings" | Get-MSGraphAllPages

            foreach ($AppleDEP in $AppleDEPs) 
                {
                    Write-Host "   Exporting Apple DEP Profile: $($AppleDEP.displayName)"
                    $AppleDEPfileName = ($AppleDEP.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AppleDEP | Out-File -LiteralPath "$Outfolder\Apple DEP\$AppleDEPfileName.txt"
                    $AppleDEPEnrollmentProfiles = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/depOnboardingSettings/$($AppleDEP.id)/enrollmentProfiles" | Get-MSGraphAllPages

                        foreach ($AppleDEPEnrollmentProfile in $AppleDEPEnrollmentProfiles) 
                            {
                            if (-not (Test-Path "$Outfolder\Apple DEP\Enrollment Profiles")) 
                                {
                                    New-Item -Path "$Outfolder\Apple DEP\Enrollment Profiles" -ItemType Directory | Out-Null
                                }
                                Write-Host "   Exporting Apple DEP Enrollment Profile: $($AppleDEPEnrollmentProfile.displayName)"
                                $AppleDEPEnrollmentProfilefileName = ($AppleDEPEnrollmentProfile.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                                $AppleDEPEnrollmentProfile | Out-File -LiteralPath "$Outfolder\Apple DEP\Enrollment Profiles\$AppleDEPEnrollmentProfilefileName.txt"
                                $AppleDEPEnrollmentProfile | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Apple DEP\Enrollment Profiles\$AppleDEPEnrollmentProfilefileName.json"
                            }
                }
        
        #endregion
    
        #region 14. Apple VPP Token

            # Policy/Data Export
                        
            If (-not (Test-Path "$Outfolder\Apple VPP Token"))            
                {
                    New-Item -Path "$Outfolder\Apple VPP Token" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Apple VPP Tokens" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }


            $AppleVPPTokens = Get-IntuneVppToken

            Foreach ($AppleVPPToken in $AppleVPPTokens) 
                {
                    Write-Output "   Exporting Apple VPP Token: $($AppleVPPToken.displayName)"
                    $AppleVPPTokenFilename = ($AppleVPPToken.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AppleVPPToken | Out-File -LiteralPath "$Outfolder\Apple VPP Token\$AppleVPPTokenFilename.txt"
                    $AppleVPPToken | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Apple VPP Token\$AppleVPPTokenFilename.Json"
                }

        #endregion

        #region 15. Android Managed Store Account Enterprise Settings

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Android Managed Store Account Enterprise"))            
                {
                    New-Item -Path "$Outfolder\Android Managed Store Account Enterprise" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Android Managed Store Account Enterprise" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }


            $AndroidManagedStoreAccounts = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/androidManagedStoreAccountEnterpriseSettings" #| Get-MSGraphAllPages

            Foreach ($AndroidManagedStoreAccount in $AndroidManagedStoreAccounts) 
                {
                    Write-Output "   Exporting Android Managed Store Account Enterprise Setting: $($AndroidManagedStoreAccount.ownerOrganizationName)"
                    $AndroidManagedStoreAccountFilename = ($AndroidManagedStoreAccount.ownerOrganizationName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AndroidManagedStoreAccount | Out-File -LiteralPath "$Outfolder\Android Managed Store Account Enterprise\$AndroidManagedStoreAccountFilename.txt"
                    $AndroidManagedStoreAccount | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Android Managed Store Account Enterprise\$AndroidManagedStoreAccountFilename.Json"
                }

        #endregion

        #region 16. Android Corporate-Owned profiles (Corp Owned & AFW)

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Android Corporate-Owned profiles"))            
                {
                    New-Item -Path "$Outfolder\Android Corporate-Owned profiles" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Android Corporate-Owned profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $AndroidCorpOwnPofiles = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/androidDeviceOwnerEnrollmentProfiles" | Get-MSGraphAllPages

            Foreach ($AndroidCorpOwnPofile in $AndroidCorpOwnPofiles) 
                {
                    Write-Output "   Exporting Android Corporate-Owned profile: $($AndroidCorpOwnPofile.displayName)"
                    $AndroidCorpOwnPofileFilename = ($AndroidCorpOwnPofile.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AndroidCorpOwnPofile | Out-File -LiteralPath "$Outfolder\Android Corporate-Owned profiles\$AndroidCorpOwnPofileFilename.txt"
                    $AndroidCorpOwnPofile | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Android Corporate-Owned profiles\$AndroidCorpOwnPofileFilename.json"
                    
                }

        #endregion

        #region 17. Android for Work profiles

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Android for Work profiles"))            
                {
                    New-Item -Path "$Outfolder\Android for Work profiles" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Android for Work profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $AFWPofiles = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/androidForWorkEnrollmentProfiles" | Get-MSGraphAllPages

            Foreach ($AFWPofile in $AFWPofiles) 
                {
                    Write-Output "   Exporting Android for Work profile: $($AFWPofile.displayName)"
                    $AFWPofileFilename = ($AFWPofile.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AFWPofile | Out-File -LiteralPath "$Outfolder\Android for Work profiles\$AFWPofileFilename.txt"
                    $AFWPofile | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Android for Work profiles\$AFWPofileFilename.json"
                }

        #endregion

        #region 18. Android for work settings 

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Android for work settings"))            
                {
                    New-Item -Path "$Outfolder\Android for work settings" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Android for work settings" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $AFWSettings = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/androidForWorkSettings" | Get-MSGraphAllPages

            Foreach ($AFWSetting in $AFWSettings) 
                {
                Write-Output "   Exporting Android for work setting: $($AFWSetting.displayName)"
                    $AFWSettingFilename = ($AFWSetting.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $AFWSetting | Out-File -LiteralPath "$Outfolder\Android for work settings\$AFWSettingFilename.txt"
                    $AFWSetting | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Android for work settings\$AFWSettingFilename.json"
                }

        #endregion        

        #region 19. Assignment Filters - TEMP

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Filters"))            
                {
                    New-Item -Path "$Outfolder\Filters" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Filters" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $Filters = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/assignmentFilters" | Get-MSGraphAllPages

            Foreach ($Filter in $Filters) 
                {
                Write-Output "   Exporting Filter: $($Filter.displayName)"
                    $FilterFilename = ($Filter.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $Filter | Out-File -LiteralPath "$Outfolder\Filters\$FilterFilename.txt"
                    $Filter | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Filters\$FilterFilename.json"
                }

        #endregion 

        #region 20. Device Categories - TEMP

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Device Categories"))            
                {
                    New-Item -Path "$Outfolder\Device Categories" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Device Categories" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $DevCats = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/deviceCategories" | Get-MSGraphAllPages

            Foreach ($DevCat in $DevCats) 
                {
                Write-Output "   Exporting Device Categorie: $($DevCat.displayName)"
                    $DevCatFilename = ($DevCat.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $DevCat | Out-File -LiteralPath "$Outfolder\Device Categories\$DevCatFilename.txt"
                    $DevCat | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Device Categories\$DevCatFilename.json"
                }

        #endregion 

        #region 21. Domain Join Connectors - TEMP

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Domain Join Connectors"))            
                {
                    New-Item -Path "$Outfolder\Domain Join Connectors" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Domain Join Connectors" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $DomJoinConnectors = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/domainJoinConnectors" | Get-MSGraphAllPages

            Foreach ($DomJoinConnector in $DomJoinConnectors) 
                {
                Write-Output "   Exporting Domain Join Connector: $($DomJoinConnector.displayName)"
                    $DomJoinConnectorFilename = ($DomJoinConnector.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $DomJoinConnector | Out-File -LiteralPath "$Outfolder\Domain Join Connectors\$DomJoinConnectorFilename.txt"
                    $DomJoinConnector | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Domain Join Connectors\$DomJoinConnectorFilename.json"
                }

        #endregion

        #region 22. Microsoft Tunnel Configurations - TEMP

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Microsoft Tunnel\Configurations"))            
                {
                    New-Item -Path "$Outfolder\Microsoft Tunnel\Configurations" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Microsoft Tunnel Configurations" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $MsftTunnelConfigs = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/microsoftTunnelConfigurations" | Get-MSGraphAllPages

            Foreach ($MsftTunnelConfig in $MsftTunnelConfigs) 
                {
                Write-Output "   Exporting Microsoft Tunnel Configuration: $($MsftTunnelConfig.displayName)"
                    $MsftTunnelConfigFilename = ($MsftTunnelConfig.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $MsftTunnelConfig | Out-File -LiteralPath "$Outfolder\Microsoft Tunnel\Configurations\$MsftTunnelConfigFilename.txt"
                    $MsftTunnelConfig | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Microsoft Tunnel\Configurations\$MsftTunnelConfigFilename.json"
                }


        #endregion

        #region 23. Microsoft Tunnel Sites - TEMP

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Microsoft Tunnel\Sites"))            
                {
                    New-Item -Path "$Outfolder\Microsoft Tunnel\Sites" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Microsoft Tunnel Sites" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $MsftTunnelsites = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/microsoftTunnelSites" | Get-MSGraphAllPages

            Foreach ($MsftTunnelsite in $MsftTunnelsites) 
                {
                Write-Output "   Exporting Microsoft Tunnel Site: $($MsftTunnelsite.displayName)"
                    $MsftTunnelsiteFilename = ($MsftTunnelsite.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $MsftTunnelsite | Out-File -LiteralPath "$Outfolder\Microsoft Tunnel\Sites\$MsftTunnelsiteFilename.txt"
                    $MsftTunnelsite | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Microsoft Tunnel\Sites\$MsftTunnelsiteFilename.json"
                }

        #endregion

        #region 24. NDES Connectors - TEMP

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\NDESConnectors"))            
                {
                    New-Item -Path "$Outfolder\NDESConnectors" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting NDES Connectors" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }

            $NDESConnectors = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/NDESConnectors" | Get-MSGraphAllPages

            Foreach ($NDESConnector in $NDESConnectors) 
                {
                Write-Output "   Exporting NDES Connector: $($NDESConnector.displayName)"
                    $NDESConnectorFilename = ($NDESConnector.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $NDESConnector | Out-File -LiteralPath "$Outfolder\NDESConnectors\$NDESConnectorFilename.txt"
                    $NDESConnector | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\NDESConnectors\$NDESConnectorFilename.json"
                }

        #endregion

        #region 25. Windows Feature Update Profiles - TEMP

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Windows Update\Feature Update"))            
                {
                    New-Item -Path "$Outfolder\Windows Update\Feature Update" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Windows Feature Update Profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }


            $FeatureUpdateProfiles = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/windowsFeatureUpdateProfiles" | Get-MSGraphAllPages

            Foreach ($FeatureUpdateProfile in $FeatureUpdateProfiles) 
                {
                    Write-Output "   Exporting Windows Feature Update Profile: $($FeatureUpdateProfile.displayName)"
                    $FeatureUpdateProfileFilename = ($FeatureUpdateProfile.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $FeatureUpdateProfile | Out-File -LiteralPath "$Outfolder\Windows Update\Feature Update\$FeatureUpdateProfileFilename.txt"
                    $FeatureUpdateProfile | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Windows Update\Feature Update\$FeatureUpdateProfileFilename.json"
                }

            # Assignments Export

            if (-not (Test-Path "$Outfolder\Windows Update\Feature Update\Assignments")) 
                {
                    New-Item -Path "$Outfolder\Windows Update\Feature Update\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting Windows Feature Update Profiles Assignments" -ForegroundColor Cyan
            

            foreach ($FeatureUpdateProfile in $FeatureUpdateProfiles) 
                {
                    $assignments = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/windowsFeatureUpdateProfiles/$($FeatureUpdateProfile.id)/assignments" | Get-MSGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Windows Feature Update Profile Assignment: $($FeatureUpdateProfile.displayName)"
                            $FeatureUpdateProfileAssignFileName = ($FeatureUpdateProfile.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\Windows Update\Feature Update\Assignments\$FeatureUpdateProfileAssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                        $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                        $AssignedAADgroupID = $AssignedAADgroup.objectid
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                        Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                        Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
                                    }
                                }
                        }
                }       

        #endregion

################################################################################################
        #region 26. Windows Drive Update Profiles - TEMP

# This is pending... I am getting a permissions error on Graph Explorer and permissions looks fine
#Forbidden - 403 - 672ms. You need to consent to the permissions on the Modify permissions (Preview) tab
#I will try later.... 

        #endregion
################################################################################################
        #region 27. Windows Quality Update Profiles - TEMP

            # Policy/Data Export

            If (-not (Test-Path "$Outfolder\Windows Update\Quality Update"))            
                {
                    New-Item -Path "$Outfolder\Windows Update\Quality Update" -ItemType Directory | Out-Null
                }

            Write-Host
            Write-host "Collecting Windows Quality Update Profiles" -ForegroundColor Green
            Write-host "*******************************************************"
            Write-host
            Start-Sleep -Seconds 1

            $ApiVersion = "Beta"
            if (-not ((Get-MSGraphEnvironment).SchemaVersion -eq $apiVersion)) 
                {
                    Update-MSGraphEnvironment -SchemaVersion $apiVersion -Quiet
                    Connect-MSGraph -ForceNonInteractive -Quiet
                }


            $QualityUpdateProfiles = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/windowsQualityUpdateProfiles" | Get-MSGraphAllPages

            Foreach ($QualityUpdateProfile in $QualityUpdateProfiles) 
                {
                    Write-Output "   Exporting Windows Quality Update Profile: $($QualityUpdateProfile.displayName)"
                    $QualityUpdateProfileFilename = ($QualityUpdateProfile.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                    $QualityUpdateProfile | Out-File -LiteralPath "$Outfolder\Windows Update\Quality Update\$QualityUpdateProfileFilename.txt"
                    $QualityUpdateProfile | ConvertTo-Json -Depth 3 | Out-File -LiteralPath "$Outfolder\Windows Update\Quality Update\$QualityUpdateProfileFilename.json"
                }

            # Assignments Export

            if (-not (Test-Path "$Outfolder\Windows Update\Quality Update\Assignments")) 
                {
                    New-Item -Path "$Outfolder\Windows Update\Quality Update\Assignments" -ItemType Directory | Out-Null
                }
                
            Write-Host
            Write-host "   Collecting Windows Quality Update Profiles Assignments" -ForegroundColor Cyan
            

            foreach ($QualityUpdateProfile in $QualityUpdateProfiles) 
                {
                    $assignments = Invoke-MSGraphRequest -HttpMethod GET -Url "deviceManagement/windowsQualityUpdateProfiles/$($QualityUpdateProfile.id)/assignments" | Get-MSGraphAllPages
            
                    if ($assignments) 
                        {
                            Write-Output "   Exporting Windows Quality Update Profile Assignment: $($QualityUpdateProfile.displayName)"
                            $QualityUpdateProfileAssignFileName = ($QualityUpdateProfile.displayName).Split([IO.Path]::GetInvalidFileNameChars()) -join '_'
                            $assignmentspath = "$Outfolder\Windows Update\Quality Update\Assignments\$QualityUpdateProfileAssignFileName.json"
                            $assignments | ConvertTo-Json | Out-File -LiteralPath "$assignmentspath"

                            $AssignedGroup = $assignments | Select-Object -ExpandProperty target -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                            $AssignedGroupIDs = $AssignedGroup.groupId
                            foreach ($AssignedGroupID in $AssignedGroupIDs) 
                                {
                                    If($AssignedGroupID)
                                    {
                                        $AssignedAADgroup = Get-AzureADGroup -ObjectId $AssignedGroupID
                                        $AssignedAADgroupName = $AssignedAADgroup.DisplayName
                                        $AssignedAADgroupID = $AssignedAADgroup.objectid
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" " "
                                        Add-Content -LiteralPath "$assignmentspath" "Group Name   Group ID"
                                        Add-Content -LiteralPath "$assignmentspath" "----------   --------"
                                        Add-Content -LiteralPath "$assignmentspath" "$AssignedAADgroupName   $AssignedAADgroupID"  
                                    }
                                }
                        }
                }       


        #endregion


#endregion Data Collection 

####################################################

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
Start-Sleep -Seconds 1
Write-Host "Script terminated" -ForegroundColor Yellow
Start-Sleep -Seconds 1
Write-Host

Stop-Transcript | Out-Null

exit
# SIG # Begin signature block
# MIInsgYJKoZIhvcNAQcCoIInozCCJ58CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDNJZEbt+nyVAWg
# n9aak+pkxmfLEcMvSXP5u+ttrclHDKCCDYUwggYDMIID66ADAgECAhMzAAACU+OD
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
# cVZOSEXAQsmbdlsKgEhr/Xmfwb1tbWrJUnMTDXpQzTGCGYMwghl/AgEBMIGVMH4x
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01p
# Y3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTECEzMAAAJT44Pelt7FbswAAAAA
# AlMwDQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQw
# HAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIIZa
# vghN0lZv9SAmskcLmsqJ0q9iQcQ9LieWyCPghbisMEQGCisGAQQBgjcCAQwxNjA0
# oBSAEgBNAGkAYwByAG8AcwBvAGYAdKEcgBpodHRwczovL3d3dy5taWNyb3NvZnQu
# Y29tIDANBgkqhkiG9w0BAQEFAASCAQChflMcMAxGFEv4BaeXsDxxLhCGQGGr+vzk
# KVuIq84+J1UYc/wDoHXyw/aMghydN7CMxQPyCa1SNaOjL7bZQrb9JF2EwOAMfusP
# OwBcNFAjDXDBQWtY0noAjEPxFwxRJYT5FT8IwjJpMIzTv79cd4uQ6VNagSzoaMi7
# gl3s+IUJUutjwfsoZjtGa+EQKHaY5q6oS4DMz6IFYlqfsnVCorN+D35AcPi9DeHJ
# v/SX08LyYvNQ72LluBpHPE/zUz70rQwSf/2AVAI/6XD3RpVavFXLkC/mJOzF0z9v
# 2ATgr3wmry7uTiqRuESA0MJtur+2kJJdJmCe5DDDs/9MLKcM7gf5oYIXCzCCFwcG
# CisGAQQBgjcDAwExghb3MIIW8wYJKoZIhvcNAQcCoIIW5DCCFuACAQMxDzANBglg
# hkgBZQMEAgEFADCCAVQGCyqGSIb3DQEJEAEEoIIBQwSCAT8wggE7AgEBBgorBgEE
# AYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIFaSxk3h23LrYZ7IikHdw5S9UC5HCcNu
# vfokEq60Ff3xAgZia0rFQJ8YEjIwMjIwNTE2MjEyNTI5LjIxWjAEgAIB9KCB1KSB
# 0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UE
# CxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRo
# YWxlcyBUU1MgRVNOOjYwQkMtRTM4My0yNjM1MSUwIwYDVQQDExxNaWNyb3NvZnQg
# VGltZS1TdGFtcCBTZXJ2aWNloIIRXzCCBxAwggT4oAMCAQICEzMAAAGmWUWDOU2e
# 60sAAQAAAaYwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTAwHhcNMjIwMzAyMTg1MTIxWhcNMjMwNTExMTg1MTIxWjCBzjELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0
# IE9wZXJhdGlvbnMgUHVlcnRvIFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNO
# OjYwQkMtRTM4My0yNjM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBT
# ZXJ2aWNlMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA2Zi/e1Ij58n8
# 1AmePPsm8Kdz5ebSsqh71goPgy8xgK6Xt6B2tP/O/m8VtCCM1DvjrvZ83B5rO2RH
# rlXzLb27k8vax/TWn65yF7Rm7i1KKD4axDplCX22M9EBj/chMEcN4hjK+rxad737
# s2g8uHENI7p21ftgK5DjNxM/dIToy8Hhvk2KCF22+hlVpiTWVemNRN92YqhfUAGr
# WwltQtKdKLRB3i++XeZn2PHC/11H+eVk/raWtlhmrss+0cPoGWZyUHk9Pz0OdKbW
# yNpmcUesrM6yarkaWYvlIW6AIJk6grPXfcUl5BoUxxcFlIJCM0AFYFschEITXKwc
# cbzcN2idGacLwQ6Vh5HBNbP9ALPqrSuI4htjIL8DYGBQSm73/0TKatOzIyvb/NLw
# Z0TJtDlbt/RatyuYoH9jrb6DpOZ85Lw21T4vWMago0bpDlGV8nBm7wn9D12Xg7HI
# cq7Lvz7CboewXu4CLOmxaHrdRRqgr84ZCIEbc0n6R5/l5ame9rhkl+ECephMBkPW
# 4eB/xV9COeXQEHZhfMr1ZpOp17x37yoLFUqvmEli9s75ff7aTk8KKtQr9Juit5f7
# FSFVpASFUNiqVq3I+20jtnYiuSEzPAW9z6nRB7IyI2ajZwFl6PHyJwM5xSJ3DKYN
# RioY8TswDy+0pbd955JJgmwISS5Q7+8CAwEAAaOCATYwggEyMB0GA1UdDgQWBBQ6
# VCE7/MaWor31SQ0v8a78CvI32DAfBgNVHSMEGDAWgBSfpxVdAF5iXYP05dJlpxtT
# NRnpcjBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20v
# cGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgx
# KS5jcmwwbAYIKwYBBQUHAQEEYDBeMFwGCCsGAQUFBzAChlBodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAl
# MjBQQ0ElMjAyMDEwKDEpLmNydDAMBgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsG
# AQUFBwMIMA0GCSqGSIb3DQEBCwUAA4ICAQCAwPFYNOkaoucWg+Gb+IN/AcYXzGvY
# 1usmXx6ASDZOFMmxN/TAET5lCydh+tGZcFt7qwJctU3vSo+4j44Rs3kw5qLsG57X
# /iPlVORaq4fkZl5Vq3Y350PuVJRanR1TyP64GEEvkYVKagNVWb7NbYZHaO48jW/b
# ngAlNvaXjnxqeWQmMa+ZifYG1FLXeH/ANHuGtBojsGB3IdYBXn4cSPlSGsiuu+3A
# mKK9JpQQDeorpkr+tkhC/+45EOQ43D7akccgTVJeb9YiWGtVLYciiB+vcmOq9mKi
# foslIPvjWPzFUMuIKXABuykehUWPG3EFwyOo/HppYIlLy+NKhOeGRXg87nmaqwzt
# DxdBEZCEDvDjM1A4m72QPjEV1ik9SYs391ohwQSWh8GMbP6wR3UHjKqoiTe7YbhX
# KBNcWa2EvxyFKjuv4Yi9OpYqFID+xqdLg3eMKAIJ7cVNImyniDmfBq8u9YC3Nw4i
# 9JGisaYB43SbbCDMEr3lP+qCsYYNdKizUk0NZFUGc/SqzDVCirkbQPyHG9A+zdfj
# coG/UYmXTCjmtwL704xbEmUHreC1OhCwDUIStihgsxm1TMkvviPBmT+CukcRCEiE
# Heyd4LzDMYom5+3tg78dYKm7B0KEiPKdOcGH7IUYx2DfBGshs5zD+IqZdmikxNAw
# 5yYh4jAkB7MDsDCCB3EwggVZoAMCAQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJ
# KoZIhvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xMjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0
# eSAyMDEwMB4XDTIxMDkzMDE4MjIyNVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQDk4aZM57RyIQt5osvXJHm9DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25
# PhdgM/9cT8dm95VTcVrifkpa/rg2Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsH
# FPPFdvWGUNzBRMhxXFExN6AKOG6N7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTa
# mDu6GnszrYBbfowQHJ1S/rboYiXcag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc
# 6XBpDco2LXCOMcg1KL3jtIckw+DJj361VI/c+gVVmG1oO5pGve2krnopN6zL64NF
# 50ZuyjLVwIYwXE8s4mKyzbnijYjklqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpG
# dc3EXzTdEonW/aUgfX782Z5F37ZyL9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOm
# TTd0lBw0gg/wEPK3Rxjtp+iZfD9M269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi
# 0b1qGFphAXPKZ6Je1yh2AuIzGHLXpyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU
# 2LlQ+QuJYfM2BjUYhEfb3BvR/bLUHMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSF
# F5PAPBXbGjfHCBUYP3irRbb1Hode2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCC
# AdkwEgYJKwYBBAGCNxUBBAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6C
# kTxGNSnPEP8vBO4wHQYDVR0OBBYEFJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1Ud
# IARVMFMwUQYMKwYBBAGCN0yDfQEBMEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvRG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUE
# DDAKBggrBgEFBQcDCDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8E
# BAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2U
# kFvXzpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5j
# b20vcGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmww
# WgYIKwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29m
# dC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkq
# hkiG9w0BAQsFAAOCAgEAnVV9/Cqt4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaT
# lz0xM7U518JxNj/aZGx80HU5bbsPMeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYu
# nKmCVgADsAW+iehp4LoJ7nvfam++Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f
# 8449xvNo32X2pFaq95W2KFUn0CS9QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVC
# s/wMnosZiefwC2qBwoEZQhlSdYo2wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzs
# kYDSPeZKPmY7T7uG+jIa2Zb0j/aRAfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzH
# VG2dY3RILLFORy3BFARxv2T5JL5zbcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+k
# KNxnGSgkujhLmm77IVRrakURR6nxt67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+
# CrvsQWY9af3LwUFJfn6Tvsv4O+S3Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAo
# GokLjzbaukz5m/8K6TT4JDVnK+ANuOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEz
# fbzL6Xu/OHBE0ZDxyKs6ijoIYn/ZcGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKh
# ggLSMIICOwIBATCB/KGB1KSB0TCBzjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldh
# c2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBD
# b3Jwb3JhdGlvbjEpMCcGA1UECxMgTWljcm9zb2Z0IE9wZXJhdGlvbnMgUHVlcnRv
# IFJpY28xJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjYwQkMtRTM4My0yNjM1MSUw
# IwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4D
# AhoDFQBqdDOtlb1MH3dV7s9rhQ9qjZ98raCBgzCBgKR+MHwxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFBDQSAyMDEwMA0GCSqGSIb3DQEBBQUAAgUA5izavjAiGA8yMDIyMDUx
# NjE4MTQyMloYDzIwMjIwNTE3MTgxNDIyWjB3MD0GCisGAQQBhFkKBAExLzAtMAoC
# BQDmLNq+AgEAMAoCAQACAiL9AgH/MAcCAQACAhEnMAoCBQDmLiw+AgEAMDYGCisG
# AQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMB
# hqAwDQYJKoZIhvcNAQEFBQADgYEABU8RQqLhRuUO9UgSjGbP94k+PZNV06H/vt+6
# bsLV1IDoroY++FHwTx0ek4Rkx7gGXhKqg/wQDOmeM1WIe8gOk8hQ9ZdozGxn+HIx
# RsX+/cgKa7e0m1g+JKBfFUFZZHsOjG/hOL8v/wh0+yRGB8qjbcJgDNfhYN/Ys8zF
# VepBHzwxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAx
# MAITMwAAAaZZRYM5TZ7rSwABAAABpjANBglghkgBZQMEAgEFAKCCAUowGgYJKoZI
# hvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCCetAWn3cLTJ+g+
# EgmyYYWR5yusIH+ySZSbt1ylhp1sGzCB+gYLKoZIhvcNAQkQAi8xgeowgecwgeQw
# gb0EIIMLGYvDP3R9a+EwpslMBBoq3cOhd6ICF+nxMP22BKsNMIGYMIGApH4wfDEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWlj
# cm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAGmWUWDOU2e60sAAQAAAaYw
# IgQgIlqK2W22VjRTrxrLwnw9zfr/LICawySxy32imicaMFkwDQYJKoZIhvcNAQEL
# BQAEggIAVXMvOidWdQae56qlP2VuqvDo1gY3hdcXJuudKrpFerlAjofQ3VkskGgg
# yfahgPZgfanPsy4CwF/CvDqHUIcLEjuP2DZNZpcZkw8G0TtRAMjlNXFVR22sAMZS
# uYKUS0io2cWWvcsM0FJcAsfeZpSw9R3VWyzxaIhrkTXPNMJ5MZVg3JSnnbafAXhM
# 7Z784XIt8lg6Ydk8sLm1dafX9zdQRbwCEKSLkgqIIy6ygMZpnAH8gQzmXokQ0isB
# iX4R2VTHvWplLUJJBEe94CijVKlT7j0tZidYQeyNIbrWNWaUqAn+i2yRVg93WqpD
# SO9sAp0hMSy8KPI3Zcy/GSe+E/zMoBspn0GrNwKJpzeNfkSh4e+DN2YPL29/mn12
# 5vQhar4j1bHTkEO9XlkfAEjxVufOW1tt/rqgXmnEzq7zgPCeYIwyewcvEqIBbeKH
# QcN9bPCm4p/uCK24UOO0BjEmQ33ccJMxkQiN7xhrmFbY8IDs9i04/z+LCsSiELGM
# qeKZR9HBW/snvpphDGeeSGXsbPHtNZ7/dOIpDD3um7q8HKWbs1RLanOZZHek810O
# 6zmzPaonTRY1+00Q2AOn3SjFkoPpRylgsTJRJLibEcWd9bgk0xDE7Mt80rKrkRsl
# Cnr4c+CJAv8OO6X4nuxF4nQKLDThcnldtlLNKaSRKjsVSuGIfgw=
# SIG # End signature block
