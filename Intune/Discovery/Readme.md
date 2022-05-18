# **INTUNE DISCOVERY SCRIPT**


## Script summary:
 -------------------
   a. Connect to AzureAD and MsGraph. 
 
   b. Installs, if missing, the Azure AD and Intune Powershell scripts modules. 
 
   c. The following is collected:

    1.   Client Apps configurations
    2.   App Configuration Policies
    3.   Apps Protection policies configurations
    4.   Compliance Policies configurations
    5.   Device Configuration Policies configurations
    6.   Windows Scripts configurations
    7.   Device Management Intents
    8.   Administrative templates
    9.   Autopilot Deployment Profiles
    10.  Device Enrollment Configurations
    11.  Apple Push Notification Certificate
    12.  Apple User Enrollment Profiles
    13.  Apple DEP Profiles
    14.  Apple VPP Tokens
    15.  Android Managed Store Account Enterprise
    16.  Android Corporate-Owned profiles
    17.  Android for Work profiles
    18.  Android for work settings
    19.  Assignment Filters
    20.  Device Categories
    21.  Domain Join Connectors
    22.  Microsoft Tunnel Configurations
    23.  Microsoft Tunnel Sites
    24.  NDES Connectors
    25.  Windows Feature Update Profiles
    26.  Windows Quality Update Profiles
 
   e. For every single policy that has and assignment:

      1. Is collected the assignment configuration. 
      2. For the GroupIDs, AzureAD is contacted and the Group Name is retrieved. 
      3. The Group Name value is appended on the related output file. 

   f. Create an output files for every single policy collected. 


   g.	All the files are compressed on a ZIP file to be ready to collected/sent by the user to a secure workspace. 
 


## **REQUIREMENTS**
---------------------

The requirements to have the script executed are the following:

   a. Windows 10 or 11 device (latest OS build the better) 

   b. Logon locally with a user with local admin permissions. Don’t need to be domain nor Azuread join/Intune enrolled. 

   c. Use an AzureAD account with the following:
	
      -  Global Admin user to execute the script to be able to get Intune and Azure Ad data. 
         or
      -  Intune admin with Azuread permissions could work.  Will be required by Global Admin to gran consent on Graph Api. 
         or
      -  Lastly Intune Admin only could help. --> Same consent is required from Graph Api. But it wont be able to resolve the AzureAD groups from the script.  
	
   **NOTE: Errors during the sctript excecution related to AD permissions are expected.**

   d. Using the AzureAD account from step C., with browser go to aka.ms/ge and sign in to the Graph Explorer. 
   Permissions consent will be requested. In case that need approval, this could be granted in the same page, for the administator itself.
   If this is a delegate, a pop-up message will appear to submit a request for access the permissions to the Global Admin. 

      More information related to Admin consent experience: 
      https://docs.microsoft.com/en-us/graph/auth-v2-service#administrator-consent-experience
                
   e. Intune and Azure AD module installation. Please answer Yes to any module installation confirmation. 
   
   f. The modules are being installed from the Script Gallery, please accept the “Untrusted” repository question, if the confirmation is requested.


## **GRAPH EXPLORER PERMISSIONS**
-------------------------------
Following are the minimun permissions to concent in order to allow the script to extract the information:

   ***DeviceManagementApps.Read.All**
      _Allows the app to read the properties, group assignments and status of apps, app configurations and app protection policies managed by Microsoft Intune._

   ***DeviceManagementConfiguration.Read.All**
      _Allows the app to read properties of Microsoft Intune-managed device configuration and device compliance policies and their assignment to groups._

   ***DeviceManagementManagedDevices.Read.All**
      _Allows the app to read the properties of devices managed by Microsoft Intune._

   ***DeviceManagementRBAC.Read.All**
      _Allows the app to read the properties relating to the Microsoft Intune Role-Based Access Control (RBAC) settings._

   ***DeviceManagementServiceConfig.Read.All**
      _Allows the app to read Microsoft Intune service properties including device enrollment and third party service connection configuration._



