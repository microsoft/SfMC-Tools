Greetings,

Instructions for using the Exchange and Exchange Online Discovery Scripts.

<br>

Perquisites:
1. Must be run from a domain joined Windows 10 machine due to a known issue with PowerShell on Windows Server, we recommend to run them on a jump box and not on an Exchange Server,
2. Requires at least PS v5,
3. You will need a Global Reader Account to run the EXO Discovery script.
4. You will need an Exchange admin account to run the on prem Exchange discover script.
5. If you are running this for Exchange Online as well, you need to install the Exchange Online Management module by following this process:
	a. Open Powershell as an admin and run "Install-Module -Name ExchangeOnlineManagement" . Answer Yes to any prompts.
	b. Next, run "Import-Module ExchangeOnlineManagement" . Answer Yes to any prompts.
	
<br>

Procedure:
Create a folder on the root of your C: drive called Discovery. 
Create a folder under the just created Discovery folder called Results. 
Also create a folder called EXOResults under the Discovery folder. 

Extract the SfMC-Discovery-Script-main scrip archive in the C:\Discovery folder.
Open PowerShell as an Administrator (you will get an error if you do not)
Enter the following command (using the directory you created)
Set-Location C:\Discovery

Enter the following command entering an Exchange server FQDN and administrator UPN
.\SfMC-Discovery.ps1 -ExchangeServer ExchServer.contoso.com -UserName Admin@contoso.com -OutputPath "C:\Discovery\Results"

Watch for any error and send any you encounter.

The above procedure will place all the data files in the \Results folder and then create a .ZIP of those files in the Discovery folder. Please upload that file to the link provided below.

To collect your Exchange Online data, run the following command from the C:\Discovery folder.

SfMC-EXODiscovery.ps1 -UserPrincipalName GlobalAdmin@YourDomain.com -OutputPath c:\Discovery\EXOResults

The above command will create a .ZIP file in the EXOResults folder. Please upload The files here: 

<br>
<br>
<br>


Here are some examples of command lines for the Exchange script. 
 .EXAMPLES
 .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -DagName E19DAG1 -OutputPath c:\Temp\Results
 This example collects the Exchange organization settings and Exchange server settings for the E19DAG1 database availability group and saves the results in C:\Temp\Results

 .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results
 This example collects the Exchange organization settings and Exchange server settings for all Exchange servers in the organization and saves the results in c:\Temp\Results

 .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results -ServerSettings:$False
 This example collects only the Exchange organization settings and saves the results to c:\Temp\Results

 .\SfMC-Discovery.ps1 -ExchangeServer clt-e19-mbx3.resource.local -UserName administrator@resource.local -OutputPath c:\Temp\Results -OrgSettings:$False -ServerName clt-e19-mbx3.resource.local
 This example collects only the Exchange server settings for clt-e19-mbx3.resource.local and saves the results to c:\Temp\Results

.NOTES
  Exchange server specified should be the latest version in the environment
  
  
.\SfMC-Discovery.ps1 -ExchangeServer exch02.fife.cc -UserName ExAdmin@fife.cc -OutputPath "C:\Exchange Discovery Scripts\Results"
