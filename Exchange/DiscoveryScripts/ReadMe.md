Prereqs: (1) Exchange on-premises EMS installed and (2) EXOv2 module installed: "Install-Module ExchangeOnlineManagement" (https://www.powershellgallery.com/packages/ExchangeOnlineManagement)

1.	Download or clone the scripts to your local PC
2.	Save/move both scripts into same directory on an Exchange server in your org (or on a tools workstation with the Exchange Management Shell (EMS) installed)
	
	a.	If you have multiple Exchange versions deployed in your Org, place and run these scripts from an Exchange server running the newest version of Exchange in your Org. It is preferred to run the scripts from an Exchange server, but not necessary.
    
	b.	It is possible to execute from a remote PowerShell session connected to the Exchange server if the server you connect to follows the guidelines previously mentioned.
	
	c.	Script 2 will attempt to login to EXO via the EXOv2 PowerShell module.
3.	Log onto the computer where you placed the scripts with an Exchange Org Admin account and open the EMS as Administrator, then navigate to the folder where you placed the scripts locally and execute the SMC-Exchange-Discovery-1.ps1 script from the Exchange Management Shell (EMS).

	a.	Script #1 (Exchange Server gets) will execute script #2 (EXO gets) and login to EXO via the EXOv2 module
    
	b.	Script #1 will create a folder on the desktop of the computer where you ran these scripts; The folder is called “SMC-Email-Discovery” and both scripts place the outputs of the get-commands into this folder.
    
	c.	Once the Exchange on-prem collection portion of the process is complete, it will prompt with a popup asking if you want to collect the EXO configuration. Please select "Yes" and then provide an O365 EXO Admin account to capture EXO configuration settings.
    
	d.	After both scripts complete gathering data, the folder on the desktop will be zipped.
4.	When the scripts have completed, please upload the Zipped file from the desktop called “SMC-Email-Discovery.zip” to your SfMC engineer.
    
	a.	Upload to the secure file transfer workspace (url provided by an SfMC engineer who asked you to run these scripts).
    
	b.	Also, please send a reply to the SfMC engineer for awareness that you have uploaded the discovery data for SfMC review.
