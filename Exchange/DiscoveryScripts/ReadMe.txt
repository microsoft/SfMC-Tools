1. Download or clone the scripts to your local PC

2. Save/move both scripts in same directory on an Exchange server in your org (or on a tools workstation with the Exchange Management Shell (EMS) installed) 

	a. If you have multiple Exchange versions deployed in your Org, place and run these scripts from an Exchange server running the newest version of Exchange in your Org.  It is preferred to run the scripts from an Exchange server, but not necessary.

	b. It is possible to execute from a remote PowerShell session connected to the Exchange server if the server you connect to follows the guidelines previously mentioned.

3. Log onto the server where you placed the scripts with an Exchange Org Admin account and open the EMS as Administrator, then navigate to the folder where you placed the scripts locally and execute the SMC-Exchange-Discovery-1.ps1 script.  

	a. Script #1 (Exchange gets) will execute script #2 (EXO gets).

	b. The scripts will create a folder on the desktop of the computer where you ran these scripts; The folder is called “SMC-Email-Discovery” and the scripts place the outputs of the get-commands into this folder.  

	c. Once the Exchange on-prem collection portion of the process is complete, it will prompt with a popup asking if you want to collect the EXO configuration.  Please select Yes and then provide an O365 EXO Admin account to capture EXO configuration settings.  We suggest/recommend using a GA account as some of the Gets we want may not be available to Exchange only Admins…however this is not required.

4. When the scripts are finished, please upload the Zipped folder from the desktop called “SMC-Email-Discovery.zip” to your SMC team 

	a. Upload to the secure file transfer workspace location provided by an SfMC CE

	b. Also, please send a reply to this email to let us know you have uploaded discovery data for our review