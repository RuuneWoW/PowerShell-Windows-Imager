# PS-Image
## Intro
This script will help you image a Windows computer that needs to become part of a domain.
It was written to be used in a Dell environment with the inclusion of Dell Command update, so if you are not using it on a Dell, just remove this code.
Please read through the code carefully to make sure that all components are needed within your environment and that all paths have been correctly added. 
I have put a comment everywhere that you should have to edit in your own path or license key. 
Also note that certain parts refer to a webpage for a download, so if you have any issues, make sure that the site had not changed.
This script is only useful if you do not have a dedicated image deployment software and have to manually set up computers. 

## Pre Requirements 
1. A Windows computer that has been joined to your domain
2. [Invoke-RemoveBuiltinApps.ps1](https://github.com/MSEndpointMgr/ConfigMgr/blob/master/Operating%20System%20Deployment/Invoke-RemoveBuiltinApps.ps1) by Nickolaj Andersen
3. Local administrator rights 

## Setup
To set the script up, make sure Invoke-RemoveBuiltinApps.ps1 and Office365Multi are in an accessible folder on your network storage. It is a good idea to keep these on a share that is not available to general users. Go through the install-script.ps1 and replace all necessary paths to match your network structure and install locations. Most of these have been marked with a comment, but if you run into errors, check back to make sure you have not missed a license key or path.

## Running the script
While storing the script on a network share is convenient **(only accessible by admins)**, it works best if you copy install-script.ps1 to the desktop and then right click and run with PowerShell. A PowerShell window will open and then open admin confirmation. Once confirmed, a second PowerShell window will open and install winget. After a minute or two, it will ask a few options based on how you have tailored the program. The default will ask what version of Office you want, if you want Visio, Project, Adobe, SAP, and internet browsers. It will then ask if you want to add a local admin and change the computer name. After these are all set, you can let it run until complete. After the reboot, you have a fully imaged computer ready to go.
