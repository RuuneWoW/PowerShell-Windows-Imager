
#Global Variables: Adjust Them when locations of Contents Change
$RemoteLoc = #Network share path here
$AdobeLoc = "$RemoteLoc\"#Fill in the rest of the path for each software you need
$OfficeLoc = "$RemoteLoc\"#Same here and add additional paths for other programs
$SAPLoc = "$RemoteLoc\"#Here
$ESETLoc = "$RemoteLoc\"#Here
$ChromeLoc = "$RemoteLoc\"#Here
$FirefoxLoc = "$RemoteLoc\"#Here
$CrowdStrikeCID = Get-Content ""#Network path for license file to get customer ID if needed
$CrowdStrikeLoc = ""

#This will restart powershell in elevated permissions
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) 
{
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

#Sets sleep settings to not log out before restart after name change
powercfg /change monitor-timeout-ac 120
powercfg /change standby-timeout-ac 0

function Install-Winget 
    {
    $hasPackageManager = Get-AppxPackage -Name 'Microsoft.Winget.Source' | Select-Object Name, Version
    $hasVCLibs = Get-AppxPackage -Name 'Microsoft.VCLibs.140.00.UWPDesktop' | Select-Object Name, Version
    $hasXAML = Get-AppxPackage -Name 'Microsoft.UI.Xaml.2.7*' | Select-Object Name, Version
    $hasAppInstaller = Get-AppxPackage -Name 'Microsoft.DesktopAppInstaller' | Select-Object Name, Version
    Write-Host -ForegroundColor Yellow "Checking if WinGet is installed"
    if (!$hasPackageManager) 
        {
            if ($hasVCLibs.Version -lt "14.0.30035.0") {
                Write-Host -ForegroundColor Yellow "Installing VCLibs dependencies..."
                Add-AppxPackage -Path "https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx"
                Write-Host -ForegroundColor Green "VCLibs dependencies successfully installed."
            }
            else {
                Write-Host -ForegroundColor Green "VCLibs is already installed. Skip..."
            }
            if ($hasXAML.Version -lt "7.2203.17001.0") {
                Write-Host -ForegroundColor Yellow "Installing XAML dependencies..."
                Add-AppxPackage -Path "https://github.com/Kugane/winget/raw/main/Microsoft.UI.Xaml.2.7_7.2203.17001.0_x64__8wekyb3d8bbwe.Appx"
                Write-Host -ForegroundColor Green "XAML dependencies successfully installed."
            }
            else {
                Write-Host -ForegroundColor Green "XAML is already installed. Skip..."
            }
            if ($hasAppInstaller.Version -lt "1.16.12653.0") {
                Write-Host -ForegroundColor Yellow "Installing WinGet..."
    	        $releases_url = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"
    		    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    		    $releases = Invoke-RestMethod -Uri "$($releases_url)"
    		    $latestRelease = $releases.assets | Where-Object { $_.browser_download_url.EndsWith("msixbundle") } | Select-Object -First 1
    		    Add-AppxPackage -Path $latestRelease.browser_download_url
                Write-Host -ForegroundColor Green "WinGet successfully installed."
        }
    }
    else 
        {
        Write-Host -ForegroundColor Green "WinGet is already installed. Skip..."
        }
}

Write-Host "Checking winget..."
Install-Winget

Install-PackageProvider -Name Nuget -Force; Install-Module -Name PSWindowsUpdate -Force
Add-WUServiceManager -ServiceID ""<#Your WSUS ID here#> -AddServiceFlag 7 -Confirm:$false

Write-Host "================New Computer Deployment================="
do {
Write-Host "=================Pick the Office Install================"
Write-Host "'A' for Office 365"
Write-Host "'B' for Office 2013"
Write-Host "'C' for Office 2016"
Write-Host "'D' for no Office"
Write-Host "========================================================"
$office_ver = Read-Host "`Enter Choice"
} until (($office_ver -eq 'A') -or ($office_ver -eq 'B') -or ($office_ver -eq 'C') -or ($office_ver -eq 'D'))
do { $VisioChoice = Read-Host "`nDoes Visio need to be installed? (Y or N)"} until (($VisioChoice -eq 'Y') -or ($VisioChoice -eq 'N'))
do { $ProjectChoice = Read-Host "`nDoes Project need to be installed? (Y or N)"} until (($ProjectChoice -eq 'Y') -or ($ProjectChoice -eq 'N'))
do { $AdobeChoice = Read-Host "`nDoes Adobe Acrobat DC need to be installed? (Y or N)"} until (($AdobeChoice -eq 'Y') -or ($AdobeChoice -eq 'N'))
do { $SAPChoice = Read-Host "`nDoes SAP need to be installed? (Y or N)"} until (($SAPChoice -eq 'Y') -or ($SAPChoice -eq 'N'))
do { $BrowserChoice = Read-Host "`nDo internet browsers need to be installed? (Y or N)"} until (($BrowserChoice -eq 'Y') -or ($BrowserChoice -eq 'N'))
do { $LocalAdminChoice = Read-Host "`nDo you want to add a local adminitrator? (Y or N)"} until (($LocalAdminChoice -eq 'Y') -or ($LocalAdminChoice -eq 'N'))
do { $NameChoice = Read-Host "`nDo you want to rename the computer? (Y or N)"} until (($NameChoice -eq 'Y') -or ($NameChoice -eq 'N'))

$domain = ""#Domain here
$installerUsr = ""#Domain\user
$installerPass = ''#admin user password
$installerPassSec = $installerPass | ConvertTo-SecureString -AsPlainText –Force
$installedCred = New-Object System.Management.Automation.PSCredential($installerUsr, $installerPassSec)

Function Set-LocalAdmin()
{
    $localAdmin = Read-Host "Enter username to set as local admin" 
    Add-LocalGroupMember -Group Administrators -Member $localAdmin -Verbose
    Set-LocalAdminAgain
}

Function Set-LocalAdminAgain()
{    
    do { $localAdminAgain = Read-Host "`nWould you like to add another user? (Y or N)"} until (($localAdminAgain -eq 'Y') -or ($localAdminAgain -eq 'N'))
    if ($localAdminAgain -eq 'Y')
    {
        Set-LocalAdmin
    }
    elseif ($localAdminAgain -eq 'N')
    {
        Write-Host "No additonal users"
    }   
}

if ($LocalAdminChoice -eq 'Y')
{
    Set-LocalAdmin
}
elseif ($LocalAdminChoice -eq 'N')
{
    Write-Host "Not setting local administrator"
}

#Domain and naming
function Name-Computer()
{
    if ($env:USERDNSDOMAIN -eq "")#Enter your domain here
    {
        Rename-Computer -NewName $PCName -Verbose
    } 
    elseif ($env:USERDNSDOMAIN -ne "")#Also enter domain here
    {
        Write-Warning "This computer is currently joined to another domain..."
        do { $removeDomainChoice = Read-Host "Would you like to remove it now? (Y or N)"} until (($removeDomainChoice -eq 'Y') -or ($removeDomainChoice -eq 'N')) 
        if ($removeDomainChoice -eq 'Y')
        {
            $localPassword = Read-Host -AsSecureString
            New-LocalUser "Installer" -Password $localPassword -FullName "Installer" -Description "Local Installer account for removing domain"
            Add-LocalGroupMember -Group "Administrators" -Member "Installer"
            Write-Host "Local admin user Installer created" -ForegroundColor Green
            Remove-Computer -UnjoinDomainCredential -PassThru -Verbose
            Restart-Computer
        }
        elseif ($removeDomainChoice -eq 'N')
        {
            Write-Warning "Script will now close. Please remove from current domain before trying again"
            Pause
            Exit
        }
    }
}
if ($NameChoice -eq 'Y') 
{
    $PCName = Read-Host "`nEnter the Name for the Computer"
    $domainCheck = (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain
    if ($domainCheck -eq $true)
    {
        Name-Computer
    }
}
elseif ($NameChoice -eq 'N')
{
    Write-Host "Not renaming the computer"
}

net use $RemoteLoc /user:$installerUsr $installerPass

Write-Host "`nNow removing Windows Store Apps and Bloatware"
Invoke-Expression -Command "$RemoteLoc\"# Add path to Invoke-RemoveBuiltinApps.ps1
Start-Sleep -Seconds 3

Write-Host "Begin Updating Dell Software/Firmware"
# Check if DCU is installed
if (Test-Path -Path "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe") 
{
    Start-Process -File "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/applyUpdates" -Wait -NoNewWindow
}
elseif (Test-Path -Path "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe") 
{
    Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/applyUpdates" -Wait -NoNewWindow
}
else {
    # Installing DCU from the Microsoft Store
    Write-Host "DCU not found, installing it now."
    try {
        winget install Dell.CommandUpdate --force --accept-package-agreements --accept-source-agreements
        Start-Process "C:\Program Files (x86)\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/applyUpdates" -Wait -NoNewWindow
    }
    catch {
        $DownloadURL = "https://dl.dell.com/FOLDER08847542M/1/Dell-Command-Update-Application_034D2_WIN_4.6.0_A00.EXE"
        $DownloadLocation = "C:\Temp"

        try {
        $TestDownloadLocation = Test-Path $DownloadLocation
            if (!$TestDownloadLocation) { 
                new-item $DownloadLocation -ItemType Directory -force 
            }
            $TestDownloadLocationZip = Test-Path "$DownloadLocation\DellCommandUpdate.exe"
            if (!$TestDownloadLocationZip) {
                Invoke-WebRequest -UseBasicParsing -Uri $DownloadURL -OutFile "$($DownloadLocation)\DellCommandUpdate.exe"
                Start-Process -FilePath "$($DownloadLocation)\DellCommandUpdate.exe" -ArgumentList '/s' -Verbose -Wait
            }
            Start-Process "C:\Program Files\Dell\CommandUpdate\dcu-cli.exe" -ArgumentList "/applyUpdates" -Wait -NoNewWindow
        }
        catch {
            Write-Host "The download and installation of DCUCli failed. Error: $($_.Exception.Message)"
            exit 1
        }
     }
}
Start-Sleep -Seconds 3

if($office_ver -eq 'A' -or $office_ver -eq 'B' -or $office_ver -eq 'C')
{
Write-Host "`nRemoving Old Versions of Office"
}

$processInfo = New-Object System.Diagnostics.ProcessStartInfo("$OfficeLoc\SaRACmd\SaRAcmd.exe");
$processInfo.Arguments = "-s OfficeScrubScenario -AcceptEULA -Officeversion All -CloseOffice";
$processInfo.CreateNoWindow = $true;     # Runs SaRA CMD in a quite mode, $false to show its console
$processInfo.UseShellExecute = $false;
$processInfo.RedirectStandardOutput = $true;

$process = [System.Diagnostics.Process]::Start($processInfo);
$process.StandardOutput.ReadToEnd();     # Displays SaRA CMD's output in the PowerShell window, Comment if not needed
$process.WaitForExit();
$process.Dispose()

switch ($office_ver) {
    'A'{
        if(($VisioChoice -eq 'Y') -and ($ProjectChoice -eq 'Y')) {
            Write-Host "Installing Office 365, Visio, and Project"
            Invoke-Expression -Command "$OfficeLoc\Office365\Office365Multi.ps1 -VisioReq -ProjectReq" #Your path to Office365Multi.ps1 here
            Write-Host "Office 365, Visio, and Project installed" -ForegroundColor Green
        }
        elseif($VisioChoice -eq 'Y') {
            Write-Host "Installing Office 365 and Visio"
            Invoke-Expression -Command "$OfficeLoc\Office365\Office365Multi.ps1 -VisioReq" #And here
            Write-Host "Office 365 and Visio installed" -ForegroundColor Green
        }
        elseif($ProjectChoice -eq 'Y') {
            Write-Host "Installing Office 365 and Project"
            Invoke-Expression -Command "$OfficeLoc\Office365\Office365Multi.ps1 -ProjectReq" #And here
            Write-Host "Office 365 and Project installed" -ForegroundColor Green
        }
        else {
            Write-Host "Installing Office 365"
            Invoke-Expression -Command "$OfficeLoc\Office365\Office365Multi.ps1" #And here
            Write-Host "Office 365 installed" -ForegroundColor Green
        }
    }
    'B'{
        Write-Host "Installing Office 2013"
        Start-Process "$OfficeLoc\Office-2013\setup.exe" -ArgumentList "/config $OfficeLoc\Office-2013\Office2013.xml" -Wait -NoNewWindow #Your path to exe or comment out if 2013 not wanted
        Write-Host "Office 2013 installed" -ForegroundColor Green
        if($VisioChoice -eq 'Y') {
            Write-Host "Installing Visio"
            Start-Process "$OfficeLoc\Visio-Std-2013\x64\setup.exe" -ArgumentList "/configure $OfficeLoc\Visio-Std-2013\Visio2013Std.xml" -Wait -NoNewWindow
            Write-Host "Visio installed" -ForegroundColor Green
        }
        if($ProjectChoice -eq 'Y') {
            Write-Host "Installing Project"
            Start-Process "$OfficeLoc\Project-Pro-2013\x64\setup.exe" -ArgumentList "/configure $OfficeLoc\Project-Pro-2013\Visio2013Pro.xml" -Wait -NoNewWindow
            Write-Host "Project installed" -ForegroundColor Green
        }
    }
    'C'{
        Write-Host "Installing Office 2016"
        Start-Process "$OfficeLoc\Office-2016\x64\setup.exe" -ArgumentList "/config $OfficeLoc\Office-2016\Office2016.xml" -Wait -NoNewWindow #Your path to exe or comment out if not needed
        Write-Host "Office 2016 installed" -ForegroundColor Green
        if($VisioChoice -eq 'Y') {
            Write-Host "Installing Visio"
            Start-Process "$OfficeLoc\Visio-Pro-2016\x64\setup.exe" -ArgumentList "/configure $OfficeLoc\Visio-Pro-2016\Visio2016Pro.xml" -Wait -NoNewWindow
            Write-Host "Visio installed" -ForegroundColor Green
        }
        if($ProjectChoice -eq 'Y') {
            Write-Host "Installing Project"
            Start-Process "$OfficeLoc\Project-Pro-2016\x64\setup.exe" -ArgumentList "/configure $OfficeLoc\Project-Pro-2016\Visio2016Pro.xml" -Wait -NoNewWindow
            Write-Host "Project installed" -ForegroundColor Green
        }
        cscript "C:\Program Files\Microsoft Office\Office16\OSPP.VBS" /act
    }
    'D'{
        Write-Host "No Office install selected"
        }
}
Start-Sleep -Seconds 3

if ($AdobeChoice -eq 'Y') 
    {
    Write-Host "Installing Adobe"
    Start-Process $AdobeLoc -Wait -NoNewWindow
    Start-Sleep -Seconds 3
    Write-Host "Adobe Acrobat installed" -ForegroundColor Green
    }
else {
    Write-Host "No Adobe install"
    }

if ($BrowserChoice -eq 'Y') 
    {
    Write-Host "Installing Internet Browsers"
    Start-Process $ChromeLoc -Wait -NoNewWindow
    Start-Process $FirefoxLoc -Wait -NoNewWindow
    Start-Sleep -Seconds 3
    Write-Host "Internet browsers installed" -ForegroundColor Green
    }
else {
    Write-Host "Not installing Browsers"
    }

Write-Host "Installing ESET Antivirus"
Start-Process $ESETLoc -ArgumentList "--silent --accepteula" -Wait -NoNewWindow
Write-Host "ESET Antivirus installed" -ForegroundColor Green
Start-Sleep -Seconds 3


if ($SAPChoice -eq 'Y') 
    {
    Write-Host "Installing SAP Front End"
    Start-Process $SAPLoc -ArgumentList '/Product="SAPGUI" /silent /NoDlg' -Wait -NoNewWindow
    Write-Host "SAP Front End installed" -ForegroundColor Green
    }
else {
    Write-Host "Not installing SAP"
    }

#CrowdStrike or other antivirus
Write-Host "Installing CrowdStrike"
& $CrowdStrikeLoc /install /quiet /norestart CID=$CrowdStrikeCID
Write-Host "CrowdStrike Installed" -ForegroundColor Green

Write-Host "Checking Windows Activation and Activating"
$activationStatus = Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | Where-Object { $_.PartialProductKey } | Select-Object Description, LicenseStatus
if($activationStatus.LicenseStatus -ne 1 -or $activationStatus.Description -inotmatch "OEM") 
    {
    Write-Host "Activating Windows"
    $OEMKey = Get-CimInstance SoftwareLicensingService
    if(($OEMKey.OA3xOriginalProductKey) -And ($OEMKey.OA3xOriginalProductKeyDescription -match "Professional"))
    {
        cscript "C:\Windows\System32\slmgr.vbs" /ipk $OEMKey.OA3xOriginalProductKey
    }
    else
    {
        cscript "C:\Windows\System32\slmgr.vbs" /ipk #Your volume license key here
    }
}

#Sets sleep setting back to default
powercfg /change monitor-timeout-ac 10
powercfg /change standby-timeout-ac 30

Remove-Item -Path "$HOME\Desktop\Install-Script.ps1" -Force -Recurse
Write-Host "Running Windows Updates"
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -ErrorAction SilentlyContinue
Write-Host "Restarting Computer" -ForegroundColor Yellow
Restart-Computer