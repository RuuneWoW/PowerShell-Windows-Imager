param(
     [Parameter()]
     [switch]$VisioReq,
 
     [Parameter()]
     [switch]$ProjectReq
 )

$OfficeInstallDownloadPath = ''#Path to Office 365 install exe
$CleanUpInstallFiles = $True
$ExcludeApps = 'Groove','Lync','Bing'

function Make-XMLFile {

  if ($ExcludeApps) {
    $ExcludeApps | ForEach-Object {
      $ExcludeAppsString += "<ExcludeApp ID =`"$_`" />"
    }
  }

  if ($VisioReq.IsPresent) {#Make sure to change PIDKEY"
    $VisioString = @"
      <Product ID="VisioProXVolume" PIDKEY="">
        <Language ID="MatchOS" />
        <Language ID="MatchPreviousMSI" />
        $ExcludeAppsString
      </Product>
"@
   }
   if ($ProjectReq.IsPresent) {#Change PIDKEY here too
    $ProjectString = @"
      <Product ID="ProjectProXVolume" PIDKEY="">
        <Language ID="MatchOS" />
        <Language ID="MatchPreviousMSI" />
        $ExcludeAppsString
      </Product>
"@
   }#Make sure to set the Value of your company in line 58 below
  $OfficeXML = [XML]@"
  <Configuration>
    <Add OfficeClientEdition="64" Channel="MonthlyEnterprise" MigrateArch="TRUE">
      <Product ID="O365ProPlusRetail">
        <Language ID="MatchOS" />
        <Language ID="MatchPreviousMSI" />
        $ExcludeAppsString
      </Product>
      $VisioString
      $ProjectString
    </Add>  
    <Property Name="SharedComputerLicensing" Value="1" />
    <Property Name="FORCEAPPSHUTDOWN" Value="TRUE" />
    <Property Name="AUTOACTIVATE" Value="1" />
    <Property Name="DeviceBasedLicensing" Value="0" />
    <Property Name="SCLCacheOverride" Value="0" />
    <Updates Enabled="TRUE" />
    <RemoveMSI />
    <AppSettings>
        <Setup Name="Company" Value="" />
    </AppSettings>
    <Display Level="None" AcceptEULA="TRUE" />
  </Configuration>
"@

  $OfficeXML.Save("$OfficeInstallDownloadPath\OfficeInstall.xml")
}
function Get-ODTURL {

  [String]$MSWebPage = Invoke-RestMethod 'https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117'

  $MSWebPage | ForEach-Object {
    if ($_ -match 'url=(https://.*officedeploymenttool.*\.exe)') {
      $matches[1]
    }
  }

}

$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!($CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
  Write-Warning 'Script is not running as Administrator'
  Write-Warning 'Please rerun this script as Administrator.'
  exit
}

if (-Not(Test-Path $OfficeInstallDownloadPath )) {
  New-Item -Path $OfficeInstallDownloadPath -ItemType Directory | Out-Null
}
Make-XMLFile
$ConfigurationXMLFile = "$OfficeInstallDownloadPath\OfficeInstall.xml"
if (!(Test-Path $ConfigurationXMLFile)) {
    Write-Warning 'The configuration XML file is not a valid file'
    Write-Warning 'Please check the path and try again'
exit
}

$ODTInstallLink = Get-ODTURL

#Download the Office Deployment Tool
Write-Verbose 'Downloading the Office Deployment Tool...'
try {
  Invoke-WebRequest -Uri $ODTInstallLink -OutFile "$OfficeInstallDownloadPath\ODTSetup.exe"
}
catch {
  Write-Warning 'There was an error downloading the Office Deployment Tool.'
  Write-Warning 'Please verify the below link is valid:'
  Write-Warning $ODTInstallLink
  exit
}

try {
  Write-Verbose 'Running the Office Deployment Tool...'
  Start-Process "$OfficeInstallDownloadPath\ODTSetup.exe" -ArgumentList "/quiet /extract:$OfficeInstallDownloadPath" -Wait
}
catch {
  Write-Warning 'Error running the Office Deployment Tool. The error is below:'
  Write-Warning $_
}

try {
  Write-Verbose 'Downloading and installing Microsoft 365'
  $Silent = Start-Process "$OfficeInstallDownloadPath\Setup.exe" -ArgumentList "/configure $ConfigurationXMLFile" -Wait -PassThru -NoNewWindow
}
catch {
  Write-Warning 'Error running the Office install. The error is below:'
  Write-Warning $_
}



#Check if Office 365 suite was installed correctly.
$RegLocations = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
)

$OfficeInstalled = $False
$VisioInstalled = $False
$ProjectInstalled = $Falee
foreach ($Key in (Get-ChildItem $RegLocations) ) {
  if ($Key.GetValue('DisplayName') -like '*Microsoft 365*') {
    $OfficeVersionInstalled = $Key.GetValue('DisplayName')
    $OfficeInstalled = $True
  }
  if ($Key.GetValue('DisplayName') -like '*Microsoft Visio Professional 2016*') {
    $VisioVersionInstalled = $Key.GetValue('DisplayName')
    $VisioInstalled = $True
  }
    if ($Key.GetValue('DisplayName') -like '*Microsoft Project Professional 2016*') {
    $ProjectVersionInstalled = $Key.GetValue('DisplayName')
    $ProjectInstalled = $True
  }
}

if (($VisioReq.IsPresent -and $VisioInstalled) -or ($ProjectReq.IsPresent-and $ProjectInstalled)) {
    cscript "C:\Program Files\Microsoft Office\Office16\OSPP.VBS" /sethst: #kms server
    cscript "C:\Program Files\Microsoft Office\Office16\OSPP.VBS" /act
}

if ($OfficeInstalled) {
  Write-Verbose "$($OfficeVersionInstalled) installed successfully!"
}
else {
  Write-Warning 'Microsoft 365 was not detected after the install ran'
}
if (($VisioInstalled) -and ($VisioReq.IsPresent)) {
  Write-Verbose "$($VisioVersionInstalled) installed successfully!"
}
elseif ($VisioReq.IsPresent) {
  Write-Warning 'Microsoft Visio Professional 2016 was not detected after the install ran'
}
if (($ProjectInstalled) -and ($ProjectReq.IsPresent)) {
  Write-Verbose "$($ProjectVersionInstalled) installed successfully!"
}
elseif ($ProjectReq.IsPresent) {
  Write-Warning 'Microsoft Project Professional 2016 was not detected after the install ran'
}

if ($CleanUpInstallFiles) {
  Remove-Item -Path $OfficeInstallDownloadPath -Force -Recurse
} 