<#
.DESCRIPTION
    The script will install PowerSyncPro on a Windows Server, including all prerequisites.
    This script will download various content from Microsoft, PowerSyncPro, and the PowerSyncPro Github.
 
.NOTES
    Date            October/2025
    Disclaimer:     This script is provided 'AS IS'. No warrantee is provided either expressed or implied. Declaration Software Ltd cannot be held responsible for any misuse of the script.
    Version: 0.1
    Updated: Initial Release.
    Copyright (c) 2025 Declaration Software
#>

#Requires -RunAsAdministrator
Set-StrictMode -Version Latest

# General Variables
$scriptVer = "v0.1"

$tempDir = "C:\Temp" # Temporary Directory for Downloads, etc.
$LogPath = "C:\Temp\PSP_AutoInstall.txt" # Logging Location

# .Net 8 Hosting Platform Variables
# Meta Data URL, link to the latest .net releases in JSON
$metadataUrl = "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/8.0/releases.json"

# VC Redistributable Variables
$vcDownloadURL = "https://aka.ms/vs/17/release/vc_redist.x64.exe"

# SQL 2022 Bootstrapper / Downloader
$SQLBootstrapperUrl = "https://download.microsoft.com/download/5/1/4/5145fe04-4d30-4b85-b0d1-39533663a2f1/SQL2022-SSEI-Expr.exe"
# SQL Suite Management Studio
$SsmsUrl = "https://aka.ms/ssmsfullsetup"
$ExpectedSQLServiceName = 'MSSQL$SQLEXPRESS'

# IIS URL Rewrite
$RewriteUrl = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
# IIS Advanced Request Routing URL
$ArrUrl = "https://download.microsoft.com/download/e/9/8/e9849d6a-020e-47e4-9fd0-a023e99b54eb/requestRouter_amd64.msi"

# Current PSP Public Download Link
$PSPUrl = "https://downloads.powersyncpro.com/current/PowerSyncProInstaller.msi"

# Target Folder for Maintenance Scripts (PoshACME Cert Puller, WebConfig Editor)
$ScriptFolder = "C:\Scripts"

# Scripts to Drop (Github Links)
# Certificate Puller Script, used to pull certificates via LetsEncrypt / ACME
$CertPullerScriptName = "Cert-Puller_PoshACME.ps1"
$CertPullerURL = "https://raw.githubusercontent.com/jrichardpsp/psp-autoinstall-beta/refs/heads/main/Cert-Puller_PoshACME.ps1"
# Certificate Renewer Script, used to manually replace a certificate on a PSP install
$CertRenewerScriptName = "Cert-Renewer.ps1"
$CertRenewerURL = "https://raw.githubusercontent.com/jrichardpsp/psp-autoinstall-beta/refs/heads/main/Cert-Renewer.ps1"
# WebConfig Editor - Used to update reverse proxy allowed IPs and proxy rewrite URL.
$WebConfigScriptName = "WebConfig_Editor.ps1"
$WebConfigScriptURL = "https://raw.githubusercontent.com/jrichardpsp/psp-autoinstall-beta/refs/heads/main/WebConfig_Editor.ps1"

# Web.Config Information
$WebConfigName = "web.config"
$WebConfigFolder = "C:\inetpub\wwwroot"

# Install Checks
# .Net Version
$DotNetVer = @("8")
# VC++ Redistributable Version
$vcVer = "14.44.35211"

$asciiLogo=@"
 ____                        ____                   ____            
|  _ \ _____      _____ _ __/ ___| _   _ _ __   ___|  _ \ _ __ ___  
| |_) / _ \ \ /\ / / _ \ '__\___ \| | | | '_ \ / __| |_) | '__/ _ \ 
|  __/ (_) \ V  V /  __/ |   ___) | |_| | | | | (__|  __/| | | (_) |
|_|   \___/ \_/\_/ \___|_|  |____/ \__, |_| |_|\___|_|   |_|  \___/ 
                                   |___/                            
"@

# ------------------ Functions ------------------
# ------------------ Installation and Requirements Checks ------------------
function Install-dotNet8Hosting {
# -----------------------
# Download and install the latest stable .NET 8 Hosting Bundle (Windows)
# -----------------------
  param(
    [string]$metadataUrl,
    [string]$tempDir
    )

  Write-Host "Installing latest stable .NET 8 Hosting Bundle...." -ForegroundColor Cyan

  $metadataUrl = "https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/8.0/releases.json"
  Write-Host "Fetching release metadata from $metadataUrl ..."
  $releases = Invoke-RestMethod $metadataUrl

  # Filter out prerelease versions like "8.0.0-rc.2"
  $stableReleases = $releases.releases |
      Where-Object { ($_.'release-version' -notmatch '-') }

  # Sort as real [version] objects
  $latestRelease = $stableReleases |
      Sort-Object { [version]($_.'release-version') } -Descending |
      Select-Object -First 1

  $version = $latestRelease.'release-version'
  Write-Host "Latest stable .NET 8 release: $version"

  # Look for the hosting bundle in aspnetcore-runtime.files
  $asset = $latestRelease.'aspnetcore-runtime'.files |
      Where-Object { $_.name -eq "dotnet-hosting-win.exe" } |
      Select-Object -First 1

  if (-not $asset) {
      throw "No Hosting Bundle found in aspnetcore-runtime.files!"
  }

  $downloadUrl = $asset.url
  $installerPath = "$tempDir\dotnet-hosting-$version-win.exe"

  Write-Host "Downloading Hosting Bundle from $downloadUrl ..."
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri $downloadUrl -OutFile $installerPath

  Write-Host "Running Hosting Bundle installer silently..."
  Start-Process $installerPath -ArgumentList "/quiet /norestart" -Wait

  Write-Host ".Net 8 Hosting Bundle $version installation complete!" -ForegroundColor Green
}
function Test-dotNet8Hosting {
    param(
        [string[]]$RequiredVersions = @("8")
    )

    Write-Host "Checking for .NET ASP.NET Core Runtimes..." -ForegroundColor Cyan

    try {
        $runtimes = & dotnet --list-runtimes
    }
    catch {
        Write-Host "Failed to execute 'dotnet' command. - Assuming no versions installed." -ForegroundColor Red
        return $false
    }

    if (-not $runtimes) {
        Write-Host "No .NET ASP.NET Core runtimes found." -ForegroundColor Red
        return $false
    }

    # Parse installed runtimes
    $installedRuntimes = $runtimes |
        Where-Object { $_ -match "^Microsoft\.AspNetCore\.App\s+([0-9]+\.[0-9]+\.[0-9]+)" } |
        ForEach-Object {
            [PSCustomObject]@{
                Full    = $_.Trim()
                Version = $Matches[1]
                Major   = $Matches[1].Split('.')[0]
            }
        }

    Write-Host "Installed .NET ASP.NET Core Runtimes:" -ForegroundColor Cyan
    $installedRuntimes.Full | ForEach-Object { Write-Host "$_ (Installed)" }

    $allFound = $true

    foreach ($version in $RequiredVersions) {
        if ($installedRuntimes.Major -contains $version) {
            Write-Host "ASP.NET Core Runtime version $version is installed." -ForegroundColor Green
        }
        else {
            Write-Host "ASP.NET Core Runtime version $version is not installed." -ForegroundColor Red
            $allFound = $false
        }
    }

    return $allFound
}
function Install-VCRedistributable {
  # -----------------------
  # Download / Install Automated VC++ 2022 Redistributable (x64)
  # -----------------------
  param(
    [string]$DownloadURL,
    [string]$TempDir
  )

  $ErrorActionPreference = "Stop"

  Write-Host "Installing Microsoft Visual C++ Redistributables (x64)..." -ForegroundColor Cyan

  # Ensure download directory exists
  if (-not (Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir | Out-Null }

  $installer = Join-Path $TempDir "vc_redist.x64.exe"

  Write-Host "Downloading VC++ Redistributable (x64) from $DownloadURL ..."
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri $DownloadURL -OutFile $installer

  Write-Host "Downloaded vc_redist.x64.exe to $installer"

  # Step 1: Run silent install (elevated)
  Write-Host "Installing VC++ Redistributable silently..."
  $proc = Start-Process -FilePath $installer `
      -ArgumentList "/quiet", "/norestart" `
      -Verb RunAs -Wait -PassThru

  if ($proc.ExitCode -ne 0) {
      throw "VC++ Redistributable install failed with exit code $($proc.ExitCode)"
  }

  # Step 2: Verify install (basic check via registry)
  $vcKey = "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64"
  $installed = Test-Path $vcKey

  if ($installed) {
      Write-Host "VC++ Redistributable (x64) installed successfully."
  } else {
      Write-Host "VC++ Redistributable verification failed. Check logs or rerun installer."
  }

}
function Test-VCRedistributable {
    param(
        [string]$RequiredVersion = "14.44.35211"  # minimum required version
    )

    $registryPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $installedSoftware = foreach ($path in $registryPaths) {
        Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
            Get-ItemProperty |
            Where-Object {
                $_.PSObject.Properties.Name -contains 'DisplayName' -and
                $_.DisplayName -like "*Visual C++*Redistributable* (x64)*"
            } |
            Select-Object DisplayName, DisplayVersion
    }

    if (-not $installedSoftware) {
        Write-Host "No Microsoft Visual C++ Redistributables (x64) installed." -ForegroundColor Red
        return $false
    }

    Write-Host "Found Microsoft Visual C++ Redistributables (x64):" -ForegroundColor Cyan
    $installedSoftware | ForEach-Object {
        Write-Host " - $($_.DisplayName) (Version $($_.DisplayVersion))"
    }

    $required = [version]$RequiredVersion
    $valid = $false

    foreach ($item in $installedSoftware) {
        try {
            $ver = [version]($item.DisplayVersion.Trim())
            if ($ver -ge $required) {
                $valid = $true
                break
            }
        }
        catch {
            # ignore if version parsing fails
        }
    }

    if ($valid) {
        Write-Host "A Visual C++ Redistributable x64 version $RequiredVersion or newer is installed." -ForegroundColor Green
        return $true
    }
    else {
        Write-Host "No Visual C++ Redistributable x64 version $RequiredVersion or newer is installed." -ForegroundColor Red
        return $false
    }
}
function Install-SQLExpress2022 {
  param(
  [string]$BootstrapperUrl,
  [string]$tempDir
  )
  # -----------------------
  # Download / Install SQL Server 2022 Express
  # -----------------------
  <#  
      Automated SQL Server 2022 Express Install
      -----------------------------------------
      - Downloads the latest bootstrapper from Microsoft
      - Runs bootstrapper in a separate elevated PowerShell window (prevents console wipe)
      - Uses it to fetch the full install media
      - Runs silent unattended install with basic config
      - Verifies that MSSQL$SQLEXPRESS service is running
  #>

  $DownloadDir = "$tempDir\SQL2022"
  $MediaDir    = "$tempDir\SQL2022\Media"

  $ErrorActionPreference = "Stop"

  Write-Host "Installing SQL Server Express..." -ForegroundColor Cyan

  # Ensure directories exist
  if (-not (Test-Path $DownloadDir)) { New-Item -ItemType Directory -Path $DownloadDir | Out-Null }
  if (-not (Test-Path $MediaDir))    { New-Item -ItemType Directory -Path $MediaDir    | Out-Null }

  $bootstrapperExe = Join-Path $DownloadDir "SQL2022-SSEI-Expr.exe"

  Write-Host "Downloading SQL Server Express bootstrapper from $BootstrapperUrl ..."
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri $BootstrapperUrl -OutFile $bootstrapperExe

  Write-Host "Downloaded bootstrapper to $bootstrapperExe"

  # Step 1: Run bootstrapper in a separate elevated PowerShell window
  Write-Host "Launching bootstrapper in a separate elevated PowerShell window to download media..."
  $bootstrapperCmd = "`"$bootstrapperExe`" /ACTION=Download /MEDIAPATH=$MediaDir /QUIET"

  Start-Process -FilePath "powershell.exe" `
      -ArgumentList "-NoProfile", "-Command", $bootstrapperCmd `
      -Verb RunAs -Wait

  # Step 2: Locate setup executable in the downloaded media
  $setupExe = Get-ChildItem -Path $MediaDir -Recurse -Filter "SQLEXPR*.exe" | Select-Object -First 1
  if (-not $setupExe) {
      throw "Could not find SQL Server Express setup executable in $MediaDir"
  }

  Write-Host "Found setup executable: $($setupExe.FullName)"

  # Step 3: Run silent SQL Express install (elevated)
  Write-Host "Starting SQL Express install..."
  Start-Process -FilePath $setupExe.FullName `
      -ArgumentList "/ENU=True",
                    "/ROLE=AllFeatures_WithDefaults",
                    "/ACTION=Install",
                    "/FEATURES=SQLENGINE,REPLICATION",
                    "/USEMICROSOFTUPDATE=True",
                    "/UpdateSource=MU",
                    "/INSTANCENAME=SQLEXPRESS",
                    "/SQLSYSADMINACCOUNTS=BUILTIN\Administrators",
                    "/TCPENABLED=1",
                    "/IACCEPTSQLSERVERLICENSETERMS",
                    "/QS" `
      -Verb RunAs -Wait

  # Step 4: Verify SQL Server Express service status
  $serviceName = "MSSQL`$SQLEXPRESS"
  $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue

  if ($null -eq $service) {
      Write-Host "SQL Server Express service not found. Installation may have failed."
      exit 1
  }
  elseif ($service.Status -ne 'Running') {
      Write-Host "SQL Server Express service is installed but not running. Attempting to start..."
      try {
          Start-Service -Name $serviceName -ErrorAction Stop
          Write-Host "SQL Server Express service started successfully."
      }
      catch {
          Write-Host "Failed to start SQL Server Express service. Error: $_"
          exit 1
      }
  }
  else {
      Write-Host "SQL Server Express service is running." -ForegroundColor Green
      Write-Host "SQL Server 2022 Express installed successfully." -ForegroundColor Green
  }

}
function Test-SqlExpressInstalled {
    <#
    .SYNOPSIS
        Checks if Microsoft SQL Server Express is installed.

    .OUTPUTS
        [bool] True if SQL Express is installed, False if not.
    #>
    [CmdletBinding()]
    param()

    $basePaths = @(
        "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server\Instance Names\SQL"
    )

    $expressInstances = @()

    foreach ($path in $basePaths) {
        if (Test-Path $path) {
            $instanceMap = Get-ItemProperty $path
            foreach ($prop in $instanceMap.PSObject.Properties) {
                $instanceName = $prop.Name
                $instanceId   = $prop.Value

                $setupKey = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$instanceId\Setup"
                if (Test-Path $setupKey) {
                    $setup = Get-ItemProperty $setupKey
                    if ($setup.Edition -like "*Express*") {
                        $expressInstances += [PSCustomObject]@{
                            Instance = $instanceName
                            Edition  = $setup.Edition
                            Version  = $setup.Version
                        }
                    }
                }
            }
        }
    }

    if ($expressInstances.Count -gt 0) {
        Write-Host "SQL Server Express is installed:" -ForegroundColor Green
        $expressInstances | ForEach-Object {
            Write-Host " - Instance: $($_.Instance), Edition: $($_.Edition), Version: $($_.Version)"
        }
        return $true
    }
    else {
        Write-Host "No SQL Server Express instances found." -ForegroundColor Red
        return $false
    }
}
function Install-SSMS {
  param(
  [string]$SsmsUrl,
  [string]$tempDir
  )
  # -----------------------
  # Download / Install SQL Studio Management Suite
  # -----------------------

  $DownloadDir = "$tempDir\SSMS"

  $ErrorActionPreference = "Stop"

  Write-Host "Installing SQL Server Management Studio (SMSS)..." -ForegroundColor Cyan

  # Ensure download directory exists
  if (-not (Test-Path $DownloadDir)) { New-Item -ItemType Directory -Path $DownloadDir | Out-Null }

  $ssmsInstaller = Join-Path $DownloadDir "SSMS-Setup-ENU.exe"

  Write-Host "Downloading SSMS installer from $SsmsUrl ..."
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri $SsmsUrl -OutFile $ssmsInstaller

  Write-Host "Downloaded SSMS installer to $ssmsInstaller"

  # Step 1: Run SSMS silent install (elevated)
  Write-Host "Installing SSMS silently..."
  $proc = Start-Process -FilePath $ssmsInstaller `
      -ArgumentList "/install", "/quiet", "/norestart", "/log", "$DownloadDir\SSMS-Install.log" `
      -Verb RunAs -Wait -PassThru

  if ($proc.ExitCode -ne 0) {
      throw "SSMS install failed with exit code $($proc.ExitCode). See log at $DownloadDir\SSMS-Install.log"
  }

  # Step 2: Verify SSMS installation
  $possiblePaths = @(
      "C:\Program Files (x86)\Microsoft SQL Server Management Studio 21\Common7\IDE\ssms.exe",
      "C:\Program Files (x86)\Microsoft SQL Server Management Studio 20\Common7\IDE\ssms.exe",
      "C:\Program Files (x86)\Microsoft SQL Server Management Studio 19\Common7\IDE\ssms.exe"
  )

  $ssmsExe = $possiblePaths | Where-Object { Test-Path $_ } | Select-Object -First 1

  if (-not $ssmsExe) {
      Write-Host "SSMS executable not found in the expected paths. Please check the install log: $DownloadDir\SSMS-Install.log"
  }

  Write-Host "SSMS installed successfully at: $ssmsExe" -ForegroundColor Green
}
function Test-SSMS {
    <#
    .SYNOPSIS
        Checks if SQL Server Management Studio (SSMS) is installed.
    .OUTPUTS
        [bool] True if SSMS is installed, False otherwise.
    #>
    [CmdletBinding()]
    param()

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $ssms = foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
                Get-ItemProperty |
                Where-Object {
                    $_.PSObject.Properties.Name -contains 'DisplayName' -and
                    $_.DisplayName -like "SQL Server Management Studio*"
                } |
                Select-Object DisplayName, DisplayVersion
        }
    }

    if ($ssms) {
        Write-Host "SQL Server Management Studio (SSMS) is installed:" -ForegroundColor Green
        $ssms | ForEach-Object {
            Write-Host " - $($_.DisplayName) (Version $($_.DisplayVersion))"
        }
        return $true
    }
    else {
        Write-Host "SQL Server Management Studio (SSMS) is not installed." -ForegroundColor Red
        return $false
    }
}
function Install-IIS {
    <#
    .SYNOPSIS
        Installs IIS and/or Web-IP-Security if missing.
    .PARAMETER IISInstalled
        Boolean indicating if IIS is already installed.
    .PARAMETER WebIPInstalled
        Boolean indicating if Web-IP-Security is already installed.
    #>
    [CmdletBinding()]
    param(
        [bool]$IISInstalled,
        [bool]$WebIPInstalled
    )

    Import-Module ServerManager

    if (-not $IISInstalled) {
        Write-Host "Installing IIS..."
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools
        Write-Host "IIS Sucessfully Installed on this Server." -ForegroundColor Green
    }
    else {
        Write-Host "IIS is already installed." -ForegroundColor Green
    }

    if (-not $WebIPInstalled) {
        Write-Host "Installing Web-IP-Security..."
        Add-WindowsFeature Web-IP-Security
        Write-Host "IIS Web IP Security Installed..." -ForegroundColor Green
    }
    else {
        Write-Host "Web-IP-Security is already installed." -ForegroundColor Green
    }
}
function Test-IISFeatures {
    <#
    .SYNOPSIS
        Checks if IIS (Web-Server) and Web-IP-Security are installed.
    .OUTPUTS
        [PSCustomObject] with IISInstalled and WebIPInstalled properties.
    #>
    [CmdletBinding()]
    param()

    Import-Module ServerManager

    $iis   = Get-WindowsFeature -Name Web-Server
    $webip = Get-WindowsFeature -Name Web-IP-Security

    return [PSCustomObject]@{
        IISInstalled   = $iis.Installed
        WebIPInstalled = $webip.Installed
    }
}
function Install-URLRewrite {
  param(
    [string]$RewriteUrl,
    [string]$tempDir
  )
  # -----------------------
  # Install URL Rewrite
  # -----------------------

  Write-Host "Installing IIS URL Rewrite Functionality..." -ForegroundColor Cyan

  $DownloadDir = "$tempDir\URLRewrite"

  # Ensure download directory exists
  if (-not (Test-Path $DownloadDir)) { New-Item -ItemType Directory -Path $DownloadDir | Out-Null }

  $installer = Join-Path $DownloadDir "rewrite_amd64_en-US.msi"

  Write-Host "Downloading IIS URL Rewrite MSI from $RewriteUrl ..."
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri $RewriteUrl -OutFile $installer

  Write-Host "Downloaded to $installer"

  # Step 1: Run silent install (elevated)
  Write-Host "Installing IIS URL Rewrite silently..."
  $proc = Start-Process -FilePath "msiexec.exe" `
      -ArgumentList "/i", "`"$installer`"", "/quiet", "/norestart", "/log", "$DownloadDir\URLRewrite-Install.log" `
      -Verb RunAs -Wait -PassThru

  if ($proc.ExitCode -ne 0) {
      throw "URL Rewrite install failed with exit code $($proc.ExitCode). See log: $DownloadDir\URLRewrite-Install.log"
  }

  # Step 2: Verify installation
  $regKey = "HKLM:\SOFTWARE\Microsoft\IIS Extensions\URL Rewrite"
  if (Test-Path $regKey) {
      Write-Host "IIS URL Rewrite installed successfully." -ForegroundColor Green
  } else {
      Write-Host "IIS URL Rewrite registry key not found. Check log: $DownloadDir\URLRewrite-Install.log" -ForegroundColor Red
  }

}
function Test-IISUrlRewrite {
    <#
    .SYNOPSIS
        Checks if IIS URL Rewrite Module is installed.
    .OUTPUTS
        [bool] True if installed, False otherwise.
    #>
    [CmdletBinding()]
    param()

    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $rewrite = foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
                Get-ItemProperty |
                Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName -like "IIS URL Rewrite*" } |
                Select-Object DisplayName, DisplayVersion
        }
    }

    if ($rewrite) {
        Write-Host "IIS URL Rewrite is installed:" -ForegroundColor Green
        $rewrite | ForEach-Object {
            Write-Host " - $($_.DisplayName) (Version $($_.DisplayVersion))"
        }
        return $true
    }
    else {
        Write-Host "IIS URL Rewrite is not installed." -ForegroundColor Red
        return $false
    }
}
function Install-ARR {
    param (
        [bool]$ARRInstalled,
        [bool]$ARRActivated,
        [string]$ArrUrl,
        [string]$tempDir
    )

    Write-Host "Installing IIS Advanced Request Routing (ARR)..." -ForegroundColor Cyan

    $DownloadDir = Join-Path $tempDir "ARR"

    # Ensure download directory exists
    if (-not (Test-Path $DownloadDir)) {
        New-Item -ItemType Directory -Path $DownloadDir -Force | Out-Null
    }

    $installer = Join-Path $DownloadDir "requestRouter_x64.msi"

    # 1. Install ARR if missing
    if (-not $ARRInstalled) {
        Write-Host "Downloading ARR 3.0 from $ArrUrl ..."
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $ArrUrl -OutFile $installer

        Write-Host "Downloaded ARR to $installer"

        Write-Host "Installing ARR silently..."
        $proc = Start-Process -FilePath "msiexec.exe" `
            -ArgumentList "/i", "`"$installer`"", "/quiet", "/norestart", "/log", "$DownloadDir\ARR-Install.log" `
            -Verb RunAs -Wait -PassThru

        if ($proc.ExitCode -ne 0) {
            throw "ARR install failed with exit code $($proc.ExitCode). See log: $DownloadDir\ARR-Install.log"
        }

        Write-Host "ARR installed successfully." -ForegroundColor Green
    }
    else {
        Write-Host "ARR already installed. Skipping installation." -ForegroundColor Green
    }

    # 2. Enable ARR proxy if not activated
    if (-not $ARRActivated) {
        Write-Host "Enabling ARR proxy in IIS..."
        Import-Module WebAdministration

        if (-not (Get-WebConfiguration "//system.webServer/proxy" -ErrorAction SilentlyContinue)) {
            Add-WebConfigurationSection -PSPath 'MACHINE/WEBROOT/APPHOST' -SectionPath 'system.webServer/proxy'
        }

        Set-WebConfigurationProperty -pspath 'MACHINE/WEBROOT/APPHOST' `
            -filter "system.webServer/proxy" `
            -name "enabled" `
            -value "True"

        Write-Host "ARR proxy enabled in IIS."
    }
    else {
        Write-Host "ARR proxy already enabled in IIS. Skipping activation."
    }
}
function Test-IISARR {
    <#
    .SYNOPSIS
        Checks if IIS Application Request Routing (ARR) is installed
        and if it is activated in IIS configuration.
    .OUTPUTS
        [PSCustomObject] with ARRInstalled and ARRActivated properties.
    #>
    [CmdletBinding()]
    param()

    # ------------------------
    # 1. Check if ARR is installed (registry)
    # ------------------------
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    $arrInstalled = $false
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $match = Get-ChildItem -Path $path -ErrorAction SilentlyContinue |
                Get-ItemProperty |
                Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName -like "*Application Request Routing*" }
            if ($match) {
                $arrInstalled = $true
                break
            }
        }
    }

    # ------------------------
    # 2. Check if ARR is activated in IIS
    # ------------------------
    $arrActivated = $false
    try {
        Import-Module WebAdministration -ErrorAction Stop

        $proxySection = Get-WebConfigurationProperty `
            -pspath 'MACHINE/WEBROOT/APPHOST' `
            -filter "system.webServer/proxy" `
            -name "." -ErrorAction Stop

        if ($proxySection -and $proxySection.enabled -eq $true) {
            $arrActivated = $true
        }
    }
    catch {
        $arrActivated = $false
    }

    # Return both values as an object
    [PSCustomObject]@{
        ARRInstalled = $arrInstalled
        ARRActivated = $arrActivated
    }
}
function Install-PSP{
  param (
    [string]$PSPUrl,
    [string]$tempDir,
    [string]$FrontendHost,
    [int]$httpPort = 5000,
    [int]$httpsPort = 5001
  )

  # -----------------------------------
  # Download and Install PowerSyncPro MSI
  # -----------------------------------

  $DownloadUrl = $PSPUrl
  $DownloadDir = $tempDir
  $Installer   = Join-Path $DownloadDir "PowerSyncProInstaller.msi"
  $LogFile     = Join-Path $DownloadDir "PSPInstaller_Log.txt"

  Write-Host "Beginning Installation of PowerSyncPro..." -ForegroundColor Cyan

  # Ensure download directory exists
  if (-not (Test-Path $DownloadDir)) {
      New-Item -Path $DownloadDir -ItemType Directory -Force | Out-Null
      Write-Host "Created folder: $DownloadDir"
  }

  # Download the MSI
  Write-Host "Downloading PowerSyncPro installer from $DownloadURL..."
  $ProgressPreference = 'SilentlyContinue'
  Invoke-WebRequest -Uri $DownloadUrl -OutFile $Installer -UseBasicParsing
  Write-Host "Downloaded to $Installer"

  # Run MSI installer silently with flags and logging
  Write-Host "Starting MSI installation..."
  $Arguments = @(
    "/i", $Installer,
    "USE_LOCAL_SYSTEM=1",
    "PSP_HTTP_PORT=$httpPort",
    "PSP_HTTPS_PORT=$httpsPort",
    "PSP_BIND_ALL=1",
    "PSP_SQL_SERVER=localhost",
    "PSP_SQL_PORT=1433",
    "PSP_SQL_INSTANCE=SQLEXPRESS",
    "PSP_SQL_DATABASE=PowerSyncProDb",
    "PSP_CREATE_PROXY=True",
    "PSP_PROXY_SITE=`"Default Web Site`"",
    "PSP_DOMAIN_REWRITE=$FrontendHost",
    "PSP_USE_LOCAL_KEY=True",
    "/qn",
    "/L*v", "`"$LogFile`""
)

  Start-Process -FilePath "msiexec.exe" -ArgumentList $Arguments -Wait -NoNewWindow

  Write-Host "Installation complete. Log file: $LogFile" -ForegroundColor Green
  Write-Host "Checking status of PowerSyncPro Service...."

  # Wait for PowerSyncPro service to appear and start
  $svc = $null
  $maxWaitSeconds = 60
  $elapsed = 0

  while ($elapsed -lt $maxWaitSeconds) {
      $svc = Get-Service -Name "PowerSyncPro" -ErrorAction SilentlyContinue
      if ($svc) {
          if ($svc.Status -eq 'Running') {
              Write-Host "PowerSyncPro service is running." -ForegroundColor Green
              break
          }
          elseif ($svc.Status -eq 'Stopped') {
              Write-Host "PowerSyncPro service is installed but stopped. Attempting to start..."
              try {
                  Start-Service -Name "PowerSyncPro"
                  $svc.WaitForStatus('Running','00:00:20')
                  Write-Host "PowerSyncPro service started successfully." -ForegroundColor Green
                  break
              } catch {
                  Write-Warning "PowerSyncPro service could not be started: $_"
                  Exit 1
              }
          }
      }

      Start-Sleep -Seconds 5
      $elapsed += 5
  }

  if (-not $svc -or $svc.Status -ne 'Running') {
      Write-Warning "PowerSyncPro service not found or not running after $maxWaitSeconds seconds."
      Exit 1
  }

}
function Test-PowerSyncPro {
    param(
        [string]$MsiGuid = "{C76A6947-4CAD-4382-9D6F-672ADFB0FCCF}"
    )

    $serviceRunning = $false
    $msiInstalled   = $false

    # 1. Check if service is running
    $svc = Get-Service -Name "PowerSyncPro" -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq "Running") {
        $serviceRunning = $true
    }

    # 2. Check if MSI is installed (registry)
    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    )

    foreach ($key in $uninstallKeys) {
        if (Test-Path "$key\$MsiGuid") {
            $msiInstalled = $true
            break
        }
    }

    # Return true if either condition is met
    return ($serviceRunning -or $msiInstalled)
}
function Install-Scripts {
    <#
    .SYNOPSIS
        Drops a PowerShell script to disk from either a Base64-encoded string or a URL.

    .PARAMETER TargetFile
        The filename to save (e.g., 'Cert-Puller_PoshACME.ps1').

    .PARAMETER TargetFolder
        The folder path where the file should be saved.

    .PARAMETER Encoded
        Base64-encoded string of the script content (optional).

    .PARAMETER Url
        HTTP/HTTPS URL to download the script from (optional).

    .EXAMPLE
        Install-Scripts -TargetFile 'Child.ps1' -TargetFolder 'C:\Scripts' -Encoded $Base64String

    .EXAMPLE
        Install-Scripts -TargetFile 'Child.ps1' -TargetFolder 'C:\Scripts' -Url 'https://example.com/script.ps1'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TargetFile,

        [Parameter(Mandatory)]
        [string]$TargetFolder,

        [string]$Encoded,

        [string]$Url
    )

    try {
        $TargetPath = Join-Path -Path $TargetFolder -ChildPath $TargetFile

        # Ensure the folder exists
        if (-not (Test-Path $TargetFolder)) {
            New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null
        }

        $ChildScript = $null

        if ($Encoded) {
            Write-Host "Decoding Base64 content..." -ForegroundColor Cyan
            $Bytes = [Convert]::FromBase64String($Encoded)
            $ChildScript = [System.Text.Encoding]::UTF8.GetString($Bytes)
        }
        elseif ($Url) {
            Write-Host "Downloading script from $Url ..." -ForegroundColor Cyan
            try {
                $ChildScript = (Invoke-WebRequest -Uri $Url -UseBasicParsing -ErrorAction Stop).Content
            }
            catch {
                throw "Failed to download script from $Url. Error: $($_.Exception.Message)"
            }
        }
        else {
            throw "You must specify either -Encoded or -Url."
        }

        if (-not $ChildScript) {
            throw "No content received. Aborting write operation."
        }

        # Write with UTF-8 (no BOM), cross-version compatible
        if ($PSVersionTable.PSEdition -eq 'Core' -or $PSVersionTable.PSVersion.Major -ge 6) {
            $ChildScript | Out-File -FilePath $TargetPath -Encoding utf8NoBOM -Force
        }
        else {
            $Utf8NoBom = New-Object System.Text.UTF8Encoding($False)
            [System.IO.File]::WriteAllText($TargetPath, $ChildScript, $Utf8NoBom)
        }

        Write-Host "Script written to $TargetPath" -ForegroundColor Green
        return $TargetPath
    }
    catch {
        Write-Host "Error in Install-Scripts: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}
function Install-WebConfig {
    param(
        [string]$FrontendHost,
        [string]$TargetFolder,
        [string]$TargetFile
    )

    # Build paths
    $TargetPath = Join-Path -Path $TargetFolder -ChildPath $TargetFile
    $ForbiddenTargetFolder = Join-Path -Path $TargetFolder -ChildPath "CustomErrors"
    $ForbiddenTarget = Join-Path -Path $ForbiddenTargetFolder -ChildPath "forbidden.html"

    # Construct the Frontend URL
    $FrontendUrl = "https://$FrontendHost/"

    # Full XML web.config with variable substitution
    $WebConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <!-- 403 Error Handling -->
    <httpErrors errorMode="Custom" existingResponse="Replace">
      <remove statusCode="403" />
      <error statusCode="403"
             path="CustomErrors\forbidden.html"
             responseMode="File" />
    </httpErrors>
    <staticContent>
      <mimeMap fileExtension="." mimeType="text/plain" />
    </staticContent>
    <handlers>
      <add name="ACMEStaticFile" path="*" verb="GET" modules="StaticFileModule" resourceType="File" requireAccess="Read" />
    </handlers>
    <proxy enabled="true" />
    <security>
      <ipSecurity allowUnlisted="false">
        <add ipAddress="127.0.0.1" subnetMask="255.255.255.255" allowed="true" />
      </ipSecurity>
    </security>
    <rewrite>
      <rules>
        <rule name="RedirectToHTTPS" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{HTTPS}" pattern="^OFF$" />
            <add input="{REQUEST_URI}" pattern="^/.well-known/" negate="true" />
          </conditions>
          <action type="Redirect" url="https://{HTTP_HOST}/{R:1}" redirectType="Permanent" />
        </rule>
        <rule name="PowerSyncProReverseProxyInboundRule" stopProcessing="true">
          <match url="(.*)" />
          <conditions>
            <add input="{REQUEST_URI}" pattern="^/.well-known/" negate="true" />
          </conditions>
          <action type="Rewrite" url="http://localhost:5000/{R:1}" />
        </rule>
      </rules>
      <outboundRules>
        <rule name="PowerSyncProReverseProxyOutboundRule1" preCondition="PowerSyncProResponseIsHtml">
          <match filterByTags="A, Form, Img" pattern="^http(s)?://localhost:5000/(.*)" />
          <action type="Rewrite" value="$FrontendUrl{R:2}" />
        </rule>
        <preConditions>
          <preCondition name="PowerSyncProResponseIsHtml">
            <add input="{RESPONSE_CONTENT_TYPE}" pattern="^text/html" />
          </preCondition>
        </preConditions>
      </outboundRules>
    </rewrite>
  </system.webServer>
  <location path="Agent">
    <system.webServer>
      <security>
        <ipSecurity allowUnlisted="true" />
      </security>
    </system.webServer>
  </location>
  <location path=".well-known">
    <system.webServer>
      <security>
        <ipSecurity allowUnlisted="true" />
      </security>
    </system.webServer>
  </location>
</configuration>
"@

    $ForbiddenPage = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>403 Forbidden</title>
  <link href="https://fonts.googleapis.com/css2?family=Source+Sans+Pro:wght@400;700&display=swap" rel="stylesheet">
  <style>
    body {
      margin: 0;
      height: 100vh;
      font-family: 'Source Sans Pro', Arial, sans-serif;
      background-color: #00a8ff;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .error-box {
      background: #ffffff;
      padding: 40px;
      border-radius: 6px;
      width: 360px;
      box-shadow: 0 2px 6px rgba(0,0,0,0.15);
      text-align: center;
    }
    h1 {
      margin: 0 0 15px;
      font-size: 2.5em;
      font-weight: 700;
      color: #e84118;
    }
    h2 {
      margin: 0 0 15px;
      font-size: 1.3em;
      font-weight: 400;
      color: #2f3640;
    }
    p {
      margin: 0;
      font-size: 0.95em;
      line-height: 1.4;
      color: #636e72;
    }
  </style>
</head>
<body>
  <div class="error-box">
    <h1>403</h1>
    <h2>Access Forbidden</h2>
    <p>
      You don't have permission to access this resource.<br>
      This may be expected behavior or an error.<br><br>
      Please review the documentation or contact your support staff for assistance.
    </p>
  </div>
</body>
</html>
"@

    # Ensure target folder exists
    if (-not (Test-Path $TargetFolder)) {
        New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null
        Write-Host "Created folder $TargetFolder"
    }

    # Ensure CustomErrors folder exists
    if (-not (Test-Path $ForbiddenTargetFolder)) {
        New-Item -Path $ForbiddenTargetFolder -ItemType Directory -Force | Out-Null
        Write-Host "Created folder $ForbiddenTargetFolder"
    }

    # Write web.config
    $WebConfig | Out-File -FilePath $TargetPath -Encoding UTF8 -Force
    Write-Host "Full web.config written to $TargetPath with backend $FrontendUrl" -ForegroundColor Green

    # Write forbidden.html
    $ForbiddenPage | Out-File -FilePath $ForbiddenTarget -Encoding UTF8 -Force
    Write-Host "Forbidden page template written to $ForbiddenTarget..." -ForegroundColor Green
}
function Harden-TlsConfiguration {
    <#
    .SYNOPSIS
        Hardens the server by disabling legacy SSL/TLS protocols and weak ciphers.

    .DESCRIPTION
        - Disables SSL 2.0, SSL 3.0, TLS 1.0, and TLS 1.1
        - Keeps TLS 1.2 (and TLS 1.3, if supported)
        - Disables weak ciphers (RC4, DES, 3DES, EXPORT, NULL, MD5)
        - Creates required SCHANNEL registry keys if missing
        - Backs up the current SCHANNEL configuration to C:\Temp\SchannelBackup.reg

    .EXAMPLE
        Harden-TlsConfiguration
    #>

    [CmdletBinding()]
    param()

    Write-Host "Starting TLS/SSL hardening..." -ForegroundColor Cyan

    $backupPath = "C:\Temp\SchannelBackup.reg"
    if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory | Out-Null }

    try {
        Write-Host "Backing up current SCHANNEL configuration to $backupPath"
        reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" $backupPath /y | Out-Null
    }
    catch {
        Write-Warning "Failed to back up SCHANNEL registry branch. Continuing anyway."
    }

    # Define protocols to disable
    $Protocols = @(
        "SSL 2.0",
        "SSL 3.0",
        "TLS 1.0",
        "TLS 1.1"
    )

    foreach ($proto in $Protocols) {
        $basePath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$proto"
        $clientKey = Join-Path $basePath "Client"
        $serverKey = Join-Path $basePath "Server"

        foreach ($key in @($clientKey, $serverKey)) {
            if (-not (Test-Path $key)) {
                New-Item -Path $key -Force | Out-Null
            }
            New-ItemProperty -Path $key -Name "Enabled" -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -Path $key -Name "DisabledByDefault" -PropertyType DWord -Value 1 -Force | Out-Null
        }

        Write-Host "Disabled $proto protocol" -ForegroundColor Yellow
    }

    # Enable TLS 1.2
    $tls12Paths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server"
    )

    foreach ($path in $tls12Paths) {
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        New-ItemProperty -Path $path -Name "Enabled" -PropertyType DWord -Value 1 -Force | Out-Null
        New-ItemProperty -Path $path -Name "DisabledByDefault" -PropertyType DWord -Value 0 -Force | Out-Null
    }

    Write-Host "Ensured TLS 1.2 is enabled." -ForegroundColor Green

    # Disable weak ciphers
    $WeakCiphers = @(
        "RC2 128/128", "RC2 40/128", "RC2 56/128",
        "RC4 40/128", "RC4 56/128", "RC4 64/128", "RC4 128/128",
        "DES 56/56", "3DES 168/168",
        "NULL", "EXP", "MD5"
    )

    foreach ($cipher in $WeakCiphers) {
        $cipherPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\$cipher"
        if (-not (Test-Path $cipherPath)) { New-Item -Path $cipherPath -Force | Out-Null }
        New-ItemProperty -Path $cipherPath -Name "Enabled" -PropertyType DWord -Value 0 -Force | Out-Null
        Write-Host "Disabled weak cipher: $cipher" -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "TLS/SSL hardening complete." -ForegroundColor Green
    Write-Host "Reboot the server for changes to take effect." -ForegroundColor Cyan
}

function Initialize-IIS{
  # Unlock IIS Configuration for Static Modules
  # Path to appcmd
  $appcmd = Join-Path $env:SystemRoot "System32\inetsrv\appcmd.exe"

  if (Test-Path $appcmd) {
      Write-Host "Unlocking IIS config sections with appcmd..."

      & $appcmd unlock config /section:system.webServer/handlers
      & $appcmd unlock config /section:system.webServer/modules
      & $appcmd unlock config /section:system.webServer/security/ipSecurity
  }
  else {
      Write-Warning "appcmd.exe not found. IIS may not be installed or management tools missing."
  }

  # Restart IIS
  Write-Host "Restarting IIS..."
  Restart-Service -Name W3SVC -Force
  Write-Host "IIS Restarted..."
  Write-Host "IIS Configuration has been sucessfully configured for use with PowerSyncPro." -ForegroundColor Green
}
function Install-HostsFile {
    param (
        [string]$FrontendHost,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 2
    )

    $HostsPath  = "$env:SystemRoot\System32\drivers\etc\hosts"
    $HostsEntry = "127.0.0.1`t$FrontendHost"

    try {
        $HostsContent = Get-Content $HostsPath -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to read hosts file: $($_.Exception.Message)"
        return $false
    }

    # Strip out existing entries for this host only
    $FilteredHosts = $HostsContent | Where-Object {
        $_ -notmatch "^\s*127\.0\.0\.1\s+$FrontendHost(\s|$)"
    }

    # Add new entry only if it isn't already present
    if (-not ($FilteredHosts -match "^\s*127\.0\.0\.1\s+$FrontendHost(\s|$)")) {
        $FilteredHosts += $HostsEntry
        Write-Host "Adding hosts entry: $HostsEntry"
    }
    else {
        Write-Host "Hosts entry already exists: $HostsEntry"
    }

    # Retry mechanism for writing
    $success = $false
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            $FilteredHosts | Set-Content -Path $HostsPath -Encoding ASCII -ErrorAction Stop
            Write-Host "Hosts file updated successfully." -ForegroundColor Green
            $success = $true
            break
        }
        catch [System.IO.IOException] {
            Write-Warning "Attempt ${i} of ${MaxRetries}: Hosts file in use. Retrying in ${RetryDelaySeconds} second(s)..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
        catch {
            Write-Warning "Unexpected error while updating hosts file: $($_.Exception.Message)"
            break
        }
    }

    if (-not $success) {
        Write-Warning "Failed to update hosts file after $MaxRetries attempts. Entry not added for $FrontendHost."
        return $false
    }
}
# ------------------ Certificate Functions ------------------
function Install-ACMECertificate{
  param(
    [string]$FrontendHost,
    [string]$ContactEmail
  )
  
  # -----------------------------------
  # Install ACME Certificate
  # -----------------------------------

  # Install Posh-ACME
  $ModuleName = "Posh-ACME"

  # Preseed Nuget to ensure user isn't prompted.
  # Ensure NuGet package provider is installed
  try {
      Write-Host "Installing NuGet to install Powershell Modules..." -ForegroundColor Cyan
      Install-PackageProvider -Name NuGet -ForceBootstrap -Force -ErrorAction Stop | Out-Null
      Write-Host "NuGet provider installed successfully." -ForegroundColor Green
  }
  catch {
      Write-Warning "Failed to install NuGet provider: $_"
      exit 1
  }

  # Install the Posh-ACME Module
  Write-Host "Installing Powershell Posh-ACME for certificate request..." -ForegroundColor Cyan
  Install-Module -Name $ModuleName -Force -Scope AllUsers -AllowClobber
  
  # Run Cert-Puller_PoshACME.ps1 with provided options above.
  Write-Host "Beginning certificate request for $FrontendHost with contact e-mail $ContactEmail" -ForegroundColor Cyan
  & C:\Scripts\Cert-Puller_PoshACME.ps1 -Domain $FrontendHost -ContactEmail $ContactEmail
}
function Install-CustomPfxCertificate {
    <#
    .SYNOPSIS
        Imports a user-provided PFX certificate and updates PowerSyncPro + IIS configs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PfxPath,

        [Parameter(Mandatory)]
        [SecureString]$Password,

        [string]$StoreLocation = "Cert:\LocalMachine\My",

        [string]$SiteName = "Default Web Site",

        [string]$AppSettingsPath = "C:\Program Files\PowerSyncPro\appsettings.json"
    )

    try {
        Write-Host "Importing PFX from $PfxPath..." -ForegroundColor Cyan
        $imported = Import-PfxCertificate -FilePath $PfxPath `
            -Password $Password `
            -CertStoreLocation $StoreLocation `
            -Exportable

        if (-not $imported) { throw "Failed to import PFX certificate." }

        $newCert = $imported[0]
        $actualSubject = $newCert.GetNameInfo('SimpleName', $false)
        Write-Host "Imported cert: $actualSubject Thumbprint=$($newCert.Thumbprint)"

        # Remove old certs for same CN
        Get-ChildItem -Path $StoreLocation | Where-Object {
            ($_.Subject -like "*CN=$actualSubject*") -and
            $_.Thumbprint -ne $newCert.Thumbprint
        } | ForEach-Object {
            Write-Host "Removing old certificate Thumbprint=$($_.Thumbprint)"
            Remove-Item -Path "$StoreLocation\$($_.Thumbprint)" -Force
        }

        # Fix private key ACLs for PSP service
        $svc = Get-WmiObject Win32_Service -Filter "Name='PowerSyncPro'"
        if ($svc) {
            $svcUser = $svc.StartName
            if ($svcUser -ne "LocalSystem") {
                try {
                    $ntAccount = New-Object System.Security.Principal.NTAccount($svcUser)
                    $resolvedUser = $ntAccount.Translate([System.Security.Principal.NTAccount]).Value

                    $keyProvInfo = $newCert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                    $machineKeysPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
                    $keyPath = Join-Path $machineKeysPath $keyProvInfo

                    if (Test-Path $keyPath) {
                        $acl = Get-Acl $keyPath
                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($resolvedUser, "FullControl", "Allow")
                        $acl.SetAccessRule($accessRule)
                        Set-Acl -Path $keyPath -AclObject $acl
                        Write-Host "Granted FullControl on private key to $resolvedUser"
                    }
                } catch {
                    Write-Warning "Failed to adjust key permissions: $_"
                }
            }
        }

        # Update appsettings.json safely
        try {
            if (Test-Path $AppSettingsPath) {
                $json = Get-Content $AppSettingsPath -Raw | ConvertFrom-Json

                if ($json.Kestrel.Endpoints.PSObject.Properties.Name -notcontains "Https") {
                    Write-Warning "HTTPS endpoint not found in appsettings.json. Creating one on port 5001."
                    $json.Kestrel.Endpoints | Add-Member -MemberType NoteProperty -Name "Https" -Value @{
                        Url       = "https://*:5001"
                        Protocols = "Http1AndHttp2"
                        Certificate = @{
                            Subject      = $actualSubject
                            Store        = "My"
                            Location     = "LocalMachine"
                            AllowInvalid = $true
                        }
                    }
                    Write-Host "Created HTTPS endpoint in appsettings.json"
                } else {
                    $configuredSubject = $json.Kestrel.Endpoints.Https.Certificate.Subject
                    if ($configuredSubject -ne $actualSubject) {
                        Write-Warning "Configured cert subject ($configuredSubject) does not match new cert ($actualSubject). Updating automatically."
                        $json.Kestrel.Endpoints.Https.Certificate.Subject = $actualSubject
                    } else {
                        Write-Host "appsettings.json already matches current certificate subject."
                    }
                }

                $json | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath -Encoding UTF8
                Write-Host "Updated appsettings.json successfully."
            } else {
                Write-Warning "appsettings.json not found at $AppSettingsPath"
            }
        }
        catch {
            Write-Warning "Failed to update appsettings.json: $($_.Exception.Message)"
        }

        # Update IIS binding (defensive logic)
        Import-Module WebAdministration -ErrorAction Stop
        $certObject = Get-Item "Cert:\LocalMachine\My\$($newCert.Thumbprint)"
        $binding = Get-WebBinding -Name $SiteName -Protocol "https" -Port 443 -ErrorAction SilentlyContinue

        if ($binding) {
            Write-Host "Found existing HTTPS binding for '$SiteName'. Updating with cert $($newCert.Thumbprint)"

            $sslBindings = Get-ChildItem IIS:\SslBindings
            if ($sslBindings) {
                $sslBinding = $sslBindings | Where-Object { $_.Port -eq 443 } | Select-Object -First 1

                if ($sslBinding) {
                    Write-Host "Updating SSL binding path $($sslBinding.PSPath)"
                    Set-Item -Path $sslBinding.PSPath -Value $certObject -Force
                } else {
                    Write-Warning "No SSL binding object found for port 443. Creating one..."
                    $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                    New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
                }
            } else {
                Write-Warning "No SSL bindings currently exist. Creating one..."
                $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
            }
        } else {
            Write-Host "No HTTPS binding found for '$SiteName'. Creating new binding with cert $($newCert.Thumbprint)"
            New-WebBinding -Name $SiteName -Protocol https -Port 443 -IPAddress * -HostHeader ""
            $sslPath = "IIS:\SslBindings\0.0.0.0!443"
            New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
        }

        Restart-Service -Name "PowerSyncPro" -Force
        Write-Host "Restarted PowerSyncPro service."
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)"
    }
}
function Install-SelfSignedCertificate {
    <#
    .SYNOPSIS
        Generates and installs a self-signed certificate for a given FQDN
        and updates PowerSyncPro + IIS configs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DnsName,

        [string]$StoreLocation = "Cert:\LocalMachine\My",

        [string]$SiteName = "Default Web Site",

        [string]$AppSettingsPath = "C:\Program Files\PowerSyncPro\appsettings.json"
    )

    try {
        Write-Host "Creating self-signed certificate for $DnsName..." -ForegroundColor Cyan

        # Generate self-signed cert
        $newCert = New-SelfSignedCertificate `
            -DnsName $DnsName `
            -CertStoreLocation $StoreLocation `
            -FriendlyName "SelfSigned - $DnsName" `
            -KeyExportPolicy Exportable `
            -KeySpec Signature `
            -KeyLength 2048 `
            -HashAlgorithm SHA256 `
            -NotAfter (Get-Date).AddYears(1) `
            -KeyUsage DigitalSignature, KeyEncipherment, DataEncipherment `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2")

        if (-not $newCert) { throw "Failed to generate self-signed certificate for $DnsName" }

        Write-Host "Generated cert: $DnsName Thumbprint=$($newCert.Thumbprint)"

        # Remove old self-signed certs for same CN
        Get-ChildItem -Path $StoreLocation | Where-Object {
            ($_.Subject -like "*CN=$DnsName*") -and
            $_.Thumbprint -ne $newCert.Thumbprint
        } | ForEach-Object {
            Write-Host "Removing old certificate Thumbprint=$($_.Thumbprint)"
            Remove-Item -Path "$StoreLocation\$($_.Thumbprint)" -Force
        }

        # Fix private key ACLs for PSP service
        $svc = Get-WmiObject Win32_Service -Filter "Name='PowerSyncPro'"
        if ($svc) {
            $svcUser = $svc.StartName
            if ($svcUser -ne "LocalSystem") {
                try {
                    $ntAccount = New-Object System.Security.Principal.NTAccount($svcUser)
                    $resolvedUser = $ntAccount.Translate([System.Security.Principal.NTAccount]).Value

                    $keyProvInfo = $newCert.PrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                    $machineKeysPath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys"
                    $keyPath = Join-Path $machineKeysPath $keyProvInfo

                    if (Test-Path $keyPath) {
                        $acl = Get-Acl $keyPath
                        $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($resolvedUser, "FullControl", "Allow")
                        $acl.SetAccessRule($accessRule)
                        Set-Acl -Path $keyPath -AclObject $acl
                        Write-Host "Granted FullControl on private key to $resolvedUser"
                    }
                } catch {
                    Write-Warning "Failed to adjust key permissions: $_"
                }
            }
        }

        # Update appsettings.json safely
        if (Test-Path $AppSettingsPath) {
            $json = Get-Content $AppSettingsPath -Raw | ConvertFrom-Json

            if ($json.Kestrel.Endpoints.PSObject.Properties.Name -notcontains "Https") {
                Write-Warning "HTTPS endpoint not found in appsettings.json. Creating one on port 5001."
                $json.Kestrel.Endpoints | Add-Member -MemberType NoteProperty -Name "Https" -Value @{
                    Url       = "https://*:5001"
                    Protocols = "Http1AndHttp2"
                    Certificate = @{
                        Subject      = $DnsName
                        Store        = "My"
                        Location     = "LocalMachine"
                        AllowInvalid = $true
                    }
                }
                Write-Host "Created HTTPS endpoint in appsettings.json"
            } else {
                $configuredSubject = $json.Kestrel.Endpoints.Https.Certificate.Subject
                if ($configuredSubject -ne $DnsName) {
                    Write-Warning "Configured cert subject ($configuredSubject) does not match new cert ($DnsName). Updating automatically."
                    $json.Kestrel.Endpoints.Https.Certificate.Subject = $DnsName
                } else {
                    Write-Host "appsettings.json already matches the current certificate subject."
                }
            }

            $json | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath -Encoding UTF8
            Write-Host "Updated appsettings.json successfully."
        } else {
            Write-Warning "appsettings.json not found at $AppSettingsPath"
        }

        # Update IIS binding (defensive version)
        Import-Module WebAdministration -ErrorAction Stop
        $certObject = Get-Item "Cert:\LocalMachine\My\$($newCert.Thumbprint)"
        $binding = Get-WebBinding -Name $SiteName -Protocol "https" -Port 443 -ErrorAction SilentlyContinue

        if ($binding) {
            Write-Host "Found existing HTTPS binding for '$SiteName'. Updating with cert $($newCert.Thumbprint)"

            $sslBindings = Get-ChildItem IIS:\SslBindings
            if ($sslBindings) {
                $sslBinding = $sslBindings | Where-Object { $_.Port -eq 443 } | Select-Object -First 1

                if ($sslBinding) {
                    Write-Host "Updating SSL binding path $($sslBinding.PSPath)"
                    Set-Item -Path $sslBinding.PSPath -Value $certObject -Force
                } else {
                    Write-Warning "No SSL binding object found for port 443. Creating one..."
                    $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                    New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
                }
            } else {
                Write-Warning "No SSL bindings currently exist. Creating one..."
                $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
            }
        } else {
            Write-Host "No HTTPS binding found for '$SiteName'. Creating new binding with cert $($newCert.Thumbprint)"
            New-WebBinding -Name $SiteName -Protocol https -Port 443 -IPAddress * -HostHeader ""
            $sslPath = "IIS:\SslBindings\0.0.0.0!443"
            New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
        }

        Restart-Service -Name "PowerSyncPro" -Force
        Write-Host "Restarted PowerSyncPro service."
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)"
    }
}
function Register-CertRenewalScheduledTask {
    <#
    .SYNOPSIS
        Creates or updates a scheduled task to run Cert-Puller_PoshACME.ps1 weekly.

    .DESCRIPTION
        This function registers a scheduled task called 'LetsEncrypt-CertRenewal' that
        runs every Sunday at 3:00 AM as SYSTEM with highest privileges. It points to
        C:\Scripts\Cert-Puller_PoshACME.ps1 and passes required parameters.

    .PARAMETER Domain
        The domain name to renew.

    .PARAMETER ContactEmail
        The email address for Let's Encrypt account registration.

    .PARAMETER DaysBeforeExpiry
        Days before expiry to trigger renewal (default 30).

    .PARAMETER WebRoot
        Path to web server root for HTTP-01 challenge. Default C:\inetpub\wwwroot.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Domain,

        [Parameter(Mandatory)]
        [string]$ContactEmail,

        [int]$DaysBeforeExpiry = 30,

        [string]$WebRoot = "C:\inetpub\wwwroot"
    )

    $taskName = "LetsEncrypt-CertRenewal"
    $scriptPath = "C:\Scripts\Cert-Puller_PoshACME.ps1"

    if (-not (Test-Path $scriptPath)) {
        throw "Script not found at $scriptPath"
    }

    # Build the action with arguments
    $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Domain `"$Domain`" -ContactEmail `"$ContactEmail`" -DaysBeforeExpiry $DaysBeforeExpiry -WebRoot `"$WebRoot`""

    $action  = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest

    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings

    Register-ScheduledTask -TaskName $taskName -InputObject $task -Force

    Write-Host "Scheduled task '$taskName' created/updated successfully." -ForegroundColor Green
}

# ------------------ Helper Functions ------------------
function Get-PfxSubject {
    param (
        [string]$PfxPath,
        [SecureString]$Password
    )

    # Load certificate
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $cert.Import($PfxPath, $Password, 'Exportable,PersistKeySet')

    # Collect DNS names from SAN
    $dnsNames = @()
    foreach ($ext in $cert.Extensions) {
        if ($ext.Oid.FriendlyName -eq "Subject Alternative Name") {
            $entries = $ext.Format($false) -split ',\s*'
            foreach ($entry in $entries) {
                if ($entry -match '^DNS Name=') {
                    $dnsNames += ($entry -replace '^DNS Name=','').Trim().ToLower()
                }
            }
        }
    }

    # If SANs exist, return them
    if ($dnsNames.Count -gt 0) {
        return ,$dnsNames
    }

    # Otherwise return CN fallback
    return ,($cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false).ToLower())
}

function Test-HostnameFormat {
    param([Parameter(Mandatory)][string]$Name)
    return $Name -match '^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$'
}
function Test-IsPublicIPv4 {
    param([Parameter(Mandatory)][string]$IP)
    if ($IP -notmatch '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') { return $false }
    $o = $IP.Split('.').ForEach({ [int]$_ })
    if ($o[0] -eq 10) { return $false }
    if ($o[0] -eq 172 -and $o[1] -ge 16 -and $o[1] -le 31) { return $false }
    if ($o[0] -eq 192 -and $o[1] -eq 168) { return $false }
    if ($o[0] -eq 127) { return $false }
    if ($o[0] -eq 169 -and $o[1] -eq 254) { return $false }
    if ($o[0] -eq 100 -and $o[1] -ge 64 -and $o[1] -le 127) { return $false }
    if ($o[0] -eq 198 -and $o[1] -ge 18 -and $o[1] -le 19) { return $false }
    if ($o[0] -ge 224) { return $false }
    return $true
}
function Resolve-IPv4A {
    param(
        [Parameter(Mandatory)][string]$Name,
        [string[]]$DnsServers = @('1.1.1.1','8.8.8.8','9.9.9.9'),
        [switch]$PublicOnly
    )
    $ips = New-Object System.Collections.Generic.List[string]
    foreach ($srv in $DnsServers) {
        try {
            $rs = Resolve-DnsName -Name $Name -Type A -Server $srv -ErrorAction Stop
            foreach ($rec in ($rs | Where-Object { $_.IPAddress })) {
                if ($rec.IPAddress -and ($ips -notcontains $rec.IPAddress)) {
                    $ips.Add($rec.IPAddress)
                }
            }
        } catch {}
    }
    $result = $ips.ToArray()
    if ($PublicOnly) {
        $result = $result | Where-Object { Test-IsPublicIPv4 $_ }
    }
    return $result
}
function Get-PublicIPv4 {
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}
    $endpoints = @(
        'https://api.ipify.org',
        'https://ifconfig.me/ip',
        'https://ipinfo.io/ip'
    )
    foreach ($u in $endpoints) {
        try {
            $ip = (Invoke-RestMethod -Uri $u -Method GET -TimeoutSec 5).ToString().Trim()
            if ($ip -match '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') { return $ip }
        } catch {}
    }
    throw "Unable to determine public IPv4 from external services."
}
function Test-PortExternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [int]$Port,

        # FQDN or IP address to check externally
        [string]$TargetHost
    )

    $result = [PSCustomObject]@{
        Port          = $Port
        TargetHost    = $TargetHost
        LocalListener = $false
        ExternalCheck = $null
        IsOpen        = $false
        Provider      = $null
    }

    $tcpListener   = $null
    $listenerBound = $false

    if (-not $result.TargetHost) {
        try {
            $pub = Get-PublicIPv4
            if ($pub) { $result.TargetHost = $pub }
        } catch { }
    }

    try {
        # Step 1: Detect existing listener
        $localListener = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
        if ($localListener) {
            Write-Host "Detected an existing listener on port $Port. Skipping local bind test." -ForegroundColor Cyan
            $listenerBound = $true
            $result.LocalListener = $true
        }
        else {
            try {
                $tcpListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $Port)
                $tcpListener.Start()
                Write-Host "Temporary listener started on port $Port." -ForegroundColor Cyan
                # Add Firewall Rule to Allow Port 80
                Add-FirewallRuleForPort -Port 80
                
            } catch {
                Write-Warning "Failed to start temporary listener on port $Port`: $($_.Exception.Message)"
            }
        }

        # Step 2: External checks
        $open = $false
        $why  = $null

        # ---- Provider 1: PortChecker.io
        try {
            $pcUri   = 'https://portchecker.io/api/v1/query'
            $payload = @{ host = $result.TargetHost; ports = @($Port) } | ConvertTo-Json -Depth 3

           # Write-Host "DEBUG: PortChecker.io POST $pcUri with host=$($result.TargetHost)" -ForegroundColor DarkGray
            $resp = Invoke-RestMethod -Method Post -Uri $pcUri -ContentType 'application/json' -Body $payload -TimeoutSec 12
            #Write-Host "DEBUG: PortChecker.io raw response:`n$($resp | ConvertTo-Json -Depth 5)" -ForegroundColor DarkGray

            if ($resp.check -and $resp.check[0].status -eq $true) {
                $open = $true; $why = 'Open (PortChecker.io)'
            }
            elseif ($resp.check -and $resp.check[0].status -eq $false) {
                $open = $false; $why = 'Closed (PortChecker.io)'
            }
            else {
                throw "Unrecognized PortChecker.io response"
            }
        } catch {
            Write-Warning "DEBUG: PortChecker.io failed -> $($_.Exception.Message)"
        }

        # ---- Provider 2: CanYouSeeMe.org fallback
        if (-not $why) {
            try {
                #Write-Host "DEBUG: CanYouSeeMe.org POST check for port $Port" -ForegroundColor DarkGray
                $resp = Invoke-WebRequest -Uri "http://canyouseeme.org/" -Method Post -Body @{ serviceport = $Port } -UseBasicParsing -TimeoutSec 12
                $content = $resp.Content

                if ($content -match "Success") {
                    $open = $true;  $why = 'Open (CanYouSeeMe)'
                }
                elseif ($content -match "Error") {
                    $open = $false; $why = 'Closed (CanYouSeeMe)'
                }
                else {
                    $why = 'Unknown (CanYouSeeMe parse failed)'
                }
            } catch {
                Write-Warning "DEBUG: CanYouSeeMe failed -> $($_.Exception.Message)"
                $why = 'External check failed (all providers)'
            }
        }

        $result.IsOpen        = $open
        $result.ExternalCheck = $why

        if ($why -match 'PortChecker') {
            $result.Provider = 'PortChecker.io'
        }
        elseif ($why -match 'CanYouSeeMe') {
            $result.Provider = 'CanYouSeeMe.org'
        }
        else {
            $result.Provider = 'Unknown'
        }
    }
    finally {
        if ($null -ne $tcpListener -and -not $listenerBound) {
            $tcpListener.Stop()
            Write-Host "Temporary listener stopped on port $Port." -ForegroundColor Cyan
            # Remove Firewall Rule
            Remove-FirewallRuleForPort -Port 80
        }
    }

    return $result
}
function Add-FirewallRuleForPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,

        [string]$RuleName = ""
    )

    if (-not $RuleName -or $RuleName -eq "") {
        $RuleName = "Allow Port $Port TCP"
    }

    $existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Firewall rule '$RuleName' already exists."
    }
    else {
        New-NetFirewallRule -DisplayName $RuleName `
                            -Direction Inbound `
                            -LocalPort $Port `
                            -Protocol TCP `
                            -Action Allow `
                            -Profile Domain,Private,Public | Out-Null
        Write-Host "Firewall rule '$RuleName' created to allow inbound TCP/$Port."
    }
}
function Remove-FirewallRuleForPort {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [int]$Port,

        [string]$RuleName = ""
    )

    if (-not $RuleName -or $RuleName -eq "") {
        $RuleName = "Allow Port $Port TCP"
    }

    $existing = Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue
    if ($existing) {
        Remove-NetFirewallRule -DisplayName $RuleName
        Write-Host "Firewall rule '$RuleName' removed."
    }
    else {
        Write-Host "Firewall rule '$RuleName' not found."
    }
}
function Test-IsServer2016OrNewer {
    <#
    .SYNOPSIS
        Checks if the machine is running Windows Server 2016 or later.
    .DESCRIPTION
        Returns $true only if the OS is a Windows Server edition AND the version
        is 10.0 build 14393 (Server 2016) or newer.
        Prints the detected OS version before returning.
    #>
    try {
        $os = Get-CimInstance Win32_OperatingSystem

        # Display what we detected
        Write-Host "Detected OS: $($os.Caption) ($($os.Version) Build $($os.BuildNumber))" -ForegroundColor Cyan

        # Workstation (desktop OS) → always false
        if ($os.ProductType -eq 1) {
            return $false
        }

        # Parse version
        $version = [version]$os.Version

        # Windows Server 2016 is version 10.0, build 14393+
        if ($version.Major -gt 10) {
            return $true
        }
        elseif ($version.Major -eq 10 -and $version.Build -ge 14393) {
            return $true
        }
        else {
            return $false
        }
    }
    catch {
        Write-Warning "Failed to detect OS version: $($_.Exception.Message)"
        return $false
    }
}
function Get-ListeningPort {
    <#
    .SYNOPSIS
        Returns all listening TCP/UDP ports and their associated processes.
        If PID 4 (System) is found, identifies which IIS site(s) use that port.

    .PARAMETER Port
        One or more port numbers to check (e.g. -Port 80,443,5001).

    .PARAMETER Protocol
        The protocol type: TCP or UDP (default: TCP).

    .PARAMETER All
        When set, lists all listening ports (IPv4 only).

    .EXAMPLE
        Get-ListeningPort -Port 80,443,5001
    .EXAMPLE
        Get-ListeningPort -All | Export-Csv C:\Temp\Ports.csv -NoTypeInformation
    #>

    [CmdletBinding(DefaultParameterSetName='ByPort')]
    param(
        [Parameter(ParameterSetName='ByPort', Mandatory=$true)]
        [ValidateRange(1,65535)]
        [int[]]$Port,

        [Parameter(ParameterSetName='ByPort')]
        [Parameter(ParameterSetName='AllPorts')]
        [ValidateSet('TCP','UDP')]
        [string]$Protocol = 'TCP',

        [Parameter(ParameterSetName='AllPorts')]
        [switch]$All
    )

    try {
        $netstatOutput = netstat -ano | Select-String "LISTENING"
        $listeners = $netstatOutput | Where-Object { $_ -match "^\s*$Protocol" }

        if (-not $listeners) {
            Write-Verbose "No $Protocol listeners found."
            return @()
        }

        # Build IIS site→port map (if available)
        $iisMap = @{}
        try {
            Import-Module WebAdministration -ErrorAction Stop
            Get-Website | ForEach-Object {
                $siteName = $_.Name
                $_.Bindings.Collection | ForEach-Object {
                    $bind = $_.bindingInformation
                    if ($bind -match ":(\d+):?") {
                        $portNum = [int]$matches[1]
                        if (-not $iisMap.ContainsKey($portNum)) { $iisMap[$portNum] = @() }
                        $iisMap[$portNum] += $siteName
                    }
                }
            }
        }
        catch { }

        # Determine which ports to scan
        $targetPorts = if ($All) {
            ($listeners | ForEach-Object {
                if ($_ -match ":(\d+)\s") { [int]$matches[1] }
            } | Sort-Object -Unique)
        }
        else { $Port }

        $results = @()

        foreach ($p in $targetPorts) {
            $portMatches = $listeners | Where-Object { $_ -match "[:.]$p\s" }
            if (-not $portMatches) {
                $results += [PSCustomObject]@{
                    Port      = $p
                    Protocol  = $Protocol
                    LocalAddr = $null
                    State     = 'Not Listening'
                    ProcId    = $null
                    Process   = $null
                    IISSite   = $null
                }
                continue
            }

            foreach ($line in $portMatches) {
                $parts = $line -split '\s+' | Where-Object { $_ -ne '' }

                # Skip IPv6 (anything in [brackets])
                if ($parts[1] -match '^\[.+\]:\d+$') { continue }

                $procId = $parts[-1]
                $process = Get-Process -Id $procId -ErrorAction SilentlyContinue
                $iisSite = if ($procId -eq 4 -and $iisMap.ContainsKey($p)) {
                    ($iisMap[$p] -join ', ')
                } else { $null }

                $results += [PSCustomObject]@{
                    Port      = $p
                    Protocol  = $Protocol
                    LocalAddr = $parts[1]
                    State     = 'LISTENING'
                    ProcId    = $procId
                    Process   = if ($process) { $process.ProcessName } else { 'Unknown' }
                    IISSite   = $iisSite
                }
            }
        }

        return $results
    }
    catch {
        Write-Warning "Error checking port usage: $_"
        return @()
    }
}
function Get-ListeningPort {
    <#
    .SYNOPSIS
        Returns all listening TCP/UDP ports and their associated processes.
        If PID 4 (System) is found, identifies which IIS site(s) use that port.

    .PARAMETER Port
        One or more port numbers to check (e.g. -Port 80,443,5001).

    .PARAMETER Protocol
        The protocol type: TCP or UDP (default: TCP).

    .PARAMETER All
        When set, lists all listening ports (IPv4 only).

    .EXAMPLE
        Get-ListeningPort -Port 80,443,5001
    .EXAMPLE
        Get-ListeningPort -All | Export-Csv C:\Temp\Ports.csv -NoTypeInformation
    #>

    [CmdletBinding(DefaultParameterSetName='ByPort')]
    param(
        [Parameter(ParameterSetName='ByPort', Mandatory=$true)]
        [ValidateRange(1,65535)]
        [int[]]$Port,

        [Parameter(ParameterSetName='ByPort')]
        [Parameter(ParameterSetName='AllPorts')]
        [ValidateSet('TCP','UDP')]
        [string]$Protocol = 'TCP',

        [Parameter(ParameterSetName='AllPorts')]
        [switch]$All
    )

    try {
        $netstatOutput = netstat -ano | Select-String "LISTENING"
        $listeners = $netstatOutput | Where-Object { $_ -match "^\s*$Protocol" }

        if (-not $listeners) {
            Write-Verbose "No $Protocol listeners found."
            return @()
        }

        # Build IIS site→port map (if available)
        $iisMap = @{}
        try {
            Import-Module WebAdministration -ErrorAction Stop
            Get-Website | ForEach-Object {
                $siteName = $_.Name
                $_.Bindings.Collection | ForEach-Object {
                    $bind = $_.bindingInformation
                    if ($bind -match ":(\d+):?") {
                        $portNum = [int]$matches[1]
                        if (-not $iisMap.ContainsKey($portNum)) { $iisMap[$portNum] = @() }
                        $iisMap[$portNum] += $siteName
                    }
                }
            }
        }
        catch { }

        # Determine which ports to scan
        $targetPorts = if ($All) {
            ($listeners | ForEach-Object {
                if ($_ -match ":(\d+)\s") { [int]$matches[1] }
            } | Sort-Object -Unique)
        }
        else { $Port }

        $results = @()

        foreach ($p in $targetPorts) {
            $portMatches = $listeners | Where-Object { $_ -match "[:.]$p\s" }
            if (-not $portMatches) {
                $results += [PSCustomObject]@{
                    Port      = $p
                    Protocol  = $Protocol
                    LocalAddr = $null
                    State     = 'Not Listening'
                    ProcId    = $null
                    Process   = $null
                    IISSite   = $null
                }
                continue
            }

            foreach ($line in $portMatches) {
                $parts = $line -split '\s+' | Where-Object { $_ -ne '' }

                # Skip IPv6 (anything in [brackets])
                if ($parts[1] -match '^\[.+\]:\d+$') { continue }

                $procId = $parts[-1]
                $process = Get-Process -Id $procId -ErrorAction SilentlyContinue
                $iisSite = if ($procId -eq 4 -and $iisMap.ContainsKey($p)) {
                    ($iisMap[$p] -join ', ')
                } else { $null }

                $results += [PSCustomObject]@{
                    Port      = $p
                    Protocol  = $Protocol
                    LocalAddr = $parts[1]
                    State     = 'LISTENING'
                    ProcId    = $procId
                    Process   = if ($process) { $process.ProcessName } else { 'Unknown' }
                    IISSite   = $iisSite
                }
            }
        }

        return $results
    }
    catch {
        Write-Warning "Error checking port usage: $_"
        return @()
    }
}
function Add-ServiceDependency {
    <#
    .SYNOPSIS
        Safely adds one or more dependencies to a Windows service using sc.exe.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string[]]$DependsOn
    )

    # Ensure elevated
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { throw "Please run this in an elevated PowerShell session." }

    # Confirm target service exists
    $null = Get-Service -Name $ServiceName -ErrorAction Stop

    # --- Gather existing dependencies (CIM first, then registry)
    $existing = @()
    try {
        $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
        if ($cim.PSObject.Properties.Name -contains 'Dependencies' -and $cim.Dependencies) {
            $existing = @($cim.Dependencies)
        }
    } catch {}

    if (-not $existing) {
        $svcPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
        try {
            $regVal = (Get-ItemProperty -Path $svcPath -Name DependOnService -ErrorAction SilentlyContinue).DependOnService
            if ($regVal) { $existing = @($regVal) }
        } catch {}
    }

    # --- Merge, remove blanks and duplicates (force array form)
    $newList = @(@($existing) + @($DependsOn)) |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Select-Object -Unique
    $newList = @($newList)

    # --- Build dependency string (slash-separated)
    $depString   = if ($newList.Count -gt 0) { ($newList -join '/') } else { '' }
    $displayList = if ($depString) { $depString } else { '<none>' }

    # --- Status output
    Write-Host "Updating Service Dependencies for $ServiceName to include $DependsOn" -ForegroundColor Cyan

    # --- Apply via sc.exe (always perform update)
    $args = @('config', $ServiceName, "depend= $depString")
    $p = Start-Process -FilePath sc.exe -ArgumentList $args -NoNewWindow -Wait -PassThru
    if ($p.ExitCode -ne 0) { throw "sc.exe failed with exit code $($p.ExitCode)." }

    Write-Host "`nAfter update:" -ForegroundColor Cyan
    sc.exe qc $ServiceName
}
# ------------------ Menu & UI ------------------
function Show-CertificateTypeMenu {
    Clear-Host 2>$null
    Write-Host $asciiLogo -ForegroundColor Cyan
    Write-Host "PowerSyncPro Automated Installation Script - $scriptVer"
    Write-Host ""
    Write-Host "Which type of certificate would you like to use for this installation?" -ForegroundColor Cyan
    Write-Host ""
    $options = @(
        @{ Key = '1'; Name = 'LetsEncrypt'; Desc = 'ACME via DNS Verification' }
        @{ Key = '2'; Name = 'BYOC';        Desc = 'Bring Your Own Certificate (PFX with Private Keys Required)' }
        @{ Key = '3'; Name = 'SelfSigned';  Desc = 'Generate a Self-Signed Certificate (May cause loss of functionality)' }
    )
    foreach ($o in $options) {
        Write-Host ("  [{0}] {1} - {2}" -f $o.Key, $o.Name, $o.Desc)
    }
    Write-Host ""
    Write-Host "  (Press Enter for default: 1 = LetsEncrypt; or type the name, e.g., 'byoc'. Type Q to quit.)"
    Write-Host ""

    while ($true) {
        $raw = Read-Host "Select 1-3, name, or Q"
        $raw = if ([string]::IsNullOrWhiteSpace($raw)) { '1' } else { $raw.Trim() }
        switch -regex ($raw) {
            '^(1|letsencrypt)$' { return 'LetsEncrypt' }
            '^(2|byoc|bring.*)$' { return 'BYOC' }
            '^(3|self.*)$' { return 'SelfSigned' }
            '^(q|quit|exit)$' {
                                throw "User cancelled the wizard."
                            }
            default { Write-Host "Invalid selection. Try again." -ForegroundColor Yellow }
        }
    }
}
# ------------------ Wizard Core ------------------
function Run-Wizard {
    $SelectedCertificateType = Show-CertificateTypeMenu
    Write-Host ""
    Write-Host ("Certificate Type selected: {0}" -f $SelectedCertificateType) -ForegroundColor Green

    $CertConfig = $null

    switch ($SelectedCertificateType) {

        'LetsEncrypt' {
            Write-Host ""
            Write-Host "LetsEncrypt Requirements:" -ForegroundColor Yellow
            Write-Host " - Port 80 must be open on this server to the Internet."
            Write-Host " - You need a public A record for the requested domain pointing here (e.g. psp.company.com --> 1.2.3.4)."
            Write-Host " - You must provide an e-mail address for renewal notifications."
            Write-Host " - LetsEncrypt certificates are only valid for 90 days."
            Write-Host "   A scheduled task will be installed to automatically handle renewal every 90 days."
            Write-Host ""

            # Hostname input with format validation
            while ($true) {
                $PublicHostname = Read-Host "Enter the public hostname (A record) for this system (e.g. psp.company.com)"
                if (Test-HostnameFormat -Name $PublicHostname) { break }
                Write-Host "Invalid hostname format. Please enter a valid FQDN." -ForegroundColor Yellow
            }

            # Email validation loop
            while ($true) {
                $ContactEmail = Read-Host "Enter your e-mail address for LetsEncrypt renewal notifications"
                if ($ContactEmail -match '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$') { break }
                Write-Host "Invalid email format. Please enter a valid e-mail (e.g. user@foo.com or user@foo.co.uk)" -ForegroundColor Yellow
            }

            # Resolve DNS A records using public resolvers
            # Wrap result in an array to allow "count" to always work.
            $ResolvedIPs = @(Resolve-IPv4A -Name $PublicHostname -PublicOnly)
            if (-not $ResolvedIPs -or $ResolvedIPs.Count -eq 0) {
                Write-Host "Warning: No public A records found for $PublicHostname from public DNS resolvers." -ForegroundColor Yellow
            } else {
                Write-Host ("Resolved public A records for {0}: {1}" -f $PublicHostname, ($ResolvedIPs -join ', '))
            }

            # Determine public IPv4 of this system
            $PublicIPv4 = $null
            try {
                $PublicIPv4 = Get-PublicIPv4
                Write-Host ("Detected public IPv4 for this system: {0}" -f $PublicIPv4) -ForegroundColor Cyan
            } catch {
                Write-Host ("Unable to determine public IPv4 automatically: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
            }

            # Handle multiple A records or mismatch
            if ($ResolvedIPs.Count -gt 1) {
                Write-Host ""
                Write-Host "Multiple A records detected for $PublicHostname. This can cause Let's Encrypt validation to fail." -ForegroundColor Yellow
                Write-Host "Resolved IPs: $($ResolvedIPs -join ', ')"
                if ($PublicIPv4) { Write-Host "This system public IP: $PublicIPv4" }
            }

            if ($PublicIPv4) {
                $match = $ResolvedIPs -contains $PublicIPv4
                if (-not $match) {
                    Write-Host ""
                    Write-Host "DNS/IP mismatch detected!" -ForegroundColor Yellow
                    Write-Host (" - Hostname: {0}" -f $PublicHostname)
                    Write-Host (" - Public A records: {0}" -f ($(if ($ResolvedIPs) { $ResolvedIPs -join ', ' } else { 'None' })))
                    Write-Host (" - This system public IP: {0}" -f $PublicIPv4)

                    while ($true) {
                        $action = Read-Host "Do you want to retry DNS (R), change hostname (H), or continue anyway (C)? [R/H/C]"
                        switch -regex ($action) {
                            '^(R|r)$' {
                                $ResolvedIPs = Resolve-IPv4A -Name $PublicHostname -PublicOnly
                                Write-Host ("Refreshed A records: {0}" -f ($(if ($ResolvedIPs) { $ResolvedIPs -join ', ' } else { 'None' })))
                            }
                            '^(H|h)$' {
                                while ($true) {
                                    $PublicHostname = Read-Host "Enter the public hostname (A record) for this system"
                                    if (Test-HostnameFormat -Name $PublicHostname) { break }
                                    Write-Host "Invalid hostname format. Please enter a valid FQDN." -ForegroundColor Yellow
                                }
                                $ResolvedIPs = Resolve-IPv4A -Name $PublicHostname -PublicOnly
                                Write-Host ("Resolved A records for {0}: {1}" -f $PublicHostname, ($(if ($ResolvedIPs) { $ResolvedIPs -join ', ' } else { 'None' })))
                            }
                            '^(C|c)$' { break }
                            default   { Write-Host "Invalid choice. Please select R, H, or C." -ForegroundColor Yellow }
                        }
                        if ($action -match '^(C|c)$') { break }
                    }
                }
            }

            # External port 80 check
            try {
                $portResult = Test-PortExternal -Port 80
                if ($null -ne $portResult) {
                    if ($portResult.IsOpen) {
                        Write-Host ("External connectivity check: Port {0} is OPEN ({1})" -f $portResult.Port, $portResult.ExternalCheck) -ForegroundColor Green
                    }
                    else {
                        Write-Host ("External connectivity check: Port {0} is CLOSED ({1})" -f $portResult.Port, $portResult.ExternalCheck) -ForegroundColor Red
                        $retry = Read-Host "Port 80 must be open for LetsEncrypt. Do you want to continue anyway? (Y/N)"
                        if ($retry -notmatch '^(Y|y)$') {
                            throw "LetsEncrypt prerequisites not met - port 80 is closed."
                        }
                    }
                }
                else {
                    Write-Host "External connectivity test did not return a result. Continuing with caution." -ForegroundColor Yellow
                }
            }
            catch {
                Write-Host "Error while testing external connectivity: $($_.Exception.Message)" -ForegroundColor Red
            }

            # Final config object
            $CertConfig = [PSCustomObject]@{
                Type         = 'LetsEncrypt'
                Hostname     = $PublicHostname
                Email        = $ContactEmail
                DnsARecords  = $ResolvedIPs
                PublicIPv4   = $PublicIPv4
                DnsMatchesIP = [bool]($PublicIPv4 -and ($ResolvedIPs -contains $PublicIPv4))
                Port80Open   = ($portResult.IsOpen -eq $true)
            }
        }

        'BYOC' {
            Write-Host ""
            Write-Host "Bring Your Own Certificate:" -ForegroundColor Cyan

            # --- Look in current directory for .pfx files ---
            $localPfxFiles = @(Get-ChildItem -Path (Get-Location) -Filter *.pfx -File -ErrorAction SilentlyContinue)

            if ($localPfxFiles.Count -gt 0) {
                Write-Host "Found the following PFX files in the current directory:" -ForegroundColor Cyan
                for ($i=0; $i -lt $localPfxFiles.Count; $i++) {
                    Write-Host ("[{0}] {1}" -f ($i+1), $localPfxFiles[$i].Name)
                }
                while ($true) {
                    $choice = Read-Host "Select which file to use (1-$($localPfxFiles.Count)), or press Enter to type a path"
                    if ([string]::IsNullOrWhiteSpace($choice)) {
                        # user wants to manually type path
                        $PfxPath = $null
                        break
                    }
                    elseif ([int]::TryParse($choice, [ref]$null) -and $choice -ge 1 -and $choice -le $localPfxFiles.Count) {
                        $PfxPath = $localPfxFiles[$choice-1].FullName
                        break
                    }
                    Write-Host "Invalid selection. Please enter a number between 1 and $($localPfxFiles.Count) or press Enter." -ForegroundColor Yellow
                }
            } 

            # If no files found, or user pressed Enter, prompt for path
            if (-not $PfxPath) {
                while ($true) {
                    $rawPath = Read-Host "Please provide the full path of a PFX file (e.g. C:\Temp\companycert.pfx)"
                    $PfxPath = $rawPath.Trim('"').Trim("'")
                    $PfxPath = [System.Environment]::ExpandEnvironmentVariables($PfxPath)
                    try { $PfxPath = [System.IO.Path]::GetFullPath((Join-Path -Path (Get-Location) -ChildPath $PfxPath)) } catch {}
                    if (-not (Test-Path -Path $PfxPath -PathType Leaf)) { Write-Host "The file path does not exist. Please try again." -ForegroundColor Yellow; continue }
                    if ([System.IO.Path]::GetExtension($PfxPath) -ne ".pfx") { Write-Host "The file must have a .pfx extension. Please try again." -ForegroundColor Yellow; continue }
                    break
                }
            }

            # --- Prompt for password + read cert ---
            while ($true) {
                $PfxPass = Read-Host "Please provide the password for the provided PFX file" -AsSecureString
                try {
                    $CertFqdns = Get-PfxSubject -PfxPath $PfxPath -Password $PfxPass

                    # Normalize to array
                    if (-not ($CertFqdns -is [System.Array])) {
                        $CertFqdns = @($CertFqdns)
                    }

                    if (-not $CertFqdns -or $CertFqdns.Count -eq 0) { throw "Unable to read any DNS names from the certificate." }

                    Write-Host "Certificate loaded. Found the following DNS names:" -ForegroundColor Green
                    $CertFqdns | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
                    break
                } catch {
                    Write-Host ("Failed to open PFX or read subject: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
                    $retry = Read-Host "Password may be incorrect. Try again? (Y/N)"
                    if ($retry -notmatch '^(Y|y)$') { throw "Invalid PFX or password." }
                }
            }

            # --- Detect wildcards ---
            $WildcardFqdns = @($CertFqdns | Where-Object { $_.StartsWith('*.') })
            $ResolvedHostname = $null
            $ChosenWildcard   = $null

            if ($WildcardFqdns.Count -gt 1) {
                Write-Host "Multiple wildcard domains detected:" -ForegroundColor Yellow
                for ($i=0; $i -lt $WildcardFqdns.Count; $i++) {
                    Write-Host ("[{0}] {1}" -f ($i+1), $WildcardFqdns[$i])
                }
                while ($true) {
                    $choice = Read-Host "Select which wildcard root to use (1-$($WildcardFqdns.Count))"
                    if ([int]::TryParse($choice, [ref]$null) -and $choice -ge 1 -and $choice -le $WildcardFqdns.Count) {
                        $ChosenWildcard = $WildcardFqdns[$choice-1]
                        break
                    }
                    Write-Host "Invalid choice. Please enter a number between 1 and $($WildcardFqdns.Count)." -ForegroundColor Yellow
                }
            } elseif ($WildcardFqdns.Count -eq 1) {
                $ChosenWildcard = $WildcardFqdns[0]
            }

            # --- Handle wildcard resolution ---
            if ($ChosenWildcard) {
                $wildRoot = $ChosenWildcard.Substring(2)
                Write-Host ("Detected wildcard certificate for: {0}" -f $wildRoot) -ForegroundColor Yellow
                while ($true) {
                    $ResolvedHostname = Read-Host ("Enter the specific FQDN for this host (must be exactly one label under {0}, e.g. host.{0})" -f $wildRoot)
                    if ([string]::IsNullOrWhiteSpace($ResolvedHostname)) { Write-Host "Hostname cannot be empty." -ForegroundColor Yellow; continue }
                    $ResolvedHostname = $ResolvedHostname.Trim()
                    if (-not (Test-HostnameFormat -Name $ResolvedHostname)) { Write-Host "Invalid hostname format. Please enter a valid FQDN." -ForegroundColor Yellow; continue }

                    $hostDots = ($ResolvedHostname -split '\.').Count
                    $rootDots = ($wildRoot -split '\.').Count
                    $endsOk   = $ResolvedHostname.ToLower().EndsWith("." + $wildRoot.ToLower())
                    $oneLevel = ($hostDots -eq ($rootDots + 1))

                    if ($endsOk -and $oneLevel) {
                        Write-Host ("Hostname {0} is valid for wildcard {1}" -f $ResolvedHostname, $ChosenWildcard) -ForegroundColor Green
                        break
                    } else {
                        Write-Host ("{0} is not valid for wildcard {1}. Must add exactly one label under {2}." -f $ResolvedHostname, $ChosenWildcard, $wildRoot) -ForegroundColor Yellow
                    }
                }
            } else {
                # No wildcard found — just pick the first SAN / CN
                $ResolvedHostname = $CertFqdns[0]
            }

            # --- Final config object ---
            $CertConfig = [PSCustomObject]@{
                Type              = 'BYOC'
                PfxPath           = $PfxPath
                PfxPass           = $PfxPass
                CertFqdns         = $CertFqdns
                ChosenWildcard    = $ChosenWildcard
                Hostname          = $ResolvedHostname
                WildcardValidated = [bool]$ChosenWildcard
            }
        }



        'SelfSigned' {
            Write-Host ""
            Write-Host "WARNING: Self-Signed certificates may cause functionality issues when using PowerSyncPro with SSL. This option is not recommended." -ForegroundColor Red
            Write-Host "You may need to export the self signed certificate produced into the Root Certificate Store on Endpoints for full functionality."

            while ($true) {
                $SelfSignedHostname = Read-Host "Enter the FQDN that will be used for this system (e.g. psp.company.com)"
                if (Test-HostnameFormat -Name $SelfSignedHostname) { break }
                Write-Host "Invalid hostname format. Please enter a valid FQDN." -ForegroundColor Yellow
            }

            $CertConfig = [PSCustomObject]@{
                Type     = 'SelfSigned'
                Hostname = $SelfSignedHostname
            }
        }
    }

    return $CertConfig
}
# -------------------------------------------------
# Menu / Script Actions / Logic
# Initialize logging

# Register exit cleanup handler
#Start Transcription
if (-not (Test-Path -Path (Split-Path $LogPath -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $LogPath -Parent) -Force | Out-Null
    }

Start-Transcript -Path $LogPath -Append

Register-EngineEvent PowerShell.Exiting -Action {
    try { Stop-Transcript | Out-Null } catch {}
} | Out-Null

try{
    $ErrorActionPreference = "Stop"

    # Test if PowerSyncPro is running, if it is we should immediately bail out.
    if (Test-PowerSyncPro) {
        Write-Warning "PowerSyncPro Service is already installed or running on this system. Aborting installation script."
        exit 1
    }

    # Test if machine is a server - we shouldn't run on non-server OS and versions under 2016.
    Write-Host "PowerSyncPro Service is *not* present or running - continuing installation..." -ForegroundColor Green

    if (-not (Test-IsServer2016OrNewer)) {
        Write-Host "This operating system is not supported. Windows Server 2016 or newer is required." -ForegroundColor Red
        exit 1   # stops the script with an error code
    }

    Write-Host "OS check passed - continuing installation..." -ForegroundColor Green

    # Test if Ports we require during the installation are in-use.  Bail out if conflicts occur.
    # Define which ports to check
    $checkPorts = 80,443,5000,5001
    $noConflicts = $false

    # Retrieve all listeners
    $listeners = Get-ListeningPort -Port $checkPorts
    $listeners = @($listeners)

    # Filter to only active listeners
    $active = @($listeners | Where-Object { $_.State -eq 'LISTENING' -and $_.LocalAddr })

    if ($active.Count -eq 0) {
        Write-Host "No conflicts detected. All required ports are available." -ForegroundColor Green
        $noConficts = $true
    }

    # Separate groups
    if (-not $noConflicts){
        $reverseProxyConflicts = $active | Where-Object { $_.Port -in 80,443 }
        $kestrelConflicts      = $active | Where-Object { $_.Port -in 5000,5001 }

    $conflictDetected = $false

    # IIS / Reverse Proxy check
    if ($reverseProxyConflicts) {
        Write-Host ""
        Write-Host "[WARNING] Reverse Proxy (IIS) Port Conflicts Detected" -ForegroundColor Yellow
        foreach ($c in $reverseProxyConflicts) {
            if ($c.IISSite) {
                Write-Host (" Port {0} in use by IIS site '{1}' (Process: {2})" -f $c.Port, $c.IISSite, $c.Process) -ForegroundColor Yellow
            } else {
                Write-Host (" Port {0} in use by process '{1}' (PID {2})" -f $c.Port, $c.Process, $c.ProcId) -ForegroundColor Yellow
            }
        }

        Write-Host ""
        Write-Host "Port 80 or 443 are used by IIS or another process." -ForegroundColor Yellow
        Write-Host "If you continue, current IIS configuration may be modified or overwritten." -ForegroundColor Yellow
        Write-Host "If you have a default IIS configuration on this system, you can safely ignore this warning." -ForegroundColor Yellow
        Write-Host "If you are using IIS on this system for another purpose, you should *NOT* continue." -ForegroundColor Yellow

        $response = Read-Host "Do you want to continue setup anyway? (Y/N)"
        if ($response -notmatch '^[Yy]$') {
            Write-Host ""
            Write-Host "Setup aborted by user to prevent overwriting IIS configuration." -ForegroundColor Red
            exit 1
        }
    }

    # Kestrel backend port conflicts
    if ($kestrelConflicts) {
        Write-Host ""
        Write-Host "[ERROR] PowerSyncPro Backend Port Conflicts Detected" -ForegroundColor Red
        foreach ($c in $kestrelConflicts) {
            Write-Host (" Port {0} in use by process '{1}' (PID {2})" -f $c.Port, $c.Process, $c.ProcId) -ForegroundColor Red
        }
        Write-Host ""
        Write-Host "PowerSyncPro will not be able to bind to these ports. Please review the processes using them and reconfigure them if possible." -ForegroundColor Red
        exit 1
    }

    Write-Host "Port check complete. No blocking conflicts detected. Continuing setup..." -ForegroundColor Green
    }
    
    Start-Sleep -Seconds 3
    
    # Start Menu Loop
    # ------------------ Main Loop ------------------
    try {
        while ($true) {
            $CertConfig = Run-Wizard

            Write-Host ""
            Write-Host "Summary of Certificate Configuration:" -ForegroundColor Green
            $CertConfig | Format-List | Out-String | Write-Host

            $confirm = Read-Host "Do you want to continue with this configuration? (Y/N)"
            if ($confirm -match '^(Y|y)$') { break }
            Write-Host ""
            Write-Host "Restarting wizard..." -ForegroundColor Yellow
        }

        Write-Host ""
        Write-Host "Certificate configuration accepted, beginning installation." -ForegroundColor Green
    }
    catch {
        Write-Host ("Error: {0}" -f $_.Exception.Message) -ForegroundColor Red
        exit 1
    }


    # Grab Details for CertConfig
    $FrontendHost = $CertConfig.Hostname # FrontendHost FQDN
    $CertType = $CertConfig.Type # Type of Cert Chosen

    # Begin Installation

    Write-Host "Beginning install of PowerSyncPro dependencies and application...." -ForegroundColor Cyan
    Write-Host "Using a $CertType Certificate with a Hostname of $FrontendHost..." -ForegroundColor Cyan

    # Check / Install All Dependencies
    if (-not (Test-dotNet8Hosting -RequiredVersions $DotNetVer)) {
    Install-dotNet8Hosting -metadataUrl $metadataUrl -tempDir $tempDir 
    }

    if (-not (Test-VCRedistributable -RequiredVersion $vcVer)){
    Install-VCRedistributable -DownloadURL $vcDownloadURL -TempDir $tempDir
    }

    if (-not (Test-SqlExpressInstalled)){
    Install-SQLExpress2022 -BootstrapperUrl $SQLBootstrapperUrl -tempDir $tempDir
    }

    if (-not (Test-SSMS)){
    Install-SSMS -SsmsUrl $SsmsUrl -tempDir $tempDir
    }

    # Test IIS and other functions are installed.
    Write-Host "Checking current IIS Status on system..." -ForegroundColor Cyan
    $features = Test-IISFeatures
    Install-IIS -IISInstalled $features.IISInstalled -WebIPInstalled $features.WebIPInstalled

    # Install IIS Dependencies
    # Install IIS URL Rewrite
    if(-not (Test-IISUrlRewrite)){
    Install-URLRewrite -RewriteUrl $RewriteUrl -tempDir $tempDir
    }

    # Install and Activate IIS ARR (Advanced Request Routing)
    $arrStatus = Test-IISARR
    Install-ARR -ARRInstalled $arrStatus.ARRInstalled -ARRActivated $arrStatus.ARRActivated -ArrUrl $ArrUrl -tempDir $tempDir


    # Install PSP w/ SQL Express Backend, Sane Defaults - We don't need to check its running, we did that above.
    Install-PSP -PSPUrl $PSPUrl -tempDir $tempDir -FrontendHost $FrontendHost

    # Set PSP to be Dependent on SQL running before it starts as a service.
    Add-ServiceDependency -ServiceName "PowerSyncPro" -DependsOn $ExpectedSQLServiceName

    # Drop Support Scripts and custom Webconfig - We don't check that they already exist.
    # ACME Cert Puller - if doing a LetsEncrypt Certificate
    if ($CertType -eq "LetsEncrypt"){
        Write-Host "Installing ACME / LetsEncrypt Certificate Tool `($CertPullerScriptName`) to $ScriptFolder" -ForegroundColor Cyan
        Install-Scripts -TargetFile $CertPullerScriptName -TargetFolder $ScriptFolder -URL $CertPullerURL
    }

    # Cert Renewer - if doing a BYOC Certificate Install
    if ($CertType -eq "BYOC"){
        Write-Host "Installing Certificate Renewal Tool `($CertRenewerScriptName`) to $ScriptFolder" -ForegroundColor Cyan
        Install-Scripts -TargetFile $CertRenewerScriptName -TargetFolder $ScriptFolder -URL $CertRenewerURL
    }
 
    # WebConfig Editor Tool
    Write-Host "Installing Web.Config Editor Tool `($WebConfigScriptName`) to $ScriptFolder" -ForegroundColor Cyan
    Install-Scripts -TargetFile $WebConfigScriptName -TargetFolder $ScriptFolder -URL $WebConfigScriptURL

    # Install Custom WebConifg
    Write-Host "Installing Customized $WebConfigName to $WebConfigFolder" -ForegroundColor Cyan
    Install-WebConfig -FrontendHost $FrontendHost -TargetFolder $WebConfigFolder -TargetFile $WebConfigName

    # Setup IIS and Unlock Required Sections
    Write-Host "Unlocking configuration section for web.config..." -ForegroundColor Cyan
    Initialize-IIS

    # Add Frontend Host to local Hosts File
    Write-Host "Editing Hosts file to add entry for $FrontendHost pointing to 127.0.0.1..." -ForegroundColor Cyan
    Install-HostsFile -FrontendHost $FrontendHost

    # Add Firewall Rule for Port 443
    Write-Host "Opening Port 443 on Firewall for IIS..."
    Add-FirewallRuleForPort -Port 443

    # Harden TLS / SSL - Disable Insecure Ciphers
    Harden-TlsConfiguration

    # Install certificate depending on type chosen at beginning if script.
    switch ($CertType) {
        'LetsEncrypt' {
            Write-Host "Installation tasks completed, getting a certificate from LetsEncrypt for $FrontendHost..." -ForegroundColor Cyan
            try{
                Write-Host "Opening Port 80 on Firewall for IIS, ensuring LetsEncrypt can reach server..."
                Add-FirewallRuleForPort -Port 80
                Install-ACMECertificate -FrontendHost $FrontendHost -ContactEmail $CertConfig.Email
                $certInstalled = $true

                # Register Scheduled Task to Renew Certificate.
                Write-Host "Registering Scheduled task to renew LetsEncrypt Certificate..."
                Register-CertRenewalScheduledTask -Domain $FrontendHost -ContactEmail $CertConfig.Email
                Write-Host "Scheduled task registered..."
                
            } catch {
                Write-Warning "LetsEncrypt install failed: $($_.Exception.Message)"
                $certInstalled = $false
            }
        }
        'BYOC' {
            Write-Host "Installation tasks completed, installing BYOC certificate for $FrontendHost..." -ForegroundColor Cyan
            try{
                Install-CustomPfxCertificate -PfxPath $CertConfig.PfxPath -Password $CertConfig.PfxPass
                $certInstalled = $true
            } catch {
                Write-Warning "BYOC certificate install failed: $($_.Exception.Message)"
                $certInstalled = $false
            }
        }
        'SelfSigned' {
            try{
                Write-Host "Installation tasks completed, installing self-signed certificate for $FrontendHost..." -ForegroundColor Cyan
                Install-SelfSignedCertificate -DnsName $FrontendHost
                $certInstalled = $true
            } catch {
                Write-Warning "Self Signed certificate install failed: $($_.Exception.Message)"
                $certInstalled = $false
            }
        }
        default {
            Write-Warning "Unknown certificate type: $CertType - Certificate has not been installed.  Please contact support."
        }
    }


    # Handle Certificate Installation Failures.
    if ($certInstalled) {
        Write-Host "Certificate installation completed successfully." -ForegroundColor Green
    }
    else {
        Write-Host "Certificate installation failed." -ForegroundColor Red

        switch ($CertType) {
            'LetsEncrypt' {
                Write-Host "Troubleshooting steps for LetsEncrypt:" -ForegroundColor Yellow
                Write-Host " - Ensure Port 80 is open to the Internet (Firewall / NSG / load balancer rules)." -ForegroundColor Yellow
                Write-Host " - Verify DNS A record for $FrontendHost points to this systems public IP." -ForegroundColor Yellow
                Write-Host " - The script to retry is located at: C:\Scripts\Cert-Puller_PoshACME.ps1" -ForegroundColor Yellow
                Write-Host " - Example retry command:" -ForegroundColor Yellow
                Write-Host "   `"C:\Scripts\Cert-Puller_PoshACME.ps1 -Domain $FrontendHost -ContactEmail $($CertConfig.Email)`"" -ForegroundColor Cyan
            }

            'BYOC' {
                Write-Host "Troubleshooting steps for BYOC (PFX Import):" -ForegroundColor Yellow
                Write-Host " - Ensure the PFX file exists at: $($CertConfig.PfxPath)" -ForegroundColor Yellow
                Write-Host " - Verify the password is correct and contains the private key." -ForegroundColor Yellow
                Write-Host " - Confirm the certificate subject matches the intended hostname $FrontendHost." -ForegroundColor Yellow
                Write-Host "Contact Support if you continue to have issues."
            }

            'SelfSigned' {
                Write-Host "Troubleshooting steps for Self-Signed certificates:" -ForegroundColor Yellow
                Write-Host " - Ensure the FQDN you provided ($FrontendHost) is correct." -ForegroundColor Yellow
                Write-Host " - Be aware self-signed certs may cause SSL/TLS trust warnings in browsers and clients." -ForegroundColor Yellow
                Write-Host " - If possible, consider switching to LetsEncrypt or BYOC for production environments." -ForegroundColor Yellow
            }

            default {
                Write-Host "Unknown certificate type $CertType - no troubleshooting guidance available. Contact Support." -ForegroundColor Yellow
            }
        }
    }

    # Complete.
    Write-Host "`n"
    Write-Host "------------------------------------------------------------------------------------------------------------" -ForegroundColor Green
    Write-Host $asciiLogo
    if ($certInstalled) {
        Write-Host "Installation Complete and Certificate Installed..." -ForegroundColor Green
    }
    else {
        Write-Host "Installation Complete but Certificate Installation Failed..." -ForegroundColor Red
    }
    Write-Host "`n"

    # Print Relevant Info per Certificate Type
    switch($CertType){
        'LetsEncrypt' {
            Write-Host "LetsEncrypt certificates must be renewed every 90 days." -ForegroundColor Cyan
            Write-Host "A scheduled task has been installed to run C:\Scripts\Cert-Puller_PoshACME.ps1 every week to check the status of the"
            Write-Host "certificate and renew it if necessary."
            Write-Host "You must leave Port 80 on this server exposed to the Internet for sucessful certificate renewals."
        }
        'BYOC' {
            Write-Host "Your BYOC PFX Certificate has been installed." -ForegroundColor Cyan
            Write-Host "To renew your certificate, please use the renewal script at C:\Scripts\Cert-Renewer.ps1"
        }
    }
    Write-Host "`n"
    Write-Host "Admin access to PSP via the Reverse Proxy - e.g. https://$FrontEndHost has been restricted to localhost only." -ForegroundColor Cyan
    Write-Host "You can modify hosts which are allowed to access the HTTPS Reverse Proxy by running C:\Scripts\WebConfig_Editor.ps1."
    Write-Host "This restriction does not apply on https://$FrontEndHost/Agent which is used for the PSP Migration Agent."
    Write-Host "`n"
    Write-Host "You can now access PowerSyncPro at https://$FrontEndHost/ from this system." -ForegroundColor Yellow
    Write-Host "The default password is admin / 123qwe, please change it." -ForegroundColor Yellow
    Write-Host "`n"
    Write-Host "We recommend you reboot your server before using PowerSyncPro." -ForegroundColor Yellow
    Write-Host "If you need additional support or assistance:"
    Write-Host "PowerSyncPro Knowledge Base: https://kb.powersyncpro.com/"
    Write-Host "Open a ticket at https://tickets.powersyncpro.com/."
    Write-Host "`n"
    Write-Host "Congrats!" -ForegroundColor Green
    Write-Host "------------------------------------------------------------------------------------------------------------" -ForegroundColor Green
}
catch {
    Write-Error "Unhandled error: $($_.Exception.Message)"
}
finally{
    Stop-Transcript
}