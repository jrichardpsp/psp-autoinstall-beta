<#
.DESCRIPTION
    Complete configuration of PowerSyncPro Azure Marketplace Image including certificate installation and system hardening.

    Script assumes that:
        - PSP is already installed w/ Necessary Dependencies
        - Cert-Puller_PoshACME.ps1, Cert-Renewer.ps1, and WebConfig_Editor.ps1 are present in C:\Scripts
        - IIS is Installed with Web IP Security Module
 
.NOTES
    Date            December/2025
    Disclaimer:     This script is provided 'AS IS'. No warrantee is provided either expressed or implied. Declaration Software Ltd cannot be held responsible for any misuse of the script.
    Version: 0.1
    Updated: Initial Public Release.
    Copyright (c) 2025 Declaration Software
#>
#Requires -RunAsAdministrator

# Logging
$tempDir = "C:\Temp" # Temporary Directory for Downloads, etc.
$LogPath = "C:\Temp\PSP_AutoInstall.txt" # Logging Location

# Web.Config Information
$WebConfigName = "web.config"
$WebConfigFolder = "C:\inetpub\wwwroot"

# General Variables
$scriptVer = "v0.1"

$asciiLogo=@"
 ____                        ____                   ____            
|  _ \ _____      _____ _ __/ ___| _   _ _ __   ___|  _ \ _ __ ___  
| |_) / _ \ \ /\ / / _ \ '__\___ \| | | | '_ \ / __| |_) | '__/ _ \ 
|  __/ (_) \ V  V /  __/ |   ___) | |_| | | | | (__|  __/| | | (_) |
|_|   \___/ \_/\_/ \___|_|  |____/ \__, |_| |_|\___|_|   |_|  \___/ 
                                   |___/                            
"@

# ------------------ Functions ------------------
# ------------------ Logging Functions ------------------
function Info  { param($Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Ok    { param($Message) Write-Host "[+] $Message" -ForegroundColor Green }
function Warn  { param($Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Err   { param($Message) Write-Host "[-] $Message" -ForegroundColor Red }
# ------------------ Test / Install Functions ------------------
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
        Info "Installing IIS..."
        Install-WindowsFeature -Name Web-Server -IncludeManagementTools
        Ok "IIS Sucessfully Installed on this Server."
    }
    else {
        Ok "IIS is already installed."
    }

    if (-not $WebIPInstalled) {
        Info "Installing Web-IP-Security..."
        Add-WindowsFeature Web-IP-Security
        Ok "IIS Web IP Security Installed..."
    }
    else {
        Ok "Web-IP-Security is already installed."
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
    <httpErrors errorMode="Custom" existingResponse="Auto" defaultResponseMode="File">
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
        Info "Created folder $TargetFolder"
    }

    # Ensure CustomErrors folder exists
    if (-not (Test-Path $ForbiddenTargetFolder)) {
        New-Item -Path $ForbiddenTargetFolder -ItemType Directory -Force | Out-Null
        Info "Created folder $ForbiddenTargetFolder"
    }

    # Write web.config
    $WebConfig | Out-File -FilePath $TargetPath -Encoding UTF8 -Force
    Ok "Full web.config written to $TargetPath with backend $FrontendUrl"

    # Write forbidden.html
    $ForbiddenPage | Out-File -FilePath $ForbiddenTarget -Encoding UTF8 -Force
    Ok "Forbidden page template written to $ForbiddenTarget..."
}
# ------------------ Activity / Helper Functions ------------------
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

    Info "Starting TLS/SSL hardening..."

    $backupPath = "C:\Temp\SchannelBackup.reg"
    if (-not (Test-Path "C:\Temp")) { New-Item -Path "C:\Temp" -ItemType Directory | Out-Null }

    try {
        Info "Backing up current SCHANNEL configuration to $backupPath"
        reg export "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" $backupPath /y | Out-Null
    }
    catch {
        Warn "Failed to back up SCHANNEL registry branch. Continuing anyway."
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

        Ok "Disabled $proto protocol"
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

    Ok "Ensured TLS 1.2 is enabled."

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
        Ok "Disabled weak cipher: $cipher"
    }

    Ok "TLS/SSL hardening complete."
    Info "Reboot the server for changes to take effect."
}
function Initialize-IIS{
  # Unlock IIS Configuration for Static Modules
  # Path to appcmd
  $appcmd = Join-Path $env:SystemRoot "System32\inetsrv\appcmd.exe"

  if (Test-Path $appcmd) {
      Info "Unlocking IIS config sections with appcmd..."

      & $appcmd unlock config /section:system.webServer/handlers
      & $appcmd unlock config /section:system.webServer/modules
      & $appcmd unlock config /section:system.webServer/security/ipSecurity
  }
  else {
      Warn "appcmd.exe not found. IIS may not be installed or management tools missing."
  }

  # Restart IIS
  Info "Restarting IIS..."
  Restart-Service -Name W3SVC -Force
  Ok "IIS Restarted..."
  Ok "IIS Configuration has been sucessfully configured for use with PowerSyncPro."
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
        Err "Failed to read hosts file: $($_.Exception.Message)"
        return $false
    }

    # Strip out existing entries for this host only
    $FilteredHosts = $HostsContent | Where-Object {
        $_ -notmatch "^\s*127\.0\.0\.1\s+$FrontendHost(\s|$)"
    }

    # Add new entry only if it isn't already present
    if (-not ($FilteredHosts -match "^\s*127\.0\.0\.1\s+$FrontendHost(\s|$)")) {
        $FilteredHosts += $HostsEntry
        Info "Adding hosts entry: $HostsEntry"
    }
    else {
        Warn "Hosts entry already exists: $HostsEntry"
    }

    # Retry mechanism for writing
    $success = $false
    for ($i = 1; $i -le $MaxRetries; $i++) {
        try {
            $FilteredHosts | Set-Content -Path $HostsPath -Encoding ASCII -ErrorAction Stop
            Ok "Hosts file updated successfully."
            $success = $true
            break
        }
        catch [System.IO.IOException] {
            Warn "Attempt ${i} of ${MaxRetries}: Hosts file in use. Retrying in ${RetryDelaySeconds} second(s)..."
            Start-Sleep -Seconds $RetryDelaySeconds
        }
        catch {
            Warn "Unexpected error while updating hosts file: $($_.Exception.Message)"
            break
        }
    }

    if (-not $success) {
        Warn "Failed to update hosts file after $MaxRetries attempts. Entry not added for $FrontendHost."
        return $false
    }
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
        Info "Firewall rule '$RuleName' already exists."
    }
    else {
        New-NetFirewallRule -DisplayName $RuleName `
                            -Direction Inbound `
                            -LocalPort $Port `
                            -Protocol TCP `
                            -Action Allow `
                            -Profile Domain,Private,Public | Out-Null
        Ok "Firewall rule '$RuleName' created to allow inbound TCP/$Port."
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
        Ok "Firewall rule '$RuleName' removed."
    }
    else {
        Warn "Firewall rule '$RuleName' not found."
    }
}
function Test-HostnameFormat {
    param([Parameter(Mandatory)][string]$Name)
    return $Name -match '^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$'
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
            Info "Detected an existing listener on port $Port. Skipping local bind test."
            $listenerBound = $true
            $result.LocalListener = $true
        }
        else {
            try {
                $tcpListener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $Port)
                $tcpListener.Start()
                Info "Temporary listener started on port $Port."
                # Add Firewall Rule to Allow Port 80
                Add-FirewallRuleForPort -Port 80
                
            } catch {
                Warn "Failed to start temporary listener on port $Port`: $($_.Exception.Message)"
            }
        }

        # Step 2: External checks
        $open = $false
        $why  = $null

        # ---- Provider 1: PortChecker.io
        try {
            $pcUri   = 'https://portchecker.io/api/v1/query'
            $payload = @{ host = $result.TargetHost; ports = @($Port) } | ConvertTo-Json -Depth 3

            $resp = Invoke-RestMethod -Method Post -Uri $pcUri -ContentType 'application/json' -Body $payload -TimeoutSec 12

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
            Warn "DEBUG: PortChecker.io failed -> $($_.Exception.Message)"
        }

        # ---- Provider 2: CanYouSeeMe.org fallback
        if (-not $why) {
            try {
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
                Warn "DEBUG: CanYouSeeMe failed -> $($_.Exception.Message)"
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
            Info "Temporary listener stopped on port $Port." -ForegroundColor Cyan
            # Remove Firewall Rule
            Remove-FirewallRuleForPort -Port 80
        }
    }

    return $result
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
      Info "Installing NuGet to install Powershell Modules..."
      Install-PackageProvider -Name NuGet -ForceBootstrap -Force -ErrorAction Stop | Out-Null
      Ok "NuGet provider installed successfully."
  }
  catch {
      Warn "Failed to install NuGet provider: $_"
      exit 1
  }

  # Install the Posh-ACME Module
  Info "Installing Powershell Posh-ACME for certificate request..."
  Install-Module -Name $ModuleName -Force -Scope AllUsers -AllowClobber
  
  # Run Cert-Puller_PoshACME.ps1 with provided options above.
  Info "Beginning certificate request for $FrontendHost with contact e-mail $ContactEmail"
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
        Info "Importing PFX from $PfxPath..."
        $imported = Import-PfxCertificate -FilePath $PfxPath `
            -Password $Password `
            -CertStoreLocation $StoreLocation `
            -Exportable

        if (-not $imported) { throw "Failed to import PFX certificate." }

        $newCert = $imported[0]
        $actualSubject = $newCert.GetNameInfo('SimpleName', $false)
        Ok "Imported cert: $actualSubject Thumbprint=$($newCert.Thumbprint)"

        # Remove old certs for same CN
        Get-ChildItem -Path $StoreLocation | Where-Object {
            ($_.Subject -like "*CN=$actualSubject*") -and
            $_.Thumbprint -ne $newCert.Thumbprint
        } | ForEach-Object {
            Info "Removing old certificate Thumbprint=$($_.Thumbprint)"
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
                        Ok "Granted FullControl on private key to $resolvedUser"
                    }
                } catch {
                    Warn "Failed to adjust key permissions: $_"
                }
            }
        }

        # Update appsettings.json safely
        try {
            if (Test-Path $AppSettingsPath) {
                $json = Get-Content $AppSettingsPath -Raw | ConvertFrom-Json

                if ($json.Kestrel.Endpoints.PSObject.Properties.Name -notcontains "Https") {
                    Warn "HTTPS endpoint not found in appsettings.json. Creating one on port 5001."
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
                    Ok "Created HTTPS endpoint in appsettings.json"
                } else {
                    $configuredSubject = $json.Kestrel.Endpoints.Https.Certificate.Subject
                    if ($configuredSubject -ne $actualSubject) {
                        Warn "Configured cert subject ($configuredSubject) does not match new cert ($actualSubject). Updating automatically."
                        $json.Kestrel.Endpoints.Https.Certificate.Subject = $actualSubject
                    } else {
                        Info "appsettings.json already matches current certificate subject."
                    }
                }

                $json | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath -Encoding UTF8
                Ok "Updated appsettings.json successfully."
            } else {
                Warn "appsettings.json not found at $AppSettingsPath"
            }
        }
        catch {
            Warn "Failed to update appsettings.json: $($_.Exception.Message)"
        }

        # Update IIS binding (defensive logic)
        Import-Module WebAdministration -ErrorAction Stop
        $certObject = Get-Item "Cert:\LocalMachine\My\$($newCert.Thumbprint)"
        $binding = Get-WebBinding -Name $SiteName -Protocol "https" -Port 443 -ErrorAction SilentlyContinue

        if ($binding) {
            Info "Found existing HTTPS binding for '$SiteName'. Updating with cert $($newCert.Thumbprint)"

            $sslBindings = Get-ChildItem IIS:\SslBindings
            if ($sslBindings) {
                $sslBinding = $sslBindings | Where-Object { $_.Port -eq 443 } | Select-Object -First 1

                if ($sslBinding) {
                    Info "Updating SSL binding path $($sslBinding.PSPath)"
                    Set-Item -Path $sslBinding.PSPath -Value $certObject -Force
                } else {
                    Warn "No SSL binding object found for port 443. Creating one..."
                    $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                    New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
                }
            } else {
                Warn "No SSL bindings currently exist. Creating one..."
                $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
            }
        } else {
            Info "No HTTPS binding found for '$SiteName'. Creating new binding with cert $($newCert.Thumbprint)"
            New-WebBinding -Name $SiteName -Protocol https -Port 443 -IPAddress * -HostHeader ""
            $sslPath = "IIS:\SslBindings\0.0.0.0!443"
            New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
        }

        Restart-Service -Name "PowerSyncPro" -Force
        Ok "Restarted PowerSyncPro service."
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
        Info "Creating self-signed certificate for $DnsName..."

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

        Ok "Generated cert: $DnsName Thumbprint=$($newCert.Thumbprint)"

        # Remove old self-signed certs for same CN
        Get-ChildItem -Path $StoreLocation | Where-Object {
            ($_.Subject -like "*CN=$DnsName*") -and
            $_.Thumbprint -ne $newCert.Thumbprint
        } | ForEach-Object {
            Info "Removing old certificate Thumbprint=$($_.Thumbprint)"
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
                        Ok "Granted FullControl on private key to $resolvedUser"
                    }
                } catch {
                    Warn "Failed to adjust key permissions: $_"
                }
            }
        }

        # Update appsettings.json safely
        if (Test-Path $AppSettingsPath) {
            $json = Get-Content $AppSettingsPath -Raw | ConvertFrom-Json

            if ($json.Kestrel.Endpoints.PSObject.Properties.Name -notcontains "Https") {
                Warn "HTTPS endpoint not found in appsettings.json. Creating one on port 5001."
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
                Ok "Created HTTPS endpoint in appsettings.json"
            } else {
                $configuredSubject = $json.Kestrel.Endpoints.Https.Certificate.Subject
                if ($configuredSubject -ne $DnsName) {
                    Warn "Configured cert subject ($configuredSubject) does not match new cert ($DnsName). Updating automatically."
                    $json.Kestrel.Endpoints.Https.Certificate.Subject = $DnsName
                } else {
                    Info "appsettings.json already matches the current certificate subject."
                }
            }

            $json | ConvertTo-Json -Depth 10 | Set-Content -Path $AppSettingsPath -Encoding UTF8
            Ok "Updated appsettings.json successfully."
        } else {
            Warn "appsettings.json not found at $AppSettingsPath"
        }

        # Update IIS binding (defensive version)
        Import-Module WebAdministration -ErrorAction Stop
        $certObject = Get-Item "Cert:\LocalMachine\My\$($newCert.Thumbprint)"
        $binding = Get-WebBinding -Name $SiteName -Protocol "https" -Port 443 -ErrorAction SilentlyContinue

        if ($binding) {
            Info "Found existing HTTPS binding for '$SiteName'. Updating with cert $($newCert.Thumbprint)"

            $sslBindings = Get-ChildItem IIS:\SslBindings
            if ($sslBindings) {
                $sslBinding = $sslBindings | Where-Object { $_.Port -eq 443 } | Select-Object -First 1

                if ($sslBinding) {
                    Info "Updating SSL binding path $($sslBinding.PSPath)"
                    Set-Item -Path $sslBinding.PSPath -Value $certObject -Force
                } else {
                    Warn "No SSL binding object found for port 443. Creating one..."
                    $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                    New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
                }
            } else {
                Warn "No SSL bindings currently exist. Creating one..."
                $sslPath = "IIS:\SslBindings\0.0.0.0!443"
                New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
            }
        } else {
            Info "No HTTPS binding found for '$SiteName'. Creating new binding with cert $($newCert.Thumbprint)"
            New-WebBinding -Name $SiteName -Protocol https -Port 443 -IPAddress * -HostHeader ""
            $sslPath = "IIS:\SslBindings\0.0.0.0!443"
            New-Item $sslPath -Value $certObject -SSLFlags 0 | Out-Null
        }

        Restart-Service -Name "PowerSyncPro" -Force
        Ok "Restarted PowerSyncPro service."
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

    Ok "Scheduled task '$taskName' created/updated successfully." -ForegroundColor Green
}
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
# ------------------ Menu & UI ------------------
function Show-CertificateTypeMenu {
    Clear-Host 2>$null
    Write-Host $asciiLogo -ForegroundColor Cyan
    Write-Host "PowerSyncPro Azure Marketplace Setup Script - $scriptVer"
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
            Write-Host " - Port 80 must be open on this server's Network Security Group to the Internet."
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
                Warn "Warning: No public A records found for $PublicHostname from public DNS resolvers."
            } else {
                Info ("Resolved public A records for {0}: {1}" -f $PublicHostname, ($ResolvedIPs -join ', '))
            }

            # Determine public IPv4 of this system
            $PublicIPv4 = $null
            try {
                $PublicIPv4 = Get-PublicIPv4
                Info ("Detected public IPv4 for this system: {0}" -f $PublicIPv4)
            } catch {
                Warn ("Unable to determine public IPv4 automatically: {0}" -f $_.Exception.Message)
            }

            # Handle multiple A records or mismatch
            if ($ResolvedIPs.Count -gt 1) {
                Write-Host ""
                Warn "Multiple A records detected for $PublicHostname. This can cause Let's Encrypt validation to fail."
                Info "Resolved IPs: $($ResolvedIPs -join ', ')"
                if ($PublicIPv4) { Info "This system public IP: $PublicIPv4" }
            }

            if ($PublicIPv4) {
                $match = $ResolvedIPs -contains $PublicIPv4
                if (-not $match) {
                    Write-Host ""
                    Warn "DNS/IP mismatch detected!"
                    Write-Host (" - Hostname: {0}" -f $PublicHostname)
                    Write-Host (" - Public A records: {0}" -f ($(if ($ResolvedIPs) { $ResolvedIPs -join ', ' } else { 'None' })))
                    Write-Host (" - This system public IP: {0}" -f $PublicIPv4)

                    while ($true) {
                        $action = Read-Host "Do you want to retry DNS (R), change hostname (H), or continue anyway (C)? [R/H/C]"
                        switch -regex ($action) {
                            '^(R|r)$' {
                                $ResolvedIPs = Resolve-IPv4A -Name $PublicHostname -PublicOnly
                                Info ("Refreshed A records: {0}" -f ($(if ($ResolvedIPs) { $ResolvedIPs -join ', ' } else { 'None' })))
                            }
                            '^(H|h)$' {
                                while ($true) {
                                    $PublicHostname = Read-Host "Enter the public hostname (A record) for this system"
                                    if (Test-HostnameFormat -Name $PublicHostname) { break }
                                    Warn "Invalid hostname format. Please enter a valid FQDN."
                                }
                                $ResolvedIPs = Resolve-IPv4A -Name $PublicHostname -PublicOnly
                                Info ("Resolved A records for {0}: {1}" -f $PublicHostname, ($(if ($ResolvedIPs) { $ResolvedIPs -join ', ' } else { 'None' })))
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
                        Ok ("External connectivity check: Port {0} is OPEN ({1})" -f $portResult.Port, $portResult.ExternalCheck)
                    }
                    else {
                        Warn ("External connectivity check: Port {0} is CLOSED ({1})" -f $portResult.Port, $portResult.ExternalCheck)
                        $retry = Read-Host "Port 80 must be open for LetsEncrypt. Please check your Network Security Group. Do you want to continue anyway? (Y/N)"
                        if ($retry -notmatch '^(Y|y)$') {
                            throw "LetsEncrypt prerequisites not met - port 80 is closed."
                        }
                    }
                }
                else {
                    Warn "External connectivity test did not return a result. Continuing with caution."
                }
            }
            catch {
                Err "Error while testing external connectivity: $($_.Exception.Message)"
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
            $PfxPath = $null
            Write-Host ""
            Write-Host "Bring Your Own Certificate:" -ForegroundColor Cyan

            # --- Look in current directory for .pfx files ---
            $localPfxFiles = @(Get-ChildItem -Path (Get-Location) -Filter *.pfx -File -ErrorAction SilentlyContinue)

            if ($localPfxFiles.Count -gt 0) {
                Info "Found the following PFX files in the current directory:"
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
                    Warn "Invalid selection. Please enter a number between 1 and $($localPfxFiles.Count) or press Enter."
                }
            } 

            # If no files found, or user pressed Enter, prompt for path
            if (-not $PfxPath) {
                while ($true) {
                    $rawPath = Read-Host "Please provide the full path of a PFX file (e.g. C:\Temp\companycert.pfx)"
                    $PfxPath = $rawPath.Trim('"').Trim("'")
                    $PfxPath = [System.Environment]::ExpandEnvironmentVariables($PfxPath)
                    try { $PfxPath = [System.IO.Path]::GetFullPath((Join-Path -Path (Get-Location) -ChildPath $PfxPath)) } catch {}
                    if (-not (Test-Path -Path $PfxPath -PathType Leaf)) { Warn "The file path does not exist. Please try again."; continue }
                    if ([System.IO.Path]::GetExtension($PfxPath) -ne ".pfx") { Warn "The file must have a .pfx extension. Please try again."; continue }
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

                    Info "Certificate loaded. Found the following DNS names:"
                    $CertFqdns | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
                    break
                } catch {
                    Warn ("Failed to open PFX or read subject: {0}" -f $_.Exception.Message)
                    $retry = Read-Host "Password may be incorrect. Try again? (Y/N)"
                    if ($retry -notmatch '^(Y|y)$') { throw "Invalid PFX or password." }
                }
            }

            # --- Detect wildcards ---
            $WildcardFqdns = @($CertFqdns | Where-Object { $_.StartsWith('*.') })
            $ResolvedHostname = $null
            $ChosenWildcard   = $null

            if ($WildcardFqdns.Count -gt 1) {
                Warn "Multiple wildcard domains detected:"
                for ($i=0; $i -lt $WildcardFqdns.Count; $i++) {
                    Write-Host ("[{0}] {1}" -f ($i+1), $WildcardFqdns[$i])
                }
                while ($true) {
                    $choice = Read-Host "Select which wildcard root to use (1-$($WildcardFqdns.Count))"
                    if ([int]::TryParse($choice, [ref]$null) -and $choice -ge 1 -and $choice -le $WildcardFqdns.Count) {
                        $ChosenWildcard = $WildcardFqdns[$choice-1]
                        break
                    }
                    Warn "Invalid choice. Please enter a number between 1 and $($WildcardFqdns.Count)."
                }
            } elseif ($WildcardFqdns.Count -eq 1) {
                $ChosenWildcard = $WildcardFqdns[0]
            }

            # --- Handle wildcard resolution ---
            if ($ChosenWildcard) {
                $wildRoot = $ChosenWildcard.Substring(2)
                Warn ("Detected wildcard certificate for: {0}" -f $wildRoot)
                while ($true) {
                    $ResolvedHostname = Read-Host ("Enter the specific FQDN for this host (must be exactly one label under {0}, e.g. host.{0})" -f $wildRoot)
                    if ([string]::IsNullOrWhiteSpace($ResolvedHostname)) { Warn "Hostname cannot be empty."; continue }
                    $ResolvedHostname = $ResolvedHostname.Trim()
                    if (-not (Test-HostnameFormat -Name $ResolvedHostname)) { Warn "Invalid hostname format. Please enter a valid FQDN."; continue }

                    $hostDots = ($ResolvedHostname -split '\.').Count
                    $rootDots = ($wildRoot -split '\.').Count
                    $endsOk   = $ResolvedHostname.ToLower().EndsWith("." + $wildRoot.ToLower())
                    $oneLevel = ($hostDots -eq ($rootDots + 1))

                    if ($endsOk -and $oneLevel) {
                        Ok ("Hostname {0} is valid for wildcard {1}" -f $ResolvedHostname, $ChosenWildcard)
                        break
                    } else {
                        Warn ("{0} is not valid for wildcard {1}. Must add exactly one label under {2}." -f $ResolvedHostname, $ChosenWildcard, $wildRoot)
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
                Warn "Invalid hostname format. Please enter a valid FQDN."
            }

            $CertConfig = [PSCustomObject]@{
                Type     = 'SelfSigned'
                Hostname = $SelfSignedHostname
            }
        }
    }

    return $CertConfig
}

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
        Ok "Certificate configuration accepted, beginning configuration."
    }
    catch {
        Err ("Error: {0}" -f $_.Exception.Message)
        exit 1
    }

    # Grab Details for CertConfig
    $FrontendHost = $CertConfig.Hostname # FrontendHost FQDN
    $CertType = $CertConfig.Type # Type of Cert Chosen

    Info "Beginning configuration of certificate and other dependencies...."
    Info "Using a $CertType Certificate with a Hostname of $FrontendHost..."

    # Install Custom WebConifg
    Info "Installing Customized $WebConfigName to $WebConfigFolder"
    Install-WebConfig -FrontendHost $FrontendHost -TargetFolder $WebConfigFolder -TargetFile $WebConfigName

    # Setup IIS and Unlock Required Sections
    Info "Unlocking configuration section for web.config..."
    Initialize-IIS

    # Add Frontend Host to local Hosts File
    Info "Editing Hosts file to add entry for $FrontendHost pointing to 127.0.0.1..."
    Install-HostsFile -FrontendHost $FrontendHost

    # Add Firewall Rule for Port 443
    Info "Opening Port 443 on Firewall for IIS..."
    Add-FirewallRuleForPort -Port 443

    # Harden TLS / SSL - Disable Insecure Ciphers
    Harden-TlsConfiguration

    # Install certificate depending on type chosen at beginning if script.
    switch ($CertType) {
        'LetsEncrypt' {
            Info "Configuration tasks completed, getting a certificate from LetsEncrypt for $FrontendHost..."
            try{
                Info "Opening Port 80 on Firewall for IIS, ensuring LetsEncrypt can reach server..."
                Add-FirewallRuleForPort -Port 80
                # Run Cert Puller Script to Install Scripts
                Info "Running CertPuller Script to grab LetsEncrypt Certificate for $FrontendHost..."
                Install-ACMECertificate -FrontendHost $FrontendHost -ContactEmail $CertConfig.Email

                if ([string]::IsNullOrWhiteSpace($PSPServiceUser) -or
                    $PSPServiceUser -eq "LocalSystem" -or
                    $PSPServiceUser -eq "NT AUTHORITY\SYSTEM" -or
                    $PSPServiceUser -eq "NT AUTHORITY\NetworkService" -or
                    $PSPServiceUser -eq "NT AUTHORITY\LocalService") {
                        Info "Skipping private key ACL update: service user is blank or system account."
                        $certInstalled = $true
                    }
                else {
                    if (-not (Test-AndFixCertPermissions -Domain $FrontendHost -User $PSPServiceUser)) {
                        Warn "Private key ACL update failed or not required. Continuing..."
                    } else {
                        Ok "Private key ACL verified for $PSPServiceUser"
                        $certInstalled = $true
                    }
                }

                # Register Scheduled Task to Renew Certificate.
                Info "Registering Scheduled task to renew LetsEncrypt Certificate..."
                Register-CertRenewalScheduledTask -Domain $FrontendHost -ContactEmail $CertConfig.Email
                Ok "Scheduled task registered..."
                
            } catch {
                Warn "LetsEncrypt install failed: $($_.Exception.Message)"
                # --- DEBUG: Check the certificate type and private key provider ---
                try {
                    $cert = Get-ChildItem -Path Cert:\LocalMachine\My |
                        Where-Object { $_.Subject -like "*$FrontendHost*" } |
                        Sort-Object NotAfter -Descending |
                        Select-Object -First 1

                    if ($null -eq $cert) {
                        Warn "DEBUG: No certificate found for $FrontendHost after Install-ACMECertificate."
                    }
                    else {
                        Info "DEBUG: Retrieved cert subject: $($cert.Subject)"
                        Info "DEBUG: Cert has private key: $($cert.HasPrivateKey)"
                        
                        # Test if CAPI (legacy) or CNG (modern) key
                        try {
                            $null = $cert.PrivateKey.CspKeyContainerInfo.ProviderName
                            Ok "DEBUG: Certificate uses CAPI (CSP) provider: $($cert.PrivateKey.CspKeyContainerInfo.ProviderName)"
                        }
                        catch {
                            if ($cert.PrivateKey -is [System.Security.Cryptography.RSACng]) {
                                Warn "DEBUG: Certificate uses CNG (KSP) provider: Microsoft Software Key Storage Provider"
                            }
                            else {
                                Warn "DEBUG: Unknown key provider type for certificate."
                            }
                        }
                    }
                }
                catch {
                    Warn "DEBUG: Error while inspecting certificate: $_"
                }
                exit 1
                # --- END DEBUG BLOCK ---
                
                $certInstalled = $false
            }
        }
        'BYOC' {
            Info "Configuration tasks completed, installing BYOC certificate for $FrontendHost..."
            try{
                Install-CustomPfxCertificate -PfxPath $CertConfig.PfxPath -Password $CertConfig.PfxPass
                $certInstalled = $true
            } catch {
                Warn "BYOC certificate install failed: $($_.Exception.Message)"
                $certInstalled = $false
            }
        }
        'SelfSigned' {
            try{
                Info "Configuration tasks completed, installing self-signed certificate for $FrontendHost..."
                Install-SelfSignedCertificate -DnsName $FrontendHost
                $certInstalled = $true
            } catch {
                Warn "Self Signed certificate install failed: $($_.Exception.Message)"
                $certInstalled = $false
            }
        }
        default {
            Warn "Unknown certificate type: $CertType - Certificate has not been installed.  Please contact support."
        }
    }
    # Handle Certificate Installation Failures.
    if ($certInstalled) {
        Ok "Certificate installation completed successfully."
    }
    else {
        Err "Certificate installation failed."

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
    Write-Host "Admin access to PSP via the Reverse Proxy - e.g. https://$FrontendHost has been restricted to localhost only." -ForegroundColor Cyan
    Write-Host "You can modify hosts which are allowed to access the HTTPS Reverse Proxy by running C:\Scripts\WebConfig_Editor.ps1."
    Write-Host "This restriction does not apply on https://$FrontendHost/Agent which is used for the PSP Migration Agent."
    Write-Host "`n"
    Write-Host "You can now access PowerSyncPro at https://$FrontendHost/ from this system." -ForegroundColor Yellow
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