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

#TODO: Add SSL Hardening Tasks from KB
#TODO: Evaluate downloading scripts from Github instead of using embedded scripts as Base64

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

# IIS URL Rewrite
$RewriteUrl = "https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi"
# IIS Advanced Request Routing URL
$ArrUrl = "https://download.microsoft.com/download/e/9/8/e9849d6a-020e-47e4-9fd0-a023e99b54eb/requestRouter_amd64.msi"

# Current PSP Public Download Link
$PSPUrl = "https://downloads.powersyncpro.com/current/PowerSyncProInstaller.msi"

# Target Folder for Maintenance Scripts (PoshACME Cert Puller, WebConfig Editor)
$ScriptFolder = "C:\Scripts"

# Scripts to Drop (Base64 UTF-8 Encoded)
$CertPullerScriptName   = 'Cert-Puller_PoshACME.ps1'
$CertPullerScriptEncoded = @"
I1JlcXVpcmVzIC1Nb2R1bGUgUG9zaC1BQ01FDQojUmVxdWlyZXMgLU1vZHVsZSBXZWJBZG1pbmlzdHJhdGlvbg0KI1JlcXVpcmVzIC1SdW5Bc0FkbWluaXN0cmF0b3INCg0KPCMNCi5TWU5PUFNJUw0KICAgIE9idGFpbnMgb3IgcmVuZXdzIGEgTGV0J3MgRW5jcnlwdCBjZXJ0aWZpY2F0ZSB1c2luZyBQb3NoLUFDTUUgYW5kIHN0b3JlcyBpdCBpbiB0aGUgTG9jYWwgTWFjaGluZSBjZXJ0aWZpY2F0ZSBzdG9yZS4NCg0KLkRFU0NSSVBUSU9ODQogICAgVGhpcyBzY3JpcHQgcmVxdWVzdHMgb3IgcmVuZXdzIGEgTGV0J3MgRW5jcnlwdCBjZXJ0aWZpY2F0ZSB2aWEgUG9zaC1BQ01FLg0KICAgIEl0IGNoZWNrcyB0aGUgTG9jYWwgTWFjaGluZSBjZXJ0aWZpY2F0ZSBzdG9yZSBmb3IgYW4gZXhpc3RpbmcgY2VydC4gSWYgdmFsaWQgYW5kIG5vdCBuZWFyIGV4cGlyeSwNCiAgICBpdCBza2lwcyByZW5ld2FsLiBPdGhlcndpc2UsIGl0IHJlcXVlc3RzIGEgbmV3IG9uZSwgaW1wb3J0cyBpdCwgYW5kIGRlbGV0ZXMgYWxsIG9sZCBvbmVzLg0KDQouUEFSQU1FVEVSIERvbWFpbg0KICAgIFRoZSBkb21haW4gZm9yIHdoaWNoIHRvIHJlcXVlc3Qgb3IgcmVuZXcgdGhlIGNlcnRpZmljYXRlIChlLmcuLCBjZXJ0LXRlc3Qucm9ja2xpZ2h0bmV0d29ya3MuY29tKS4NCg0KLlBBUkFNRVRFUiBDb250YWN0RW1haWwNCiAgICBUaGUgZW1haWwgYWRkcmVzcyBmb3IgTGV0J3MgRW5jcnlwdCBhY2NvdW50IHJlZ2lzdHJhdGlvbi4NCg0KLlBBUkFNRVRFUiBEYXlzQmVmb3JlRXhwaXJ5DQogICAgRGF5cyBiZWZvcmUgY2VydGlmaWNhdGUgZXhwaXJ5IHRvIHRyaWdnZXIgcmVuZXdhbCAoZGVmYXVsdDogMzApLg0KDQouUEFSQU1FVEVSIFN0b3JlTG9jYXRpb24NCiAgICBUaGUgY2VydGlmaWNhdGUgc3RvcmUgbG9jYXRpb24gKGRlZmF1bHQ6IENlcnQ6XExvY2FsTWFjaGluZVxNeSkuDQoNCi5QQVJBTUVURVIgV2ViUm9vdA0KICAgIFRoZSB3ZWIgc2VydmVyIHJvb3QgZm9yIEhUVFAtMDEgY2hhbGxlbmdlIGZpbGVzIChkZWZhdWx0OiBDOlxpbmV0cHViXHd3d3Jvb3QpLg0KDQouUEFSQU1FVEVSIExvZ1BhdGgNCiAgICBQYXRoIHRvIHNhdmUgbG9nIGZpbGUgKGRlZmF1bHQ6IEM6XExvZ3NcTGV0c0VuY3J5cHRSZW5ld2FsXzxkYXRlPi50eHQpLg0KDQouUEFSQU1FVEVSIEhlbHANCiAgICBTaG93cyB1c2FnZSBpbmZvcm1hdGlvbi4NCiM+DQoNCltDbWRsZXRCaW5kaW5nKCldDQpwYXJhbSAoDQogICAgW1BhcmFtZXRlcihNYW5kYXRvcnk9JGZhbHNlKV0NCiAgICBbc3RyaW5nXSREb21haW4sDQoNCiAgICBbUGFyYW1ldGVyKE1hbmRhdG9yeT0kZmFsc2UpXQ0KICAgIFtzdHJpbmddJENvbnRhY3RFbWFpbCwNCg0KICAgIFtQYXJhbWV0ZXIoTWFuZGF0b3J5PSRmYWxzZSldDQogICAgW2ludF0kRGF5c0JlZm9yZUV4cGlyeSA9IDMwLA0KDQogICAgW1BhcmFtZXRlcihNYW5kYXRvcnk9JGZhbHNlKV0NCiAgICBbc3RyaW5nXSRTdG9yZUxvY2F0aW9uID0gIkNlcnQ6XExvY2FsTWFjaGluZVxNeSIsDQoNCiAgICBbUGFyYW1ldGVyKE1hbmRhdG9yeT0kZmFsc2UpXQ0KICAgIFtzdHJpbmddJFdlYlJvb3QgPSAiQzpcaW5ldHB1Ylx3d3dyb290IiwNCg0KICAgIFtQYXJhbWV0ZXIoTWFuZGF0b3J5PSRmYWxzZSldDQogICAgW3N0cmluZ10kTG9nUGF0aCA9ICJDOlxMb2dzXExldHNFbmNyeXB0UmVuZXdhbF8kKEdldC1EYXRlIC1Gb3JtYXQgJ3l5eXlNTWRkJykudHh0IiwNCg0KICAgIFtQYXJhbWV0ZXIoTWFuZGF0b3J5PSRmYWxzZSldDQogICAgW3N3aXRjaF0kSGVscA0KKQ0KDQojIFNob3cgdXNhZ2UvaGVscCBpZiAtSGVscCwgbm8gcGFyYW1ldGVycywgT1IgcmVxdWlyZWQgdmFsdWVzIG1pc3NpbmcNCmlmICgkUFNCb3VuZFBhcmFtZXRlcnMuQ291bnQgLWVxIDAgLW9yICRIZWxwIC1vciAtbm90ICREb21haW4gLW9yIC1ub3QgJENvbnRhY3RFbWFpbCkgew0KJHVzYWdlID0gQCcNClVzYWdlOiAuXENlcnQtUHVsbGVyX1Bvc2hBQ01FLnBzMSAtRG9tYWluIDxkb21haW4+IC1Db250YWN0RW1haWwgPGVtYWlsPiBbLURheXNCZWZvcmVFeHBpcnkgPGRheXM+XSBbLVN0b3JlTG9jYXRpb24gPHN0b3JlPl0gWy1XZWJSb290IDxwYXRoPl0gWy1Mb2dQYXRoIDxwYXRoPl0gWy1IZWxwXQ0KDQpQYXJhbWV0ZXJzOg0KICAgIC1Eb21haW4gICAgICAgICAgIChSZXF1aXJlZCkgRG9tYWluIG5hbWUgdG8gcmVxdWVzdCBvciByZW5ldyBhIGNlcnRpZmljYXRlIGZvci4NCiAgICAtQ29udGFjdEVtYWlsICAgICAoUmVxdWlyZWQpIEVtYWlsIGFkZHJlc3MgZm9yIExldCdzIEVuY3J5cHQgYWNjb3VudCByZWdpc3RyYXRpb24uDQogICAgLURheXNCZWZvcmVFeHBpcnkgKE9wdGlvbmFsKSBEYXlzIGJlZm9yZSBleHBpcnkgdG8gdHJpZ2dlciByZW5ld2FsLiBEZWZhdWx0OiAzMA0KICAgIC1TdG9yZUxvY2F0aW9uICAgIChPcHRpb25hbCkgQ2VydGlmaWNhdGUgc3RvcmUgbG9jYXRpb24uIERlZmF1bHQ6IENlcnQ6XExvY2FsTWFjaGluZVxNeQ0KICAgIC1XZWJSb290ICAgICAgICAgIChPcHRpb25hbCkgUGF0aCB0byB3ZWIgc2VydmVyIHJvb3QgZm9yIEhUVFAtMDEgY2hhbGxlbmdlLiBEZWZhdWx0OiBDOlxpbmV0cHViXHd3d3Jvb3QNCiAgICAtTG9nUGF0aCAgICAgICAgICAoT3B0aW9uYWwpIFBhdGggdG8gc2F2ZSBsb2cgZmlsZS4gRGVmYXVsdDogQzpcTG9nc1xMZXRzRW5jcnlwdFJlbmV3YWxfPGRhdGU+LnR4dA0KICAgIC1IZWxwICAgICAgICAgICAgIChPcHRpb25hbCkgRGlzcGxheSB0aGlzIHVzYWdlIGluZm9ybWF0aW9uLg0KDQpFeGFtcGxlOg0KICAgIC5cQ2VydC1QdWxsZXJfUG9zaEFDTUUucHMxIC1Eb21haW4gImV4YW1wbGUuY29tIiAtQ29udGFjdEVtYWlsICJhZG1pbkBleGFtcGxlLmNvbSINCidADQogICAgV3JpdGUtT3V0cHV0ICR1c2FnZQ0KICAgIHJldHVybg0KfQ0KDQojIEluaXRpYWxpemUgbG9nZ2luZw0KaWYgKC1ub3QgKFRlc3QtUGF0aCAtUGF0aCAoU3BsaXQtUGF0aCAkTG9nUGF0aCAtUGFyZW50KSkpIHsNCiAgICBOZXctSXRlbSAtSXRlbVR5cGUgRGlyZWN0b3J5IC1QYXRoIChTcGxpdC1QYXRoICRMb2dQYXRoIC1QYXJlbnQpIC1Gb3JjZSB8IE91dC1OdWxsDQp9DQpTdGFydC1UcmFuc2NyaXB0IC1QYXRoICRMb2dQYXRoIC1BcHBlbmQNCg0KdHJ5IHsNCiAgICAjIExvZyBQb3NoLUFDTUUgdmVyc2lvbg0KICAgICRwb3NoQWNtZVZlcnNpb24gPSAoR2V0LU1vZHVsZSAtTmFtZSBQb3NoLUFDTUUgLUxpc3RBdmFpbGFibGUgfCBTb3J0LU9iamVjdCBWZXJzaW9uIC1EZXNjZW5kaW5nIHwgU2VsZWN0LU9iamVjdCAtRmlyc3QgMSkuVmVyc2lvbg0KICAgIFdyaXRlLU91dHB1dCAiUG9zaC1BQ01FIE1vZHVsZSBWZXJzaW9uOiAkcG9zaEFjbWVWZXJzaW9uIg0KDQogICAgIyBDaGVjayBpZiBjZXJ0aWZpY2F0ZSBleGlzdHMgaW4gdGhlIHN0b3JlIGFuZCBpcyB2YWxpZA0KICAgICRyZW5ld05lZWRlZCA9ICR0cnVlDQogICAgJGV4aXN0aW5nQ2VydCA9IEdldC1DaGlsZEl0ZW0gLVBhdGggJFN0b3JlTG9jYXRpb24gfCBXaGVyZS1PYmplY3Qgew0KICAgICAgICAoJF8uU3ViamVjdCAtbGlrZSAiKkNOPSREb21haW4qIiAtb3IgJF8uRG5zTmFtZUxpc3QgLWNvbnRhaW5zICREb21haW4pIC1hbmQNCiAgICAgICAgJF8uSXNzdWVyIC1saWtlICIqTGV0J3MgRW5jcnlwdCoiIC1hbmQNCiAgICAgICAgJF8uTm90QWZ0ZXIgLWd0IChHZXQtRGF0ZSkNCiAgICB9IHwgU29ydC1PYmplY3QgTm90QWZ0ZXIgLURlc2NlbmRpbmcgfCBTZWxlY3QtT2JqZWN0IC1GaXJzdCAxDQoNCiAgICBpZiAoJGV4aXN0aW5nQ2VydCkgew0KICAgICAgICAkZGF5c1VudGlsRXhwaXJ5ID0gKCRleGlzdGluZ0NlcnQuTm90QWZ0ZXIgLSAoR2V0LURhdGUpKS5EYXlzDQogICAgICAgIGlmICgkZGF5c1VudGlsRXhwaXJ5IC1ndCAkRGF5c0JlZm9yZUV4cGlyeSkgew0KICAgICAgICAgICAgV3JpdGUtT3V0cHV0ICJDZXJ0aWZpY2F0ZSBmb3IgJERvbWFpbiBpcyB2YWxpZCB1bnRpbCAkKCRleGlzdGluZ0NlcnQuTm90QWZ0ZXIpLiBObyByZW5ld2FsIG5lZWRlZC4iDQogICAgICAgICAgICAkcmVuZXdOZWVkZWQgPSAkZmFsc2UNCiAgICAgICAgfSBlbHNlIHsNCiAgICAgICAgICAgIFdyaXRlLU91dHB1dCAiQ2VydGlmaWNhdGUgZm9yICREb21haW4gZXhwaXJlcyBvbiAkKCRleGlzdGluZ0NlcnQuTm90QWZ0ZXIpLiBSZW5ld2FsIG5lZWRlZC4iDQogICAgICAgIH0NCiAgICB9IGVsc2Ugew0KICAgICAgICBXcml0ZS1PdXRwdXQgIk5vIHZhbGlkIGNlcnRpZmljYXRlIGZvdW5kIGZvciAkRG9tYWluIGluICRTdG9yZUxvY2F0aW9uLiBSZXF1ZXN0aW5nIG5ldyBjZXJ0aWZpY2F0ZS4iDQogICAgfQ0KDQogICAgaWYgKC1ub3QgJHJlbmV3TmVlZGVkKSB7DQogICAgICAgIHJldHVybg0KICAgIH0NCg0KICAgICMgQ29uZmlndXJlIFBvc2gtQUNNRSBzZXJ2ZXINCiAgICBTZXQtUEFTZXJ2ZXIgIkxFX1BST0QiDQogICAgV3JpdGUtVmVyYm9zZSAiU2V0IFBvc2gtQUNNRSBzZXJ2ZXIgdG8gcHJvZHVjdGlvbiINCg0KICAgICMgU2V0IHVwIGFjY291bnQNCiAgICAkYWNjb3VudCA9IEdldC1QQUFjY291bnQNCiAgICBpZiAoLW5vdCAkYWNjb3VudCkgew0KICAgICAgICBOZXctUEFBY2NvdW50IC1Db250YWN0ICRDb250YWN0RW1haWwgLUFjY2VwdFRPUyAtRm9yY2UNCiAgICAgICAgV3JpdGUtVmVyYm9zZSAiQ3JlYXRlZCBuZXcgUG9zaC1BQ01FIGFjY291bnQgZm9yICRDb250YWN0RW1haWwiDQogICAgfSBlbHNlIHsNCiAgICAgICAgU2V0LVBBQWNjb3VudCAtSUQgJGFjY291bnQuSUQgLUNvbnRhY3QgJENvbnRhY3RFbWFpbCAtRm9yY2UNCiAgICAgICAgV3JpdGUtVmVyYm9zZSAiVXNpbmcgZXhpc3RpbmcgUG9zaC1BQ01FIGFjY291bnQgZm9yICRDb250YWN0RW1haWwiDQogICAgfQ0KDQogICAgIyBSZXF1ZXN0IG9yIHJlbmV3IGNlcnRpZmljYXRlDQogICAgJGNlcnQgPSBOZXctUEFDZXJ0aWZpY2F0ZSAkRG9tYWluIC1QbHVnaW4gV2ViUm9vdCAtUGx1Z2luQXJncyBAeyBXUlBhdGggPSAkV2ViUm9vdCB9IC1Gb3JjZQ0KICAgIGlmICgtbm90ICRjZXJ0KSB7IHRocm93ICJGYWlsZWQgdG8gb2J0YWluL3JlbmV3IGNlcnRpZmljYXRlIGZvciAkRG9tYWluIiB9DQogICAgV3JpdGUtT3V0cHV0ICJTdWNjZXNzZnVsbHkgb2J0YWluZWQvcmVuZXdlZCBjZXJ0aWZpY2F0ZSBmb3IgJERvbWFpbiINCg0KICAgICMgR2V0IGNlcnRpZmljYXRlIGRldGFpbHMNCiAgICAkY2VydERldGFpbHMgPSBHZXQtUEFDZXJ0aWZpY2F0ZSAtTWFpbkRvbWFpbiAkRG9tYWluDQogICAgaWYgKC1ub3QgJGNlcnREZXRhaWxzKSB7IHRocm93ICJGYWlsZWQgdG8gcmV0cmlldmUgY2VydGlmaWNhdGUgZGV0YWlscyBmb3IgJERvbWFpbiIgfQ0KDQogICAgIyBJbXBvcnQgbmV3IGNlcnQNCiAgICAkaW1wb3J0ZWQgPSBJbXBvcnQtUGZ4Q2VydGlmaWNhdGUgLUZpbGVQYXRoICRjZXJ0RGV0YWlscy5QZnhGdWxsQ2hhaW4gYA0KICAgICAgICAtUGFzc3dvcmQgJGNlcnREZXRhaWxzLlBmeFBhc3MgYA0KICAgICAgICAtQ2VydFN0b3JlTG9jYXRpb24gJFN0b3JlTG9jYXRpb24gYA0KICAgICAgICAtRXhwb3J0YWJsZQ0KDQogICAgaWYgKCRpbXBvcnRlZCkgew0KICAgICAgICBXcml0ZS1PdXRwdXQgIkNlcnRpZmljYXRlIGZvciAkRG9tYWluIGltcG9ydGVkIHRvICRTdG9yZUxvY2F0aW9uIg0KICAgIH0gZWxzZSB7DQogICAgICAgIHRocm93ICJGYWlsZWQgdG8gaW1wb3J0IGNlcnRpZmljYXRlIGZvciAkRG9tYWluIGludG8gJFN0b3JlTG9jYXRpb24iDQogICAgfQ0KDQogICAgIyBDbGVhbiB1cCBvbGQgY2VydHMNCiAgICAkbmV3Q2VydCA9IEdldC1DaGlsZEl0ZW0gLVBhdGggJFN0b3JlTG9jYXRpb24gfCBXaGVyZS1PYmplY3Qgew0KICAgICAgICAoJF8uU3ViamVjdCAtbGlrZSAiKkNOPSREb21haW4qIiAtb3IgJF8uRG5zTmFtZUxpc3QgLWNvbnRhaW5zICREb21haW4pIC1hbmQNCiAgICAgICAgJF8uSXNzdWVyIC1saWtlICIqTGV0J3MgRW5jcnlwdCoiDQogICAgfSB8IFNvcnQtT2JqZWN0IE5vdEFmdGVyIC1EZXNjZW5kaW5nIHwgU2VsZWN0LU9iamVjdCAtRmlyc3QgMQ0KDQogICAgaWYgKCRuZXdDZXJ0KSB7DQogICAgICAgIEdldC1DaGlsZEl0ZW0gLVBhdGggJFN0b3JlTG9jYXRpb24gfCBXaGVyZS1PYmplY3Qgew0KICAgICAgICAgICAgKCRfLlN1YmplY3QgLWxpa2UgIipDTj0kRG9tYWluKiIgLW9yICRfLkRuc05hbWVMaXN0IC1jb250YWlucyAkRG9tYWluKSAtYW5kDQogICAgICAgICAgICAkXy5Jc3N1ZXIgLWxpa2UgIipMZXQncyBFbmNyeXB0KiIgLWFuZA0KICAgICAgICAgICAgJF8uVGh1bWJwcmludCAtbmUgJG5ld0NlcnQuVGh1bWJwcmludA0KICAgICAgICB9IHwgRm9yRWFjaC1PYmplY3Qgew0KICAgICAgICAgICAgV3JpdGUtT3V0cHV0ICJSZW1vdmluZyBvbGQgY2VydGlmaWNhdGUgKFRodW1icHJpbnQ9JCgkXy5UaHVtYnByaW50KSwgRXhwaXJlcz0kKCRfLk5vdEFmdGVyKSkiDQogICAgICAgICAgICBSZW1vdmUtSXRlbSAtUGF0aCAiJFN0b3JlTG9jYXRpb25cJCgkXy5UaHVtYnByaW50KSIgLUZvcmNlDQogICAgICAgIH0NCiAgICB9DQoNCiAgICBXcml0ZS1PdXRwdXQgIkNlcnRpZmljYXRlIGZvciAkRG9tYWluIHN1Y2Nlc3NmdWxseSBvYnRhaW5lZC9yZW5ld2VkIGFuZCBvbGQgY2VydGlmaWNhdGVzIGNsZWFuZWQgdXAuIg0KfQ0KY2F0Y2ggew0KICAgIFdyaXRlLUVycm9yICJBbiBlcnJvciBvY2N1cnJlZDogJCgkXy5FeGNlcHRpb24uTWVzc2FnZSkiDQogICAgRXhpdCAxDQp9DQpmaW5hbGx5IHsNCiAgICAjIENsZWFuIHVwIGNoYWxsZW5nZSBmaWxlcw0KICAgICRjaGFsbGVuZ2VEaXIgPSBKb2luLVBhdGggLVBhdGggJFdlYlJvb3QgLUNoaWxkUGF0aCAiLndlbGwta25vd25cYWNtZS1jaGFsbGVuZ2UiDQogICAgaWYgKFRlc3QtUGF0aCAtUGF0aCAkY2hhbGxlbmdlRGlyKSB7DQogICAgICAgIFJlbW92ZS1JdGVtIC1QYXRoICRjaGFsbGVuZ2VEaXIgLVJlY3Vyc2UgLUZvcmNlIC1FcnJvckFjdGlvbiBTaWxlbnRseUNvbnRpbnVlDQogICAgICAgIFdyaXRlLVZlcmJvc2UgIkNsZWFuZWQgdXAgY2hhbGxlbmdlIGZpbGVzIGF0ICRjaGFsbGVuZ2VEaXIiDQogICAgfQ0KfQ0KDQojIFVwZGF0ZSBwZXJtaXNzaW9ucyBmb3IgUFNQIFNlcnZpY2UgQWNjb3VudA0KV3JpdGUtT3V0cHV0ICJDaGVja2luZyBjZXJ0aWZpY2F0ZSBhbmQgYWRkaW5nIHBlcm1pc3Npb25zIHRvIFBTUCBTZXJ2aWNlIGFjY291bnQgaWYgbmVjZXNzYXJ5Li4uIg0KJHN2YyA9IEdldC1XbWlPYmplY3QgV2luMzJfU2VydmljZSAtRmlsdGVyICJOYW1lPSdQb3dlclN5bmNQcm8nIg0KaWYgKC1ub3QgJHN2Yykgew0KICAgIFdyaXRlLVdhcm5pbmcgIlNlcnZpY2UgJ1Bvd2VyU3luY1Bybycgbm90IGZvdW5kLiBTa2lwcGluZyBrZXkgcGVybWlzc2lvbiBjaGVjay4iDQp9IGVsc2Ugew0KICAgICRzdmNVc2VyID0gJHN2Yy5TdGFydE5hbWUNCiAgICBpZiAoJHN2Y1VzZXIgLWVxICJMb2NhbFN5c3RlbSIpIHsNCiAgICAgICAgV3JpdGUtT3V0cHV0ICJQb3dlclN5bmNQcm8gaXMgcnVubmluZyBhcyBMb2NhbFN5c3RlbS4gTm8gcGVybWlzc2lvbnMgdXBkYXRlIG5lZWRlZC4iDQogICAgfSBlbHNlIHsNCiAgICAgICAgdHJ5IHsNCiAgICAgICAgICAgICRudEFjY291bnQgPSBOZXctT2JqZWN0IFN5c3RlbS5TZWN1cml0eS5QcmluY2lwYWwuTlRBY2NvdW50KCRzdmNVc2VyKQ0KICAgICAgICAgICAgJHJlc29sdmVkVXNlciA9ICRudEFjY291bnQuVHJhbnNsYXRlKFtTeXN0ZW0uU2VjdXJpdHkuUHJpbmNpcGFsLk5UQWNjb3VudF0pLlZhbHVlDQogICAgICAgICAgICBXcml0ZS1PdXRwdXQgIlBvd2VyU3luY1BybyBpcyBydW5uaW5nIGFzICRyZXNvbHZlZFVzZXIuIFVwZGF0aW5nIHByaXZhdGUga2V5IEFDTC4uLiINCg0KICAgICAgICAgICAgJGtleVByb3ZJbmZvID0gJG5ld0NlcnQuUHJpdmF0ZUtleS5Dc3BLZXlDb250YWluZXJJbmZvLlVuaXF1ZUtleUNvbnRhaW5lck5hbWUNCiAgICAgICAgICAgICRtYWNoaW5lS2V5c1BhdGggPSAiJGVudjpQcm9ncmFtRGF0YVxNaWNyb3NvZnRcQ3J5cHRvXFJTQVxNYWNoaW5lS2V5cyINCiAgICAgICAgICAgICRrZXlQYXRoID0gSm9pbi1QYXRoICRtYWNoaW5lS2V5c1BhdGggJGtleVByb3ZJbmZvDQoNCiAgICAgICAgICAgIGlmIChUZXN0LVBhdGggJGtleVBhdGgpIHsNCiAgICAgICAgICAgICAgICAkYWNsID0gR2V0LUFjbCAka2V5UGF0aA0KICAgICAgICAgICAgICAgICRhY2Nlc3NSdWxlID0gTmV3LU9iamVjdCBTeXN0ZW0uU2VjdXJpdHkuQWNjZXNzQ29udHJvbC5GaWxlU3lzdGVtQWNjZXNzUnVsZSgkcmVzb2x2ZWRVc2VyLCAiRnVsbENvbnRyb2wiLCAiQWxsb3ciKQ0KICAgICAgICAgICAgICAgICRhY2wuU2V0QWNjZXNzUnVsZSgkYWNjZXNzUnVsZSkNCiAgICAgICAgICAgICAgICBTZXQtQWNsIC1QYXRoICRrZXlQYXRoIC1BY2xPYmplY3QgJGFjbA0KICAgICAgICAgICAgICAgIFdyaXRlLU91dHB1dCAiR3JhbnRlZCBGdWxsQ29udHJvbCBvbiBwcml2YXRlIGtleSB0byAkcmVzb2x2ZWRVc2VyIg0KICAgICAgICAgICAgfSBlbHNlIHsNCiAgICAgICAgICAgICAgICBXcml0ZS1XYXJuaW5nICJQcml2YXRlIGtleSBmaWxlIG5vdCBmb3VuZCBhdCAka2V5UGF0aCINCiAgICAgICAgICAgIH0NCiAgICAgICAgfSBjYXRjaCB7DQogICAgICAgICAgICBXcml0ZS1FcnJvciAiRmFpbGVkIHRvIGFkanVzdCBwcml2YXRlIGtleSBwZXJtaXNzaW9ucyBmb3IgJHN2Y1VzZXIgOiAkKCRfLkV4Y2VwdGlvbi5NZXNzYWdlKSINCiAgICAgICAgfQ0KICAgIH0NCn0NCg0KIyBVcGRhdGUgYXBwc2V0dGluZ3MuanNvbg0KJGFwcFNldHRpbmdzUGF0aCA9ICJDOlxQcm9ncmFtIEZpbGVzXFBvd2VyU3luY1Byb1xhcHBzZXR0aW5ncy5qc29uIg0KDQp0cnkgew0KICAgIGlmIChUZXN0LVBhdGggJGFwcFNldHRpbmdzUGF0aCkgew0KICAgICAgICAkanNvbiA9IEdldC1Db250ZW50ICRhcHBTZXR0aW5nc1BhdGggLVJhdyB8IENvbnZlcnRGcm9tLUpzb24NCiAgICAgICAgJGFjdHVhbFN1YmplY3QgPSAkbmV3Q2VydC5HZXROYW1lSW5mbygnU2ltcGxlTmFtZScsICRmYWxzZSkNCg0KICAgICAgICBpZiAoJGpzb24uS2VzdHJlbC5FbmRwb2ludHMuUFNPYmplY3QuUHJvcGVydGllcy5OYW1lIC1ub3Rjb250YWlucyAiSHR0cHMiKSB7DQogICAgICAgICAgICBXcml0ZS1XYXJuaW5nICJIVFRQUyBlbmRwb2ludCBub3QgZm91bmQgaW4gYXBwc2V0dGluZ3MuanNvbi4gQ3JlYXRpbmcgb25lIG9uIHBvcnQgNTAwMS4iDQoNCiAgICAgICAgICAgICRqc29uLktlc3RyZWwuRW5kcG9pbnRzIHwgQWRkLU1lbWJlciAtTWVtYmVyVHlwZSBOb3RlUHJvcGVydHkgLU5hbWUgIkh0dHBzIiAtVmFsdWUgQHsNCiAgICAgICAgICAgICAgICBVcmwgICAgICAgPSAiaHR0cHM6Ly8qOjUwMDEiDQogICAgICAgICAgICAgICAgUHJvdG9jb2xzID0gIkh0dHAxQW5kSHR0cDIiDQogICAgICAgICAgICAgICAgQ2VydGlmaWNhdGUgPSBAew0KICAgICAgICAgICAgICAgICAgICBTdWJqZWN0ICAgICAgPSAkYWN0dWFsU3ViamVjdA0KICAgICAgICAgICAgICAgICAgICBTdG9yZSAgICAgICAgPSAiTXkiDQogICAgICAgICAgICAgICAgICAgIExvY2F0aW9uICAgICA9ICJMb2NhbE1hY2hpbmUiDQogICAgICAgICAgICAgICAgICAgIEFsbG93SW52YWxpZCA9ICR0cnVlDQogICAgICAgICAgICAgICAgfQ0KICAgICAgICAgICAgfQ0KDQogICAgICAgICAgICAkanNvbiB8IENvbnZlcnRUby1Kc29uIC1EZXB0aCAxMCB8IFNldC1Db250ZW50IC1QYXRoICRhcHBTZXR0aW5nc1BhdGggLUVuY29kaW5nIFVURjgNCiAgICAgICAgICAgIFdyaXRlLU91dHB1dCAiQWRkZWQgSFRUUFMgZW5kcG9pbnQgd2l0aCBuZXcgY2VydGlmaWNhdGUgc3ViamVjdCAkYWN0dWFsU3ViamVjdC4iDQogICAgICAgIH0NCiAgICAgICAgZWxzZSB7DQogICAgICAgICAgICAkY29uZmlndXJlZFN1YmplY3QgPSAkanNvbi5LZXN0cmVsLkVuZHBvaW50cy5IdHRwcy5DZXJ0aWZpY2F0ZS5TdWJqZWN0DQoNCiAgICAgICAgICAgIGlmICgkY29uZmlndXJlZFN1YmplY3QgLW5lICRhY3R1YWxTdWJqZWN0KSB7DQogICAgICAgICAgICAgICAgV3JpdGUtV2FybmluZyAiQ29uZmlndXJlZCBjZXJ0IHN1YmplY3QgKCRjb25maWd1cmVkU3ViamVjdCkgZG9lcyBub3QgbWF0Y2ggbmV3IGNlcnQgKCRhY3R1YWxTdWJqZWN0KS4gVXBkYXRpbmcgYXV0b21hdGljYWxseS4iDQogICAgICAgICAgICAgICAgJGpzb24uS2VzdHJlbC5FbmRwb2ludHMuSHR0cHMuQ2VydGlmaWNhdGUuU3ViamVjdCA9ICRhY3R1YWxTdWJqZWN0DQogICAgICAgICAgICAgICAgJGpzb24gfCBDb252ZXJ0VG8tSnNvbiAtRGVwdGggMTAgfCBTZXQtQ29udGVudCAtUGF0aCAkYXBwU2V0dGluZ3NQYXRoIC1FbmNvZGluZyBVVEY4DQogICAgICAgICAgICAgICAgV3JpdGUtT3V0cHV0ICJVcGRhdGVkIGFwcHNldHRpbmdzLmpzb24gd2l0aCBuZXcgc3ViamVjdCAkYWN0dWFsU3ViamVjdC4iDQogICAgICAgICAgICB9IGVsc2Ugew0KICAgICAgICAgICAgICAgIFdyaXRlLU91dHB1dCAiYXBwc2V0dGluZ3MuanNvbiBhbHJlYWR5IG1hdGNoZXMgdGhlIGN1cnJlbnQgY2VydGlmaWNhdGUgc3ViamVjdC4iDQogICAgICAgICAgICB9DQogICAgICAgIH0NCiAgICB9DQogICAgZWxzZSB7DQogICAgICAgIFdyaXRlLVdhcm5pbmcgImFwcHNldHRpbmdzLmpzb24gbm90IGZvdW5kIGF0ICRhcHBTZXR0aW5nc1BhdGgiDQogICAgfQ0KfQ0KY2F0Y2ggew0KICAgIFdyaXRlLUVycm9yICJGYWlsZWQgdG8gdXBkYXRlIGFwcHNldHRpbmdzLmpzb246ICQoJF8uRXhjZXB0aW9uLk1lc3NhZ2UpIg0KfQ0KDQojIFVwZGF0ZSBJSVMgd2l0aCBuZXcgQ2VydA0KSW1wb3J0LU1vZHVsZSBXZWJBZG1pbmlzdHJhdGlvbiAtRXJyb3JBY3Rpb24gU3RvcA0KDQokc2l0ZU5hbWUgICA9ICJEZWZhdWx0IFdlYiBTaXRlIg0KJG5ld1RodW1iICAgPSAkbmV3Q2VydC5UaHVtYnByaW50DQokY2VydE9iamVjdCA9IEdldC1JdGVtICJDZXJ0OlxMb2NhbE1hY2hpbmVcTXlcJG5ld1RodW1iIg0KDQokYmluZGluZyA9IEdldC1XZWJCaW5kaW5nIC1OYW1lICRzaXRlTmFtZSAtUHJvdG9jb2wgImh0dHBzIiAtUG9ydCA0NDMgLUVycm9yQWN0aW9uIFNpbGVudGx5Q29udGludWUNCg0KaWYgKCRiaW5kaW5nKSB7DQogICAgV3JpdGUtT3V0cHV0ICJGb3VuZCBleGlzdGluZyBIVFRQUyBiaW5kaW5nIGZvciAnJHNpdGVOYW1lJy4gVXBkYXRpbmcgd2l0aCBjZXJ0ICRuZXdUaHVtYiINCg0KICAgICRzc2xCaW5kaW5ncyA9IEdldC1DaGlsZEl0ZW0gSUlTOlxTc2xCaW5kaW5ncw0KICAgIGlmICgkc3NsQmluZGluZ3MpIHsNCiAgICAgICAgJHNzbEJpbmRpbmcgPSAkc3NsQmluZGluZ3MgfCBXaGVyZS1PYmplY3QgeyAkXy5Qb3J0IC1lcSA0NDMgfSB8IFNlbGVjdC1PYmplY3QgLUZpcnN0IDENCg0KICAgICAgICBpZiAoJHNzbEJpbmRpbmcpIHsNCiAgICAgICAgICAgIFdyaXRlLU91dHB1dCAiVXBkYXRpbmcgU1NMIGJpbmRpbmcgcGF0aCAkKCRzc2xCaW5kaW5nLlBTUGF0aCkiDQogICAgICAgICAgICBTZXQtSXRlbSAtUGF0aCAkc3NsQmluZGluZy5QU1BhdGggLVZhbHVlICRjZXJ0T2JqZWN0IC1Gb3JjZQ0KICAgICAgICB9IGVsc2Ugew0KICAgICAgICAgICAgV3JpdGUtV2FybmluZyAiTm8gU1NMIGJpbmRpbmcgb2JqZWN0IGZvdW5kIGZvciBwb3J0IDQ0My4gQ3JlYXRpbmcgb25lLi4uIg0KICAgICAgICAgICAgJHNzbFBhdGggPSAiSUlTOlxTc2xCaW5kaW5nc1wwLjAuMC4wITQ0MyINCiAgICAgICAgICAgIE5ldy1JdGVtICRzc2xQYXRoIC1WYWx1ZSAkY2VydE9iamVjdCAtU1NMRmxhZ3MgMCB8IE91dC1OdWxsDQogICAgICAgIH0NCiAgICB9IGVsc2Ugew0KICAgICAgICBXcml0ZS1XYXJuaW5nICJObyBTU0wgYmluZGluZ3MgY3VycmVudGx5IGV4aXN0LiBDcmVhdGluZyBvbmUuLi4iDQogICAgICAgICRzc2xQYXRoID0gIklJUzpcU3NsQmluZGluZ3NcMC4wLjAuMCE0NDMiDQogICAgICAgIE5ldy1JdGVtICRzc2xQYXRoIC1WYWx1ZSAkY2VydE9iamVjdCAtU1NMRmxhZ3MgMCB8IE91dC1OdWxsDQogICAgfQ0KfSBlbHNlIHsNCiAgICBXcml0ZS1PdXRwdXQgIk5vIEhUVFBTIGJpbmRpbmcgZm91bmQgZm9yICckc2l0ZU5hbWUnLiBDcmVhdGluZyBuZXcgYmluZGluZyB3aXRoIGNlcnQgJG5ld1RodW1iIg0KICAgIE5ldy1XZWJCaW5kaW5nIC1OYW1lICRzaXRlTmFtZSAtUHJvdG9jb2wgaHR0cHMgLVBvcnQgNDQzIC1JUEFkZHJlc3MgKiAtSG9zdEhlYWRlciAiIg0KICAgICRzc2xQYXRoID0gIklJUzpcU3NsQmluZGluZ3NcMC4wLjAuMCE0NDMiDQogICAgTmV3LUl0ZW0gJHNzbFBhdGggLVZhbHVlICRjZXJ0T2JqZWN0IC1TU0xGbGFncyAwIHwgT3V0LU51bGwNCn0NCg0KV3JpdGUtT3V0cHV0ICJJSVMgYmluZGluZyB1cGRhdGVkIHN1Y2Nlc3NmdWxseS4iDQoNCiMgUmVzdGFydCB0aGUgc2VydmljZQ0KUmVzdGFydC1TZXJ2aWNlIC1OYW1lICJQb3dlclN5bmNQcm8iIC1Gb3JjZQ0KV3JpdGUtT3V0cHV0ICJQb3dlclN5bmNQcm8gc2VydmljZSByZXN0YXJ0ZWQuIg0KDQpTdG9wLVRyYW5zY3JpcHQNCg==
"@

$WebConfigScriptName = "WebConfig_Editor.ps1"
$WebConfigScriptEncoded = @"
cGFyYW0oDQogICAgW3N0cmluZ10kQ29uZmlnUGF0aCA9ICJDOlxpbmV0cHViXHd3d3Jvb3Rcd2ViLmNvbmZpZyIsDQoNCiAgICBbc3RyaW5nW11dJEFkZEFsbG93ZWRBZGRyZXNzZXMsDQogICAgW3N0cmluZ1tdXSRSZW1vdmVBbGxvd2VkQWRkcmVzc2VzLA0KDQogICAgW3N0cmluZ10kU2V0RlFETiwNCiAgICBbc3dpdGNoXSRHZXRDb25maWcsDQoNCiAgICBbc3dpdGNoXSRBc0pzb24sDQogICAgW3N3aXRjaF0kRHJ5UnVuDQopDQoNCiMgTG9hZCBYTUwNClt4bWxdJHhtbCA9IEdldC1Db250ZW50ICRDb25maWdQYXRoDQokaXBTZWN1cml0eU5vZGUgPSAkeG1sLmNvbmZpZ3VyYXRpb24uJ3N5c3RlbS53ZWJTZXJ2ZXInLnNlY3VyaXR5LmlwU2VjdXJpdHkNCg0KIyAtLS0gQ0lEUiBDb252ZXJzaW9uIHdpdGggLzMyIGRlZmF1bHQgYW5kIGdyYWNlZnVsIGVycm9yIGhhbmRsaW5nIC0tLQ0KZnVuY3Rpb24gQ29udmVydC1DSURSVG9JUE1hc2sgew0KICAgIHBhcmFtKFtzdHJpbmddJENJRFIpDQoNCiAgICAjIElmIHVzZXIgZW50ZXJlZCBqdXN0IGFuIElQLCBhc3N1bWUgLzMyDQogICAgaWYgKCRDSURSIC1ub3RtYXRjaCAiLyIpIHsgJENJRFIgKz0gIi8zMiIgfQ0KDQogICAgaWYgKCRDSURSIC1ub3RtYXRjaCAiXihcZHsxLDN9KFwuXGR7MSwzfSl7M30pLyhcZHsxLDJ9KSQiKSB7DQogICAgICAgIFdyaXRlLUhvc3QgIkVycm9yOiBJbnZhbGlkIElQIG9yIENJRFIgZm9ybWF0OiAkQ0lEUiIgLUZvcmVncm91bmRDb2xvciBSZWQNCiAgICAgICAgcmV0dXJuICRudWxsDQogICAgfQ0KDQogICAgJGlwU3RyID0gJE1hdGNoZXNbMV0NCiAgICAkcHJlZml4ID0gW2ludF0kTWF0Y2hlc1szXQ0KDQogICAgIyBWYWxpZGF0ZSBJUCBvY3RldHMNCiAgICAkb2N0ZXRzID0gJGlwU3RyLlNwbGl0KCcuJykgfCBGb3JFYWNoLU9iamVjdCB7IFtpbnRdJF8gfQ0KICAgIGlmICgkb2N0ZXRzIHwgV2hlcmUtT2JqZWN0IHsgJF8gLWx0IDAgLW9yICRfIC1ndCAyNTUgfSkgew0KICAgICAgICBXcml0ZS1Ib3N0ICJFcnJvcjogSW52YWxpZCBJUCBhZGRyZXNzOiAkaXBTdHIiIC1Gb3JlZ3JvdW5kQ29sb3IgUmVkDQogICAgICAgIHJldHVybiAkbnVsbA0KICAgIH0NCg0KICAgIGlmICgkcHJlZml4IC1sdCAwIC1vciAkcHJlZml4IC1ndCAzMikgew0KICAgICAgICBXcml0ZS1Ib3N0ICJFcnJvcjogSW52YWxpZCBDSURSIHByZWZpeCBsZW5ndGg6ICRwcmVmaXgiIC1Gb3JlZ3JvdW5kQ29sb3IgUmVkDQogICAgICAgIHJldHVybiAkbnVsbA0KICAgIH0NCg0KICAgICRtYXNrQml0cyA9ICgiMSIgKiAkcHJlZml4KS5QYWRSaWdodCgzMiwgIjAiKQ0KICAgICRtYXNrQnl0ZXMgPSBAKCkNCiAgICBmb3JlYWNoICgkaSBpbiAwLi4zKSB7DQogICAgICAgICRtYXNrQnl0ZXMgKz0gW0NvbnZlcnRdOjpUb0ludDMyKCRtYXNrQml0cy5TdWJzdHJpbmcoJGkqOCw4KSwyKQ0KICAgIH0NCiAgICAkbWFzayA9IFtTeXN0ZW0uTmV0LklQQWRkcmVzc106Om5ldygkbWFza0J5dGVzKQ0KDQogICAgcmV0dXJuIEB7DQogICAgICAgIElQQWRkcmVzcyA9ICRpcFN0cg0KICAgICAgICBTdWJuZXRNYXNrID0gJG1hc2suVG9TdHJpbmcoKQ0KICAgIH0NCn0NCg0KIyBDb252ZXJ0IHN1Ym5ldCBtYXNrIGJhY2sgdG8gcHJlZml4IGxlbmd0aA0KZnVuY3Rpb24gU3VibmV0TWFza1RvUHJlZml4IHsNCiAgICBwYXJhbShbc3RyaW5nXSRTdWJuZXRNYXNrKQ0KICAgICRieXRlcyA9ICRTdWJuZXRNYXNrLlNwbGl0KCcuJykgfCBGb3JFYWNoLU9iamVjdCB7IFtDb252ZXJ0XTo6VG9TdHJpbmcoW2ludF0kXywyKS5QYWRMZWZ0KDgsJzAnKSB9DQogICAgJGJpbmFyeSA9ICgkYnl0ZXMgLWpvaW4gJycpDQogICAgcmV0dXJuICgkYmluYXJ5LlRvQ2hhckFycmF5KCkgfCBXaGVyZS1PYmplY3QgeyAkXyAtZXEgJzEnIH0pLkNvdW50DQp9DQoNCiMgLS0tIElQIE1hbmFnZW1lbnQgLS0tDQpmdW5jdGlvbiBTaG93LUFsbG93ZWRJUHMgeyAkaXBTZWN1cml0eU5vZGUuYWRkIHwgRm9yRWFjaC1PYmplY3QgeyBAeyBJUEFkZHJlc3MgPSAkXy5pcEFkZHJlc3M7IFN1Ym5ldE1hc2sgPSAkXy5zdWJuZXRNYXNrIH0gfSB9DQoNCmZ1bmN0aW9uIEFkZC1BbGxvd2VkSVAgew0KICAgIHBhcmFtKFtzdHJpbmddJENJRFIpDQogICAgJHJlc3VsdCA9IENvbnZlcnQtQ0lEUlRvSVBNYXNrICRDSURSDQogICAgaWYgKC1ub3QgJHJlc3VsdCkgeyByZXR1cm4gJGZhbHNlIH0NCg0KICAgICRJUEFkZHJlc3MgPSAkcmVzdWx0LklQQWRkcmVzcw0KICAgICRTdWJuZXRNYXNrID0gJHJlc3VsdC5TdWJuZXRNYXNrDQogICAgJHByZWZpeCA9IFN1Ym5ldE1hc2tUb1ByZWZpeCAkU3VibmV0TWFzaw0KDQogICAgJGV4aXN0cyA9ICRpcFNlY3VyaXR5Tm9kZS5hZGQgfCBXaGVyZS1PYmplY3QgeyAkXy5pcEFkZHJlc3MgLWVxICRJUEFkZHJlc3MgLWFuZCAkXy5zdWJuZXRNYXNrIC1lcSAkU3VibmV0TWFzayB9DQogICAgaWYgKC1ub3QgJGV4aXN0cykgew0KICAgICAgICBpZiAoJERyeVJ1bikgew0KICAgICAgICAgICAgV3JpdGUtSG9zdCAiRHJ5UnVuOiBXb3VsZCBhZGQgSVAgJElQQWRkcmVzcy8kcHJlZml4IiAtRm9yZWdyb3VuZENvbG9yIEN5YW4NCiAgICAgICAgfSBlbHNlIHsNCiAgICAgICAgICAgICRuZXdJUCA9ICR4bWwuQ3JlYXRlRWxlbWVudCgiYWRkIikNCiAgICAgICAgICAgICRuZXdJUC5TZXRBdHRyaWJ1dGUoImlwQWRkcmVzcyIsICRJUEFkZHJlc3MpDQogICAgICAgICAgICAkbmV3SVAuU2V0QXR0cmlidXRlKCJzdWJuZXRNYXNrIiwgJFN1Ym5ldE1hc2spDQogICAgICAgICAgICAkbmV3SVAuU2V0QXR0cmlidXRlKCJhbGxvd2VkIiwgInRydWUiKQ0KICAgICAgICAgICAgJGlwU2VjdXJpdHlOb2RlLkFwcGVuZENoaWxkKCRuZXdJUCkgfCBPdXQtTnVsbA0KICAgICAgICAgICAgV3JpdGUtSG9zdCAiQWRkZWQgSVAgJElQQWRkcmVzcy8kcHJlZml4IiAtRm9yZWdyb3VuZENvbG9yIEdyZWVuDQogICAgICAgIH0NCiAgICAgICAgcmV0dXJuICR0cnVlDQogICAgfSBlbHNlIHsNCiAgICAgICAgV3JpdGUtSG9zdCAiSVAgJElQQWRkcmVzcy8kcHJlZml4IGFscmVhZHkgZXhpc3RzIiAtRm9yZWdyb3VuZENvbG9yIFllbGxvdw0KICAgICAgICByZXR1cm4gJGZhbHNlDQogICAgfQ0KfQ0KDQpmdW5jdGlvbiBSZW1vdmUtQWxsb3dlZElQIHsNCiAgICBwYXJhbShbc3RyaW5nXSRDSURSKQ0KICAgICRyZXN1bHQgPSBDb252ZXJ0LUNJRFJUb0lQTWFzayAkQ0lEUg0KICAgIGlmICgtbm90ICRyZXN1bHQpIHsgcmV0dXJuICRmYWxzZSB9DQoNCiAgICAkSVBBZGRyZXNzID0gJHJlc3VsdC5JUEFkZHJlc3MNCiAgICAkU3VibmV0TWFzayA9ICRyZXN1bHQuU3VibmV0TWFzaw0KICAgICRwcmVmaXggPSBTdWJuZXRNYXNrVG9QcmVmaXggJFN1Ym5ldE1hc2sNCg0KICAgICRub2RlID0gJGlwU2VjdXJpdHlOb2RlLmFkZCB8IFdoZXJlLU9iamVjdCB7ICRfLmlwQWRkcmVzcyAtZXEgJElQQWRkcmVzcyAtYW5kICRfLnN1Ym5ldE1hc2sgLWVxICRTdWJuZXRNYXNrIH0NCiAgICBpZiAoJG5vZGUpIHsNCiAgICAgICAgaWYgKCREcnlSdW4pIHsNCiAgICAgICAgICAgIFdyaXRlLUhvc3QgIkRyeVJ1bjogV291bGQgcmVtb3ZlIElQICRJUEFkZHJlc3MvJHByZWZpeCIgLUZvcmVncm91bmRDb2xvciBDeWFuDQogICAgICAgIH0gZWxzZSB7DQogICAgICAgICAgICAkaXBTZWN1cml0eU5vZGUuUmVtb3ZlQ2hpbGQoJG5vZGUpIHwgT3V0LU51bGwNCiAgICAgICAgICAgIFdyaXRlLUhvc3QgIlJlbW92ZWQgSVAgJElQQWRkcmVzcy8kcHJlZml4IiAtRm9yZWdyb3VuZENvbG9yIEdyZWVuDQogICAgICAgIH0NCiAgICAgICAgcmV0dXJuICR0cnVlDQogICAgfSBlbHNlIHsNCiAgICAgICAgV3JpdGUtSG9zdCAiSVAgJElQQWRkcmVzcy8kcHJlZml4IG5vdCBmb3VuZCIgLUZvcmVncm91bmRDb2xvciBZZWxsb3cNCiAgICAgICAgcmV0dXJuICRmYWxzZQ0KICAgIH0NCn0NCg0KIyAtLS0gRlFETiBNYW5hZ2VtZW50IC0tLQ0KZnVuY3Rpb24gR2V0LUZRRE4geyAoJHhtbC5jb25maWd1cmF0aW9uLidzeXN0ZW0ud2ViU2VydmVyJy5yZXdyaXRlLm91dGJvdW5kUnVsZXMucnVsZSB8IFdoZXJlLU9iamVjdCB7ICRfLm5hbWUgLWVxICJQb3dlclN5bmNQcm9SZXZlcnNlUHJveHlPdXRib3VuZFJ1bGUxIiB9KS5hY3Rpb24udmFsdWUgLXJlcGxhY2UgJ2h0dHBzOi8vKFteL10rKS8uKicsJyQxJyB9DQoNCmZ1bmN0aW9uIFNldC1GUUROIHsNCiAgICBwYXJhbShbc3RyaW5nXSROZXdEb21haW4pDQogICAgJHJ1bGUgPSAkeG1sLmNvbmZpZ3VyYXRpb24uJ3N5c3RlbS53ZWJTZXJ2ZXInLnJld3JpdGUub3V0Ym91bmRSdWxlcy5ydWxlIHwgV2hlcmUtT2JqZWN0IHsgJF8ubmFtZSAtZXEgIlBvd2VyU3luY1Byb1JldmVyc2VQcm94eU91dGJvdW5kUnVsZTEiIH0NCiAgICAkb2xkRG9tYWluID0gJHJ1bGUuYWN0aW9uLnZhbHVlIC1yZXBsYWNlICdodHRwczovLyhbXi9dKykvLionLCckMScNCg0KICAgIGlmICgkb2xkRG9tYWluIC1uZSAkTmV3RG9tYWluKSB7DQogICAgICAgIGlmICgkRHJ5UnVuKSB7DQogICAgICAgICAgICBXcml0ZS1Ib3N0ICJEcnlSdW46IFdvdWxkIHVwZGF0ZSByZXdyaXRlIGRvbWFpbiBmcm9tICRvbGREb21haW4gdG8gJE5ld0RvbWFpbiIgLUZvcmVncm91bmRDb2xvciBDeWFuDQogICAgICAgIH0gZWxzZSB7DQogICAgICAgICAgICAkcnVsZS5hY3Rpb24udmFsdWUgPSAkcnVsZS5hY3Rpb24udmFsdWUgLXJlcGxhY2UgImh0dHBzOi8vW14vXSsvIiwgImh0dHBzOi8vJE5ld0RvbWFpbi8iDQogICAgICAgICAgICBXcml0ZS1Ib3N0ICJVcGRhdGVkIHJld3JpdGUgZG9tYWluIGZyb20gJG9sZERvbWFpbiB0byAkTmV3RG9tYWluIiAtRm9yZWdyb3VuZENvbG9yIEdyZWVuDQogICAgICAgIH0NCiAgICAgICAgcmV0dXJuICR0cnVlDQogICAgfSBlbHNlIHsNCiAgICAgICAgV3JpdGUtSG9zdCAiUmV3cml0ZSBkb21haW4gaXMgYWxyZWFkeSAkTmV3RG9tYWluIiAtRm9yZWdyb3VuZENvbG9yIFllbGxvdw0KICAgICAgICByZXR1cm4gJGZhbHNlDQogICAgfQ0KfQ0KDQojIC0tLSBTYXZlIENvbmZpZyB3aXRoIEJhY2t1cCBhbmQgSUlTIFJlbWluZGVyIC0tLQ0KZnVuY3Rpb24gU2F2ZS1Db25maWcgew0KICAgIGlmICgkRHJ5UnVuKSB7IA0KICAgICAgICBXcml0ZS1Ib3N0ICJEcnlSdW4gZW5hYmxlZDogd2ViLmNvbmZpZyB3b3VsZCBiZSB1cGRhdGVkIGFuZCBiYWNrZWQgdXAiIC1Gb3JlZ3JvdW5kQ29sb3IgQ3lhbg0KICAgICAgICByZXR1cm4gDQogICAgfQ0KDQogICAgJHRpbWVzdGFtcCA9IEdldC1EYXRlIC1Gb3JtYXQgInl5eXlNTWRkSEhtbXNzIg0KICAgICRiYWNrdXAgPSAiJENvbmZpZ1BhdGguJHRpbWVzdGFtcCINCiAgICBSZW5hbWUtSXRlbSAtUGF0aCAkQ29uZmlnUGF0aCAtTmV3TmFtZSAkYmFja3VwDQogICAgJHhtbC5TYXZlKCRDb25maWdQYXRoKQ0KICAgIFdyaXRlLUhvc3QgIndlYi5jb25maWcgdXBkYXRlZCBzdWNjZXNzZnVsbHkiIC1Gb3JlZ3JvdW5kQ29sb3IgQ3lhbg0KICAgIFdyaXRlLUhvc3QgIkJhY2t1cCBzYXZlZCBhcyAkYmFja3VwIiAtRm9yZWdyb3VuZENvbG9yIERhcmtDeWFuDQogICAgV3JpdGUtSG9zdCAiUmVtaW5kZXI6IFJlc3RhcnQgSUlTIGZvciBjaGFuZ2VzIHRvIHRha2UgZWZmZWN0OiIgLUZvcmVncm91bmRDb2xvciBZZWxsb3cNCiAgICBXcml0ZS1Ib3N0ICIgICAgaWlzcmVzZXQgL25vZm9yY2UiIC1Gb3JlZ3JvdW5kQ29sb3IgWWVsbG93DQp9DQoNCiMgLS0tIFBvcHVsYXRlIGN1cnJlbnQgY29uZmlnIGJlZm9yZSBhbnkgY2hhbmdlcyAtLS0NCiRvdXRwdXQgPSBAew0KICAgIEFsbG93ZWRJUHMgPSBTaG93LUFsbG93ZWRJUHMNCiAgICBSZXdyaXRlRlFETiA9IEdldC1GUURODQp9DQoNCiMgLS0tIENMSSBPcGVyYXRpb25zIC0tLQ0KJGNoYW5nZWQgPSAkZmFsc2UNCiRyYW5BbnlBY3Rpb24gPSAkZmFsc2UNCg0KaWYgKCRHZXRDb25maWcpIHsgJHJhbkFueUFjdGlvbiA9ICR0cnVlIH0NCg0KaWYgKCRBZGRBbGxvd2VkQWRkcmVzc2VzKSB7IA0KICAgIGZvcmVhY2ggKCRjaWRyIGluICRBZGRBbGxvd2VkQWRkcmVzc2VzKSB7IA0KICAgICAgICBpZiAoQWRkLUFsbG93ZWRJUCAtQ0lEUiAkY2lkcikgeyAkY2hhbmdlZCA9ICR0cnVlIH0gDQogICAgfSANCiAgICAkcmFuQW55QWN0aW9uID0gJHRydWUgDQp9DQoNCmlmICgkUmVtb3ZlQWxsb3dlZEFkZHJlc3NlcykgeyANCiAgICBmb3JlYWNoICgkY2lkciBpbiAkUmVtb3ZlQWxsb3dlZEFkZHJlc3NlcykgeyANCiAgICAgICAgaWYgKFJlbW92ZS1BbGxvd2VkSVAgLUNJRFIgJGNpZHIpIHsgJGNoYW5nZWQgPSAkdHJ1ZSB9IA0KICAgIH0gDQogICAgJHJhbkFueUFjdGlvbiA9ICR0cnVlIA0KfQ0KDQppZiAoJFNldEZRRE4pIHsgDQogICAgaWYgKFNldC1GUUROIC1OZXdEb21haW4gJFNldEZRRE4pIHsgJGNoYW5nZWQgPSAkdHJ1ZSB9IA0KICAgICRyYW5BbnlBY3Rpb24gPSAkdHJ1ZSANCn0NCg0KIyBSZWZyZXNoIG91dHB1dCBhZnRlciBhbnkgY2hhbmdlcw0KaWYgKCRjaGFuZ2VkKSB7DQogICAgJG91dHB1dC5BbGxvd2VkSVBzID0gU2hvdy1BbGxvd2VkSVBzDQogICAgJG91dHB1dC5SZXdyaXRlRlFETiA9IEdldC1GUURODQp9DQoNCiMgU2F2ZSBjaGFuZ2VzDQppZiAoJGNoYW5nZWQgLWFuZCAtbm90ICREcnlSdW4pIHsgU2F2ZS1Db25maWcgfQ0KZWxzZWlmICgkY2hhbmdlZCAtYW5kICREcnlSdW4pIHsgV3JpdGUtSG9zdCAiRHJ5UnVuOiBubyBjaGFuZ2VzIHNhdmVkIiAtRm9yZWdyb3VuZENvbG9yIEN5YW4gfQ0KDQojIE91dHB1dCByZXN1bHRzDQppZiAoJEFzSnNvbikgew0KICAgICRvdXRwdXQgfCBDb252ZXJ0VG8tSnNvbiAtRGVwdGggMw0KfQ0KZWxzZSB7DQogICAgV3JpdGUtSG9zdCAiQWxsb3dlZCBJUHM6Ig0KICAgICRvdXRwdXQuQWxsb3dlZElQcyB8IEZvckVhY2gtT2JqZWN0IHsgDQogICAgICAgICRwcmVmaXggPSBTdWJuZXRNYXNrVG9QcmVmaXggJF8uU3VibmV0TWFzaw0KICAgICAgICBXcml0ZS1Ib3N0ICIgICQoJF8uSVBBZGRyZXNzKS8kcHJlZml4Ig0KICAgIH0NCiAgICBXcml0ZS1Ib3N0ICJSZXdyaXRlIEZRRE46ICQoJG91dHB1dC5SZXdyaXRlRlFETikiDQoNCiAgICAjIFNob3cgYXZhaWxhYmxlIGZsYWdzIGlmIG5vIGFjdGlvbiB3YXMgcmVxdWVzdGVkDQogICAgaWYgKC1ub3QgJHJhbkFueUFjdGlvbikgew0KICAgICAgICBXcml0ZS1Ib3N0ICJgbkF2YWlsYWJsZSBmbGFnczoiIC1Gb3JlZ3JvdW5kQ29sb3IgQ3lhbg0KICAgICAgICBXcml0ZS1Ib3N0ICIgIC1HZXRDb25maWcgICAgICAgICAgICAgICAjIFNob3cgY3VycmVudCBJUHMgYW5kIEZRRE4iDQogICAgICAgIFdyaXRlLUhvc3QgIiAgLUFkZEFsbG93ZWRBZGRyZXNzZXMgICAgICMgQWRkIElQKHMpIGluIENJRFIgb3IgcGxhaW4gSVAgKGRlZmF1bHRzIHRvIC8zMikiDQogICAgICAgIFdyaXRlLUhvc3QgIiAgLVJlbW92ZUFsbG93ZWRBZGRyZXNzZXMgICMgUmVtb3ZlIElQKHMpIGluIENJRFIgb3IgcGxhaW4gSVAiDQogICAgICAgIFdyaXRlLUhvc3QgIiAgLVNldEZRRE4gPGRvbWFpbj4gICAgICAgICMgU2V0IG5ldyByZXdyaXRlIGRvbWFpbiINCiAgICAgICAgV3JpdGUtSG9zdCAiICAtRHJ5UnVuICAgICAgICAgICAgICAgICAgIyBTaG93IHdoYXQgd291bGQgY2hhbmdlIHdpdGhvdXQgbW9kaWZ5aW5nIHdlYi5jb25maWciDQogICAgICAgIFdyaXRlLUhvc3QgIiAgLUFzSnNvbiAgICAgICAgICAgICAgICAgICMgT3V0cHV0IGluIEpTT04gZm9ybWF0Ig0KICAgIH0NCn0NCg==
"@

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
    [string]$FrontendHost
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
    "PSP_HTTP_PORT=5000",
    "PSP_HTTPS_PORT=5001",
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
function Install-Scripts{
  param(
    [string]$TargetFile,
    [string]$TargetFolder,
    [string]$Encoded
  )

  $TargetPath   = Join-Path -Path $TargetFolder -ChildPath $TargetFile

  # Decode back to original script text
  $Bytes       = [Convert]::FromBase64String($Encoded)
  $ChildScript = [System.Text.Encoding]::UTF8.GetString($Bytes)

  # Ensure the folder exists
  if (-not (Test-Path $TargetFolder)) {
      New-Item -Path $TargetFolder -ItemType Directory -Force | Out-Null
  }

  # Write the decoded script with UTF-8 (no BOM), compatible across PS versions
  if ($PSVersionTable.PSEdition -eq 'Core' -or $PSVersionTable.PSVersion.Major -ge 6) {
      # PowerShell 7+ supports utf8NoBOM
      $ChildScript | Out-File -FilePath $TargetPath -Encoding utf8NoBOM -Force
  }
  else {
      # Windows PowerShell 5.1 fallback: use .NET directly
      $Utf8NoBom = New-Object System.Text.UTF8Encoding($False)  # $False = no BOM
      [System.IO.File]::WriteAllText($TargetPath, $ChildScript, $Utf8NoBom)
  }

  Write-Host "Dropped script to $TargetPath"
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
    param(
        [Parameter(Mandatory)][string]$PfxPath,
        [Parameter(Mandatory)][SecureString]$Password
    )
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($PfxPath, $Password)
    $name = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
    if ($name -and $name -match '^[^=]+=([^,]+)') { return $matches[1].Trim() }
    return $name
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
                                Stop-Transcript
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

            while ($true) {
                $rawPath = Read-Host "Please provide the full path of a PFX file (e.g. C:\Temp\companycert.pfx)"
                $PfxPath = $rawPath.Trim('"').Trim("'")
                $PfxPath = [System.Environment]::ExpandEnvironmentVariables($PfxPath)
                try { $PfxPath = [System.IO.Path]::GetFullPath((Join-Path -Path (Get-Location) -ChildPath $PfxPath)) } catch {}
                if (-not (Test-Path -Path $PfxPath -PathType Leaf)) { Write-Host "The file path does not exist. Please try again." -ForegroundColor Yellow; continue }
                if ([System.IO.Path]::GetExtension($PfxPath) -ne ".pfx") { Write-Host "The file must have a .pfx extension. Please try again." -ForegroundColor Yellow; continue }
                break
            }

            while ($true) {
                $PfxPass = Read-Host "Please provide the password for the provided PFX file" -AsSecureString
                try {
                    $CertFqdn = Get-PfxSubject -PfxPath $PfxPath -Password $PfxPass
                    if (-not $CertFqdn) { throw "Unable to read a DNS name from the certificate." }
                    Write-Host ("Certificate loaded. Subject DNS name: {0}" -f $CertFqdn) -ForegroundColor Green
                    break
                } catch {
                    Write-Host ("Failed to open PFX or read subject: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
                    $retry = Read-Host "Password may be incorrect. Try again? (Y/N)"
                    if ($retry -notmatch '^(Y|y)$') { throw "Invalid PFX or password." }
                }
            }

            $ResolvedHostname = $null
            if ($CertFqdn.StartsWith('*.')) {
                $wildRoot = $CertFqdn.Substring(2)
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
                        Write-Host ("Hostname {0} is valid for wildcard {1}" -f $ResolvedHostname, $CertFqdn) -ForegroundColor Green
                        break
                    } else {
                        Write-Host ("{0} is not valid for wildcard {1}. Must add exactly one label under {2}." -f $ResolvedHostname, $CertFqdn, $wildRoot) -ForegroundColor Yellow
                    }
                }
            } else {
                $ResolvedHostname = $CertFqdn
            }

            $CertConfig = [PSCustomObject]@{
                Type              = 'BYOC'
                PfxPath           = $PfxPath
                PfxPass           = $PfxPass
                CertFqdn          = $CertFqdn
                Hostname          = $ResolvedHostname
                WildcardValidated = [bool]($CertFqdn.StartsWith('*.'))
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


# Menu / Script Actions / Logic
# Initialize logging

# Register exit cleanup handler
Register-EngineEvent PowerShell.Exiting -Action {
    try { Stop-Transcript | Out-Null } catch {}
} | Out-Null

try{
    if (-not (Test-Path -Path (Split-Path $LogPath -Parent))) {
        New-Item -ItemType Directory -Path (Split-Path $LogPath -Parent) -Force | Out-Null
    }

    Start-Transcript -Path $LogPath -Append
    $ErrorActionPreference = "Stop"

    # Test if PowerSyncPro is running, if it is we should immediately bail out.
    if (Test-PowerSyncPro) {
        Write-Warning "PowerSyncPro Service is already installed or running on this system. Aborting installation script."
        Stop-Transcript
        exit 1
    }

    Write-Host "PowerSyncPro Service is *not* present or running - continuing installation..." -ForegroundColor Green

    if (-not (Test-IsServer2016OrNewer)) {
        Write-Host "This operating system is not supported. Windows Server 2016 or newer is required." -ForegroundColor Red
        Stop-Transcript
        exit 1   # stops the script with an error code
    }

    Write-Host "OS check passed - continuing installation..." -ForegroundColor Green
    Start-Sleep -Seconds 3

    # Test if machine is a server - we shouldn't run on non-server OS and versions under 2016.

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


    # Install PSP w/ SQLExpress Backend, Sane Defaults - We don't need to check its running, we did that above.
    Install-PSP -PSPUrl $PSPUrl -tempDir $tempDir -FrontendHost $FrontendHost

    # Drop Support Scripts and custom Webconfig - We don't check that they already exist.

    # ACME Cert Puller - if doing a LetsEncrypt Certificate
    if ($CertType -eq "LetsEncrypt"){
        Write-Host "Installing ACME / LetsEncrypt Certificate Tool `($CertPullerScriptName`) to $ScriptFolder" -ForegroundColor Cyan
        Install-Scripts -TargetFile $CertPullerScriptName -TargetFolder $ScriptFolder -Encoded $CertPullerScriptEncoded
    }
 
    # WebConfig Editor Tool
    Write-Host "Installing Web.Config Editor Tool `($WebConfigScriptName`) to $ScriptFolder" -ForegroundColor Cyan
    Install-Scripts -TargetFile $WebConfigScriptName -TargetFolder $ScriptFolder -Encoded $WebConfigScriptEncoded

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

    #if ($certInstalled) {
    #    Write-Host "Installation Complete and Certificate Installed..." -ForegroundColor Green
    #}
    #else {
    #    Write-Host "Installation Complete but Certificate Installation Failed..." -ForegroundColor Red
    #}

    Write-Host "Admin access to PSP via the Reverse Proxy - e.g. https://$FrontEndHost"
    Write-Host "has been restricted to localhost only."
    Write-Host "`n"
    Write-Host "You can modify hosts which are allowed to access the HTTPS Reverse Proxy by running C:\Scripts\WebConfig_Editor.ps1."
    Write-Host "This restriction does not apply to https://$FrontEndHost/Agent which is used for the PSP Migration Agent."
    Write-Host "`n"
    Write-Host "You can now access PowerSyncPro at https://$FrontEndHost/ from this system." -ForegroundColor Yellow
    Write-Host "The default password is admin / 123qwe, please change it." -ForegroundColor Yellow
    Write-Host "`n"
    Write-Host "If you need additional support or assistance, please open a ticket at https://tickets.powersyncpro.com/."
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