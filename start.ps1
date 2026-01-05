<#
    Nubrix Management Program - Bootstrapper (start.ps1)

    What this does:
    - Creates standard folders under ProgramData
    - Downloads latest package ZIP from GitHub
    - Extracts and deploys to "Current"
    - Unblocks files
    - Ensures config lives in ProgramData\Config (survives updates)
    - Migrates config from Current -> Config if needed
    - Ensures an app-only certificate exists in LocalMachine\My (and updates config thumbprint if it generates one)
    - Creates a shortcut on the Public Desktop (works even when elevated)
    - Launches Main.ps1

    Notes:
    - No Git required
    - Runs best as Administrator (ProgramData + shortcut + LocalMachine cert store)
    - This bootstrapper does NOT create the app registration or grant consent (you already did that).
#>

[CmdletBinding()]
param(
    # Package ZIP URL (raw). Replace with your package URL.
    [Parameter(Mandatory = $false)]
    [string]$RepoZipUrl = "https://raw.githubusercontent.com/nubrixsecurity/expatride-management-tool/main/main.zip",

    # Folder name under ProgramData
    [Parameter(Mandatory = $false)]
    [string]$ProductFolderName = "Nubrix\AdminTool",

    # Shortcut name (Public Desktop)
    [Parameter(Mandatory = $false)]
    [string]$ShortcutName = "ExpatRide-Management-Program",

    # Script to launch after install (relative to extracted root folder)
    [Parameter(Mandatory = $false)]
    [string]$EntryScript = "Main.ps1",

    # If set, will NOT overwrite Current (useful for testing)
    [Parameter(Mandatory = $false)]
    [switch]$NoOverwrite
)

#region Helpers (no emojis/icons)
function Write-Info { param([string]$m) Write-Host $m -ForegroundColor Cyan }
function Write-Warn { param([string]$m) Write-Host $m -ForegroundColor Yellow }
function Write-Err  { param([string]$m) Write-Host $m -ForegroundColor Red }

function Ensure-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warn "Re-launching as Administrator..."
        $args = @(
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", "`"$PSCommandPath`""
        )
        Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs
        exit
    }
}

function New-Shortcut {
    param(
        [Parameter(Mandatory)] [string]$ShortcutPath,
        [Parameter(Mandatory)] [string]$TargetPath,
        [Parameter(Mandatory)] [string]$Arguments,
        [Parameter(Mandatory)] [string]$WorkingDirectory
    )

    $wsh = New-Object -ComObject WScript.Shell
    $sc = $wsh.CreateShortcut($ShortcutPath)
    $sc.TargetPath = $TargetPath
    $sc.Arguments = $Arguments
    $sc.WorkingDirectory = $WorkingDirectory
    $sc.IconLocation = $TargetPath
    $sc.Save()
}

function Test-ZipHeader {
    param([Parameter(Mandatory)][string]$Path)
    try {
        $fs = [System.IO.File]::OpenRead($Path)
        $b1 = $fs.ReadByte()
        $b2 = $fs.ReadByte()
        $fs.Close()
        return ($b1 -eq 0x50 -and $b2 -eq 0x4B) # 'PK'
    } catch {
        return $false
    }
}
#endregion Helpers

Ensure-Admin

#region Folder Structure
$root    = Join-Path $env:ProgramData $ProductFolderName
$current = Join-Path $root "Current"
$cache   = Join-Path $root "Cache"
$config  = Join-Path $root "Config"
$logs    = Join-Path $root "Logs"

foreach ($f in @($root, $current, $cache, $config, $logs)) {
    if (-not (Test-Path -LiteralPath $f)) {
        New-Item -ItemType Directory -Path $f -Force | Out-Null
    }
}

Write-Info "Install root: $root"
#endregion Folder Structure

#region Download + Extract
$zipPath     = Join-Path $cache "repo.zip"
$tempExtract = Join-Path $cache ("extract_" + [Guid]::NewGuid().ToString("N"))

if (Test-Path -LiteralPath $tempExtract) {
    Remove-Item -LiteralPath $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $tempExtract -Force | Out-Null

Write-Info "Downloading package..."
try {
    Invoke-WebRequest -Uri $RepoZipUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Err "Download failed: $($_.Exception.Message)"
    exit 1
}

if (-not (Test-ZipHeader -Path $zipPath)) {
    Write-Err "Downloaded file is not a ZIP. Verify RepoZipUrl points to a raw ZIP download."
    Write-Err "RepoZipUrl: $RepoZipUrl"
    exit 1
}

Write-Info "Extracting..."
try {
    Expand-Archive -LiteralPath $zipPath -DestinationPath $tempExtract -Force
} catch {
    Write-Err "Extract failed: $($_.Exception.Message)"
    exit 1
}

# ZIP extracts to a single top-level folder in most cases
$extractedRoot = Get-ChildItem -LiteralPath $tempExtract -Directory | Select-Object -First 1
if (-not $extractedRoot) {
    Write-Err "Could not find extracted root folder."
    exit 1
}

$sourcePath = $extractedRoot.FullName
$entryPath  = Join-Path $sourcePath $EntryScript
if (-not (Test-Path -LiteralPath $entryPath)) {
    Write-Err "Entry script not found: $EntryScript"
    Write-Err "Expected at: $entryPath"
    exit 1
}

if (-not $NoOverwrite) {
    Write-Info "Deploying to Current..."
    Get-ChildItem -LiteralPath $current -Force | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Copy-Item -Path (Join-Path $sourcePath "*") -Destination $current -Recurse -Force
} else {
    Write-Warn "NoOverwrite set. Skipping deployment to Current."
}

Write-Info "Unblocking files..."
Get-ChildItem -LiteralPath $current -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    try { Unblock-File -LiteralPath $_.FullName -ErrorAction SilentlyContinue } catch {}
}
#endregion Download + Extract

#region Config (Seed + Migration)
$configPrimary  = Join-Path $config  "customer.config.json"
$configFallback = Join-Path $current "customer.config.json"

# One-time migration: if config exists in Current but not in Config, copy it over
if (-not (Test-Path -LiteralPath $configPrimary) -and (Test-Path -LiteralPath $configFallback)) {
    try {
        Copy-Item -LiteralPath $configFallback -Destination $configPrimary -Force
        Write-Info "Migrated config to: $configPrimary"
    } catch {
        Write-Warn "Config migration failed: $($_.Exception.Message)"
    }
}

# Seed config if still missing
if (-not (Test-Path -LiteralPath $configPrimary)) {
@"
{
  "auth": {
    "mode": "app",
    "tenantId": "",
    "clientId": "",
    "certThumbprint": ""
  },
  "userDefaults": {
    "addToGroups": []
  }
}
"@ | Set-Content -LiteralPath $configPrimary -Encoding UTF8 -Force

    Write-Info "Seeded: $configPrimary"
} else {
    Write-Info "Config present: $configPrimary"
}
#endregion Config (Seed + Migration)

#region Ensure Certificate (app-only)
function Get-ConfigJson {
    param([Parameter(Mandatory)][string]$Path)
    return (Get-Content -Raw -LiteralPath $Path) | ConvertFrom-Json
}

function Save-ConfigJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Object
    )
    ($Object | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $Path -Encoding UTF8 -Force
}

function Find-CertByThumbprint {
    param([Parameter(Mandatory)][string]$Thumbprint)
    $t = ($Thumbprint -replace '\s','').ToUpper()
    return Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
        Where-Object { $_.Thumbprint.ToUpper() -eq $t } |
        Select-Object -First 1
}

function New-NubrixCertLocalMachine {
    param(
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][int]$YearsValid
    )

    return New-SelfSignedCertificate `
        -Subject $Subject `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -KeyExportPolicy Exportable `
        -KeySpec Signature `
        -KeyLength 2048 `
        -HashAlgorithm SHA256 `
        -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
        -NotAfter (Get-Date).AddYears($YearsValid)
}

if (-not (Test-Path -LiteralPath $configPrimary)) {
    Write-Err "Config not found at: $configPrimary"
    exit 1
}

$cfg = Get-ConfigJson -Path $configPrimary

if (-not $cfg.auth -or [string]::IsNullOrWhiteSpace($cfg.auth.mode)) {
    Write-Warn "Auth section missing in config. Skipping certificate setup."
} elseif ("$($cfg.auth.mode)".Trim().ToLower() -ne "app") {
    Write-Info "Auth mode is not 'app' (mode=$($cfg.auth.mode)). Skipping certificate setup."
} else {

    $thumb = "$($cfg.auth.certThumbprint)".Trim()
    $cert = $null

    if (-not [string]::IsNullOrWhiteSpace($thumb)) {
        $cert = Find-CertByThumbprint -Thumbprint $thumb
    }

    if ($cert) {
        Write-Info "Certificate found in LocalMachine\My: $($cert.Thumbprint)"
    } else {
        Write-Warn "Certificate not found (or thumbprint missing). Generating a new certificate..."
        $newCert = New-NubrixCertLocalMachine -Subject "CN=Nubrix-Management-Tool" -YearsValid 2

        $cerOut = Join-Path $config "Nubrix-Management-Tool.cer"
        try {
            Export-Certificate -Cert "Cert:\LocalMachine\My\$($newCert.Thumbprint)" -FilePath $cerOut | Out-Null
        } catch {
            Write-Err "Failed to export public cert: $($_.Exception.Message)"
            exit 1
        }

        # Update config thumbprint to match this machine
        if (-not $cfg.auth) { $cfg | Add-Member -MemberType NoteProperty -Name auth -Value ([PSCustomObject]@{}) }
        $cfg.auth.certThumbprint = $newCert.Thumbprint
        Save-ConfigJson -Path $configPrimary -Object $cfg

        Write-Info "Exported public cert to: $cerOut"
        Write-Info "Updated config thumbprint to: $($newCert.Thumbprint)"
        Write-Warn "If this new cert is not yet uploaded to the app registration, upload: $cerOut"
    }
}
#endregion Ensure Certificate (app-only)

#region Shortcut + Launch
# Use Public Desktop so shortcut appears even when running elevated
$publicDesktop = Join-Path $env:PUBLIC "Desktop"
$shortcutPath  = Join-Path $publicDesktop ($ShortcutName + ".lnk")

$psExe = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
$main  = Join-Path $current $EntryScript

New-Shortcut -ShortcutPath $shortcutPath `
    -TargetPath $psExe `
    -Arguments "-NoProfile -ExecutionPolicy Bypass -File `"$main`"" `
    -WorkingDirectory $current

Write-Info "Shortcut created: $shortcutPath"
Write-Info "Launching program..."
Start-Process -FilePath $psExe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$main`""
#endregion Shortcut + Launch

