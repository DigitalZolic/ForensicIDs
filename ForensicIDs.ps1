<# ================================================================================
  Hardware Identification & System Information Utility
================================================================================
Description:
  Collects detailed hardware, firmware, bios, tpm and other system identifiers
  for inventory, diagnostics, compliance, security and forensic analysis purposes.

Name:
  ForensicIDs

Author:
  DigitalZolic

Last Updated:
  2026-04-30

Notes:
  This script is intended for authorized use only. Ensure compliance with
  applicable policies, laws, and user consent requirements before execution.
================================================================================ #>

[CmdletBinding()]
param(
    [switch]$LogErrors
)

# Bind logging switch to script scope
$script:LogErrors = $LogErrors

# ======================================================
# SECTION 0 - GLOBAL CONTROLS
# ======================================================

$script:WmiRestarted = $false
$Global:DefaultSeparator = " / "
$ErrorActionPreference = 'Stop'

# ======================================================
# SECTION 1 - EXPLICIT ADMIN CHECK
# ======================================================

function Assert-Administrator {

    # --------------------------------------------------
    # Ensure execution from a script file
    # --------------------------------------------------
    if (-not $PSCommandPath) {
        throw "Administrator elevation requires execution from a .ps1 file."
    }

    # --------------------------------------------------
    # Detect current privilege level
    # --------------------------------------------------
    $isAdministrator = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($isAdministrator) {
        return
    }

    # --------------------------------------------------
    # Prevent elevation relaunch loop
    # --------------------------------------------------
    if ($env:__MY_SCRIPT_ELEVATED -eq '1') {
        throw "Administrator elevation failed or was cancelled."
    }

    Write-Host
    Write-Host "Administrator privileges are required." -ForegroundColor Red
    Write-Host "Requesting elevation..." -ForegroundColor Green

    # --------------------------------------------------
    # Resolve PowerShell executable
    # --------------------------------------------------
    try {
        $psExecutable = if ($PSVersionTable.PSEdition -eq 'Core') {
            (Get-Command pwsh -ErrorAction Stop).Source
        }
        else {
            (Get-Command powershell -ErrorAction Stop).Source
        }
    }
    catch {
        throw "Unable to locate PowerShell executable."
    }

    # --------------------------------------------------
    # Build encoded command (safe)
    # --------------------------------------------------
    $escapedPath = $PSCommandPath.Replace("'", "''")

    $command = @"
`$env:__MY_SCRIPT_ELEVATED = '1'
Set-Location -LiteralPath '$(Get-Location)'
& '$escapedPath'
"@

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $encodedCommand = [Convert]::ToBase64String($bytes)

    # --------------------------------------------------
    # Relaunch elevated (DO NOT wait, DO NOT kill process)
    # --------------------------------------------------

    try {
    $wtPath = Get-Command wt.exe -ErrorAction SilentlyContinue

    if ($wtPath) {
        Start-Process `
            -FilePath "wt.exe" `
            -Verb RunAs `
            -ArgumentList @(
                "new-tab",
                $psExecutable,
                "-NoProfile",
                "-EncodedCommand", $encodedCommand
            ) `
            -WorkingDirectory (Get-Location) | Out-Null
    }
    else {
        Start-Process `
            -FilePath $psExecutable `
            -Verb RunAs `
            -ArgumentList @(
                '-NoProfile',
                '-EncodedCommand', $encodedCommand
            ) `
            -WorkingDirectory (Get-Location) `
            -WindowStyle Normal | Out-Null
    }
}
catch {
    throw "Failed to relaunch script with elevated privileges."
}

exit
}

# Exit Point - Administrator
# ------------------------------------------------------
Assert-Administrator

# ======================================================
# SECTION 2 - USER CONSENT GUARD
# ======================================================

# --------------------------------------------------
# SUB-SECTION 2.1 - WMI Service Restart Handler
# --------------------------------------------------
function Restart-WmiServiceSafely {

    if ($script:WmiRestarted) { return }

    try {
        Write-Host "Restarting WMI (Winmgmt) service to ensure fresh data retrieval..."

        $wmiService = Get-Service -Name 'Winmgmt' -ErrorAction Stop

        if ($wmiService.Status -eq 'Running') {
            Restart-Service -Name 'Winmgmt' -Force -ErrorAction Stop
        }
        else {
            Start-Service -Name 'Winmgmt' -ErrorAction Stop
        }

        # --- Verification loop ---
        $timeoutSeconds = 15
        $elapsed = 0

        do {
            Start-Sleep -Seconds 1
            $elapsed++
            $wmiService = Get-Service -Name 'Winmgmt'
        }
        until ($wmiService.Status -eq 'Running' -or $elapsed -ge $timeoutSeconds)

        if ($wmiService.Status -ne 'Running') {
            throw "WMI service failed to reach 'Running' state within timeout."
        }

        $script:WmiRestarted = $true

        # --- Success confirmation ---
        Write-Host "WMI service successfully restarted and verified." -ForegroundColor Green
        Start-Sleep -Milliseconds 500

        # --- Clear console ONLY after confirmed success ---
        Clear-Host

        Write-Host "Scanning system for serials..." -ForegroundColor Green
        Start-Sleep -Milliseconds 500
    }
    catch {
        Write-Host "WARNING: WMI restart failed." -ForegroundColor Red
        Write-Host $_.Exception.Message
        Write-Host
        throw
    }
}

# --------------------------------------------------
# SUB-SECTION 2.2 - Explicit Consent Handler
# --------------------------------------------------
function Assert-ExplicitConsent {
    [CmdletBinding()]
    param (
        [string]$ConsentPhrase = 'Proceed',
        [string]$ExitPhrase    = 'Close',
        [string]$ExplicitConsent,
        [string]$EnvVarName    = 'PS_EXPLICIT_CONSENT',
        [int]   $MaxAttempts   = 5
    )

    # --------------------------------------------------
    # Detect interactivity
    # --------------------------------------------------
    $isInteractive =
        $Host.Name -ne 'ServerRemoteHost' -and
        [Environment]::UserInteractive -and
        -not [Console]::IsInputRedirected

    # ==================================================
    # Non-interactive authorization path
    # ==================================================
    if (-not $isInteractive) {

        # --- Environment variable lookup across scopes ---
        $envConsent = [Environment]::GetEnvironmentVariable($EnvVarName, 'Process')
        $envConsent = $envConsent -or [Environment]::GetEnvironmentVariable($EnvVarName, 'User')
        $envConsent = $envConsent -or [Environment]::GetEnvironmentVariable($EnvVarName, 'Machine')

        if ($ExplicitConsent -ceq $ConsentPhrase -or
            $envConsent     -ceq $ConsentPhrase) {

            Write-Verbose "Explicit consent validated (non-interactive)."
            return $true
        }

        throw @"
Explicit user consent is required.

Non-interactive execution detected.
You must provide consent using ONE of the following:

1) Script parameter:
   -ExplicitConsent "$ConsentPhrase"

2) Environment variable:
   $EnvVarName="$ConsentPhrase"

Execution aborted.
"@
    }

    # --------------------------------------------------
    # Interactive consent UI
    # --------------------------------------------------
    Write-Host
    Write-Host "=======================================" -ForegroundColor Green
    Write-Host "        ForensicIDs Utility            "
    Write-Host "                                       "
    Write-Host "        Author: DigitalZolic           "
    Write-Host "        Discord: DigitalZolic          "
    Write-Host "        Github: DigitalZolic           "
    Write-Host "=======================================" -ForegroundColor Green
    Write-Host
    Write-Host "WARNING:" -ForegroundColor Red
    Write-Host "This script will perform administrative operations for Hardware Identification."
    Write-Host
    Write-Host "This script will retrieve and display detailed system hardware, firmware, bios, tpm,"
    Write-Host "virtualization and other high security-related identifiers from this machine."
    Write-Host
    Write-Host "By proceeding, you confirm that:" -ForegroundColor Red
    Write-Host " - You are authorized to run this script on this system."
    Write-Host " - You understand the operations being performed."
    Write-Host " - You have obtained all required organizational approvals."
    Write-Host
    Write-Host "To confirm and continue type: $ConsentPhrase"
    Write-Host "To cancel and exit type: $ExitPhrase"
    Write-Host

    # --------------------------------------------------
    # Bounded input loop (robust)
    # --------------------------------------------------
    for ($i = 0; $i -lt $MaxAttempts; $i++) {

        $userInput = Read-Host "Authorization command"
        $command   = ($userInput -replace '\s+$','').Trim()

        if ($command -ceq $ConsentPhrase) {
            Write-Host
            Write-Host "Authorization confirmed." -ForegroundColor Green
            Write-Host
            return $true
        }

        if ($command -ceq $ExitPhrase) {
            Write-Host
            Write-Host "Execution cancelled by user." -ForegroundColor Red
            Write-Host
            throw "User cancelled execution."
        }

        Write-Host "Invalid input. Type '$ConsentPhrase' or '$ExitPhrase'." -ForegroundColor Red
    }

    throw "Maximum authorization attempts exceeded."
}

# ------------------------------------------------------
# Exit Point - User Authorization
# ------------------------------------------------------
if (Assert-ExplicitConsent @PSBoundParameters) {
    Restart-WmiServiceSafely
}

# ======================================================
# SECTION 3 - SYSTEM ENCODING
# ======================================================

function Use-Utf8 {
    [CmdletBinding()]
    param ()

    # -----------------------------------------------------------------
    # UTF-8 Encoding Instance
    # -----------------------------------------------------------------
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)

    # -----------------------------------------------------------------
    # Console Output Encoding
    # -----------------------------------------------------------------
    try {
        [Console]::OutputEncoding = $utf8NoBom
    }
    catch {
        # The host does not expose a writable console
        # (ISE, remoting, scheduled tasks, services).
    }

    # -----------------------------------------------------------------
    # Native Command Interoperability
    # -----------------------------------------------------------------
    try {
        $global:OutputEncoding = $utf8NoBom
    }
    catch {
        # Extremely constrained environments may block this.
    }

    # -----------------------------------------------------------------
    # PowerShell Cmdlet Default Encoding
    # -----------------------------------------------------------------
    if ($PSVersionTable.PSVersion.Major -ge 6) {
        try {
            $global:PSDefaultParameterValues['*:Encoding'] = 'utf8'
        }
        catch {
            # Defensive no-op
        }
    }
}

# ------------------------------------------------------
# Exit Point - UTF8 Encoding
Use-Utf8

# ========================================================================
# SECTION 4 - CORE: LOGGING
# ========================================================================

$ErrorLogPath = Join-Path $PSScriptRoot 'HardwareInfo_Log.txt'

function Log-Error {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Message
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry     = "[${timestamp}] ERROR: $Message"

    # ---------- FILE LOGGING ----------
    if ($script:LogErrors -eq $true) {

        try {
            # Ensure directory exists
            $logDir = Split-Path $ErrorLogPath -Parent
            if (-not (Test-Path $logDir)) {
                New-Item -ItemType Directory -Path $logDir -Force | Out-Null
            }

            # Faster and more reliable than Out-File
            Add-Content -Path $ErrorLogPath -Value $entry -Encoding UTF8 -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to write to error log file: $($_.Exception.Message)"
        }
    }

    # ---------- ERROR STREAM OUTPUT ----------
    Write-Error -Message $Message
}

# ========================================================================
# SECTION 5 - CORE: CIM CACHE (Improved & Resilient)
# ========================================================================

# Initialize empty structure first (prevents null reference issues later)
$CIM = @{
    BIOS      = $null
    System    = $null
    Product   = $null
    Enclosure = $null
    BaseBoard = $null
    Processor = $null
    Memory    = $null
    Disk      = $null
    Network   = $null
}

# Optional: Use a shared CIM session (better performance & consistency)
$cimSession = $null

try {
    $cimSession = New-CimSession -ErrorAction Stop
}
catch {
    Log-Error "Failed to create CIM session. Falling back to default session. $_"
}

function Get-CimSafe {
    param(
        [Parameter(Mandatory)]
        [string]$ClassName,

        [string]$Namespace = "root/cimv2",

        [scriptblock]$PostProcess
    )

    try {
        $result = if ($cimSession) {
            Get-CimInstance -CimSession $cimSession -ClassName $ClassName -Namespace $Namespace -ErrorAction Stop
        }
        else {
            Get-CimInstance -ClassName $ClassName -Namespace $Namespace -ErrorAction Stop
        }

        if ($PostProcess) {
            return & $PostProcess $result
        }

        return $result
    }
    catch {
        Log-Error "CIM retrieval failed for ${ClassName}: $_"
        return $null
    }
}

# ------------------------------------------------------------------------
# Retrieve CIM Data (Individually Safe)
# ------------------------------------------------------------------------

$CIM.BIOS      = Get-CimSafe -ClassName "Win32_BIOS"
$CIM.System    = Get-CimSafe -ClassName "Win32_ComputerSystem"
$CIM.Product   = Get-CimSafe -ClassName "Win32_ComputerSystemProduct"
$CIM.Enclosure = Get-CimSafe -ClassName "Win32_SystemEnclosure"
$CIM.BaseBoard = Get-CimSafe -ClassName "Win32_BaseBoard"
$CIM.Processor = Get-CimSafe -ClassName "Win32_Processor"
$CIM.Memory    = Get-CimSafe -ClassName "Win32_PhysicalMemory"
$CIM.Disk      = Get-CimSafe -ClassName "Win32_DiskDrive"

$CIM.Network   = Get-CimSafe -ClassName "Win32_NetworkAdapterConfiguration" `
    -PostProcess {
        param($data)
        $data | Where-Object { $_.IPEnabled }
    }

# ------------------------------------------------------------------------
# Cleanup Session
# ------------------------------------------------------------------------

if ($cimSession) {
    try {
        Remove-CimSession $cimSession -ErrorAction Stop
    }
    catch {
        Log-Error "Failed to remove CIM session: $_"
    }
}

# ========================================================================
# SECTION 6 - CORE: SHARED UTILITIES
# ========================================================================

function Join-Values {
    param(
        [object[]]$Values,
        [string]$Separator = " / "
    )

    $clean = $Values |
        ForEach-Object { $_ -as [string] } |
        Where-Object { $_ -and $_.Trim() } |
        Sort-Object -Unique

    if ($clean) {
        $clean -join $Separator
    }
    else {
        "Not Available"
    }
}

# ========================================================================
# SECTION 7 - HARDWARE FINGERPRINT
# ========================================================================

function Get-HardwareFingerprint {

    param(
        [string[]]$Parts,
        [string]$Key = "DigitalZolic"
    )

    # ------------------------------------------------------------
    # Validate input
    # ------------------------------------------------------------
    if (-not $Parts -or $Parts.Count -eq 0) {
        Write-Warning "No parts provided for fingerprint."
        return $null
    }

    # ------------------------------------------------------------
    # Normalize and filter input for deterministic hash
    # ------------------------------------------------------------
    $normalizedParts = $Parts |
        Where-Object { $_ -and $_.Trim() } |             # remove null or empty
        ForEach-Object { $_.Trim().ToUpperInvariant() } | # normalize whitespace & case
        Sort-Object                                      # ensure deterministic order

    if (-not $normalizedParts) {
        Write-Warning "All parts were empty or null."
        return $null
    }

    # ------------------------------------------------------------
    # Join parts with a safe delimiter
    # ------------------------------------------------------------
    $data = [string]::Join([char]0x1F, $normalizedParts) # Unit Separator

    # ------------------------------------------------------------
    # Convert key and data to bytes
    # ------------------------------------------------------------
    $keyBytes  = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $dataBytes = [System.Text.Encoding]::UTF8.GetBytes($data)

    # ------------------------------------------------------------
    # Compute HMAC-SHA256
    # ------------------------------------------------------------
    $hmac = [System.Security.Cryptography.HMACSHA256]::new($keyBytes)
    try {
        $hashBytes = $hmac.ComputeHash($dataBytes)
        return ([BitConverter]::ToString($hashBytes) -replace "-")
    } finally {
        $hmac.Dispose()
    }
}

# ========================================================================
# SECTION 8 - CORE: COLLECTION ORCHESTRATOR
# ========================================================================

$hardwareDetails = [ordered]@{}

function Collect-Info {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Block
    )

    try {
        $val = & $Block

        if ($null -eq $val) {
            $hardwareDetails[$Name] = "Not Available"
        }
        elseif ($val -is [string] -and [string]::IsNullOrWhiteSpace($val)) {
            $hardwareDetails[$Name] = "Not Available"
        }
        else {
            $hardwareDetails[$Name] = $val
        }
    }
    catch {
        Log-Error "Failed to retrieve ${Name}: $_"
        $hardwareDetails[$Name] = "Error Retrieving $Name"
    }
}

# ========================================================================
# SECTION 9 - NETWORK CATEGORY
# ========================================================================

function Collect-NetworkCategory {
    Collect-Info "Local IPv4 Address" {
        $CIM.Network.IPAddress | Where-Object { $_ -match '\.' } | Select-Object -First 1
    }

    Collect-Info "Public IPv4 Address" {
        try { (Invoke-RestMethod "https://ipinfo.io/json" -TimeoutSec 5).ip }
        catch { "Not Available" }
    }

    Collect-Info "Local DNS Address" {
        try {
            Join-Values (
                Get-DnsClientServerAddress -AddressFamily IPv4 |
                Where-Object { $_.ServerAddresses } |
                Select-Object -ExpandProperty ServerAddresses
            )
        }
        catch { "Not Available" }
    }

    Collect-Info "Primary NIC MAC Address" {
        $CIM.Network.MACAddress | Select-Object -First 1
    }
}

# ========================================================================
# SECTION 10 - BIOS CATEGORY
# ========================================================================

function Collect-BiosCategory {

    function Get-HashHex {
        param ([byte[]]$Data)

        if (-not $Data -or $Data.Length -eq 0) {
            return "Not Available"
        }

        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = $sha.ComputeHash($Data)
            return (-join ($hash | ForEach-Object { $_.ToString("X2") }))
        }
        finally {
            $sha.Dispose()
        }
    }

    Collect-Info "BIOS Vendor Name"   { $CIM.BIOS.Manufacturer }
    Collect-Info "BIOS Version"       { $CIM.BIOS.SMBIOSBIOSVersion }

    Collect-Info "BIOS Release Date" {
        try {
            if ($CIM.BIOS.ReleaseDate) {
                $CIM.BIOS.ReleaseDate.ToString("yyyy-MM-dd - HH-mm")
            } else { "Not Available" }
        }
        catch { "Not Available" }
    }

    Collect-Info "BIOS Serial Number" { $CIM.BIOS.SerialNumber }

    # -------------------------------------------------
    # BIOS FINGERPRINT SHA256 (Deterministic)
    # -------------------------------------------------
    Collect-Info "BIOS Fingerprint SHA256" {

        $parts = @(
            $CIM.BIOS.Manufacturer
            $CIM.BIOS.SMBIOSBIOSVersion
            $CIM.BIOS.SerialNumber
            $CIM.BIOS.ReleaseDate
            $CIM.System.Model
        ) | Where-Object { $_ }

        if (-not $parts) { return "Not Available" }

        $normalized = $parts |
            ForEach-Object { $_.ToString().Trim().ToUpperInvariant() } |
            Sort-Object

        $joined = [string]::Join([char]0x1F, $normalized)
        $bytes  = [Text.Encoding]::UTF8.GetBytes($joined)

        Get-HashHex -Data $bytes
    }
}

# ========================================================================
# SECTION 11 - SYSTEM CATEGORY
# ========================================================================

function Collect-SystemCategory {
    Collect-Info "System Hostname"     { $env:COMPUTERNAME }
    Collect-Info "System Domain"       { $CIM.System.Domain }
    Collect-Info "System Manufacturer" { $CIM.Product.Vendor }
    Collect-Info "System Product"      { $CIM.Product.Name }
    Collect-Info "System Type"         { $CIM.System.SystemType }
    Collect-Info "System SKU Number"   { $CIM.System.SystemSKUNumber }
    Collect-Info "System Family Number"{ $CIM.System.SystemFamily }
    Collect-Info "System UUID"         { $CIM.Product.UUID }
    Collect-Info "System Serial Number" {
        if ($CIM.Product.IdentifyingNumber) { $CIM.Product.IdentifyingNumber }
        elseif ($CIM.Enclosure.SerialNumber) { $CIM.Enclosure.SerialNumber }
        else { "Not Available" }
    }
}

# ========================================================================
# SECTION 12 - MOTHERBOARD CATEGORY
# ========================================================================

function Collect-MotherboardCategory {
    Collect-Info "Motherboard Manufacturer" { $CIM.BaseBoard.Manufacturer }
    Collect-Info "Motherboard Product"      { $CIM.BaseBoard.Product }
    Collect-Info "Motherboard Serial Number"{ $CIM.BaseBoard.SerialNumber }
    Collect-Info "Motherboard Asset Tag" {
        if ($CIM.BaseBoard.PSObject.Properties.Name -contains 'AssetTag') {
            $CIM.BaseBoard.AssetTag
        } else { 
            "Not Available" 
        }
    }
}

# ========================================================================
# SECTION 13 - PROCESSOR CATEGORY
# ========================================================================

function Collect-ProcessorCategory {
    Collect-Info "Processor Name"         { $CIM.Processor.Name }
    Collect-Info "Processor Manufacturer" { $CIM.Processor.Manufacturer }
    Collect-Info "Processor Part Number"  { $CIM.Processor.PartNumber }
    Collect-Info "Processor Serial Number"{ $CIM.Processor.ProcessorId }
    Collect-Info "Processor Asset Tag"    { $CIM.Processor.AssetTag }
}

# ========================================================================
# SECTION 14 - CHASSIS CATEGORY
# ========================================================================

function Collect-ChassisCategory {
    Collect-Info "Chassis Manufacturer"      { $CIM.Enclosure.Manufacturer }
    Collect-Info "Chassis Model"             { $CIM.Enclosure.Model }
    Collect-Info "Chassis Asset Tag"         { $CIM.Enclosure.SMBIOSAssetTag }
    Collect-Info "Chassis Tag Serial Number" { $CIM.Enclosure.Tag }
    Collect-Info "Chassis Serial Number"     { $CIM.Enclosure.SerialNumber }
}

# ========================================================================
# SECTION 15 - RAM CATEGORY
# ========================================================================

function Collect-MemoryCategory {
    Collect-Info "RAM Manufacturer"    { Join-Values $CIM.Memory.Manufacturer }
    Collect-Info "RAM Part Number(s)"  { Join-Values $CIM.Memory.PartNumber }
    Collect-Info "RAM Serial Number(s)"{ Join-Values $CIM.Memory.SerialNumber }
}

# ========================================================================
# SECTION 16 - DISK CATEGORY
# ========================================================================

function Collect-DiskCategory {

    Collect-Info "Disk Model" {
        ($CIM.Disk | ForEach-Object { ($_.Model -as [string]).Trim() }) -join " / "
    }

    Collect-Info "Disk Interface" {
        ($CIM.Disk | ForEach-Object { ($_.InterfaceType -as [string]).Trim() }) -join " / "
    }

    Collect-Info "Disk Media Type" {
        ($CIM.Disk | ForEach-Object { ($_.MediaType -as [string]).Trim() }) -join " / "
    }

    Collect-Info "Disk Serial Number" {

        $serials = foreach ($disk in $CIM.Disk) {

            $serial = $disk.SerialNumber

            # --- Primary source ---
            if ($serial -and $serial.Trim()) {
                $serial.Trim()
                continue
            }

            # --- USB fallback via PNPDeviceID ---
            if ($disk.PNPDeviceID -match '\\([^\\]+)$') {

                $candidate = $matches[1].Trim()

                # Ignore fake USB instance IDs
                if ($candidate -notmatch '^[0-9A-F]{1,2}&') {
                    $candidate
                    continue
                }
            }

            "Not Available"
        }

        $serials -join " / "
    }
}

# ========================================================================
# SECTION 17 - TPM CATEGORY
# ========================================================================

function Collect-TpmInfo {

    param(
        [CimSession]$CimSession
    )

    # --------------------------------------------------------------------
    # Initialize result structure
    # --------------------------------------------------------------------
    $result = [ordered]@{
        "TPM Present"                     = "Not Available"
        "TPM Specification Version"       = "Not Available"
        "TPM Type"                        = "Unknown"
        "TPM Enabled"                     = "Not Available"
        "TPM Activated"                   = "Not Available"
        "TPM Owned"                       = "Not Available"
        "TPM Manufacturer ID"             = "Not Available"
        "TPM Manufacturer Version"        = "Not Available"
        "TPM Vendor"                      = "Not Available"
        "TPM EK Certificate Serial"       = @()
        "TPM EK Certificate Thumbprint"   = @()
        "TPM EK Certificate SHA256 Hash"  = @()
        "TPM EK Hash"                     = "Not Available"
        "TPM EK MD5"                      = "Not Available"
        "TPM EK SHA1"                     = "Not Available"
        "TPM EK SHA256"                   = "Not Available"
        "TPM SRK Status"                  = "Not Available"
        "TPM Identity Composite SHA256"   = "Not Available"
    }

    # --------------------------------------------------------------------
    # Helper: Compute Hashes
    # --------------------------------------------------------------------
    function Get-HashHex {
        param(
            [Parameter(Mandatory)][byte[]]$Data,
            [Parameter(Mandatory)][ValidateSet("MD5","SHA1","SHA256")][string]$Algorithm
        )
        switch ($Algorithm.ToUpper()) {
            "MD5"    { $hashAlg = [System.Security.Cryptography.MD5]::Create() }
            "SHA1"   { $hashAlg = [System.Security.Cryptography.SHA1]::Create() }
            "SHA256" { $hashAlg = [System.Security.Cryptography.SHA256]::Create() }
        }
        try { return (-join ($hashAlg.ComputeHash($Data) | ForEach-Object { $_.ToString("X2") })) }
        finally { if ($hashAlg) { $hashAlg.Dispose() } }
    }

    # --------------------------------------------------------------------
    # Helper: Vendor mapping
    # --------------------------------------------------------------------
    function Get-TpmVendorName {
        param([uint32]$ManufacturerId)
        $bytes = [BitConverter]::GetBytes($ManufacturerId)
        [Array]::Reverse($bytes)
        $ascii = [Text.Encoding]::ASCII.GetString($bytes).Trim([char]0)
        $vendorMap = @{
            "IFX"  = "Infineon"
            "NTC"  = "Nuvoton"
            "STM"  = "STMicroelectronics"
            "INTC" = "Intel"
            "AMD"  = "AMD"
            "QCOM" = "Qualcomm"
            "MSFT" = "Microsoft (Virtual TPM)"
            "GOOG" = "Google (Virtual TPM)"
        }
        if ($vendorMap.ContainsKey($ascii)) { return $vendorMap[$ascii] } else { return $ascii }
    }

    # --------------------------------------------------------------------
    # Retrieve TPM base info
    # --------------------------------------------------------------------
    try {
        $tpm = if ($CimSession) {
            Get-CimInstance -CimSession $CimSession -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName "Win32_Tpm" -ErrorAction Stop
        }
        else {
            Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName "Win32_Tpm" -ErrorAction Stop
        }

        if (-not $tpm) { return $result }

        # Enabled / Activated / Owned
        $enabled   = if ($CimSession) { Invoke-CimMethod -CimSession $CimSession -InputObject $tpm -MethodName "IsEnabled" } else { Invoke-CimMethod -InputObject $tpm -MethodName "IsEnabled" }
        $activated = if ($CimSession) { Invoke-CimMethod -CimSession $CimSession -InputObject $tpm -MethodName "IsActivated" } else { Invoke-CimMethod -InputObject $tpm -MethodName "IsActivated" }
        $owned     = if ($CimSession) { Invoke-CimMethod -CimSession $CimSession -InputObject $tpm -MethodName "IsOwned" } else { Invoke-CimMethod -InputObject $tpm -MethodName "IsOwned" }

        $result["TPM Present"]   = "Yes"
        $result["TPM Enabled"]   = if ($enabled.IsEnabled)     { "Yes" } else { "No" }
        $result["TPM Activated"] = if ($activated.IsActivated) { "Yes" } else { "No" }
        $result["TPM Owned"]     = if ($owned.IsOwned)         { "Yes" } else { "No" }

        # Manufacturer info
        $result["TPM Manufacturer ID"]      = $tpm.ManufacturerId
        $result["TPM Manufacturer Version"] = $tpm.ManufacturerVersion
        if ($tpm.ManufacturerId -ne $null) {
            $result["TPM Vendor"] = Get-TpmVendorName ([uint32]$tpm.ManufacturerId)
        }

        # TPM Type determination
        if ($result["TPM Vendor"] -match "Microsoft|Google") { $result["TPM Type"] = "Virtual TPM" }
        elseif ($result["TPM Vendor"] -match "Intel|AMD") { $result["TPM Type"] = "Firmware TPM (fTPM/PTT)" }
        else { $result["TPM Type"] = "Discrete TPM (dTPM)" }

        # TPM Specification Version
        $specVersion = $tpm.SpecVersion
        if ($specVersion -and $specVersion.Count -ge 1) {
        $major = $specVersion[0] -replace ',', '.'
        $minor = if ($specVersion.Count -ge 2) { $specVersion[1] } else { 0 }

        if ($major -eq 2) {
        $result["TPM Specification Version"] = "$major.0"
        }
        elseif ($major -eq 1) {
        $result["TPM Specification Version"] = "$major.$minor"
        }
        else {
        $result["TPM Specification Version"] = "$major.$minor"
        }
        }

        # SRK Status
        $result["TPM SRK Status"] = if ($owned.IsOwned) { "Present (SRK Exists Internally)" } else { "Not Created (TPM Not Owned)" }

    }
    catch { return $result }

    # --------------------------------------------------------------------
    # EK retrieval
    # --------------------------------------------------------------------
    try {
    $ek = Get-TpmEndorsementKeyInfo -ErrorAction Stop
    if ($ek -and $ek.PublicKey -and $ek.PublicKey.RawData) {
        $ekBytes = $ek.PublicKey.RawData
        $result["TPM EK MD5"]    = Get-HashHex $ekBytes "MD5"
        $result["TPM EK SHA1"]   = Get-HashHex $ekBytes "SHA1"
        $result["TPM EK SHA256"] = Get-HashHex $ekBytes "SHA256"
        $result["TPM EK Hash"]   = $result["TPM EK SHA256"]

        # Check both ManufacturerCertificates and AdditionalCertificates
        $certificates = $ek.ManufacturerCertificates + $ek.AdditionalCertificates

        if ($certificates) {
            foreach ($cert in $certificates) {
                $result["TPM EK Certificate Serial"]      += $cert.SerialNumber
                $result["TPM EK Certificate Thumbprint"]  += $cert.Thumbprint
                $result["TPM EK Certificate SHA256 Hash"] += Get-HashHex $cert.RawData "SHA256"
            }
        }
      }
    }
     catch { }

    # --------------------------------------------------------------------
    # Composite TPM Identity Hash
    # --------------------------------------------------------------------
    try {
        $identityObject = [ordered]@{
            ManufacturerId  = $result["TPM Manufacturer ID"]
            ManufacturerVer = $result["TPM Manufacturer Version"]
            Vendor          = $result["TPM Vendor"]
            Type            = $result["TPM Type"]
            SpecVersion     = $result["TPM Specification Version"]
            EkSha256        = $result["TPM EK SHA256"]
            Owned           = $result["TPM Owned"]
            Activated       = $result["TPM Activated"]
        }
        $json  = $identityObject | ConvertTo-Json -Compress
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        $result["TPM Identity Composite SHA256"] = Get-HashHex $bytes "SHA256"
    }
    catch { }

    return $result
}

# ========================================================================
# SECTION 18 - SECURE BOOT CATEGORY
# ========================================================================

function Collect-SecureBootInfo {

    $result = [ordered]@{
        "Firmware Type"                       = "Unknown"
        "Secure Boot"                         = "Not Available"
        "Secure Boot Interpretation"          = "Not Available"
        "UEFI Variable Access Privilege"      = "Unknown"
        "Secure Boot PK SHA256"               = "Not Available"
        "Secure Boot KEK SHA256"              = "Not Available"
        "Secure Boot DB SHA256"               = "Not Available"
        "Secure Boot DBX SHA256"              = "Not Available"
    }

    # -------------------------------------------------
    # Helper: Compute SHA256 as hex
    # -------------------------------------------------
    function Get-HashHex {
        param ([byte[]]$Data)
        if (-not $Data -or $Data.Length -eq 0) { return $null }

        try {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $hash = $sha.ComputeHash($Data)
            return (-join ($hash | ForEach-Object { $_.ToString("X2") }))
        }
        catch {
            Write-Warning "Failed to compute SHA256 hash: $_"
            return $null
        }
        finally {
            $sha.Dispose()
        }
    }

    # -------------------------------------------------
    # Helper: Detect Firmware Type
    # -------------------------------------------------
    function Get-FirmwareType {

        # --- Registry Method (Most Reliable) ---
        try {
            $fw = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name PEFirmwareType -ErrorAction Stop).PEFirmwareType
            switch ([int]$fw) {
                1 { return "Legacy BIOS" }
                2 { return "UEFI" }
            }
        }
        catch {
            Write-Verbose "Registry method failed, proceeding with alternative checks."
        }

        # --- Check for SecureBoot Key Existence ---
        if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot") {
            return "UEFI"
        }

        # --- CIM Method Fallback ---
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            if ($cs.FirmwareType -eq 3) { return "Legacy BIOS" }
            if ($cs.FirmwareType -eq 4) { return "UEFI" }
        }
        catch {
            Write-Warning "CIM method failed, returning Legacy BIOS as fallback."
        }

        return "Legacy BIOS"
    }

    # -------------------------------------------------
    # Populate Firmware Type
    # -------------------------------------------------
    $result["Firmware Type"] = Get-FirmwareType

    # -------------------------------------------------
    # Fetch CIM instance once for virtualization check
    # -------------------------------------------------
    $cs = $null
    try { $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop } catch {}

    # -------------------------------------------------
    # Detect Secure Boot State (Only for UEFI)
    # -------------------------------------------------
    if ($result["Firmware Type"] -eq "UEFI") {
        $result["Secure Boot"] = Get-SecureBootState

        # Detect UEFI Variable Access Privilege
        $result["UEFI Variable Access Privilege"] = Get-UEFIPrivilege

        # Extract Secure Boot Variables (if cmdlet exists)
        if ($result["Secure Boot"] -eq "Enabled" -and
            $result["UEFI Variable Access Privilege"] -eq "Present" -and
            (Get-Command Get-SecureBootUEFI -ErrorAction SilentlyContinue)) {
            $result = Get-SecureBootVariables $result
        }
    }

    # -------------------------------------------------
    # Interpretation Logic
    # -------------------------------------------------
    $result["Secure Boot Interpretation"] = Get-SecureBootInterpretation $result

    return $result
}

# -------------------------------------------------
# Helper: Detect Secure Boot State
# -------------------------------------------------
function Get-SecureBootState {
    try {
        $enabled = Confirm-SecureBootUEFI -ErrorAction Stop
        return if ($enabled) { "Enabled" } else { "Disabled" }
    }
    catch {
        $reg = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
        if (Test-Path $reg) {
            try {
                $val = (Get-ItemProperty -Path $reg -ErrorAction Stop).UEFISecureBootEnabled
                return if ($null -ne $val -and $val -eq 1) { "Enabled" } else { "Disabled" }
            }
            catch { return "Not Available" }
        }
    }
    return "Not Available"
}

# -------------------------------------------------
# Helper: Detect UEFI Variable Access Privilege
# -------------------------------------------------
function Get-UEFIPrivilege {
    try {
        $priv = whoami /priv 2>$null
        if ($priv -match "SeSystemEnvironmentPrivilege\s+Enabled") {
            return "Present"
        }
        else {
            return "Denied (OS blocked from reading UEFI variables by policy)"
        }
    }
    catch {
        return "Missing (Unable to determine privilege)"
    }
}

# -------------------------------------------------
# Helper: Extract Secure Boot Variables
# -------------------------------------------------
function Get-SecureBootVariables ($result) {
    $vars = @("PK","KEK","db","dbx")
    foreach ($name in $vars) {
        try {
            $varObj = Get-SecureBootUEFI -Name $name -ErrorAction Stop
            if ($varObj -and $varObj.Bytes) {
                $hash = Get-HashHex -Data $varObj.Bytes
                if ($hash) {
                    switch ($name) {
                        "PK"  { $result["Secure Boot PK SHA256"]  = $hash }
                        "KEK" { $result["Secure Boot KEK SHA256"] = $hash }
                        "db"  { $result["Secure Boot DB SHA256"]  = $hash }
                        "dbx" { $result["Secure Boot DBX SHA256"] = $hash }
                    }
                }
            }
        }
        catch {}
    }
    return $result
}

# -------------------------------------------------
# Helper: Secure Boot Interpretation Logic
# -------------------------------------------------
function Get-SecureBootInterpretation ($result) {
    if ($result["Firmware Type"] -eq "Legacy BIOS") {
        return "Not Available (Legacy BIOS system)"
    }
    elseif ($result["Secure Boot"] -eq "Enabled") {
        if ($isVirtual) {
            return "Enabled (Virtualized - Hypervisor-managed Secure Boot)"
        }
        elseif ($result["Secure Boot PK SHA256"] -eq "Not Available") {
            return "Enabled (Firmware protected - Variables inaccessible)"
        }
        else {
            return "Enabled (Root-of-Trust variables accessible)"
        }
    }
    elseif ($result["Secure Boot"] -eq "Disabled") {
        return "Disabled (No firmware boot-chain enforcement)"
    }
    else {
        return "Not Available (Unsupported firmware or restricted environment)"
    }
}

# ========================================================================
# SECTION 19 - MAIN COLLECTION EXECUTION
# ========================================================================

Collect-NetworkCategory
Collect-BiosCategory
Collect-SystemCategory
Collect-MotherboardCategory
Collect-ProcessorCategory
Collect-ChassisCategory
Collect-MemoryCategory
Collect-DiskCategory

$hardwareDetails += Collect-TpmInfo
$hardwareDetails += Collect-SecureBootInfo

# ========================================================================
# SECTION 20 - HYPERVISOR & VIRTUALIZATION
# ========================================================================

# ------------------------------------------------------------------------
# CPU Virtualization Detection (Reliable Method - CPUID + Firmware API)
# ------------------------------------------------------------------------
function Get-CPUFlags {
    [CmdletBinding()]
    param()

    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class CpuIdReader {
    [DllImport("kernel32")]
    public static extern bool IsProcessorFeaturePresent(uint ProcessorFeature);
}
"@

    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    $vendor = $cpu.Manufacturer

    # PF_VIRT_FIRMWARE_ENABLED = 10
    $firmwareEnabled = [CpuIdReader]::IsProcessorFeaturePresent(10)

    $intelVMX = $false
    $amdSVM   = $false

    if ($vendor -match "Intel") {
        $intelVMX = $cpu.VirtualizationFirmwareEnabled -or $firmwareEnabled
    }
    elseif ($vendor -match "AMD") {
        $amdSVM = $cpu.SecondLevelAddressTranslationExtensions -or $firmwareEnabled
    }

    $virtualizationSupported = $intelVMX -or $amdSVM

    return [PSCustomObject]@{
        Vendor                         = $vendor
        IntelVMX                       = $intelVMX
        AMDSVM                         = $amdSVM
        VirtualizationFirmwareEnabled  = $firmwareEnabled
        VirtualizationSupported        = $virtualizationSupported
    }
}

# Execute once and cache result
$cpuFlags = Get-CPUFlags

# ------------------------------------------------------------------------
# Cached Context (CIM Objects & CPU/BIOS Info)
# ------------------------------------------------------------------------
$system = $CIM.System
$bios   = $CIM.BIOS
$cpu    = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue

$modelNorm = ($system.Model -as [string]).Trim()
$biosNorm  = ($bios.Manufacturer -as [string]).Trim()

$hvPresent = $system.HypervisorPresent

# OS Hyper-V feature
$hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
$hyperVState   = $hyperVFeature.State
$isHyperVHost  = ($hyperVState -eq "Enabled")

# VBS (Virtualization Based Security)
$vbs = Get-CimInstance Win32_DeviceGuard -ErrorAction SilentlyContinue
$vbsEnabled = ($vbs.SecurityServicesRunning -contains 1 -or $vbs.SecurityServicesRunning -contains 2)

# Guest detection
$isGuestVM = $modelNorm -match '(?i)Virtual|VMware|KVM|VirtualBox|Xen|HVM domU|Standard|OpenStack|Bochs'

# CPU capabilities (hardware layer)
$cpuVirtCapable = ($cpu.VMMonitorModeExtensions -or $cpu.SecondLevelAddressTranslationExtensions)
$firmwareEnabled = $cpu.VirtualizationFirmwareEnabled

# ------------------------------------------------------------------------
# 1. CPU Virtualization Capability (Hardware Layer)
# ------------------------------------------------------------------------
Collect-Info "CPU Virtualization Capability" {
    try {
        if ($cpuFlags.VirtualizationSupported) { 
            "Supported" 
        } else { 
            "Not Supported" 
        }
    }
    catch {
        "Not Available"
    }
}

# ------------------------------------------------------------------------
# 2. Firmware Virtualization (BIOS / UEFI Layer)
# ------------------------------------------------------------------------
Collect-Info "Firmware Virtualization" {
    try {
        if (-not $cpuFlags.VirtualizationSupported) { 
            return "Not Supported" 
        }

        if ($cpuFlags.VirtualizationFirmwareEnabled) { 
            return "Enabled" 
        }

        return "Disabled"
    }
    catch {
        return "Not Available"
    }
}

# ------------------------------------------------------------------------
# 3. OS Virtualization (Hypervisor Layer)
# ------------------------------------------------------------------------
Collect-Info "OS Virtualization" {
    try {
        if (-not $hvPresent) { return "Not Active" }

        if ($isGuestVM) { return "Active (Guest Environment)" }
        if ($isHyperVHost) { return "Active (Hyper-V Role)" }
        if ($vbsEnabled) { return "Active (VBS Security Hypervisor)" }

        return "Active (Unknown Hypervisor)"
    }
    catch {
        return "Not Available"
    }
}

# ------------------------------------------------------------------------
# 4. Hypervisor Vendor (Host / Guest / Security aware)
# ------------------------------------------------------------------------
Collect-Info "Hypervisor Vendor" {
    try {
        if (-not $hvPresent) { return "None (Bare Metal)" }

        # Guest detection priority
        if ($isGuestVM) {
            $hvVendor = switch -Regex ($modelNorm) {
                '(?i)^Amazon EC2'   { 'Amazon EC2 (Nitro)' }
                '(?i)Google'        { 'Google Cloud Platform' }
                '(?i)^Standard.*'   { if ($biosNorm -match '(?i)Microsoft') { 'Microsoft Azure' } }
                '(?i)VMware'        { 'VMware' }
                '(?i)VirtualBox'    { 'Oracle VirtualBox' }
                '(?i)KVM|QEMU'      { 'KVM / QEMU' }
                '(?i)Xen|HVM domU'  { 'Xen / Citrix' }
                '(?i)OpenStack'     { 'OpenStack (KVM)' }
                '(?i)Bochs'         { 'Bochs' }
                default             { 'Guest Hypervisor (Unknown)' }
            }
            return $hvVendor
        }

        # Host detection
        if ($isHyperVHost) { return "Microsoft Hyper-V (Host)" }

        # VBS detection
        if ($vbsEnabled) { return "Microsoft Hyper-V (Security Mode)" }

        # BIOS fallback detection
        $hvVendor = switch -Regex ($biosNorm) {
            '(?i)Microsoft'          { 'Microsoft Hyper-V (Guest)' }
            '(?i)VMware'             { 'VMware' }
            '(?i)Xen'                { 'Xen / Citrix' }
            '(?i)innotek|VirtualBox' { 'Oracle VirtualBox' }
            '(?i)QEMU|SeaBIOS'       { 'KVM / QEMU' }
            default                  { $null }
        }

        if ($hvVendor) { return $hvVendor }
        else { return "Hypervisor Present (Unknown Vendor)" }
    }
    catch {
        return "Not Available"
    }
}

# ------------------------------------------------------------------------
# 5. Hypervisor Detection Method
# ------------------------------------------------------------------------
Collect-Info "Hypervisor Detection Method" {
    try {
        if (-not $hvPresent) { return "None" }

        if ($isGuestVM) { return "System Model Heuristic" }

        if ($biosNorm -match '(?i)Microsoft|VMware|Xen|QEMU|innotek|VirtualBox') { 
            return "SMBIOS Heuristic" 
        }

        return "Windows Hypervisor Interface"
    }
    catch {
        return "Not Available"
    }
}

# ========================================================================
# SECTION 21 - HARDWARE FINGERPRINT
# ========================================================================

# Initialize parts array
$fpParts = @()

# Add Machine GUID (OS-bound identifier)
try {
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Cryptography'
    $machineGuid = (Get-ItemProperty -Path $regPath -ErrorAction Stop).MachineGuid

    if ($null -ne $machineGuid) {

        $machineGuid = $machineGuid.ToString().Trim()

        # Filter invalid / placeholder GUIDs
        if (
            $machineGuid -ne "" -and
            $machineGuid -notmatch '^(?i)(00000000-0000-0000-0000-000000000000|FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF)$'
        ) {
            $fpParts += $machineGuid.ToUpperInvariant()
        }
    }
}
catch {
    Log-Error "Failed to retrieve MachineGuid: $_"
}

# Add other hardware identifiers safely
$fpParts += @(
    $hardwareDetails['System UUID']
    $hardwareDetails['BIOS Serial Number']
    $hardwareDetails['Disk Serial Number']
    $hardwareDetails['Processor Serial Number']
    $hardwareDetails['Motherboard Serial Number']
    $hardwareDetails['RAM Serial Number(s)']
)

# Filter out invalid or placeholder values
$fpParts = $fpParts |
    Where-Object {
        $_ -and
        $_ -notmatch '(?i)OEM|DEFAULT|FILLED|TO BE|UNKNOWN|NONE|N/A'
    } |
    ForEach-Object {
        $_.ToString().Trim().ToUpper()
    } |
    Sort-Object

# Compute the keyed HMAC-SHA256 fingerprint
$hardwareDetails["Hardware Fingerprint"] = Get-HardwareFingerprint -Parts $fpParts

# ========================================================================
# SECTION 22 - DEFINE OUTPUT PATHS + CLEAR HOST
# ========================================================================

# Base output directory (Desktop)
$OutputDirectory = [Environment]::GetFolderPath(
    [Environment+SpecialFolder]::Desktop
)

# Validate directory exists (defensive check)
if (-not (Test-Path $OutputDirectory)) {
    throw "Output directory does not exist: $OutputDirectory"
}

# Timestamp
$timestamp = Get-Date -Format 'yyyy.MM.dd-HH.mm'

# Output file path
$path = Join-Path $OutputDirectory "HardwareIds_$timestamp.txt"

Clear-Host

# ========================================================================
# SECTION 23 - BUILD FINAL FORMATTED OUTPUT
# ========================================================================

$hardwareDetailsFormatted = @"

=======================================
      Found Hardware Information
=======================================

=============== NETWORK ===============
Local IPv4 Address: $($hardwareDetails['Local IPv4 Address'])
Public IPv4 Address: $($hardwareDetails['Public IPv4 Address'])
Local DNS Address: $($hardwareDetails['Local DNS Address'])
Primary NIC MAC Address: $($hardwareDetails['Primary NIC MAC Address'])

=============== BIOS ===============
BIOS Vendor Name: $($hardwareDetails['BIOS Vendor Name'])
BIOS Version: $($hardwareDetails['BIOS Version'])
BIOS Release Date: $($hardwareDetails['BIOS Release Date'])
BIOS Serial Number: $($hardwareDetails['BIOS Serial Number'])
BIOS Fingerprint SHA256: $($hardwareDetails['BIOS Fingerprint SHA256'])

=============== SYSTEM ===============
System Hostname: $($hardwareDetails['System Hostname'])
System Domain: $($hardwareDetails['System Domain'])
System Manufacturer: $($hardwareDetails['System Manufacturer'])
System Product: $($hardwareDetails['System Product'])
System Type: $($hardwareDetails['System Type'])
System SKU Number: $($hardwareDetails['System SKU Number'])
System Family Number: $($hardwareDetails['System Family Number'])
System Serial Number: $($hardwareDetails['System Serial Number'])
System UUID: $($hardwareDetails['System UUID'])

=============== MOTHERBOARD ===============
Motherboard Manufacturer: $($hardwareDetails['Motherboard Manufacturer'])
Motherboard Product: $($hardwareDetails['Motherboard Product'])
Motherboard Asset Tag: $($hardwareDetails['Motherboard Asset Tag'])
Motherboard Serial Number: $($hardwareDetails['Motherboard Serial Number'])

=============== PROCESSOR ===============
Processor Name: $($hardwareDetails['Processor Name'])
Processor Manufacturer: $($hardwareDetails['Processor Manufacturer'])
Processor Serial Number: $($hardwareDetails['Processor Serial Number'])
Processor Asset Tag: $($hardwareDetails['Processor Asset Tag'])
Processor Part Number: $($hardwareDetails['Processor Part Number'])

=============== CHASSIS ===============
Chassis Manufacturer: $($hardwareDetails['Chassis Manufacturer'])
Chassis Model: $($hardwareDetails['Chassis Model'])
Chassis Asset Tag: $($hardwareDetails['Chassis Asset Tag'])
Chassis Tag Serial Number: $($hardwareDetails['Chassis Tag Serial Number'])
Chassis Serial Number: $($hardwareDetails['Chassis Serial Number'])

=============== RAM ===============
RAM Manufacturer: $($hardwareDetails['RAM Manufacturer'])
RAM Part Number(s): $($hardwareDetails['RAM Part Number(s)'])
RAM Serial Number(s): $($hardwareDetails['RAM Serial Number(s)'])

=============== DISK ===============
Disk Model: $($hardwareDetails['Disk Model'])
Disk Interface Type: $($hardwareDetails['Disk Interface'])
Disk Media Type: $($hardwareDetails['Disk Media Type'])
Disk Serial Number: $($hardwareDetails['Disk Serial Number'])

================= TPM =================
TPM Vendor: $($hardwareDetails['TPM Vendor'])
TPM Type: $($hardwareDetails['TPM Type'])
TPM Spec Version: $($hardwareDetails['TPM Specification Version'])
TPM Present: $($hardwareDetails['TPM Present'])
TPM Enabled: $($hardwareDetails['TPM Enabled'])
TPM Activated: $($hardwareDetails['TPM Activated'])
TPM Owned: $($hardwareDetails['TPM Owned'])
TPM Manufacturer ID: $($hardwareDetails['TPM Manufacturer ID'])
TPM Manufacturer Version: $($hardwareDetails['TPM Manufacturer Version'])
TPM SRK Status: $($hardwareDetails['TPM SRK Status'])

===== TPM Endorsement Key (EK) =====
EK Certificate Serial: $($hardwareDetails['TPM EK Certificate Serial'])
EK Certificate Thumbprint: $($hardwareDetails['TPM EK Certificate Thumbprint'])
EK Certificate Hash: $($hardwareDetails['TPM EK Hash'])

EK Public Key MD5: $($hardwareDetails['TPM EK MD5'])
EK Public Key SHA1: $($hardwareDetails['TPM EK SHA1'])
EK Public Key SHA256: $($hardwareDetails['TPM EK SHA256'])

=============== SECURE BOOT ===============
Secure Boot: $($hardwareDetails['Secure Boot'])
Firmware Type: $($hardwareDetails['Firmware Type'])
Interpretation: $($hardwareDetails['Secure Boot Interpretation'])
UEFI Variable Access Privilege: $($hardwareDetails['UEFI Variable Access Privilege'])

===== VARIABLES =====
Platform Key (PK) SHA256: $($hardwareDetails['Secure Boot PK SHA256'])
Key Exchange Key (KEK) SHA256: $($hardwareDetails['Secure Boot KEK SHA256'])
Allowed Signature Database (db): $($hardwareDetails['Secure Boot DB SHA256'])
Revoked Signature Database (dbx): $($hardwareDetails['Secure Boot DBX SHA256'])

=============== VIRTUALIZATION ===============
CPU Virtualization Capability: $($hardwareDetails['CPU Virtualization Capability'])
FW Virtualization: $($hardwareDetails['Firmware Virtualization'])
OS Virtualization: $($hardwareDetails['OS Virtualization'])
Hypervisor Vendor: $($hardwareDetails['Hypervisor Vendor'])
Hypervisor Detection Method: $($hardwareDetails['Hypervisor Detection Method'])

=============== FINGERPRINT ===============
Hardware Fingerprint: $($hardwareDetails['Hardware Fingerprint'])

=============== HARDWARE INFO SAVED ===============

$path
"@

Write-Host $hardwareDetailsFormatted
$hardwareDetailsFormatted | Out-File $path -Encoding UTF8

# ======================================================
# SECTION 24 - WAIT FOR EXIT
# ======================================================

function Confirm-Exit {
    [CmdletBinding()]
    param ()

    # Require interactive session
    if (-not [Environment]::UserInteractive) {
        return
    }

    # Prevent Ctrl+C termination
    $originalCtrlC = [Console]::TreatControlCAsInput
    [Console]::TreatControlCAsInput = $true

    try {

        Write-Host
        Write-Host "      Script Execution Completed       " -ForegroundColor Green
        Write-Host
        Write-Host "=======================================" -ForegroundColor Green
        Write-Host "        ForensicIDs Utility            "
        Write-Host "                                       "
        Write-Host "        Author: DigitalZolic           "
        Write-Host "        Discord: DigitalZolic          "
        Write-Host "        Github: DigitalZolic           "
        Write-Host "=======================================" -ForegroundColor Green
        Write-Host
        Write-Host 'Press "CTRL+C" to close the script.' -ForegroundColor Green
        Write-Host

        while ($true) {

            $userInput = Read-Host "Command"

            # Only allow EXACT match
            if ($userInput -ceq 'Exit') {
                Write-Host
                Write-Host "Termination confirmed. Closing script." -ForegroundColor Green
                break
            }

            # Everything else does absolutely nothing
        }
    }
    finally {
        # Restore Ctrl+C behavior
        [Console]::TreatControlCAsInput = $originalCtrlC
    }

    return
}

Confirm-Exit
