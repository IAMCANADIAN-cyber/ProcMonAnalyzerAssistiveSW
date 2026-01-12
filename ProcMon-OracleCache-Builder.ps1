<#
.SYNOPSIS
    ProcMon-OracleCache-Builder (V1.0)
    "The Harvester" - Fetches online knowledge base articles for the ProcMon-Enterprise Offline Oracle.

.DESCRIPTION
    This script is designed to be run on an INTERNET-CONNECTED machine.
    It scrapes specific vendor "Known Issues" and "Release Notes" pages (Microsoft, Freedom Scientific)
    and saves them as sanitized HTML/JSON artifacts in a local 'OracleCache' folder.

    These artifacts are then copied to your secure/offline analysis machine to feed the
    ProcMon-Enterprise-Unified.ps1 "Oracle" engine.

.NOTES
    - Targets:
        1. Windows 11/10 Release Health (Known Issues)
        2. Microsoft 365 Apps (Office) Release Notes
        3. Freedom Scientific JAWS/ZoomText What's New
    - Output: .\OracleCache\*.html (Raw snapshots for the offline parser)

.USAGE
    .\ProcMon-OracleCache-Builder.ps1 -OutPath ".\OracleCache"
#>

param(
    [string]$OutPath = ".\OracleCache"
)

# --- CONFIGURATION ---
$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
$Targets = @(
    @{ Name="win11_24h2_release_health.html"; Url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2" },
    @{ Name="win11_23h2_release_health.html"; Url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2" },
    @{ Name="win10_22h2_release_health.html"; Url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2" },
    @{ Name="office_known_issues.html";        Url="https://learn.microsoft.com/en-us/officeupdates/known-issues" },
    @{ Name="office_current_channel.html";     Url="https://learn.microsoft.com/en-us/officeupdates/current-channel" },
    @{ Name="jaws_whats_new.html";             Url="https://support.freedomscientific.com/downloads/jaws/JAWSWhatsNew" }
)

# --- INIT ---
$Start = Get-Date
Write-Host "[*] Starting Oracle Cache Builder..." -ForegroundColor Cyan
if (-not (Test-Path $OutPath)) {
    New-Item -ItemType Directory -Path $OutPath -Force | Out-Null
    Write-Host "[+] Created output directory: $OutPath" -ForegroundColor Gray
}

# --- EXECUTION ---
foreach ($t in $Targets) {
    $outFile = Join-Path $OutPath $t.Name
    Write-Host "[-] Fetching: $($t.Url)" -ForegroundColor Yellow

    try {
        # Use .NET WebClient for PS 5.1 compatibility and simplicity
        $wc = New-Object System.Net.WebClient
        $wc.Headers.Add("User-Agent", $UserAgent)
        $wc.Encoding = [System.Text.Encoding]::UTF8

        $content = $wc.DownloadString($t.Url)

        if (-not [string]::IsNullOrWhiteSpace($content)) {
            $content | Out-File -FilePath $outFile -Encoding UTF8
            Write-Host "[+] Saved: $outFile ($([math]::Round($content.Length/1KB, 1)) KB)" -ForegroundColor Green
        } else {
            Write-Warning "Downloaded content was empty for $($t.Url)"
        }
    }
    catch {
        Write-Error "Failed to fetch $($t.Url): $($_.Exception.Message)"
    }

    # Be polite to servers
    Start-Sleep -Milliseconds 500
}

# --- WRAP UP ---
Write-Host "`n[V] Oracle Cache Build Complete." -ForegroundColor Cyan
Write-Host "    1. Copy the '$OutPath' folder to your USB drive / transfer location."
Write-Host "    2. Place it next to 'ProcMon-Enterprise-Unified.ps1' on the offline machine."
Write-Host "    3. Run the forensic engine with: -UpdateOracleDb" -ForegroundColor White
