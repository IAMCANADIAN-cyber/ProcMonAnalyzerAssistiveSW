<#
.SYNOPSIS
    ProcMon-OracleCache-Builder.ps1 ("The Harvester")
    Companion script to fetch knowledge base updates into a local OracleCache folder for offline consumption by the main engine.

.DESCRIPTION
    This script must be run on a machine with Internet access.
    It downloads the latest "Known Issues" and release notes pages from Microsoft and Freedom Scientific.
    The resulting "OracleCache" folder should be copied to the offline analysis environment.

.NOTES
    This restores the "Online Harvester" component of the architecture.
#>

$ScriptVersion = "V1300-Builder"
$CacheDir = ".\OracleCache"

Write-Host "[*] $ScriptVersion - Oracle Cache Builder starting..." -ForegroundColor Cyan

if (-not (Test-Path -LiteralPath $CacheDir)) {
    New-Item -Path $CacheDir -ItemType Directory -Force | Out-Null
    Write-Host "[+] Created cache directory: $CacheDir" -ForegroundColor Green
}

# Target Definitions
$Targets = @(
    @{ name="Windows 11 24H2 release health"; url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2"; cache_file="win11_24h2_release_health.html" },
    @{ name="Windows 11 23H2 release health"; url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2"; cache_file="win11_23h2_release_health.html" },
    @{ name="Windows 10 22H2 release health"; url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2"; cache_file="win10_22h2_release_health.html" },
    @{ name="Office known issues"; url="https://learn.microsoft.com/en-us/officeupdates/known-issues"; cache_file="office_known_issues.html" },
    @{ name="Office Current Channel release notes"; url="https://learn.microsoft.com/en-us/officeupdates/current-channel"; cache_file="office_current_channel.html" },
    @{ name="JAWS What's New"; url="https://support.freedomscientific.com/downloads/jaws/JAWSWhatsNew"; cache_file="jaws_whats_new.html" },
    @{ name="ChangeWindows Timeline (PC)"; url="https://www.changewindows.org/timeline/pc"; cache_file="changewindows_timeline_pc.html" },
    @{ name="Microsoft Error Lookup Tool"; url="https://learn.microsoft.com/en-us/windows/win32/debug/system-error-code-lookup-tool"; cache_file="system_error_code_lookup_tool.html" }
)

foreach ($t in $Targets) {
    $outPath = Join-Path -Path $CacheDir -ChildPath $t.cache_file
    Write-Host "[-] Fetching: $($t.name)..." -NoNewline
    try {
        # Using Invoke-WebRequest with basic parsing
        $response = Invoke-WebRequest -Uri $t.url -UseBasicParsing -ErrorAction Stop

        # Save Content
        $response.Content | Out-File -LiteralPath $outPath -Encoding UTF8
        Write-Host " [OK]" -ForegroundColor Green
    } catch {
        Write-Host " [FAIL]" -ForegroundColor Red
        Write-Host "    Error: $_" -ForegroundColor Red
    }
}

Write-Host "[*] Done. Copy '$CacheDir' to your offline environment." -ForegroundColor Cyan
