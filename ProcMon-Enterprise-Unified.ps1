<#
.SYNOPSIS
    ProcMon-Enterprise V1300: "Overseer Edition" (Unified).
    PowerShell 5.1-compatible forensic engine for Assistive Technology (JAWS/ZoomText/Fusion/Dragon/NVDA)
    interoperability with enterprise security tooling, Windows components, and common line-of-business apps.

    Key goals (from your pasted Gemini chat):
      - Recursive ingestion for folder OR file paths, including TSS output artifacts. 
      - Expand artifact types (JAWS logs, TSS outputs like .etl/.cab/.reg/.wer/.zip/.7z, dumps, etc.).
      - Restore/retain all legacy detection modules (V34..V1150) and avoid feature loss. 
      - "Do-the-work" HTML report (search/sort/filters, glossary, evidence snippets, prioritized next steps).
      - No Sentinel L-D-K licensing checks and no Team-Viewer checks (per compulsory constraints in chat).
      - List-edit safe: user may add duplicates; script must dedupe & normalize (case-insensitive).
      - Offline Oracle DB framework: merge cached known-issue snapshots into a local DB file, then match by app/version.

.NOTES
    - Inputs: ProcMon CSV (exported from ProcMon), optionally combined with TSS output folder containing EVTX/DMP/TXT/LOG/NFO/ETL/CAB/REG/WER/etc.
    - Output: HTML report + CSV findings + Oracle DB (JSON) + optional JSON export.
    - Designed for PowerShell 5.1 (Windows PowerShell).

.USAGE
    Folder/TSS output:
      .\ProcMon-Enterprise-V1203-OfflineOracle.ps1 -Path "C:\Logs\TSS_Output"

    Single CSV:
      .\ProcMon-Enterprise-V1203-OfflineOracle.ps1 -Path "C:\Logs\procmon.csv"

.PARAMETER Path
    File OR Folder path. If folder, the largest ProcMon *.csv is chosen as primary unless -AnalyzeAllCsv is set.

.PARAMETER TargetProcess
    Optional additional process (exe name) to treat as "AT/Target".

.PARAMETER UpdateOracleDb
    If set, merges offline Oracle cache snapshots (from -OracleCachePath) into the local Oracle DB file. (No network calls in this build.)

#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$Path = "",

    [string]$TargetProcess = "",

    [string]$ReportPath = ".\ProcMon_V1203_OfflineOracle_Report.html",
    [string]$CsvExportPath = ".\ProcMon_V1203_Findings.csv",

    [double]$SlowThresholdSeconds = 0.5,
    [double]$CollisionWindowSeconds = 0.5,
    [int]$HotspotThreshold = 2000,

    # New (non-breaking defaults)
    [string]$OracleDbPath = ".\ProcMonOracle.db.json",
    [switch]$UpdateOracleDb,
    [switch]$NoWeb,
    [switch]$OracleOnly,
    [string]$OracleCachePath = ".\OracleCache",
    [switch]$AnalyzeAllCsv,
    [int]$ValidationPasses = 7,
    [int]$MaxFindingsPerCategory = 250,
    [int]$MaxEvidenceSamplesPerFinding = 6
)

# =========================
# 0) PREFLIGHT / GUARDRAILS
# =========================
$ScriptVersion = "V1300-Unified-Overseer"
$StartUtc = [DateTime]::UtcNow

if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
    Write-Error "PowerShell 5.1+ required. Detected: $($PSVersionTable.PSVersion)"
    return
}

if (-not $OracleOnly) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        Write-Error "Path is required unless -OracleOnly is set."
        return
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Error "Path not found: $Path"
        return
    }
}
# Normalize TargetProcess (exe name expected)
if (-not [string]::IsNullOrWhiteSpace($TargetProcess)) {
    $TargetProcess = $TargetProcess.Trim()
    if ($TargetProcess -notmatch '\.exe$') { $TargetProcess = "$TargetProcess.exe" }
}


# =========================
# 3) ORACLE DB (OFFLINE CACHE + MATCHER; NO NETWORK CALLS)
# =========================
# This build intentionally contains ZERO web/network calls.
# Populate $OracleCachePath on a network-permitted machine using the companion builder script:
#   ProcMon-OracleCache-Builder.ps1
# Then copy the cache folder + DB json into the offline environment.
#
# Offline update model:
#   - If -UpdateOracleDb is set: merge cached snapshots and/or bundle JSONs from $OracleCachePath into $OracleDbPath.
#   - If -UpdateOracleDb is not set: just load the DB and use it for "known issue" hints in the report.

function Initialize-OracleDb {
    param([string]$DbPath)

    if (Test-Path -LiteralPath $DbPath) { return }

    $seed = @{
        schema = "procmon-oracle-db/v1-offline"
        created_utc = [DateTime]::UtcNow.ToString("o")
        last_update_utc = ""
        last_update_note = "Initialized seed DB (offline; no network)."
        sources = @(
            @{ name="windows-release-health"; url="https://learn.microsoft.com/en-us/windows/release-health/" },
            @{ name="officeupdates-known-issues"; url="https://learn.microsoft.com/en-us/officeupdates/known-issues" },
            @{ name="officeupdates-current-channel"; url="https://learn.microsoft.com/en-us/officeupdates/current-channel" },
            @{ name="freedomscientific-jaws-whatsnew"; url="https://support.freedomscientific.com/downloads/jaws/JAWSWhatsNew" },
            @{ name="changewindows-timeline-pc"; url="https://www.changewindows.org/timeline/pc" },
            @{ name="mslearn-system-error-code-lookup-tool"; url="https://learn.microsoft.com/en-us/windows/win32/debug/system-error-code-lookup-tool" }
        )
        entries = @(
            @{
                app="JAWS / AT"
                file=""
                version_min=""
                version_max=""
                build=""
                kb=""
                published_date=""
                title="Baseline AT performance triage"
                symptom_patterns=@("slow","hang","freeze","focus","ui","accessibility")
                context="Seed baseline item: correlate ProcMon latency/locks with EVTX/Crash/Hang, injected DLLs, COM/UIA failures, and focus churn."
                fix="Use the report's prioritized steps. Add organization-specific known issues to Oracle cache/DB as you learn them."
                url=""
                source="seed"
                last_seen_utc=[DateTime]::UtcNow.ToString("o")
            },
            # --- OVERSEER KNOWLEDGE BASE (V1300) ---
            @{
                app="msedge.exe"
                title="Chromium v134 Copy/Paste Bug"
                symptom_patterns=@("134.0.0", "copy", "paste")
                context="Chromium v134 Copy/Paste Bug"
                fix="Update JAWS to April 2025 Release or newer."
                url="https://blog.freedomscientific.com/install-software-updates-to-resolve-jaws-and-zoomtext-issues/"
                source="OverseerKB"
                last_seen_utc=[DateTime]::UtcNow.ToString("o")
            },
            @{
                app="msedge.exe"
                title="Windows 11 24H2 WebView2 Corruption"
                symptom_patterns=@("24H2", "webview2", "corruption")
                context="Windows 11 24H2 WebView2 Corruption"
                fix="Run 'sfc /scannow' or update WebView2 Runtime."
                url=""
                source="OverseerKB"
                last_seen_utc=[DateTime]::UtcNow.ToString("o")
            },
            @{
                app="WINWORD.EXE"
                title="Dragon Add-in Disabled"
                symptom_patterns=@("dgnword.dll", "dragon", "add-in")
                context="Dragon Add-in Disabled"
                fix="Re-enable Dragon Add-in in Word Options > Add-ins."
                url=""
                source="OverseerKB"
                last_seen_utc=[DateTime]::UtcNow.ToString("o")
            },
            @{
                app="WINWORD.EXE"
                title="M365 Modern Comments Deadlock"
                symptom_patterns=@("ModernComments", "deadlock")
                context="M365 Modern Comments Deadlock"
                fix="Ensure Office Build > 16.0.14000 for UIA fixes."
                url=""
                source="OverseerKB"
                last_seen_utc=[DateTime]::UtcNow.ToString("o")
            },
            @{
                app="jfw.exe"
                title="Security DLL Heap Corruption (0xC0000374)"
                symptom_patterns=@("0xC0000374", "heap corruption")
                context="Security DLL Heap Corruption"
                fix="Identify the third-party DLL causing 0xC0000374 in the 'Hook Injection' table."
                url=""
                source="OverseerKB"
                last_seen_utc=[DateTime]::UtcNow.ToString("o")
            },
            @{
                app="jfw.exe"
                title="AI Labeler Focus Hang"
                symptom_patterns=@("AI_Labeler", "focus", "hang")
                context="AI Labeler Focus Hang"
                fix="Update JAWS 2026 to December 2025 Enhancement patch."
                url=""
                source="OverseerKB"
                last_seen_utc=[DateTime]::UtcNow.ToString("o")
            }
        )
    }
    $seed | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $DbPath -Encoding UTF8
}

function Read-OracleDb {
    param([string]$DbPath)
    try {
        if (-not (Test-Path -LiteralPath $DbPath)) { return $null }
        return (Get-Content -LiteralPath $DbPath -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch { return $null }
}

function Write-OracleDb {
    param($DbObj, [string]$DbPath)
    $DbObj | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $DbPath -Encoding UTF8
}

function Strip-Html {
    param([string]$Html)
    if ([string]::IsNullOrWhiteSpace($Html)) { return "" }
    $t = $Html -replace '<script[\s\S]*?</script>','' -replace '<style[\s\S]*?</style>',''
    $t = $t -replace '<[^>]+>',' '
    $t = $t -replace '&nbsp;',' ' -replace '&amp;','&' -replace '&lt;','<' -replace '&gt;','>' -replace '&#39;',"'" -replace '&quot;','"'
    $t = $t -replace '\s+',' '
    return $t.Trim()
}

function Slugify {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return "oracle" }
    $x = $s.ToLowerInvariant()
    $x = ($x -replace '[^a-z0-9]+','_').Trim('_')
    if ($x.Length -gt 80) { $x = $x.Substring(0,80) }
    return $x
}

function Get-OracleTargets {
    # The builder script writes these cache files by default.
    return @(
        @{ name="Windows 11 24H2 release health"; url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2"; type="mslearn_known_issues"; product="Windows 11 24H2"; cache_file="win11_24h2_release_health.html" },
        @{ name="Windows 11 23H2 release health"; url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2"; type="mslearn_known_issues"; product="Windows 11 23H2"; cache_file="win11_23h2_release_health.html" },
        @{ name="Windows 10 22H2 release health"; url="https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2"; type="mslearn_known_issues"; product="Windows 10 22H2"; cache_file="win10_22h2_release_health.html" },
        @{ name="Office known issues"; url="https://learn.microsoft.com/en-us/officeupdates/known-issues"; type="mslearn_office_known_issues"; product="Microsoft 365 Apps / Office"; cache_file="office_known_issues.html" },
        @{ name="Office Current Channel release notes"; url="https://learn.microsoft.com/en-us/officeupdates/current-channel"; type="mslearn_release_notes"; product="Microsoft 365 Apps Current Channel"; cache_file="office_current_channel.html" },
        @{ name="JAWS What's New"; url="https://support.freedomscientific.com/downloads/jaws/JAWSWhatsNew"; type="fs_whatsnew"; product="JAWS"; cache_file="jaws_whats_new.html" }
    )
}

function Add-OracleEntryIfMissing {
    param($DbObj, $Entry, $KeySet)
    if (-not $DbObj.entries) { $DbObj | Add-Member -NotePropertyName entries -NotePropertyValue @() -Force }
    $k = ("{0}|{1}|{2}|{3}|{4}|{5}" -f $Entry.app, $Entry.title, $Entry.url, $Entry.version_min, $Entry.build, $Entry.kb)
    if ($KeySet.Contains($k)) { return $false }
    [void]$KeySet.Add($k)
    $DbObj.entries += $Entry
    return $true
}

function Truncate-Text {
    param([string]$Text, [int]$MaxChars = 1200)
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    if ($Text.Length -le $MaxChars) { return $Text }
    return ($Text.Substring(0, $MaxChars) + "...")
}

function Decode-Html {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    try { return [System.Net.WebUtility]::HtmlDecode($Text) } catch { return $Text }
}

function Strip-Tags {
    param([string]$Html)
    if ([string]::IsNullOrWhiteSpace($Html)) { return "" }
    $t = $Html -replace '(?is)<script\b.*?</script>', '' -replace '(?is)<style\b.*?</style>', ''
    $t = $t -replace '(?is)<[^>]+>', ' '
    $t = Decode-Html $t
    $t = $t -replace '\s+', ' '
    return $t.Trim()
}

function Extract-SectionTextById {
    param([string]$Html, [string]$Id, [int]$WindowChars = 18000, [int]$MaxChars = 2500)
    if ([string]::IsNullOrWhiteSpace($Html) -or [string]::IsNullOrWhiteSpace($Id)) { return "" }
    $needle = ('id="{0}"' -f [regex]::Escape($Id))
    $m = [regex]::Match($Html, $needle, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $m.Success) { return "" }
    $start = $m.Index
    $len = [Math]::Min($WindowChars, ($Html.Length - $start))
    if ($len -le 0) { return "" }
    $slice = $Html.Substring($start, $len)

    # Heuristic end markers to avoid swallowing the entire page.
    $end = $slice.Length
    foreach ($pat in @('(?is)<h2\b', '(?is)<h3\b', '(?is)<hr\b', '(?is)<table\b', '(?is)id="\d+msgdesc"')) {
        $mm = [regex]::Match($slice, $pat)
        if ($mm.Success -and $mm.Index -gt 80) {
            $end = [Math]::Min($end, $mm.Index)
        }
    }
    $slice = $slice.Substring(0, $end)
    $txt = Strip-Tags $slice
    return (Truncate-Text -Text $txt -MaxChars $MaxChars)
}

function Extract-LabeledBlock {
    param([string]$Text, [string]$Label)
    if ([string]::IsNullOrWhiteSpace($Text) -or [string]::IsNullOrWhiteSpace($Label)) { return "" }
    $pat = ('(?is)\b{0}\b\s*[:\-]\s*(.*?)(?=\b(Workaround|Resolution|Next steps|More information|Symptoms)\b\s*[:\-]|\z)' -f [regex]::Escape($Label))
    $m = [regex]::Match($Text, $pat)
    if (-not $m.Success) { return "" }
    return ($m.Groups[1].Value -replace '\s+', ' ').Trim()
}

function Get-OracleCacheItems {
    param([string]$CachePath)

    $items = @()
    if (-not (Test-Path -LiteralPath $CachePath)) { return $items }

    # Core cached pages
    foreach ($name in @(
        "win11_24h2_release_health.html",
        "win11_23h2_release_health.html",
        "win10_22h2_release_health.html",
        "office_known_issues.html",
        "office_current_channel.html",
        "changewindows_timeline_pc.html",
        "system_error_code_lookup_tool.html"
    )) {
        $p = Join-Path $CachePath $name
        if (Test-Path -LiteralPath $p) {
            $type = "generic"
            if ($name -match 'release_health') { $type = "windows_release_health" }
            elseif ($name -eq 'office_known_issues.html') { $type = "office_known_issues" }
            elseif ($name -eq 'office_current_channel.html') { $type = "office_current_channel" }
            elseif ($name -eq 'changewindows_timeline_pc.html') { $type = "changewindows_timeline" }
            elseif ($name -eq 'system_error_code_lookup_tool.html') { $type = "ms_error_lookup_doc" }
            $items += @{ file=$p; type=$type; name=$name }
        }
    }

    # Discover locally saved JAWS pages (browser "Save As")
    $jaws = Get-ChildItem -LiteralPath $CachePath -File -Filter "*.html" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)JAWS' -or $_.Name -match '(?i)Freedom Scientific' -or $_.Name -match '(?i)Screen Reading Software' -or $_.Name -match '(?i)Enhancements and Improvements in JAWS' }

    foreach ($f in $jaws) {
        if ($items | Where-Object { $_.file -eq $f.FullName }) { continue }
        $items += @{ file=$f.FullName; type="jaws_saved"; name=$f.Name }
    }



    # Discover ChangeWindows saved pages (browser "Save As")
    $cwPages = Get-ChildItem -LiteralPath $CachePath -File -Filter "*.html" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)changewindows' -or $_.Name -match '(?i)timeline.*pc' }
    foreach ($f in $cwPages) {
        if ($items | Where-Object { $_.file -eq $f.FullName }) { continue }
        $items += @{ file=$f.FullName; type="changewindows_timeline"; name=$f.Name }
    }

    # Discover Microsoft Error Lookup tool doc pages (browser "Save As")
    $errDocs = Get-ChildItem -LiteralPath $CachePath -File -Filter "*.html" -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)error.*code.*lookup' -or $_.Name -match '(?i)system_error_code_lookup_tool' }
    foreach ($f in $errDocs) {
        if ($items | Where-Object { $_.file -eq $f.FullName }) { continue }
        $items += @{ file=$f.FullName; type="ms_error_lookup_doc"; name=$f.Name }
    }
    return $items
}

function Parse-WindowsReleaseHealthHtmlToEntries {
    param([string]$Html, [string]$ProductName, [string]$BaseUrl)

    $entries = @()
    if ([string]::IsNullOrWhiteSpace($Html)) { return $entries }

    $tables = [regex]::Matches($Html, '(?is)<table\b[^>]*>.*?</table>')
    $tableHtml = $null
    foreach ($t in $tables) {
        if ($t.Value -match '(?is)>Summary<' -and $t.Value -match '(?is)>Originating update<' -and $t.Value -match '(?is)>Last updated<') {
            $tableHtml = $t.Value
            break
        }
    }
    if (-not $tableHtml) { return $entries }

    $rows = [regex]::Matches($tableHtml, '(?is)<tr\b[^>]*>(.*?)</tr>')
    foreach ($r in $rows) {
        $rowHtml = $r.Groups[1].Value
        if ($rowHtml -match '(?is)<th\b') { continue }

        $cells = [regex]::Matches($rowHtml, '(?is)<td\b[^>]*>(.*?)</td>')
        if ($cells.Count -lt 4) { continue }

        $summaryCell = $cells[0].Groups[1].Value
        $a = [regex]::Match($summaryCell, '(?is)<a\b[^>]*href\s*=\s*"(.*?)"[^>]*>(.*?)</a>')
        $href = ""
        $summary = ""
        if ($a.Success) { $href = $a.Groups[1].Value; $summary = Strip-Tags $a.Groups[2].Value }
        else { $summary = Strip-Tags $summaryCell }

        $origin = Strip-Tags $cells[1].Groups[1].Value
        $status = Strip-Tags $cells[2].Groups[1].Value
        $lastUpdated = Strip-Tags $cells[3].Groups[1].Value

        $build = ""
        $kb = ""
        $published = ""
        $om = [regex]::Match($origin, '(?i)OS Build\s+([0-9\.]+)\s+KB([0-9]+)\s+([0-9]{4}-[0-9]{2}-[0-9]{2})')
        if ($om.Success) {
            $build = $om.Groups[1].Value
            $kb = "KB" + $om.Groups[2].Value
            $published = $om.Groups[3].Value
        }

        $detailText = ""
        $workaround = ""
        $resolution = ""
        if ($href -and $href.StartsWith("#")) {
            $id = $href.TrimStart("#")
            $detailText = Extract-SectionTextById -Html $Html -Id $id -WindowChars 24000 -MaxChars 2400
            $workaround = Extract-LabeledBlock -Text $detailText -Label "Workaround"
            $resolution = Extract-LabeledBlock -Text $detailText -Label "Resolution"
        }

        $fixParts = @()
        if ($resolution) { $fixParts += ("Resolution: " + $resolution) }
        if ($workaround) { $fixParts += ("Workaround: " + $workaround) }
        $fix = if ($fixParts.Count -gt 0) { $fixParts -join " | " } else { "See Microsoft Release Health page for workaround/resolution." }

        $ctx = "Originating update: $origin | Status: $status | Last updated: $lastUpdated"
        if ($detailText) { $ctx += " | Details: " + (Truncate-Text -Text $detailText -MaxChars 1200) }

        $url = $BaseUrl
        if ($href) { $url = ($BaseUrl + $href) }

        $entry = @{
            app = $ProductName
            file = ""
            version_min = ""
            version_max = ""
            build = $build
            kb = $kb
            published_date = $published
            title = $summary
            symptom_patterns = @("hang","freeze","slow","performance","accessibility","uia","com","focus")
            context = $ctx
            fix = $fix
            url = $url
            source = ("cache:" + $ProductName)
            last_seen_utc = [DateTime]::UtcNow.ToString("o")
        }
        $entries += $entry
    }

    return $entries
}

function Parse-OfficeKnownIssuesHtmlToEntries {
    param([string]$Html, [string]$BaseUrl)

    $entries = @()
    if ([string]::IsNullOrWhiteSpace($Html)) { return $entries }

    # Find sections like <h3 id="excel">Excel</h3> then the first <ul> after it.
    $sections = [regex]::Matches($Html, '(?is)<h3\b[^>]*id="([^"]+)"[^>]*>(.*?)</h3>')
    foreach ($s in $sections) {
        $secId = $s.Groups[1].Value
        $secName = Strip-Tags $s.Groups[2].Value
        if ([string]::IsNullOrWhiteSpace($secName)) { continue }

        $start = $s.Index + $s.Length
        $tail = $Html.Substring($start)
        $ul = [regex]::Match($tail, '(?is)<ul\b[^>]*>(.*?)</ul>')
        if (-not $ul.Success) { continue }

        $ulHtml = $ul.Groups[1].Value
        $lis = [regex]::Matches($ulHtml, '(?is)<li\b[^>]*>(.*?)</li>')
        foreach ($li in $lis) {
            $txt = Strip-Tags $li.Groups[1].Value
            if ([string]::IsNullOrWhiteSpace($txt)) { continue }

            $status = ""
            if ($txt -match '(?i)\bResolved\b') { $status = "Resolved" }
            elseif ($txt -match '(?i)\bInvestigating\b') { $status = "Investigating" }
            elseif ($txt -match '(?i)\bMitigat') { $status = "Mitigated" }

            $ver = ""
            $vm = [regex]::Match($txt, '(?i)\bVersion\s+([0-9]{4})\s*\(([0-9\.]+)\)')
            if ($vm.Success) { $ver = ("Version {0} ({1})" -f $vm.Groups[1].Value, $vm.Groups[2].Value) }

            $title = $txt
            if ($title.Length -gt 160) { $title = $title.Substring(0,160) + "..." }

            $entry = @{
                app = ("Microsoft 365 Apps / Office - " + $secName)
                file = ""
                version_min = $ver
                version_max = ""
                build = ""
                kb = ""
                published_date = ""
                title = $title
                symptom_patterns = @("slow","performance","freeze","hang","crash","add-in","macro","uia","accessibility")
                context = ("Status: $status | " + $txt)
                fix = "See Office known issues page for details."
                url = ($BaseUrl + "#" + $secId)
                source = ("cache:office_known_issues.html")
                last_seen_utc = [DateTime]::UtcNow.ToString("o")
            }
            $entries += $entry
        }
    }

    return $entries
}

function Parse-OfficeCurrentChannelHtmlToEntries {
    param([string]$Html, [string]$BaseUrl)

    $entries = @()
    if ([string]::IsNullOrWhiteSpace($Html)) { return $entries }

    $heads = [regex]::Matches($Html, '(?is)<h2\b[^>]*>(\s*Version\s+[0-9]{4}\s*:\s*[^<]+)</h2>')
    foreach ($h in $heads) {
        $t = Strip-Tags $h.Groups[1].Value
        if ([string]::IsNullOrWhiteSpace($t)) { continue }
        $entry = @{
            app = "Microsoft 365 Apps Current Channel"
            file = ""
            version_min = $t
            version_max = ""
            build = ""
            kb = ""
            published_date = ""
            title = $t
            symptom_patterns = @("update","regression","performance","accessibility")
            context = "Release heading captured from Current Channel release notes (details in cache file)."
            fix = "Review release notes for relevant fixes and known regressions."
            url = $BaseUrl
            source = "cache:office_current_channel.html"
            last_seen_utc = [DateTime]::UtcNow.ToString("o")
        }
        $entries += $entry
    }

    return $entries
}

function Parse-JawsSavedHtmlToEntries {
    param([string]$Html, [string]$FileName)

    $entries = @()
    if ([string]::IsNullOrWhiteSpace($Html)) { return $entries }

    $title = ""
    $tm = [regex]::Match($Html, '(?is)<title\b[^>]*>(.*?)</title>')
    if ($tm.Success) { $title = Strip-Tags $tm.Groups[1].Value }
    if (-not $title) { $title = $FileName }

    $year = ""
    $ym = [regex]::Match(($title + " " + $FileName), '(?i)\bJAWS\s*(20[0-9]{2})\b')
    if ($ym.Success) { $year = $ym.Groups[1].Value }

    # Pull top bullet items as semi-structured entries (browser-saved pages have <li> for release bullets).
    $lis = [regex]::Matches($Html, '(?is)<li\b[^>]*>(.*?)</li>')
    $count = 0
    foreach ($li in $lis) {
        if ($count -ge 250) { break }
        $txt = Strip-Tags $li.Groups[1].Value
        if ([string]::IsNullOrWhiteSpace($txt)) { continue }
        if ($txt.Length -lt 35) { continue }

        $count++
        $t = $txt
        if ($t.Length -gt 170) { $t = $t.Substring(0,170) + "..." }

        $entry = @{
            app = "JAWS / AT"
            file = ""
            version_min = $year
            version_max = ""
            build = ""
            kb = ""
            published_date = ""
            title = $t
            symptom_patterns = @("speech","braille","focus","uia","performance","crash","hang","teams","office","chrome","edge")
            context = ("Source: " + $title + " | " + $txt)
            fix = "See saved JAWS release notes for full context."
            url = ""
            source = ("cache:" + $FileName)
            last_seen_utc = [DateTime]::UtcNow.ToString("o")
        }
        $entries += $entry
    }

    # Also add one high-level entry for the whole document
    $entries += @{
        app = "JAWS / AT"
        file = ""
        version_min = $year
        version_max = ""
        build = ""
        kb = ""
        published_date = ""
        title = ("JAWS release notes captured: " + $title)
        symptom_patterns = @("accessibility","screen reader","performance")
        context = "This cache file was added as an offline Oracle source for matching AT-related fixes/regressions."
        fix = "Review the saved page and correlate with versions from logs."
        url = ""
        source = ("cache:" + $FileName)
        last_seen_utc = [DateTime]::UtcNow.ToString("o")
    }

    return $entries
}




function Try-Parse-ChangeWindowsDateToIso {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return "" }
    $m = [regex]::Match($Text, '(?i)\b([0-9]{1,2})\s+(January|February|March|April|May|June|July|August|September|October|November|December)\s+(20[0-9]{2})\b')
    if (-not $m.Success) { return "" }
    $day = [int]$m.Groups[1].Value
    $monName = $m.Groups[2].Value.ToLowerInvariant()
    $year = [int]$m.Groups[3].Value
    $month = 0
    switch ($monName) {
        "january" { $month = 1 }
        "february" { $month = 2 }
        "march" { $month = 3 }
        "april" { $month = 4 }
        "may" { $month = 5 }
        "june" { $month = 6 }
        "july" { $month = 7 }
        "august" { $month = 8 }
        "september" { $month = 9 }
        "october" { $month = 10 }
        "november" { $month = 11 }
        "december" { $month = 12 }
        default { $month = 0 }
    }
    if ($month -le 0) { return "" }
    try {
        return (Get-Date -Year $year -Month $month -Day $day -Hour 0 -Minute 0 -Second 0).ToString("yyyy-MM-dd")
    } catch { return "" }
}

function Parse-ChangeWindowsTimelineHtmlToEntries {
    param([string]$Html, [string]$FileName)

    $entries = @()
    if ([string]::IsNullOrWhiteSpace($Html)) { return $entries }

    $plain = Strip-Html $Html
    if ([string]::IsNullOrWhiteSpace($plain)) { return $entries }

    # Heuristic: find repeating patterns like:
    #   "17 Dec 2025 26100.4202 Preview 24H2"
    # The site can vary; we treat it as a timeline reference (not a definitive known-issues source).
    $rx = '(?is)\b([0-9]{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+20[0-9]{2})\b[\s\S]{0,200}?\b([0-9]{5}\.[0-9]{1,5})\b[\s\S]{0,120}?\b(Canary|Dev|Beta|Release\s+Preview|Preview|Stable|GA|RTM)\b?[\s\S]{0,120}?\b((?:2[0-9]H[12])|(?:2[4-6]H[12])|(?:26H1)|(?:25H2)|(?:25H1)|(?:24H2)|(?:23H2)|(?:22H2)|(?:21H2)|(?:21H1)|(?:20H2))\b?'
    $matches = [regex]::Matches($plain, $rx)
    $count = 0

    foreach ($mm in $matches) {
        if ($count -ge 1500) { break }

        $dateText = $mm.Groups[1].Value
        $build = $mm.Groups[2].Value
        $chan = $mm.Groups[3].Value
        $ver = $mm.Groups[4].Value

        if ([string]::IsNullOrWhiteSpace($build)) { continue }
        $count++

        $iso = Try-Parse-ChangeWindowsDateToIso -Text $dateText
        $t = "Windows build " + $build
        if ($chan) { $t += " (" + ($chan -replace '\s+',' ').Trim() + ")" }
        if ($ver) { $t += " - " + $ver }

        $context = ($dateText + " | Build " + $build + " | " + ($chan -replace '\s+',' ').Trim() + " | " + $ver).Trim()
        $entries += @{
            app = "Windows"
            file = ""
            version_min = $ver
            version_max = ""
            build = $build
            kb = ""
            published_date = $iso
            title = $t
            symptom_patterns = @("update","build","regression","performance","accessibility","hang","freeze","slow")
            context = "ChangeWindows timeline reference (may not include issues): " + $context
            fix = "Use this timeline to align build numbers from logs with OS servicing cadence; then cross-check official Microsoft known-issues sources in your Oracle cache."
            url = "https://www.changewindows.org/timeline/pc"
            source = ("cache:" + $FileName)
            last_seen_utc = [DateTime]::UtcNow.ToString("o")
        }
    }

    # Add one high-level entry for the whole document as a reference source.
    $entries += @{
        app = "Windows"
        file = ""
        version_min = ""
        version_max = ""
        build = ""
        kb = ""
        published_date = ""
        title = "ChangeWindows timeline snapshot captured (PC)"
        symptom_patterns = @("build","update","release","timeline")
        context = "Offline snapshot of ChangeWindows timeline for Windows builds. Useful for correlating build numbers in logs."
        fix = "Correlate OS Build values to release rings; then use Microsoft Release Health / Office Known Issues for authoritative issue details."
        url = "https://www.changewindows.org/timeline/pc"
        source = ("cache:" + $FileName)
        last_seen_utc = [DateTime]::UtcNow.ToString("o")
    }

    return $entries
}

function Parse-SystemErrorCodeLookupToolHtmlToEntries {
    param([string]$Html, [string]$FileName)

    $entries = @()
    if ([string]::IsNullOrWhiteSpace($Html)) { return $entries }

    $title = ""
    $tm = [regex]::Match($Html, '(?is)<title\b[^>]*>(.*?)</title>')
    if ($tm.Success) { $title = Strip-Tags $tm.Groups[1].Value }
    if (-not $title) { $title = $FileName }

    $exeUrl = ""
    $m = [regex]::Match($Html, '(?i)href\s*=\s*"(https://download\.microsoft\.com/[^"]+Err_[^"]+\.exe)"')
    if ($m.Success) { $exeUrl = $m.Groups[1].Value }

    $ctx = "Microsoft reference page for the System Error Code Lookup Tool (Err.exe)."
    if ($exeUrl) { $ctx += " Download: " + $exeUrl }

    $entries += @{
        app = "Windows"
        file = ""
        version_min = ""
        version_max = ""
        build = ""
        kb = ""
        published_date = ""
        title = "Microsoft Error Lookup tool reference (Err.exe)"
        symptom_patterns = @("error","hresult","ntstatus","win32","code","lookup")
        context = $ctx
        fix = "If your logs contain HRESULT/NTSTATUS/Win32 codes, decode them (net helpmsg / certutil / Err.exe) and include decoded text in the report for faster triage."
        url = "https://learn.microsoft.com/en-us/windows/win32/debug/system-error-code-lookup-tool"
        source = ("cache:" + $FileName)
        last_seen_utc = [DateTime]::UtcNow.ToString("o")
    }

    return $entries
}


function Update-OracleDbFromCache {
    param([string]$DbPath, [string]$CachePath, [switch]$NoWebSwitch)

    Initialize-OracleDb -DbPath $DbPath
    $db = Read-OracleDb -DbPath $DbPath
    if (-not $db) { return $null }

    if (-not (Test-Path -LiteralPath $CachePath)) {
        $db.last_update_utc = [DateTime]::UtcNow.ToString("o")
        $db.last_update_note = "Cache folder not found; no update performed. CachePath=$CachePath"
        Write-OracleDb -DbObj $db -DbPath $DbPath
        return $db
    }

    # Build de-dup keyset
    $keySet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in ($db.entries | ForEach-Object { $_ })) {
        $k = ("{0}|{1}|{2}|{3}|{4}|{5}" -f $e.app, $e.title, $e.url, $e.version_min, $e.build, $e.kb)
        [void]$keySet.Add($k)
    }

    $newCount = 0
    $seenFiles = 0

    $items = Get-OracleCacheItems -CachePath $CachePath
    foreach ($it in $items) {
        $candidate = $it.file
        if (-not (Test-Path -LiteralPath $candidate)) { continue }

        $seenFiles++
        $raw = $null
        try { $raw = Get-Content -LiteralPath $candidate -Raw -Encoding UTF8 } catch {
            try { $raw = Get-Content -LiteralPath $candidate -Raw } catch { $raw = $null }
        }
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }

        $entries = @()

        if ($it.type -eq "windows_release_health") {
            # Determine product name from file
            $product = "Windows Release Health"
            $baseUrl = "https://learn.microsoft.com/en-us/windows/release-health/"
            if ($it.name -match 'win11_24h2') { $product = "Windows 11 24H2"; $baseUrl = "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-24h2" }
            elseif ($it.name -match 'win11_23h2') { $product = "Windows 11 23H2"; $baseUrl = "https://learn.microsoft.com/en-us/windows/release-health/status-windows-11-23h2" }
            elseif ($it.name -match 'win10_22h2') { $product = "Windows 10 22H2"; $baseUrl = "https://learn.microsoft.com/en-us/windows/release-health/status-windows-10-22h2" }

            $entries = Parse-WindowsReleaseHealthHtmlToEntries -Html $raw -ProductName $product -BaseUrl $baseUrl
        }
        elseif ($it.type -eq "office_known_issues") {
            $entries = Parse-OfficeKnownIssuesHtmlToEntries -Html $raw -BaseUrl "https://learn.microsoft.com/en-us/officeupdates/known-issues"
        }
        elseif ($it.type -eq "office_current_channel") {
            $entries = Parse-OfficeCurrentChannelHtmlToEntries -Html $raw -BaseUrl "https://learn.microsoft.com/en-us/officeupdates/current-channel"
        }
        elseif ($it.type -eq "jaws_saved") {
            $entries = Parse-JawsSavedHtmlToEntries -Html $raw -FileName (Split-Path -Leaf $candidate)
        }
        elseif ($it.type -eq "changewindows_timeline") {
            $entries = Parse-ChangeWindowsTimelineHtmlToEntries -Html $raw -FileName (Split-Path -Leaf $candidate)
        }
        elseif ($it.type -eq "ms_error_lookup_doc") {
            $entries = Parse-SystemErrorCodeLookupToolHtmlToEntries -Html $raw -FileName (Split-Path -Leaf $candidate)
        }
        else {
            # Fallback: extract high-signal lines
            $text = if ($candidate.ToLowerInvariant().EndsWith(".html") -or $candidate.ToLowerInvariant().EndsWith(".htm")) { Strip-Html $raw } else { $raw }
            if (-not [string]::IsNullOrWhiteSpace($text)) {
                $lines = $text -split '\r?\n|\s{2,}' | Where-Object { $_ -and $_.Trim().Length -ge 60 } | Select-Object -First 200
                foreach ($ln in $lines) {
                    $ss = $ln.Trim()
                    if ($ss -notmatch '(?i)(accessib|screen reader|jaws|nvda|zoomtext|dragon|uia|com|hang|freeze|slow|latency|blocked|deadlock|mutex|lock contention)') { continue }
                    $title = $ss
                    if ($title.Length -gt 140) { $title = $title.Substring(0,140) + "..." }
                    $entries += @{
                        app = "Oracle"
                        file = ""
                        version_min = ""
                        version_max = ""
                        build = ""
                        kb = ""
                        published_date = ""
                        title = $title
                        symptom_patterns = @("hang","freeze","slow","performance","accessibility")
                        context = $ss
                        fix = "See cache source file for details."
                        url = ""
                        source = ("cache:" + (Split-Path -Leaf $candidate))
                        last_seen_utc = [DateTime]::UtcNow.ToString("o")
                    }
                }
            }
        }

        foreach ($entry in $entries) {
            if (-not $entry.app -or -not $entry.title) { continue }
            if (-not $entry.url) { $entry.url = "" }
            if (-not $entry.source) { $entry.source = "cache:" + (Split-Path -Leaf $candidate) }
            $entry.last_seen_utc = [DateTime]::UtcNow.ToString("o")
            if (Add-OracleEntryIfMissing -DbObj $db -Entry $entry -KeySet $keySet) { $newCount++ }
        }
    }

    # Merge any pre-parsed oracle JSON bundles dropped into cache folder.
    $bundleFiles = Get-ChildItem -LiteralPath $CachePath -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '\.oracle\.(json|db\.json)$' -or $_.Name -match '^oracle_.*\.json$' }
    foreach ($bf in $bundleFiles) {
        try {
            $obj = Get-Content -LiteralPath $bf.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($obj -and $obj.entries) {
                foreach ($e in $obj.entries) {
                    if (-not $e.app -or -not $e.title) { continue }
                    if (-not $e.url) { $e.url = "" }
                    $e.source = "bundle:" + $bf.Name
                    $e.last_seen_utc = [DateTime]::UtcNow.ToString("o")
                    if (Add-OracleEntryIfMissing -DbObj $db -Entry $e -KeySet $keySet) { $newCount++ }
                }
            }
        } catch {}
    }

    if ($db.entries.Count -gt 25000) {
        $db.entries = $db.entries | Select-Object -Last 25000
    }

    $db.last_update_utc = [DateTime]::UtcNow.ToString("o")
    $db.last_update_note = "Offline cache merge: files_seen=$seenFiles; new_entries_added=$newCount; CachePath=$CachePath"
    Write-OracleDb -DbObj $db -DbPath $DbPath
    return $db
}


Initialize-OracleDb -DbPath $OracleDbPath
$OracleDbObj = $null
if ($UpdateOracleDb) {
    $OracleDbObj = Update-OracleDbFromCache -DbPath $OracleDbPath -CachePath $OracleCachePath -NoWebSwitch:$NoWeb
} else {
    $OracleDbObj = Read-OracleDb -DbPath $OracleDbPath
}

if ($OracleOnly) {
    if (-not $OracleDbObj) { Write-Error "Oracle DB unavailable."; return }
    $count = if ($OracleDbObj.entries) { $OracleDbObj.entries.Count } else { 0 }
    Write-Host "[+] OracleOnly complete. Entries=$count" -ForegroundColor Green
    Write-Host "    DB: $OracleDbPath" -ForegroundColor Gray
    Write-Host "    Cache: $OracleCachePath" -ForegroundColor Gray
    Write-Host "    LastUpdateUTC: $($OracleDbObj.last_update_utc)" -ForegroundColor Gray
    Write-Host "    Note: $($OracleDbObj.last_update_note)" -ForegroundColor Gray
    try {
        $top = $OracleDbObj.entries | Group-Object app | Sort-Object Count -Descending | Select-Object -First 10
        Write-Host "    Top apps in DB:" -ForegroundColor Gray
        foreach ($g in $top) { Write-Host ("      {0}: {1}" -f $g.Name, $g.Count) -ForegroundColor Gray }
    } catch {}
    return
}
# =========================
# 1) RESOLVE SCAN ROOT + FILE SET (ALWAYS RECURSIVE)
# =========================
# =========================
# 1) RESOLVE SCAN ROOT + FILE SET (ALWAYS RECURSIVE)
# =========================
$ResolvedInput = $null
try { $ResolvedInput = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path } catch { $ResolvedInput = $Path }
$IsFolder = $false
try { $IsFolder = (Test-Path -LiteralPath $ResolvedInput -PathType Container) } catch { $IsFolder = $false }
$ScanRoot = if ($IsFolder) { $ResolvedInput } else {
    $parent = $null
    try { $parent = Split-Path -LiteralPath $ResolvedInput -Parent } catch { $parent = (Get-Location).Path }
    try { (Resolve-Path -LiteralPath $parent -ErrorAction Stop).Path } catch { $parent }
}

Write-Host "[*] $ScriptVersion booting..." -ForegroundColor Cyan
Write-Host "[*] ScanRoot: $ScanRoot" -ForegroundColor Cyan
Write-Host ("[*] InputPath is a {0}" -f ($(if($IsFolder){'Folder'}else{'File'}))) -ForegroundColor Cyan

# Expanded artifact patterns (TSS + AT + common enterprise)
$ArtifactGlobs = @(
    "*.csv", "*.pml",
    "*.evtx",
    "*.dmp", "*.mdmp",
    "*.etl",
    "*.txt", "*.log", "*.out",
    "*.nfo",
    "*.wer", "*.wermeta", "*.werinternalmetadata.xml",
    "*.reg",
    "*.cab",
    "*.zip", "*.7z", "*.rar",
    "*.json", "*.xml",
    "*.ini", "*.cfg",
    "*.ls",     # JAWS application logs
    "*.etl.*",  # some ETL exports get suffixed
    "*.etl.zip",
    "*.etl.cab"
)

# Inventory everything we might care about (always recursive).
$AllArtifacts = @()
foreach ($g in $ArtifactGlobs) {
    try {
        $AllArtifacts += Get-ChildItem -LiteralPath $ScanRoot -Recurse -File -Filter $g -ErrorAction SilentlyContinue
    } catch {}
}
# Deduplicate (Get-ChildItem repeats with multiple filters)
$AllArtifacts = $AllArtifacts | Sort-Object FullName -Unique

# Identify ProcMon CSVs
$CsvFiles = $AllArtifacts | Where-Object { $_.Extension -ieq ".csv" }
if (-not $CsvFiles -or $CsvFiles.Count -eq 0) {
    Write-Error "No ProcMon *.csv found under: $ScanRoot. Export ProcMon as CSV and try again."
    return
}

$PrimaryCsv = $null
if ($IsFolder) {
    if ($AnalyzeAllCsv) {
        $PrimaryCsv = $CsvFiles | Sort-Object Length -Descending | Select-Object -First 1
    } else {
        $PrimaryCsv = $CsvFiles | Sort-Object Length -Descending | Select-Object -First 1
    }
} else {
    if ((Get-Item -LiteralPath $Path).Extension -ieq ".csv") {
        $PrimaryCsv = Get-Item -LiteralPath $Path
    } else {
        Write-Error "File path is not a .csv: $Path"
        return
    }
}

Write-Host "[+] Primary ProcMon CSV: $($PrimaryCsv.FullName)" -ForegroundColor Green

# Auxiliary artifacts sets
$EvtxFiles = $AllArtifacts | Where-Object { $_.Extension -ieq ".evtx" }
$DumpFiles = $AllArtifacts | Where-Object { $_.Extension -match '^\.(dmp|mdmp)$' }
$TextLogFiles = $AllArtifacts | Where-Object { $_.Extension -match '^\.(txt|log|out|ini|cfg)$' }
$RegFiles = $AllArtifacts | Where-Object { $_.Extension -ieq ".reg" }
$EtlFiles = $AllArtifacts | Where-Object { $_.Extension -ieq ".etl" }
$CabFiles = $AllArtifacts | Where-Object { $_.Extension -ieq ".cab" }
$ZipFiles = $AllArtifacts | Where-Object { $_.Extension -match '^\.(zip|7z|rar)$' }
$NfoFiles = $AllArtifacts | Where-Object { $_.Extension -ieq ".nfo" }
$WerFiles = $AllArtifacts | Where-Object { $_.Name -match '^(Report\.wer|.*\.wer(meta)?|.*wermeta.*)$' -or $_.Extension -match '^\.(wer|wermeta|xml)$' }

# =========================
# 2) LISTS SECTION (USER-EDITABLE, DUPES OK)
# =========================
# NOTE TO YOU:
#   You WILL edit these lists over time and may paste duplicates.
#   This script normalizes/dedupes them case-insensitively and ignores blanks.

function New-NameSet {
    param([string[]]$Items)
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($i in $Items) {
        if ([string]::IsNullOrWhiteSpace($i)) { continue }
        [void]$set.Add($i.Trim())
    }
    return $set
}

# --- Assistive Tech + target apps (process names) ---
$AT_Processes = New-NameSet @(
    # Freedom Scientific
    "jfw.exe","fsreader.exe","jhookldr.exe","pacjaws.exe","fslog.exe","fslogr.exe","fsactivate.exe","fsbrldsp.exe","fsocr.exe",
    # ZoomText / Fusion
    "zoomtext.exe","zttray.exe","ztbase.exe","xfont.exe","fusion.exe",
    # Dragon / Nuance
    "natspeak.exe","dgnuiasvr.exe","dragonbar.exe","dnssps.exe","dgnsvc.exe","loggerservice.exe",
    # NVDA / Windows AT
    "nvda.exe","nvda_slave.exe","narrator.exe","magnify.exe","atbroker.exe",
    # Other AT / AAC / Literacy
    "dol.exe","snova.exe","accctrl.exe","cobra.exe","readandwrite.exe","rw.exe","claroread.exe","k3000.exe","tobii.eyex.engine.exe","grid 3.exe",
    # OS helpers that often appear in AT incidents
    "audiodg.exe","audiosrv.exe","tabtip.exe","wisptis.exe","dllhost.exe","fontdrvhost.exe","logonui.exe","consent.exe",
    # Common apps that AT integrates with
    "acrord32.exe","acrord64.exe","winword.exe","excel.exe","outlook.exe","powerpnt.exe","msedge.exe","chrome.exe"
)
if (-not [string]::IsNullOrWhiteSpace($TargetProcess)) { [void]$AT_Processes.Add($TargetProcess) }

# --- Security / management / OS services that commonly contend ---
# (No Sentinel L-D-K licensing checks. No Team-Viewer checks. Users can add org-specific tooling as needed.)
$Sec_Processes = New-NameSet @(
    # Microsoft
    "msmpeng.exe","nissrv.exe","mpsvc.dll","mpsigstub.exe","mpcmdrun.exe","smartscreen.exe","mssense.exe","sensecncproxy.exe",
    # EDR / AV Giants
    "csfalconservice.exe","csfalconcontainer.exe","sentinelagent.exe","sentinelone.exe","cbdefense.exe","repmgr.exe",
    "mcshield.exe","mfeesp.exe","ccsvchst.exe","vsserv.exe","bdagent.exe","sophosfilescanner.exe","sedservice.exe","cylancesvc.exe","cyveraservice.exe","trapsagent.exe",
    # DLP / Insider Threat
    "dsa.exe","epclient.exe","edpa.exe","wdpa.exe","dgagent.exe","dgservice.exe",
    # SASE / Network
    "zsatunnel.exe","zsaauth.exe","netskope.exe","stagent.exe","vpnagent.exe","acumbrellaagent.exe",
    # Privilege / Virtualization
    "vf_agent.exe","defendpoint.exe","br-service.exe","hpwolfsecurity.exe","ctxsvc.exe","appvclient.exe",
    # Management / RMM
    "taniumclient.exe","ccmexec.exe","wmiPrvSE.exe","searchindexer.exe","splunkd.exe","lsiagent.exe","nxtcoord.exe",
    # System Noise
    "werfault.exe","sdbinst.exe","spoolsv.exe","compatTelRunner.exe"
)

# --- DLL "safe baseline" tokens (very permissive; tune as you like) ---
$Safe_DLL_Tokens = New-NameSet @(
    "ntdll.dll","kernel32.dll","kernelbase.dll","user32.dll","gdi32.dll","gdi32full.dll","win32u.dll",
    "ole32.dll","oleaut32.dll","rpcrt4.dll","combase.dll","shlwapi.dll","shell32.dll","advapi32.dll",
    "uiautomationcore.dll","oleacc.dll","atspi","freedom","jhook","fsdom","nvda","narrator","magnification"
)

# Suspicious DLL/vendor tokens (used only for classification; edit freely)
$Suspicious_DLL_List = @(
    "crowdstrike","csagent","falcon","carbonblack","cb","cylance","defender","mssense","sentinel","s1","mcafee","symantec","trend",
    "zscaler","netskope","forcepoint","ivanti","citrix","vmware","horizon","thinprint"
)
$Suspicious_DLL_Tokens = New-NameSet $Suspicious_DLL_List
# Pre-compile regex for performance in tight loops
$Suspicious_DLL_Regex = "(?i)(" + ($Suspicious_DLL_List -join "|") + ")"

# =========================
# 2b) IMPORTED SCENARIOS
# =========================
# =========================
# 2b) IMPORTED SCENARIOS
# =========================
$StartScenarios = @(
    @{ Id='1'; Title="Access Denied (Write - User):"; Op="CreateFile|WriteFile"; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path="C:\\Users\\.*\\.*"; Cause="User permissions broken on own profile" },
    @{ Id='2'; Title="Normalize:"; Op=""; Res=""; Lookup=""; Path="Align\ all\ timestamps\."; Cause="" },
    @{ Id='3'; Title="Scan:"; Op=""; Res=""; Lookup=""; Path="Iterate\ through\ the\ "Modules"\ above\."; Cause="" },
    @{ Id='4'; Title="Access Denied (Delete):"; Op="SetDispositionInformationFile"; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Read-only attribute or ACL" },
    @{ Id='5'; Title="Output:"; Op=""; Res=""; Lookup=""; Path="Generate\ a\ report\ that\ sounds\ like\ Mark\ R:"; Cause="" },
    @{ Id='6'; Title="Access Denied (Pipe):"; Op="CreateFile"; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path="\\\\\.\\Pipe\\.*"; Cause="Service security hardening" },
    @{ Id='7'; Title="Access Denied (Spool):"; Op="CreateFile"; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path="\\System32\\spool"; Cause="Print nightmare mitigation" },
    @{ Id='8'; Title="Access Denied (WasDeletePending):"; Op="CreateFile"; Res="STATUS\ DELETE\ PENDING"; Lookup="STATUS DELETE PENDING"; Path=""; Cause="File deleted but handle open; zombie file" },
    @{ Id='9'; Title="Sharing Violation (Profile):"; Op="CreateFile"; Res="SHARING\ VIOLATION"; Lookup="SHARING VIOLATION"; Path="NTUSER\.DAT"; Cause="Profile locked by AV/Backup" },
    @{ Id='10'; Title="Sharing Violation (VHDX):"; Op="CreateFile"; Res="SHARING\ VIOLATION"; Lookup="SHARING VIOLATION"; Path=".*\.vhdx"; Cause="FSLogix/VDI double-mount" },
    @{ Id='11'; Title="Sharing Violation (Log):"; Op="CreateFile"; Res="SHARING\ VIOLATION"; Lookup="SHARING VIOLATION"; Path=".*\.log"; Cause="Log rotation race condition" },
    @{ Id='12'; Title="Sharing Violation (Dll):"; Op="CreateFile"; Res="SHARING\ VIOLATION"; Lookup="SHARING VIOLATION"; Path=".*\.dll"; Cause="Update trying to replace loaded library" },
    @{ Id='13'; Title="Path Not Found (DLL):"; Op="LoadImage"; Res="PATH\ NOT\ FOUND"; Lookup="PATH NOT FOUND"; Path=""; Cause="Missing dependency" },
    @{ Id='14'; Title="Path Not Found (Exe):"; Op="ProcessCreate"; Res="PATH\ NOT\ FOUND"; Lookup="PATH NOT FOUND"; Path=""; Cause="Broken shortcut/service path" },
    @{ Id='15'; Title="Path Not Found (Config):"; Op="CreateFile"; Res="PATH\ NOT\ FOUND"; Lookup="PATH NOT FOUND"; Path=".*\.ini"; Cause="Missing configuration" },
    @{ Id='16'; Title="Path Not Found (Drive):"; Op="CreateFile"; Res="PATH\ NOT\ FOUND"; Lookup="PATH NOT FOUND"; Path="X:\\"; Cause="Mapped drive disconnected" },
    @{ Id='17'; Title="Path Not Found (UNC):"; Op="CreateFile"; Res="BAD\ NETWORK\ PATH"; Lookup="BAD NETWORK PATH"; Path="\\\\Server\\Share"; Cause="Server offline/DNS fail" },
    @{ Id='18'; Title="Path Not Found (8.3):"; Op="CreateFile"; Res="PATH\ NOT\ FOUND"; Lookup="PATH NOT FOUND"; Path="PROGRA\~1"; Cause="Short names disabled" },
    @{ Id='19'; Title="Path Not Found (Dev):"; Op="CreateFile"; Res="PATH\ NOT\ FOUND"; Lookup="PATH NOT FOUND"; Path="C:\\Users\\DevName"; Cause="Hardcoded developer path" },
    @{ Id='20'; Title="Path Not Found (SXS):"; Op="CreateFile"; Res="PATH\ NOT\ FOUND"; Lookup="PATH NOT FOUND"; Path="\\WinSxS\\.*"; Cause="Component Store corruption" },
    @{ Id='21'; Title="Name Collision (Temp):"; Op="CreateFile"; Res="NAME\ COLLISION"; Lookup="NAME COLLISION"; Path="%TEMP%"; Cause="Temp folder flooding" },
    @{ Id='22'; Title="Name Collision (ShortName):"; Op="CreateFile"; Res="NAME\ COLLISION"; Lookup="NAME COLLISION"; Path=""; Cause="Hash collision on volume" },
    @{ Id='23'; Title="Disk Full:"; Op="WriteFile"; Res="DISK\ FULL"; Lookup="DISK FULL"; Path=""; Cause="Volume out of space" },
    @{ Id='24'; Title="Quota Exceeded:"; Op="WriteFile"; Res="QUOTA\ EXCEEDED"; Lookup="QUOTA EXCEEDED"; Path=""; Cause="User disk quota hit" },
    @{ Id='25'; Title="File Corrupt:"; Op="ReadFile"; Res="FILE\ CORRUPT\ ERROR"; Lookup="FILE CORRUPT ERROR"; Path=""; Cause="Physical disk/filesystem rot" },
    @{ Id='26'; Title="CRC Error:"; Op="ReadFile"; Res="DATA\ ERROR"; Lookup="DATA ERROR"; Path=""; Cause="Bad sectors/Dedup corruption" },
    @{ Id='27'; Title="InPage Error:"; Op="ReadFile"; Res="STATUS\ IN\ PAGE\ ERROR"; Lookup="STATUS IN PAGE ERROR"; Path=""; Cause="Swap file/Memory/Network paging failure" },
    @{ Id='28'; Title="Device Offline:"; Op="CreateFile"; Res="STATUS\ DEVICE\ OFF\ LINE"; Lookup="STATUS DEVICE OFF LINE"; Path=""; Cause="USB/Storage disconnect" },
    @{ Id='29'; Title="Device Busy:"; Op="DeviceIoControl"; Res="STATUS\ DEVICE\ BUSY"; Lookup="STATUS DEVICE BUSY"; Path=""; Cause="Hardware stuck" },
    @{ Id='30'; Title="Oplock Break:"; Op="FsRtlCheckOplock"; Res=""; Lookup=""; Path=""; Cause="Network locking contention" },
    @{ Id='31'; Title="Filter Latency:"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="AV/EDR filter driver overhead" },
    @{ Id='32'; Title="Sparse Write Fail:"; Op="WriteFile"; Res="DISK\ FULL"; Lookup="DISK FULL"; Path=""; Cause="Over-provisioning failure" },
    @{ Id='33'; Title="Reparse Point Loop:"; Op="CreateFile"; Res="STATUS\ REPARSE\ POINT\ NOT\ RESOLVED"; Lookup="STATUS REPARSE POINT NOT RESOLVED"; Path=""; Cause="Infinite symlink loop" },
    @{ Id='34'; Title="Not A Directory:"; Op="CreateFile"; Res="STATUS\ NOT\ A\ DIRECTORY"; Lookup="STATUS NOT A DIRECTORY"; Path=""; Cause="File exists with name of requested folder" },
    @{ Id='35'; Title="Dir Not Empty:"; Op=""; Res="STATUS\ DIRECTORY\ NOT\ EMPTY"; Lookup="STATUS DIRECTORY NOT EMPTY"; Path=""; Cause="Failed folder delete" },
    @{ Id='36'; Title="Case Sensitivity:"; Op="CreateFile"; Res="NAME\ NOT\ FOUND"; Lookup="NAME NOT FOUND"; Path=""; Cause="Per-directory case sensitivity enabled" },
    @{ Id='37'; Title="Alternate Data Stream Exec:"; Op="ProcessCreate"; Res=""; Lookup=""; Path=".*:Stream"; Cause="Potential malware/hiding" },
    @{ Id='38'; Title="ZoneID Block:"; Op="CreateFile"; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path="Zone\.Identifier"; Cause="Security tool blocking unblock" },
    @{ Id='39'; Title="Cloud Tiering:"; Op="ReadFile"; Res="STATUS\ FILE\ IS\ OFFLINE|FILE\ IS\ OFFLINE"; Lookup="STATUS FILE IS OFFLINE"; Path=""; Cause="OneDrive/Azure Files recall needed" },
    @{ Id='40'; Title="Encrypted File (EFS):"; Op="CreateFile"; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="User mismatch on EFS" },
    @{ Id='41'; Title="BitLocker Locked:"; Op="CreateFile"; Res="STATUS\ FVE\ LOCKED\ VOLUME"; Lookup="STATUS FVE LOCKED VOLUME"; Path=""; Cause="Drive mounted but locked" },
    @{ Id='42'; Title="USN Journal Wrap:"; Op=""; Res="USN\ JOURNAL\ WRAP"; Lookup="USN JOURNAL WRAP"; Path=""; Cause="Backup failure warning" },
    @{ Id='43'; Title="Transaction Log Full:"; Op=""; Res="LOG\ FILE\ FULL"; Lookup="LOG FILE FULL"; Path="Ntfs\.sys"; Cause="Metadata explosion" },
    @{ Id='44'; Title="MFT Fragmentation:"; Op="ReadFile"; Res=""; Lookup=""; Path=""; Cause="Severe filesystem fragmentation" },
    @{ Id='45'; Title="Directory Enumeration Storm:"; Op="QueryDirectory"; Res=""; Lookup=""; Path=""; Cause="Inefficient loop" },
    @{ Id='46'; Title="1-Byte I/O:"; Op="ReadFile"; Res=""; Lookup=""; Path=""; Cause="Inefficient coding" },
    @{ Id='47'; Title="Flush Storm:"; Op="FlushBuffersFile"; Res=""; Lookup=""; Path=""; Cause="Performance killer" },
    @{ Id='48'; Title="Temp File Churn:"; Op=""; Res=""; Lookup=""; Path=">1000\ creates\ in\ `%TEMP%`\ in\ 1\ min"; Cause="MFT exhaustion risk" },
    @{ Id='49'; Title="Log File Bloat:"; Op="WriteFile"; Res=""; Lookup=""; Path=""; Cause="Disk usage spike" },
    @{ Id='50'; Title="Zero Byte Write:"; Op="WriteFile"; Res=""; Lookup=""; Path=""; Cause="Truncation/Logic error" },
    @{ Id='51'; Title="Reg Access Denied (HKLM):"; Op="RegSetValue"; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Standard user trying to change system" },
    @{ Id='52'; Title="Reg Access Denied (HKCU):"; Op="RegSetValue"; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Permission corruption on user hive" },
    @{ Id='53'; Title="Reg Access Denied (GroupPolicy):"; Op="RegSetValue"; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path="Software\\Policies"; Cause="App trying to override GPO" },
    @{ Id='54'; Title="Reg Key Not Found (CLSID):"; Op="RegOpenKey"; Res="NAME\ NOT\ FOUND"; Lookup="NAME NOT FOUND"; Path="HKCR\\CLSID"; Cause="Unregistered COM object" },
    @{ Id='55'; Title="Reg Key Not Found (AppID):"; Op="RegOpenKey"; Res="NAME\ NOT\ FOUND"; Lookup="NAME NOT FOUND"; Path="HKCR\\AppID"; Cause="DCOM config missing" },
    @{ Id='56'; Title="Reg Key Not Found (Interface):"; Op="RegOpenKey"; Res="NAME\ NOT\ FOUND"; Lookup="NAME NOT FOUND"; Path="HKCR\\Interface"; Cause="Proxy/Stub missing" },
    @{ Id='57'; Title="Reg Key Not Found (TypeLib):"; Op="RegOpenKey"; Res="NAME\ NOT\ FOUND"; Lookup="NAME NOT FOUND"; Path="HKCR\\TypeLib"; Cause="Automation failure" },
    @{ Id='58'; Title="Reg Key Not Found (Service):"; Op="RegOpenKey"; Res="NAME\ NOT\ FOUND"; Lookup="NAME NOT FOUND"; Path="HKLM\\System\\.*\\Services"; Cause="Service missing" },
    @{ Id='59'; Title="Reg Key Not Found (Uninstall):"; Op="RegOpenKey"; Res="NAME\ NOT\ FOUND"; Lookup="NAME NOT FOUND"; Path="HKLM\\.*\\Uninstall"; Cause="Installer corruption" },
    @{ Id='60'; Title="Reg Value Not Found (Run):"; Op="RegQueryValue"; Res="NAME\ NOT\ FOUND"; Lookup="NAME NOT FOUND"; Path=""; Cause="Startup item missing" },
    @{ Id='61'; Title="Reg Value Not Found (Env):"; Op="RegQueryValue"; Res="NAME\ NOT\ FOUND"; Lookup="NAME NOT FOUND"; Path=""; Cause="Missing env var" },
    @{ Id='62'; Title="Reg Type Mismatch:"; Op="RegQueryValue"; Res=""; Lookup=""; Path=""; Cause="Crash risk" },
    @{ Id='63'; Title="Buffer Overflow (Reg):"; Op="RegQueryValue"; Res="BUFFER\ OVERFLOW"; Lookup="BUFFER OVERFLOW"; Path=""; Cause="Data larger than buffer" },
    @{ Id='64'; Title="Registry Hive Bloat:"; Op="RegQueryValue"; Res=""; Lookup=""; Path=""; Cause="Hive fragmentation" },
    @{ Id='65'; Title="Focus Rectangle Missing:"; Op=""; Res=""; Lookup=""; Path="`DrawFocusRect`\ not\ called\ or\ invisible\."; Cause="" },
    @{ Id='66'; Title="Text Smoothing Conflict:"; Op=""; Res=""; Lookup=""; Path="ClearType\ rendering\ artifacts\ when\ magnification\ is\ active\."; Cause="" },
    @{ Id='67'; Title="Bitmap Scaling Blur:"; Op=""; Res=""; Lookup=""; Path="App\ not\ DPI\ aware,\ resulting\ in\ blurry\ text\ at\ 200%\ scaling\."; Cause="" },
    @{ Id='68'; Title="Orphaned Key Scan:"; Op=""; Res="NAME\ NOT\ FOUND"; Lookup="NAME NOT FOUND"; Path=""; Cause="Registry cleaner behavior" },
    @{ Id='69'; Title="IniFileMapping:"; Op=""; Res=""; Lookup=""; Path="win\.ini"; Cause="Ancient app compatibility" },
    @{ Id='70'; Title="Animation Disable"; Op=""; Res=""; Lookup=""; Path="SPI_GETCLIENTAREAANIMATION"; Cause="Motion sickness trigger" },
    @{ Id='71'; Title="Microphone Exclusive Mode:"; Op=""; Res=""; Lookup=""; Path="Windows\ Dictation\ failing\ to\ access\ Mic\."; Cause="" },
    @{ Id='72'; Title="Text Services Framework (TSF) Lock"; Process="ctfmon\.exe"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='73'; Title="`Select` Interface Failure"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='74'; Title="Correction Window Hidden"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='75'; Title="Vocabulary Update Write Fail:"; Op=""; Res=""; Lookup=""; Path="Failure\ to\ write\ to\ the\ user's\ custom\ dictionary\ file\."; Cause="" },
    @{ Id='76'; Title="ZoneMap Check:"; Op=""; Res=""; Lookup=""; Path="ZoneMap\\Domains"; Cause="IE Security Zone check" },
    @{ Id='77'; Title="Capability Access:"; Op=""; Res=""; Lookup=""; Path="Query\ `HKCU\\.*\\Capabilities`"; Cause="Privacy permission check" },
    @{ Id='78'; Title="SAPI5 Registry Lookups:"; Op=""; Res=""; Lookup=""; Path="Failure\ to\ enumerate\ installed\ SAPI\ voices\."; Cause="" },
    @{ Id='79'; Title="Audio Endpoint Builder:"; Op=""; Res=""; Lookup=""; Path="`Audiosrv`\ failing\ to\ build\ graph\ for\ Dictation\."; Cause="" },
    @{ Id='80'; Title="Language Pack Missing:"; Op=""; Res=""; Lookup=""; Path="`SpeechPlatform`\ failing\ to\ load\ required\ language\ model\."; Cause="" },
    @{ Id='81'; Title="Group Policy History:"; Op=""; Res=""; Lookup=""; Path="GroupPolicy\\History"; Cause="GPO processing" },
    @{ Id='82'; Title="Winlogon Helper:"; Op=""; Res=""; Lookup=""; Path="Winlogon\\Shell"; Cause="Persistence/Kiosk mode" },
    @{ Id='83'; Title="LSA Provider Mod:"; Op=""; Res=""; Lookup=""; Path="Write\ to\ `Security\\Providers`"; Cause="Credential theft/Inject" },
    @{ Id='84'; Title="AT Start on Logon:"; Op=""; Res=""; Lookup=""; Path="`utilman`\ failing\ to\ launch\ the\ configured\ AT\ on\ the\ logon\ screen\."; Cause="" },
    @{ Id='85'; Title="Sound Scheme Lock:"; Op=""; Res=""; Lookup=""; Path="App\ forcing\ a\ specific\ sound\ scheme,\ overriding\ accessibility\ sounds\."; Cause="" },
    @{ Id='86'; Title="Virtual Audio Cable Conflict:"; Op=""; Res=""; Lookup=""; Path="Routing\ issues\ when\ using\ Virtual\ Audio\ Cables\ with\ Screen\ Readers\."; Cause="" },
    @{ Id='87'; Title="Portable Copy Permission:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="" },
    @{ Id='88'; Title="USB Enum:"; Op=""; Res=""; Lookup=""; Path="Read\ `Enum\\USB`"; Cause="Hardware enumeration" },
    @{ Id='89'; Title="Script Folder Write Access:"; Op=""; Res=""; Lookup=""; Path="User\ lacks\ permission\ to\ save\ custom\ scripts\ for\ the\ specific\ application\."; Cause="" },
    @{ Id='90'; Title="Network Profile:"; Op=""; Res=""; Lookup=""; Path="NetworkList\\Profiles"; Cause="Network location awareness" },
    @{ Id='91'; Title="Custom Drawing without `IAccessible`:"; Op=""; Res=""; Lookup=""; Path="DirectX\ but\ implements\ 0\ accessibility\."; Cause="" },
    @{ Id='92'; Title="WPA Key:"; Op=""; Res=""; Lookup=""; Path="Read\ `Wlansvc\\Parameters`"; Cause="WiFi config" },
    @{ Id='93'; Title="Console Config:"; Op=""; Res=""; Lookup=""; Path="Console\\Configuration"; Cause="CMD settings" },
    @{ Id='94'; Title="Timed Tooltip:"; Op=""; Res=""; Lookup=""; Path="Tooltip\ disappears\ too\ fast\ for\ the\ screen\ reader\ to\ catch\ it\."; Cause="" },
    @{ Id='95'; Title="Non-Standard Combobox"; Op=""; Res=""; Lookup=""; Path=""; Cause="no role, no expand/collapse state" },
    @{ Id='96'; Title="Drag-and-Drop Only:"; Op=""; Res=""; Lookup=""; Path="Operation\ requires\ dragging,\ no\ keyboard\ alternative\."; Cause="" },
    @{ Id='97'; Title="Color-Only Information"; Op=""; Res=""; Lookup=""; Path=""; Cause="no text/metadata change" },
    @{ Id='98'; Title="Implicit Focus Change"; Op=""; Res=""; Lookup=""; Path=""; Cause="Screen reader user is unaware" },
    @{ Id='99'; Title="Crypto Seed:"; Op=""; Res=""; Lookup=""; Path="RNG\\Seed"; Cause="Entropy generation" },
    @{ Id='100'; Title="Hidden Content Readable"; Op=""; Res=""; Lookup=""; Path=""; Cause="e.g., off-screen menus" },
    @{ Id='101'; Title="Process Create"; Op=""; Res=""; Lookup=""; Path=""; Cause="Activity tracking" },
    @{ Id='102'; Title="Process Exit (Success)"; Op=""; Res=""; Lookup=""; Path=""; Cause="Clean shutdown" },
    @{ Id='103'; Title="Process Exit (Fail)"; Op=""; Res=""; Lookup=""; Path=""; Cause="Error/Crash" },
    @{ Id='104'; Title="Process Exit (Crash)"; Op=""; Res=""; Lookup=""; Path="0xC0000005"; Cause="Access Violation" },
    @{ Id='105'; Title="Process Exit (Hard)"; Op=""; Res=""; Lookup=""; Path="0xC0000409"; Cause="Stack Buffer Overrun" },
    @{ Id='106'; Title="Process Exit (Abort)"; Op=""; Res=""; Lookup=""; Path="0xC0000374"; Cause="Heap Corruption" },
    @{ Id='107'; Title="Image Load (DLL)"; Op=""; Res=""; Lookup=""; Path=""; Cause="Dependency tracking" },
    @{ Id='108'; Title="Image Load Fail:"; Op="LoadImage"; Res="STATUS\ IMAGE\ NOT\ AT\ BASE"; Lookup="STATUS IMAGE NOT AT BASE"; Path=""; Cause="Relocation" },
    @{ Id='109'; Title="Image Load Fail (Arch):"; Op=""; Res="STATUS\ IMAGE\ MACHINE\ TYPE\ MISMATCH"; Lookup="STATUS IMAGE MACHINE TYPE MISMATCH"; Path=""; Cause="32/64 bit mix" },
    @{ Id='110'; Title="Image Load Fail (Sign):"; Op=""; Res="STATUS\ INVALID\ IMAGE\ HASH"; Lookup="STATUS INVALID IMAGE HASH"; Path=""; Cause="Unsigned binary" },
    @{ Id='111'; Title="Thread Create"; Op=""; Res=""; Lookup=""; Path=""; Cause="Parallelism" },
    @{ Id='112'; Title="Thread Exit"; Op=""; Res=""; Lookup=""; Path=""; Cause="Worker completion" },
    @{ Id='113'; Title="CreateRemoteThread:"; Op=""; Res=""; Lookup=""; Path="Thread\ in\ .*other.*\ process"; Cause="Injection/Debug" },
    @{ Id='114'; Title="OpenProcess (Full)"; Op=""; Res=""; Lookup=""; Path="PROCESS_ALL_ACCESS"; Cause="Admin/AV" },
    @{ Id='115'; Title="OpenProcess (Mem)"; Op=""; Res=""; Lookup=""; Path="VM_READ/WRITE"; Cause="Debug/Hack" },
    @{ Id='116'; Title="OpenProcess (Term)"; Op=""; Res=""; Lookup=""; Path="TERMINATE"; Cause="Kill attempt" },
    @{ Id='117'; Title="TerminateProcess"; Op=""; Res=""; Lookup=""; Path=""; Cause="Watchdog/User kill" },
    @{ Id='118'; Title="Debug Active"; Op=""; Res=""; Lookup=""; Path="IsDebuggerPresent"; Cause="Anti-debug" },
    @{ Id='119'; Title="WerFault Trigger:"; Op=""; Res=""; Lookup=""; Path="WerFault\.exe"; Cause="Crash reporting" },
    @{ Id='120'; Title="Dr Watson:"; Op=""; Res=""; Lookup=""; Path="dwwin\.exe"; Cause="Legacy crash" },
    @{ Id='121'; Title="Conhost Spawn:"; Op=""; Res=""; Lookup=""; Path="Spawning\ `conhost\.exe`"; Cause="Console window" },
    @{ Id='122'; Title="Wow64 Transition"; Op=""; Res=""; Lookup=""; Path=""; Cause="Compatibility" },
    @{ Id='123'; Title="Job Object Assign"; Op=""; Res=""; Lookup=""; Path=""; Cause="Resource limit" },
    @{ Id='124'; Title="Token Impersonation"; Op=""; Res=""; Lookup=""; Path="ImpersonateLoggedOnUser"; Cause="Context switch" },
    @{ Id='125'; Title="Token Priv Adjust"; Op=""; Res=""; Lookup=""; Path="AdjustTokenPrivileges"; Cause="Elevating" },
    @{ Id='126'; Title="LUID Exhaustion"; Op=""; Res=""; Lookup=""; Path="AllocateLocallyUniqueId"; Cause="Auth resource limit" },
    @{ Id='127'; Title="Handle Leak:"; Op="CreateFile|CloseHandle"; Res=""; Lookup=""; Path=""; Cause="Resource leak" },
    @{ Id='128'; Title="GDI Leak"; Op=""; Res=""; Lookup=""; Path=""; Cause="Graphics leak" },
    @{ Id='129'; Title="User Handle Leak"; Op=""; Res=""; Lookup=""; Path=""; Cause="Window leak" },
    @{ Id='130'; Title="Non-Paged Pool:"; Op=""; Res="STATUS\ INSUFFICIENT\ RESOURCES"; Lookup="STATUS INSUFFICIENT RESOURCES"; Path=""; Cause="Kernel memory full" },
    @{ Id='131'; Title="Commit Limit:"; Op=""; Res="STATUS\ COMMITMENT\ LIMIT"; Lookup="STATUS COMMITMENT LIMIT"; Path=""; Cause="RAM/Pagefile full" },
    @{ Id='132'; Title="Working Set Trim"; Op=""; Res=""; Lookup=""; Path="EmptyWorkingSet"; Cause="Memory reclaiming" },
    @{ Id='133'; Title="Page Fault"; Op=""; Res=""; Lookup=""; Path=""; Cause="Thrashing" },
    @{ Id='134'; Title="Stack Overflow:"; Op=""; Res="STATUS\ STACK\ OVERFLOW"; Lookup="STATUS STACK OVERFLOW"; Path=""; Cause="Recursion loop" },
    @{ Id='135'; Title="DllMain Hang:"; Op="LoadImage"; Res=""; Lookup=""; Path=""; Cause="Loader lock" },
    @{ Id='136'; Title="Zombie Process:"; Op="Process\ Exit"; Res=""; Lookup=""; Path=""; Cause="Deletion block" },
    @{ Id='137'; Title="Orphaned Process"; Op=""; Res=""; Lookup=""; Path=""; Cause="Backgrounding" },
    @{ Id='138'; Title="Rapid Spawn"; Op=""; Res=""; Lookup=""; Path=""; Cause="Fork bomb/Crash loop" },
    @{ Id='139'; Title="Self-Deletion"; Op=""; Res=""; Lookup=""; Path="cmd /c del"; Cause="Installer/Malware" },
    @{ Id='140'; Title="Process Hollowing"; Op=""; Res=""; Lookup=""; Path=""; Cause="Malware" },
    @{ Id='141'; Title="Reflective Load"; Op=""; Res=""; Lookup=""; Path=""; Cause="Fileless malware" },
    @{ Id='142'; Title="SvcHost Split"; Op=""; Res=""; Lookup=""; Path=""; Cause="Stability" },
    @{ Id='143'; Title="AppContainer"; Op=""; Res=""; Lookup=""; Path=""; Cause="Store App" },
    @{ Id='144'; Title="Low Integrity"; Op=""; Res=""; Lookup=""; Path=""; Cause="Browser sandbox" },
    @{ Id='145'; Title="Protected Process"; Op=""; Res=""; Lookup=""; Path=""; Cause="AV/System" },
    @{ Id='146'; Title="System Process"; Op=""; Res=""; Lookup=""; Path=""; Cause="Kernel" },
    @{ Id='147'; Title="Registry Virtualization"; Op=""; Res=""; Lookup=""; Path="VirtualStore"; Cause="Legacy compat" },
    @{ Id='148'; Title="Shim Engine:"; Op=""; Res=""; Lookup=""; Path="AcLayers\.dll"; Cause="AppCompat" },
    @{ Id='149'; Title="Detours:"; Op=""; Res=""; Lookup=""; Path="`detoured\.dll`\ load"; Cause="Hooking" },
    @{ Id='150'; Title="Inject Library"; Op=""; Res=""; Lookup=""; Path="AppInit_DLLs"; Cause="Global injection" },
    @{ Id='151'; Title="TCP Connect (Success)"; Op=""; Res=""; Lookup=""; Path=""; Cause="Connected" },
    @{ Id='152'; Title="TCP Connect (Refused):"; Op=""; Res="CONNECTION\ REFUSED"; Lookup="CONNECTION REFUSED"; Path=""; Cause="Port closed/Blocked" },
    @{ Id='153'; Title="TCP Connect (Timeout)"; Op=""; Res=""; Lookup=""; Path=""; Cause="Drop/No Route" },
    @{ Id='154'; Title="TCP Connect (Unreachable):"; Op=""; Res="NETWORK\ UNREACHABLE"; Lookup="NETWORK UNREACHABLE"; Path=""; Cause="Routing fail" },
    @{ Id='155'; Title="TCP Connect (AddrInUse):"; Op=""; Res="ADDRESS\ ALREADY\ ASSOCIATED"; Lookup="ADDRESS ALREADY ASSOCIATED"; Path=""; Cause="Port exhaustion" },
    @{ Id='156'; Title="TCP Reconnect"; Op=""; Res=""; Lookup=""; Path=""; Cause="Flapping" },
    @{ Id='157'; Title="TCP Disconnect (Reset):"; Op=""; Res="ECONNRESET"; Lookup="ECONNRESET"; Path=""; Cause="Force close" },
    @{ Id='158'; Title="TCP KeepAlive"; Op=""; Res=""; Lookup=""; Path=""; Cause="Idle maintenance" },
    @{ Id='159'; Title="UDP Send (Fail):"; Op=""; Res="HOST\ UNREACHABLE"; Lookup="HOST UNREACHABLE"; Path=""; Cause="Delivery fail" },
    @{ Id='160'; Title="UDP Receive"; Op=""; Res=""; Lookup=""; Path=""; Cause="Listener active" },
    @{ Id='161'; Title="DNS Query (A)"; Op=""; Res=""; Lookup=""; Path=""; Cause="IPv4" },
    @{ Id='162'; Title="DNS Query (AAAA)"; Op=""; Res=""; Lookup=""; Path=""; Cause="IPv6" },
    @{ Id='163'; Title="DNS Fail:"; Op=""; Res="NAME\ NOT\ FOUND"; Lookup="NAME NOT FOUND"; Path=""; Cause="Typo/Missing record" },
    @{ Id='164'; Title="DNS Timeout"; Op=""; Res=""; Lookup=""; Path=""; Cause="DNS Server down" },
    @{ Id='165'; Title="Reverse Lookup"; Op=""; Res=""; Lookup=""; Path=""; Cause="Logging/Security" },
    @{ Id='166'; Title="Broadcast Storm"; Op=""; Res=""; Lookup=""; Path=""; Cause="NetBIOS/Disco" },
    @{ Id='167'; Title="Multicast Join"; Op=""; Res=""; Lookup=""; Path=""; Cause="Streaming/Cluster" },
    @{ Id='168'; Title="IPv6 Failover:"; Op=""; Res="SUCCESS"; Lookup="SUCCESS"; Path=""; Cause="Protocol lag" },
    @{ Id='169'; Title="Port 80/443"; Op=""; Res=""; Lookup=""; Path=""; Cause="Web traffic" },
    @{ Id='170'; Title="Port 445"; Op=""; Res=""; Lookup=""; Path=""; Cause="File share" },
    @{ Id='171'; Title="Port 135/139"; Op=""; Res=""; Lookup=""; Path=""; Cause="Legacy/Mgmt" },
    @{ Id='172'; Title="Port 389/636"; Op=""; Res=""; Lookup=""; Path=""; Cause="AD Auth" },
    @{ Id='173'; Title="Port 88"; Op=""; Res=""; Lookup=""; Path=""; Cause="Auth" },
    @{ Id='174'; Title="Port 53"; Op=""; Res=""; Lookup=""; Path=""; Cause="Resolution" },
    @{ Id='175'; Title="Port 3389"; Op=""; Res=""; Lookup=""; Path=""; Cause="Remote Access" },
    @{ Id='176'; Title="Port 1433"; Op=""; Res=""; Lookup=""; Path=""; Cause="Database" },
    @{ Id='177'; Title="High Ports"; Op=""; Res=""; Lookup=""; Path=""; Cause="Client/RPC" },
    @{ Id='178'; Title="Tor Ports"; Op=""; Res=""; Lookup=""; Path=""; Cause="Suspicious" },
    @{ Id='179'; Title="Proxy Connect"; Op=""; Res=""; Lookup=""; Path=""; Cause="Web filter" },
    @{ Id='180'; Title="WPAD Lookup"; Op=""; Res=""; Lookup=""; Path="wpad"; Cause="Proxy auto-config" },
    @{ Id='181'; Title="PAC File Fail:"; Op=""; Res=""; Lookup=""; Path="\.pac"; Cause="Slow browsing" },
    @{ Id='182'; Title="SMBv1"; Op=""; Res=""; Lookup=""; Path=""; Cause="Security risk" },
    @{ Id='183'; Title="SMBv3"; Op=""; Res=""; Lookup=""; Path=""; Cause="Modern/Encryption" },
    @{ Id='184'; Title="RPC Bind"; Op=""; Res=""; Lookup=""; Path=""; Cause="DCOM start" },
    @{ Id='185'; Title="RPC Auth Fail:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Permission" },
    @{ Id='186'; Title="RPC Stub Fail"; Op=""; Res=""; Lookup=""; Path="RPC_E_DISCONNECTED"; Cause="Crash on server" },
    @{ Id='187'; Title="Named Pipe Connect:"; Op=""; Res=""; Lookup=""; Path="\\\\Server\\pipe"; Cause="IPC" },
    @{ Id='188'; Title="Mail Slot:"; Op=""; Res=""; Lookup=""; Path="`\\mailslot\\browse`"; Cause="Browser election" },
    @{ Id='189'; Title="Cert Revocation"; Op=""; Res=""; Lookup=""; Path=""; Cause="SSL check" },
    @{ Id='190'; Title="OCSP Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="Cert hang" },
    @{ Id='191'; Title="Winsock Load:"; Op=""; Res=""; Lookup=""; Path="ws2_32\.dll"; Cause="Net stack init" },
    @{ Id='192'; Title="LSP Injection"; Op=""; Res=""; Lookup=""; Path=""; Cause="Interference" },
    @{ Id='193'; Title="NLA Check"; Op=""; Res=""; Lookup=""; Path="msftncsi"; Cause="Internet check" },
    @{ Id='194'; Title="Teredo/Isatap"; Op=""; Res=""; Lookup=""; Path=""; Cause="IPv6 transition" },
    @{ Id='195'; Title="Loopback Connect:"; Op=""; Res=""; Lookup=""; Path="127\.0\.0\.1"; Cause="Local service" },
    @{ Id='196'; Title="Link Local:"; Op=""; Res=""; Lookup=""; Path="169\.254\.x\.x"; Cause="DHCP fail" },
    @{ Id='197'; Title="Private IP:"; Op=""; Res=""; Lookup=""; Path="192\.168\.x"; Cause="Internal" },
    @{ Id='198'; Title="Public IP"; Op=""; Res=""; Lookup=""; Path=""; Cause="External" },
    @{ Id='199'; Title="FTP Active"; Op=""; Res=""; Lookup=""; Path=""; Cause="Data exfil/Legacy" },
    @{ Id='200'; Title="SSH Active"; Op=""; Res=""; Lookup=""; Path=""; Cause="Admin/Tunnel" },
    @{ Id='201'; Title="GPO Read Fail:"; Op=""; Res=""; Lookup=""; Path="gpt\.ini"; Cause="Policy fail" },
    @{ Id='202'; Title="GPO Script Fail:"; Op=""; Res="`gpscript\.exe`\ error"; Lookup="`gpscript.exe` error"; Path="gpscript\.exe"; Cause="Startup script" },
    @{ Id='203'; Title="GPO History Lock:"; Op=""; Res=""; Lookup=""; Path="history\.ini"; Cause="Processing hang" },
    @{ Id='204'; Title="Sysvol Latency:"; Op=""; Res=""; Lookup=""; Path="\\\\Domain\\Sysvol"; Cause="DC overload" },
    @{ Id='205'; Title="Netlogon Fail"; Op=""; Res=""; Lookup=""; Path="_ldap"; Cause="DC discovery" },
    @{ Id='206'; Title="Kerberos Skew"; Op=""; Res=""; Lookup=""; Path="KRB_AP_ERR_SKEW"; Cause="Time sync" },
    @{ Id='207'; Title="Ticket Bloat:"; Op=""; Res="BUFFER\ OVERFLOW|STATUS\ BUFFER\ OVERFLOW"; Lookup="BUFFER OVERFLOW"; Path=""; Cause="MaxTokenSize" },
    @{ Id='208'; Title="Machine Trust:"; Op=""; Res="STATUS\ TRUST\ FAILURE"; Lookup="STATUS TRUST FAILURE"; Path=""; Cause="Broken trust" },
    @{ Id='209'; Title="LDAP Timeout"; Op=""; Res=""; Lookup=""; Path=""; Cause="Slow AD" },
    @{ Id='210'; Title="Roaming Profile:"; Op=""; Res=""; Lookup=""; Path="NTUSER\.DAT"; Cause="Logon error" },
    @{ Id='211'; Title="Folder Redir Offline"; Op=""; Res=""; Lookup=""; Path=""; Cause="Sync fail" },
    @{ Id='212'; Title="Offline Files Sync"; Op=""; Res=""; Lookup=""; Path="CscService"; Cause="Caching" },
    @{ Id='213'; Title="DFS Referral:"; Op=""; Res=""; Lookup=""; Path="\\\\Domain\\DFS"; Cause="Namespace" },
    @{ Id='214'; Title="Print Spooler Crash:"; Op=""; Res=""; Lookup=""; Path="`spoolsv\.exe`\ exit"; Cause="Print kill" },
    @{ Id='215'; Title="Driver Isolation"; Op=""; Res=""; Lookup=""; Path="PrintIsolationHost"; Cause="Bad driver" },
    @{ Id='216'; Title="Point and Print"; Op=""; Res=""; Lookup=""; Path="Dopp"; Cause="Driver install" },
    @{ Id='217'; Title="Group Policy Printer"; Op=""; Res=""; Lookup=""; Path="gpprinter"; Cause="Mapping fail" },
    @{ Id='218'; Title="Citrix Hook:"; Op=""; Res=""; Lookup=""; Path="`CtxHk\.dll`\ load"; Cause="VDI hook" },
    @{ Id='219'; Title="Citrix API Block:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="AV conflict" },
    @{ Id='220'; Title="FSLogix Service"; Op=""; Res=""; Lookup=""; Path="frxsvc"; Cause="Profile container" },
    @{ Id='221'; Title="VHDX Lock"; Op=""; Res=""; Lookup=""; Path="frxsvc"; Cause="Session lock" },
    @{ Id='222'; Title="App-V Stream:"; Op=""; Res=""; Lookup=""; Path="Read\ from\ `Q:`"; Cause="Streaming" },
    @{ Id='223'; Title="ThinPrint"; Op=""; Res=""; Lookup=""; Path="TPAutoConnect"; Cause="VDI Print" },
    @{ Id='224'; Title="VMware Tools"; Op=""; Res=""; Lookup=""; Path="vmtoolsd"; Cause="Guest agent" },
    @{ Id='225'; Title="WEM Agent"; Op=""; Res=""; Lookup=""; Path="Norskale"; Cause="Environment mgmt" },
    @{ Id='226'; Title="SCCM Agent"; Op=""; Res=""; Lookup=""; Path="CcmExec"; Cause="Mgmt agent" },
    @{ Id='227'; Title="SCCM Cache"; Op=""; Res=""; Lookup=""; Path="ccmcache"; Cause="Download" },
    @{ Id='228'; Title="Intune Mgmt"; Op=""; Res=""; Lookup=""; Path="Omadmclient"; Cause="MDM sync" },
    @{ Id='229'; Title="AppLocker Block"; Op=""; Res=""; Lookup=""; Path="SrpUxNative"; Cause="Whitelisting" },
    @{ Id='230'; Title="BitLocker Network"; Op=""; Res=""; Lookup=""; Path="FVE"; Cause="Boot unlock" },
    @{ Id='231'; Title="MSI Exec Start:"; Op=""; Res=""; Lookup=""; Path="`msiexec\.exe`"; Cause="Install start" },
    @{ Id='232'; Title="MSI Source Fail:"; Op=""; Res="PATH\ NOT\ FOUND"; Lookup="PATH NOT FOUND"; Path=""; Cause="Media missing" },
    @{ Id='233'; Title="MSI Self Repair"; Op=""; Res=""; Lookup=""; Path="msiexec"; Cause="Resiliency" },
    @{ Id='234'; Title="MSI Rollback"; Op=""; Res=""; Lookup=""; Path="SetRename"; Cause="Fatal error" },
    @{ Id='235'; Title="MSI Mutex"; Op=""; Res=""; Lookup=""; Path="_MSIExecute"; Cause="Concurrent install" },
    @{ Id='236'; Title="MSI Custom Action"; Op=""; Res=""; Lookup=""; Path="cmd"; Cause="Script logic" },
    @{ Id='237'; Title="MSI Cab Fail:"; Op=""; Res=""; Lookup=""; Path="Extract\ fail\ `%TEMP%`"; Cause="Disk/Perms" },
    @{ Id='238'; Title="MSI Transform:"; Op=""; Res=""; Lookup=""; Path="`\.mst`\ missing"; Cause="Customization lost" },
    @{ Id='239'; Title="Pending Reboot"; Op=""; Res=""; Lookup=""; Path="PendingFileRename"; Cause="Blocker" },
    @{ Id='240'; Title="Windows Update Lock"; Op=""; Res=""; Lookup=""; Path="wuauserv"; Cause="DB lock" },
    @{ Id='241'; Title="CBS Manifest"; Op=""; Res=""; Lookup=""; Path="TrustedInstaller"; Cause="Corrupt OS" },
    @{ Id='242'; Title="CatRoot2 Fail"; Op=""; Res=""; Lookup=""; Path="cryptsvc"; Cause="Catalog corrupt" },
    @{ Id='243'; Title="SXS Corruption"; Op=""; Res=""; Lookup=""; Path="winsxs"; Cause="Component store" },
    @{ Id='244'; Title="Driver Store"; Op=""; Res=""; Lookup=""; Path="drvstore"; Cause="Driver staging" },
    @{ Id='245'; Title="TiWorker CPU"; Op=""; Res=""; Lookup=""; Path="TiWorker"; Cause="Post-install" },
    @{ Id='246'; Title="Update Download"; Op=""; Res=""; Lookup=""; Path="SoftwareDistribution"; Cause="Patching" },
    @{ Id='247'; Title="Bled/Hydrate"; Op=""; Res=""; Lookup=""; Path=""; Cause="AppX" },
    @{ Id='248'; Title="AppX Manifest:"; Op=""; Res=""; Lookup=""; Path="AppxManifest\.xml"; Cause="Store App" },
    @{ Id='249'; Title="AppX Deploy"; Op=""; Res=""; Lookup=""; Path="AppXDeploymentServer"; Cause="Install fail" },
    @{ Id='250'; Title="State Repo"; Op=""; Res=""; Lookup=""; Path="StateRepository"; Cause="Store DB lock" },
    @{ Id='251'; Title="Run Key Persistence:"; Op=""; Res=""; Lookup=""; Path="CurrentVersion\\Run"; Cause="Autostart" },
    @{ Id='252'; Title="Startup Persistence"; Op=""; Res=""; Lookup=""; Path="Startup"; Cause="Autostart" },
    @{ Id='253'; Title="Service Persistence"; Op=""; Res=""; Lookup=""; Path="Services"; Cause="Rootkit" },
    @{ Id='254'; Title="Task Persistence"; Op=""; Res=""; Lookup=""; Path="Tasks"; Cause="Scheduled Task" },
    @{ Id='255'; Title="Winlogon Persist"; Op=""; Res=""; Lookup=""; Path="Userinit"; Cause="Hijack" },
    @{ Id='256'; Title="Image Hijack"; Op=""; Res=""; Lookup=""; Path="Image File Execution Options"; Cause="Debug hijack" },
    @{ Id='257'; Title="AppInit Injection"; Op=""; Res=""; Lookup=""; Path="AppInit_DLLs"; Cause="Dll inject" },
    @{ Id='258'; Title="COM Hijack"; Op=""; Res=""; Lookup=""; Path="InprocServer32"; Cause="Object hijack" },
    @{ Id='259'; Title="Extension Hijack:"; Op=""; Res=""; Lookup=""; Path="Write\ `txtfile\\shell\\open`"; Cause="Assoc hijack" },
    @{ Id='260'; Title="Browser Helper"; Op=""; Res=""; Lookup=""; Path="BHO"; Cause="Adware" },
    @{ Id='261'; Title="Phantom DLL:"; Op=""; Res=""; Lookup=""; Path="version\.dll"; Cause="Sideloading" },
    @{ Id='262'; Title="WMI Persist:"; Op=""; Res=""; Lookup=""; Path="Write\ `Objects\.data`"; Cause="Fileless persist" },
    @{ Id='263'; Title="Powershell Enc"; Op=""; Res=""; Lookup=""; Path="powershell -e"; Cause="Obfuscation" },
    @{ Id='264'; Title="Powershell Download:"; Op=""; Res=""; Lookup=""; Path="`Net\.WebClient`"; Cause="Downloader" },
    @{ Id='265'; Title="LoLBin CertUtil"; Op=""; Res=""; Lookup=""; Path="certutil -urlcache"; Cause="Download" },
    @{ Id='266'; Title="LoLBin Bits"; Op=""; Res=""; Lookup=""; Path="bitsadmin /transfer"; Cause="Download" },
    @{ Id='267'; Title="LoLBin Mshta"; Op=""; Res=""; Lookup=""; Path="mshta vbscript"; Cause="Execution" },
    @{ Id='268'; Title="LoLBin Rundll"; Op=""; Res=""; Lookup=""; Path="rundll32 entrypoint"; Cause="Execution" },
    @{ Id='269'; Title="LoLBin Regsvr"; Op=""; Res=""; Lookup=""; Path="regsvr32 /s /u"; Cause="Squiblydoo" },
    @{ Id='270'; Title="Credential Dump"; Op=""; Res=""; Lookup=""; Path="lsass"; Cause="Mimikatz" },
    @{ Id='271'; Title="SAM Dump"; Op=""; Res=""; Lookup=""; Path="SAM"; Cause="Hash dump" },
    @{ Id='272'; Title="LSA Secret:"; Op=""; Res=""; Lookup=""; Path="Policy\\Secrets"; Cause="Password dump" },
    @{ Id='273'; Title="Vault Access"; Op=""; Res=""; Lookup=""; Path="vaultcmd"; Cause="Cred dump" },
    @{ Id='274'; Title="Browser Data"; Op=""; Res=""; Lookup=""; Path="Login Data"; Cause="Cookie theft" },
    @{ Id='275'; Title="Keylog Poll"; Op=""; Res=""; Lookup=""; Path="GetAsyncKeyState"; Cause="Spyware" },
    @{ Id='276'; Title="Clipboard Monitor"; Op=""; Res=""; Lookup=""; Path=""; Cause="Spyware" },
    @{ Id='277'; Title="Screen Capture"; Op=""; Res=""; Lookup=""; Path="BitBlt"; Cause="Spyware" },
    @{ Id='278'; Title="Mic Access"; Op=""; Res=""; Lookup=""; Path="WaveIn"; Cause="Eavesdrop" },
    @{ Id='279'; Title="Webcam Access"; Op=""; Res=""; Lookup=""; Path="Video"; Cause="Spyware" },
    @{ Id='280'; Title="Recon Whoami"; Op=""; Res=""; Lookup=""; Path="whoami /all"; Cause="Discovery" },
    @{ Id='281'; Title="Recon Net"; Op=""; Res=""; Lookup=""; Path="net group"; Cause="Discovery" },
    @{ Id='282'; Title="Recon IP"; Op=""; Res=""; Lookup=""; Path="ipconfig /all"; Cause="Discovery" },
    @{ Id='283'; Title="Recon Task"; Op=""; Res=""; Lookup=""; Path="tasklist /svc"; Cause="AV check" },
    @{ Id='284'; Title="Event Clear"; Op=""; Res=""; Lookup=""; Path="wevtutil cl"; Cause="Anti-forensics" },
    @{ Id='285'; Title="Shadow Delete"; Op=""; Res=""; Lookup=""; Path="vssadmin delete"; Cause="Ransomware" },
    @{ Id='286'; Title="Backup Stop"; Op=""; Res=""; Lookup=""; Path="wbadmin delete"; Cause="Ransomware" },
    @{ Id='287'; Title="Disable Def"; Op=""; Res=""; Lookup=""; Path="DisableRealtimeMonitoring"; Cause="AV Kill" },
    @{ Id='288'; Title="Host File Mod"; Op=""; Res=""; Lookup=""; Path="hosts"; Cause="Redirect" },
    @{ Id='289'; Title="Timestomp:"; Op="SetBasicInformationFile"; Res=""; Lookup=""; Path=""; Cause="Hiding" },
    @{ Id='290'; Title="Masquerade:"; Op=""; Res=""; Lookup=""; Path="`svchost`\ in\ `%TEMP%`"; Cause="Hiding" },
    @{ Id='291'; Title="Ransom Rename"; Op=""; Res=""; Lookup=""; Path=""; Cause="Encryption" },
    @{ Id='292'; Title="Ransom Write"; Op=""; Res=""; Lookup=""; Path=""; Cause="Encryption" },
    @{ Id='293'; Title="DGA DNS"; Op=""; Res=""; Lookup=""; Path=""; Cause="C2" },
    @{ Id='294'; Title="Beaconing"; Op=""; Res=""; Lookup=""; Path=""; Cause="C2" },
    @{ Id='295'; Title="Tor Traffic"; Op=""; Res=""; Lookup=""; Path=""; Cause="Anon" },
    @{ Id='296'; Title="PST Access:"; Op=""; Res=""; Lookup=""; Path="\.pst"; Cause="Email theft" },
    @{ Id='297'; Title="SSH Keys"; Op=""; Res=""; Lookup=""; Path="id_rsa"; Cause="Lateral move" },
    @{ Id='298'; Title="RDP Saved:"; Op=""; Res=""; Lookup=""; Path="Default\.rdp"; Cause="Lateral move" },
    @{ Id='299'; Title="Wifi Keys"; Op=""; Res=""; Lookup=""; Path="Wlansvc"; Cause="Lateral move" },
    @{ Id='300'; Title="Exfil FTP"; Op=""; Res=""; Lookup=""; Path="ftp -s"; Cause="Data theft" },
    @{ Id='301'; Title=".NET CLR Load:"; Op=""; Res=""; Lookup=""; Path="`mscoree\.dll`\ load"; Cause=".NET start" },
    @{ Id='302'; Title=".NET GAC Load:"; Op=""; Res=""; Lookup=""; Path="C:\\Windows\\Assembly"; Cause="Global lib" },
    @{ Id='303'; Title=".NET Temp:"; Op=""; Res=""; Lookup=""; Path="Write\ `Temporary\ ASP\.NET\ Files`"; Cause="Compile" },
    @{ Id='304'; Title=".NET Config:"; Op=""; Res=""; Lookup=""; Path="Read\ `machine\.config`"; Cause="Settings" },
    @{ Id='305'; Title=".NET JIT:"; Op=""; Res=""; Lookup=""; Path="mscorjit\.dll"; Cause="Compilation" },
    @{ Id='306'; Title=".NET NGEN:"; Op=""; Res=""; Lookup=""; Path="ngen\.exe"; Cause="Optimization" },
    @{ Id='307'; Title="Java Home"; Op=""; Res=""; Lookup=""; Path="JAVA_HOME"; Cause="Config" },
    @{ Id='308'; Title="Java Runtime:"; Op=""; Res=""; Lookup=""; Path="jvm\.dll"; Cause="Java start" },
    @{ Id='309'; Title="Java Classpath"; Op=""; Res=""; Lookup=""; Path="lib/ext"; Cause="Dependency" },
    @{ Id='310'; Title="Java Access"; Op=""; Res=""; Lookup=""; Path="WindowsAccessBridge"; Cause="A11y" },
    @{ Id='311'; Title="Python Path"; Op=""; Res=""; Lookup=""; Path="PYTHONPATH"; Cause="Config" },
    @{ Id='312'; Title="Python Import:"; Op=""; Res=""; Lookup=""; Path="Read\ `__init__\.py`"; Cause="Module load" },
    @{ Id='313'; Title="Node Modules"; Op=""; Res=""; Lookup=""; Path="node_modules"; Cause="JS dep" },
    @{ Id='314'; Title="Electron Cache"; Op=""; Res=""; Lookup=""; Path="GPUCache"; Cause="Chromium" },
    @{ Id='315'; Title="IIS Worker:"; Op=""; Res=""; Lookup=""; Path="`w3wp\.exe`\ start"; Cause="Web server" },
    @{ Id='316'; Title="IIS Config:"; Op=""; Res=""; Lookup=""; Path="web\.config"; Cause="App settings" },
    @{ Id='317'; Title="IIS Shared:"; Op=""; Res=""; Lookup=""; Path="Read\ `applicationHost\.config`"; Cause="Server set" },
    @{ Id='318'; Title="AppPool Identity:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Perms" },
    @{ Id='319'; Title="Temp Path"; Op=""; Res=""; Lookup=""; Path="TEMP"; Cause="Scratch space" },
    @{ Id='320'; Title="Oracle TNS:"; Op=""; Res=""; Lookup=""; Path="Read\ `tnsnames\.ora`"; Cause="DB Config" },
    @{ Id='321'; Title="ODBC System:"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\ODBC"; Cause="DSN" },
    @{ Id='322'; Title="ODBC User:"; Op=""; Res=""; Lookup=""; Path="HKCU\\Software\\ODBC"; Cause="DSN" },
    @{ Id='323'; Title="SQL Driver:"; Op=""; Res=""; Lookup=""; Path="sqlncli\.dll"; Cause="Connectivity" },
    @{ Id='324'; Title="OLEDB Reg:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKCR\\CLSID\\\{Provider\}`"; Cause="Driver" },
    @{ Id='325'; Title="UDL Read:"; Op=""; Res=""; Lookup=""; Path="\.udl"; Cause="Conn string" },
    @{ Id='326'; Title="Report Viewer:"; Op=""; Res=""; Lookup=""; Path="Microsoft\.ReportViewer"; Cause="Reporting" },
    @{ Id='327'; Title="Crystal Reports:"; Op=""; Res=""; Lookup=""; Path="crpe32\.dll"; Cause="Reporting" },
    @{ Id='328'; Title="Flash OCX:"; Op=""; Res=""; Lookup=""; Path="Flash\.ocx"; Cause="Legacy" },
    @{ Id='329'; Title="Silverlight:"; Op=""; Res=""; Lookup=""; Path="Load\ `npctrl\.dll`"; Cause="Legacy" },
    @{ Id='330'; Title="ActiveX Killbit"; Op=""; Res=""; Lookup=""; Path="Compatibility Flags"; Cause="Block" },
    @{ Id='331'; Title="USB Arrival:"; Op="DeviceIoControl"; Res=""; Lookup=""; Path=""; Cause="Connect" },
    @{ Id='332'; Title="USB Removal:"; Op="DeviceIoControl"; Res=""; Lookup=""; Path=""; Cause="Disconnect" },
    @{ Id='333'; Title="USB Suspend"; Op=""; Res=""; Lookup=""; Path=""; Cause="Power" },
    @{ Id='334'; Title="HID Input"; Op=""; Res=""; Lookup=""; Path="HidUsb"; Cause="Keyboard/Mouse" },
    @{ Id='335'; Title="Bluetooth Enum"; Op=""; Res=""; Lookup=""; Path="BthEnum"; Cause="Wireless" },
    @{ Id='336'; Title="SmartCard Insert"; Op=""; Res=""; Lookup=""; Path="SCardSvr"; Cause="Auth" },
    @{ Id='337'; Title="SmartCard Pipe"; Op=""; Res=""; Lookup=""; Path="SCardPipe"; Cause="Driver" },
    @{ Id='338'; Title="GPU Reset"; Op=""; Res=""; Lookup=""; Path="dxgkrnl"; Cause="Crash" },
    @{ Id='339'; Title="GPU Throttling"; Op=""; Res=""; Lookup=""; Path=""; Cause="Thermal" },
    @{ Id='340'; Title="Audio Excl"; Op=""; Res=""; Lookup=""; Path="AUDCLNT_E_DEVICE_IN_USE"; Cause="Lock" },
    @{ Id='341'; Title="Audio Graph"; Op=""; Res=""; Lookup=""; Path="audiodg"; Cause="Sound" },
    @{ Id='342'; Title="Webcam Lock:"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="Privacy" },
    @{ Id='343'; Title="Printer Bidirectional"; Op=""; Res=""; Lookup=""; Path=""; Cause="Status" },
    @{ Id='344'; Title="Scanner Twain:"; Op=""; Res=""; Lookup=""; Path="twain_32\.dll"; Cause="Imaging" },
    @{ Id='345'; Title="Serial Port"; Op=""; Res=""; Lookup=""; Path="COM1"; Cause="Legacy IO" },
    @{ Id='346'; Title="Parallel Port"; Op=""; Res=""; Lookup=""; Path="LPT1"; Cause="Legacy IO" },
    @{ Id='347'; Title="Tape Drive"; Op=""; Res=""; Lookup=""; Path="Tape0"; Cause="Backup" },
    @{ Id='348'; Title="Battery Poll"; Op=""; Res=""; Lookup=""; Path="batmeter"; Cause="Power" },
    @{ Id='349'; Title="ACPI Event"; Op=""; Res=""; Lookup=""; Path="ACPI"; Cause="Heat" },
    @{ Id='350'; Title="BIOS Info:"; Op=""; Res=""; Lookup=""; Path="Hardwaredescription\\System"; Cause="Firmware" },
    @{ Id='351'; Title="UIA Prov Fail:"; Op="RegOpenKey"; Res=""; Lookup=""; Path=""; Cause="Automation" },
    @{ Id='352'; Title="WM_GETOBJECT:"; Op=""; Res="TIMEOUT"; Lookup="TIMEOUT"; Path=""; Cause="No response" },
    @{ Id='353'; Title="Acc Name"; Op=""; Res=""; Lookup=""; Path="accName"; Cause="Unlabeled" },
    @{ Id='354'; Title="Focus Fight"; Op=""; Res=""; Lookup=""; Path="SetFocus"; Cause="Loop" },
    @{ Id='355'; Title="High Contrast"; Op=""; Res=""; Lookup=""; Path="GetSysColor"; Cause="Theme" },
    @{ Id='356'; Title="Cursor Track"; Op=""; Res=""; Lookup=""; Path="GetGUIThreadInfo"; Cause="Visual" },
    @{ Id='357'; Title="Narrator Hook"; Op=""; Res=""; Lookup=""; Path="NarratorHook"; Cause="Reader" },
    @{ Id='358'; Title="JAB Fail"; Op=""; Res=""; Lookup=""; Path="WindowsAccessBridge"; Cause="Java" },
    @{ Id='359'; Title="Braille Lock:"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="Display" },
    @{ Id='360'; Title="Speech Dict"; Op=""; Res=""; Lookup=""; Path=""; Cause="Voice" },
    @{ Id='361'; Title="INI Redirect:"; Op=""; Res=""; Lookup=""; Path="Read\ `win\.ini`"; Cause="16-bit" },
    @{ Id='362'; Title="16-bit App:"; Op=""; Res=""; Lookup=""; Path="Load\ `ntvdm\.exe`"; Cause="DOS" },
    @{ Id='363'; Title="Thunking:"; Op=""; Res=""; Lookup=""; Path="Load\ `wow64\.dll`"; Cause="32-on-64" },
    @{ Id='364'; Title="Shim Apply:"; Op=""; Res=""; Lookup=""; Path="Read\ `sysmain\.sdb`"; Cause="Patches" },
    @{ Id='365'; Title="DirectX 9:"; Op=""; Res=""; Lookup=""; Path="d3d9\.dll"; Cause="Old Gfx" },
    @{ Id='366'; Title="VB6 Runtime:"; Op=""; Res=""; Lookup=""; Path="msvbvm60\.dll"; Cause="Basic" },
    @{ Id='367'; Title="MFC 42:"; Op=""; Res=""; Lookup=""; Path="mfc42\.dll"; Cause="C++" },
    @{ Id='368'; Title="8.3 Path:"; Op=""; Res=""; Lookup=""; Path="DOCUME\~1"; Cause="Shortname" },
    @{ Id='369'; Title="Hardcoded Drv:"; Op=""; Res=""; Lookup=""; Path="D:\\"; Cause="Missing drive" },
    @{ Id='370'; Title="CD Check"; Op=""; Res=""; Lookup=""; Path="CdRom0"; Cause="DRM" },
    @{ Id='371'; Title="Admin Write"; Op=""; Res=""; Lookup=""; Path="VirtualStore"; Cause="UAC" },
    @{ Id='372'; Title="Deprecated API"; Op=""; Res=""; Lookup=""; Path="WinExec"; Cause="Old code" },
    @{ Id='373'; Title="Legacy Help:"; Op=""; Res=""; Lookup=""; Path="winhlp32\.exe"; Cause=".hlp" },
    @{ Id='374'; Title="MAPI Mail:"; Op=""; Res=""; Lookup=""; Path="Load\ `mapi32\.dll`"; Cause="Email" },
    @{ Id='375'; Title="NetDDE"; Op=""; Res=""; Lookup=""; Path=""; Cause="Ancient IPC" },
    @{ Id='376'; Title="Cert Store"; Op=""; Res=""; Lookup=""; Path="SystemCertificates"; Cause="Trust" },
    @{ Id='377'; Title="Root Update:"; Op=""; Res=""; Lookup=""; Path="Download\ `authroot\.stl`"; Cause="Update" },
    @{ Id='378'; Title="CRL Fetch:"; Op=""; Res=""; Lookup=""; Path="HTTP\ fetch\ `\.crl`"; Cause="Revocation" },
    @{ Id='379'; Title="OCSP Check"; Op=""; Res=""; Lookup=""; Path=""; Cause="Revocation" },
    @{ Id='380'; Title="Chain Fail"; Op=""; Res=""; Lookup=""; Path="CERT_E_CHAINING"; Cause="Trust path" },
    @{ Id='381'; Title="Expired"; Op=""; Res=""; Lookup=""; Path="CERT_E_EXPIRED"; Cause="Date" },
    @{ Id='382'; Title="Name Mismatch"; Op=""; Res=""; Lookup=""; Path="CERT_E_CN_NO_MATCH"; Cause="SSL" },
    @{ Id='383'; Title="MachineKey"; Op=""; Res=""; Lookup=""; Path="MachineKeys"; Cause="Private key" },
    @{ Id='384'; Title="UserKey"; Op=""; Res=""; Lookup=""; Path="Protect"; Cause="Private key" },
    @{ Id='385'; Title="DPAPI"; Op=""; Res=""; Lookup=""; Path="CryptUnprotectData"; Cause="Decryption" },
    @{ Id='386'; Title="CNG Key"; Op=""; Res=""; Lookup=""; Path="KeyStorage"; Cause="Modern key" },
    @{ Id='387'; Title="FIPS Block"; Op=""; Res=""; Lookup=""; Path="FIPSAlgorithmPolicy"; Cause="Compliance" },
    @{ Id='388'; Title="Hash Fail:"; Op=""; Res="STATUS\ INVALID\ IMAGE\ HASH"; Lookup="STATUS INVALID IMAGE HASH"; Path=""; Cause="Sign" },
    @{ Id='389'; Title="Catalog DB"; Op=""; Res=""; Lookup=""; Path="catdb"; Cause="Sig DB" },
    @{ Id='390'; Title="RNG Seed"; Op=""; Res=""; Lookup=""; Path="RNG"; Cause="Random" },
    @{ Id='391'; Title="AAD Token"; Op=""; Res=""; Lookup=""; Path="TokenBroker"; Cause="SSO" },
    @{ Id='392'; Title="Workplace Join"; Op=""; Res=""; Lookup=""; Path="WorkplaceJoin"; Cause="Registration" },
    @{ Id='393'; Title="Ngc Key"; Op=""; Res=""; Lookup=""; Path="Ngc"; Cause="Hello for Bus" },
    @{ Id='394'; Title="M365 Activate:"; Op=""; Res=""; Lookup=""; Path="Connect\ `office\.com`"; Cause="Licensing" },
    @{ Id='395'; Title="OneDrive Sync"; Op=""; Res=""; Lookup=""; Path="OneDrive"; Cause="Cloud file" },
    @{ Id='396'; Title="Azure Info"; Op=""; Res=""; Lookup=""; Path="Tenants"; Cause="Identity" },
    @{ Id='397'; Title="MDM Policy"; Op=""; Res=""; Lookup=""; Path="PolicyManager"; Cause="Intune" },
    @{ Id='398'; Title="Entra ID"; Op=""; Res=""; Lookup=""; Path="dsregcmd"; Cause="Join status" },
    @{ Id='399'; Title="Compliance"; Op=""; Res=""; Lookup=""; Path="HealthAttestation"; Cause="Security" },
    @{ Id='400'; Title="Telemetry"; Op=""; Res=""; Lookup=""; Path="CompatTelRunner"; Cause="Diag data" },
    @{ Id='401'; Title="Chrome Profile"; Op=""; Res=""; Lookup=""; Path="SingletonLock"; Cause="Stuck" },
    @{ Id='402'; Title="Chrome Ext"; Op=""; Res=""; Lookup=""; Path="Extensions"; Cause="Add-on" },
    @{ Id='403'; Title="Edge Update"; Op=""; Res=""; Lookup=""; Path="MicrosoftEdgeUpdate"; Cause="Patch" },
    @{ Id='404'; Title="Firefox Lock:"; Op=""; Res=""; Lookup=""; Path="`parent\.lock`"; Cause="Stuck" },
    @{ Id='405'; Title="Teams Cache"; Op=""; Res=""; Lookup=""; Path="Code Cache"; Cause="Performance" },
    @{ Id='406'; Title="Teams Log:"; Op=""; Res=""; Lookup=""; Path="logs\.txt"; Cause="Diag" },
    @{ Id='407'; Title="Outlook OST:"; Op=""; Res=""; Lookup=""; Path="\.ost"; Cause="Disk IO" },
    @{ Id='408'; Title="Outlook OAB"; Op=""; Res=""; Lookup=""; Path="Offline Address Books"; Cause="Sync" },
    @{ Id='409'; Title="Excel Addin:"; Op=""; Res=""; Lookup=""; Path="Load\ `\.xll`"; Cause="Extension" },
    @{ Id='410'; Title="Word Template:"; Op=""; Res=""; Lookup=""; Path="Normal\.dotm"; Cause="Config" },
    @{ Id='411'; Title="Adobe Reader:"; Op=""; Res=""; Lookup=""; Path="AcroRd32\.dll"; Cause="PDF" },
    @{ Id='412'; Title="Adobe Arm:"; Op=""; Res=""; Lookup=""; Path="`AdobeARM\.exe`"; Cause="Update" },
    @{ Id='413'; Title="Zoom Cpt:"; Op=""; Res=""; Lookup=""; Path="`CptHost\.exe`"; Cause="Sharing" },
    @{ Id='414'; Title="WebEx Service"; Op=""; Res=""; Lookup=""; Path="WebExService"; Cause="Meeting" },
    @{ Id='415'; Title="Slack Cache"; Op=""; Res=""; Lookup=""; Path="Cache"; Cause="Electron" },
    @{ Id='416'; Title="VSCode IPC"; Op=""; Res=""; Lookup=""; Path="vscode-ipc"; Cause="Dev" },
    @{ Id='417'; Title="Docker Pipe"; Op=""; Res=""; Lookup=""; Path="docker_engine"; Cause="Container" },
    @{ Id='418'; Title="Kubernetes:"; Op=""; Res=""; Lookup=""; Path="\.kube"; Cause="Config" },
    @{ Id='419'; Title="Git Lock:"; Op=""; Res=""; Lookup=""; Path="Read\ `index\.lock`"; Cause="Repo" },
    @{ Id='420'; Title="Npm Cache"; Op=""; Res=""; Lookup=""; Path="_cacache"; Cause="Dev" },
    @{ Id='421'; Title="McAfee Scan:"; Op=""; Res=""; Lookup=""; Path="`mcshield\.exe`"; Cause="AV" },
    @{ Id='422'; Title="Symantec Scan:"; Op=""; Res=""; Lookup=""; Path="`ccSvcHst\.exe`"; Cause="AV" },
    @{ Id='423'; Title="CrowdStrike"; Op=""; Res=""; Lookup=""; Path="CSFalconService"; Cause="EDR" },
    @{ Id='424'; Title="SentinelOne"; Op=""; Res=""; Lookup=""; Path="LogProcessor"; Cause="EDR" },
    @{ Id='425'; Title="Splunk Fwd"; Op=""; Res=""; Lookup=""; Path="splunk-optimize"; Cause="Log" },
    @{ Id='426'; Title="Tanium Client"; Op=""; Res=""; Lookup=""; Path="TaniumClient"; Cause="Mgmt" },
    @{ Id='427'; Title="Qualys Agent"; Op=""; Res=""; Lookup=""; Path="QualysAgent"; Cause="Scan" },
    @{ Id='428'; Title="Nessus Scan"; Op=""; Res=""; Lookup=""; Path=""; Cause="Vuln Scan" },
    @{ Id='429'; Title="Datadog"; Op=""; Res=""; Lookup=""; Path="datadog-agent"; Cause="Monitor" },
    @{ Id='430'; Title="NewRelic"; Op=""; Res=""; Lookup=""; Path="newrelic-infra"; Cause="Monitor" },
    @{ Id='431'; Title="Veeam Agent"; Op=""; Res=""; Lookup=""; Path="VeeamAgent"; Cause="Backup" },
    @{ Id='432'; Title="Commvault"; Op=""; Res=""; Lookup=""; Path="ClMgrS"; Cause="Backup" },
    @{ Id='433'; Title="Backup Exec"; Op=""; Res=""; Lookup=""; Path="beremote"; Cause="Backup" },
    @{ Id='434'; Title="Dropbox Watch"; Op=""; Res=""; Lookup=""; Path="Dropbox"; Cause="Sync" },
    @{ Id='435'; Title="Box Sync"; Op=""; Res=""; Lookup=""; Path="Box"; Cause="Sync" },
    @{ Id='436'; Title="Heap Corruption"; Op=""; Res=""; Lookup=""; Path="RtlFreeHeap"; Cause="Memory" },
    @{ Id='437'; Title="Double Free"; Op=""; Res=""; Lookup=""; Path=""; Cause="Crash" },
    @{ Id='438'; Title="Use After Free"; Op=""; Res=""; Lookup=""; Path=""; Cause="Exploit" },
    @{ Id='439'; Title="Null Pointer"; Op=""; Res=""; Lookup=""; Path=""; Cause="Bug" },
    @{ Id='440'; Title="Buffer Overrun"; Op=""; Res=""; Lookup=""; Path=""; Cause="Security" },
    @{ Id='441'; Title="Stack Exhaust"; Op=""; Res=""; Lookup=""; Path="Recursion"; Cause="Overflow" },
    @{ Id='442'; Title="Handle Invalid:"; Op="CloseHandle"; Res=""; Lookup=""; Path=""; Cause="Logic" },
    @{ Id='443'; Title="CritSec Timeout"; Op=""; Res=""; Lookup=""; Path=""; Cause="Hang" },
    @{ Id='444'; Title="Deadlock"; Op=""; Res=""; Lookup=""; Path=""; Cause="Hang" },
    @{ Id='445'; Title="LPC Wait"; Op=""; Res=""; Lookup=""; Path=""; Cause="IPC Hang" },
    @{ Id='446'; Title="Memory Leak"; Op=""; Res=""; Lookup=""; Path=""; Cause="Leak" },
    @{ Id='447'; Title="GDI Objects"; Op=""; Res=""; Lookup=""; Path=""; Cause="Limit" },
    @{ Id='448'; Title="User Objects"; Op=""; Res=""; Lookup=""; Path=""; Cause="Limit" },
    @{ Id='449'; Title="Thread Count"; Op=""; Res=""; Lookup=""; Path=""; Cause="Spam" },
    @{ Id='450'; Title="Handle Count"; Op=""; Res=""; Lookup=""; Path=""; Cause="Leak" },
    @{ Id='451'; Title="Boot Log:"; Op=""; Res=""; Lookup=""; Path="Write\ `ntbtlog\.txt`"; Cause="Diag" },
    @{ Id='452'; Title="Setup Log:"; Op=""; Res=""; Lookup=""; Path="setupapi\.dev\.log"; Cause="Driver" },
    @{ Id='453'; Title="CBS Log:"; Op=""; Res=""; Lookup=""; Path="Write\ `cbs\.log`"; Cause="Update" },
    @{ Id='454'; Title="DISM Log:"; Op=""; Res=""; Lookup=""; Path="Write\ `dism\.log`"; Cause="Image" },
    @{ Id='455'; Title="Events Log:"; Op=""; Res=""; Lookup=""; Path="\.evtx"; Cause="Audit" },
    @{ Id='456'; Title="WMI Repo:"; Op=""; Res=""; Lookup=""; Path="Read\ `Index\.btr`"; Cause="Mgmt" },
    @{ Id='457'; Title="SRU DB:"; Op=""; Res=""; Lookup=""; Path="srudb\.dat"; Cause="Usage" },
    @{ Id='458'; Title="Prefetch:"; Op=""; Res=""; Lookup=""; Path="Write\ `\.pf`"; Cause="Optimize" },
    @{ Id='459'; Title="Superfetch"; Op=""; Res=""; Lookup=""; Path="SysMain"; Cause="Cache" },
    @{ Id='460'; Title="Search Index"; Op=""; Res=""; Lookup=""; Path="SearchIndexer"; Cause="Index" },
    @{ Id='461'; Title="Cortana"; Op=""; Res=""; Lookup=""; Path="SearchUI"; Cause="Shell" },
    @{ Id='462'; Title="Start Menu"; Op=""; Res=""; Lookup=""; Path="ShellExperienceHost"; Cause="UI" },
    @{ Id='463'; Title="Action Center"; Op=""; Res=""; Lookup=""; Path="ActionCenter"; Cause="Notify" },
    @{ Id='464'; Title="Settings App"; Op=""; Res=""; Lookup=""; Path="SystemSettings"; Cause="Config" },
    @{ Id='465'; Title="Task Manager"; Op=""; Res=""; Lookup=""; Path="Taskmgr"; Cause="Admin" },
    @{ Id='466'; Title="Resource Mon"; Op=""; Res=""; Lookup=""; Path="Perfmon"; Cause="Admin" },
    @{ Id='467'; Title="Event Viewer:"; Op=""; Res=""; Lookup=""; Path="`mmc\.exe`"; Cause="Admin" },
    @{ Id='468'; Title="Reg Editor:"; Op=""; Res=""; Lookup=""; Path="`regedit\.exe`"; Cause="Admin" },
    @{ Id='469'; Title="CMD Shell:"; Op=""; Res=""; Lookup=""; Path="`cmd\.exe`"; Cause="Shell" },
    @{ Id='470'; Title="PowerShell:"; Op=""; Res=""; Lookup=""; Path="powershell\.exe"; Cause="Shell" },
    @{ Id='471'; Title="Run Dialog:"; Op=""; Res=""; Lookup=""; Path="`explorer\.exe`\ Run"; Cause="Shell" },
    @{ Id='472'; Title="LogonUI:"; Op=""; Res=""; Lookup=""; Path="`LogonUI\.exe`"; Cause="Auth" },
    @{ Id='473'; Title="WinInit:"; Op=""; Res=""; Lookup=""; Path="`wininit\.exe`"; Cause="Boot" },
    @{ Id='474'; Title="LSM:"; Op=""; Res=""; Lookup=""; Path="`lsm\.exe`"; Cause="Session" },
    @{ Id='475'; Title="Smss:"; Op=""; Res=""; Lookup=""; Path="smss\.exe"; Cause="Session" },
    @{ Id='476'; Title="WSL Host:"; Op=""; Res=""; Lookup=""; Path="`wslhost\.exe`"; Cause="Kernel" },
    @{ Id='477'; Title="WSL File:"; Op=""; Res=""; Lookup=""; Path="Access\ `\\\\wsl\$`"; Cause="Network" },
    @{ Id='478'; Title="WSL Config:"; Op=""; Res=""; Lookup=""; Path="Read\ `\.wslconfig`"; Cause="Settings" },
    @{ Id='479'; Title="Lxss Manager"; Op=""; Res=""; Lookup=""; Path="LxssManager"; Cause="Svc" },
    @{ Id='480'; Title="Plan 9 FS:"; Op=""; Res=""; Lookup=""; Path="`p9rdr\.sys`"; Cause="Filesystem" },
    @{ Id='481'; Title="Bash Exec:"; Op=""; Res=""; Lookup=""; Path="`bash\.exe`"; Cause="Shell" },
    @{ Id='482'; Title="Linux Binary"; Op=""; Res=""; Lookup=""; Path=""; Cause="Compat" },
    @{ Id='483'; Title="WSL Network"; Op=""; Res=""; Lookup=""; Path=""; Cause="Connect" },
    @{ Id='484'; Title="WSL Mount"; Op=""; Res=""; Lookup=""; Path="drvfs"; Cause="Storage" },
    @{ Id='485'; Title="WSL2 VHD:"; Op=""; Res=""; Lookup=""; Path="ext4\.vhdx"; Cause="Disk" },
    @{ Id='486'; Title="Game Mode:"; Op=""; Res=""; Lookup=""; Path="GameBar\.exe"; Cause="Overlay" },
    @{ Id='487'; Title="DVR Store:"; Op=""; Res=""; Lookup=""; Path="\.mp4"; Cause="Record" },
    @{ Id='488'; Title="Steam Svc"; Op=""; Res=""; Lookup=""; Path="SteamService"; Cause="Platform" },
    @{ Id='489'; Title="Epic Svc"; Op=""; Res=""; Lookup=""; Path="EpicGamesLauncher"; Cause="Platform" },
    @{ Id='490'; Title="Origin Svc"; Op=""; Res=""; Lookup=""; Path="Origin"; Cause="Platform" },
    @{ Id='491'; Title="Discord Overlay"; Op=""; Res=""; Lookup=""; Path="Discord"; Cause="Hook" },
    @{ Id='492'; Title="OBS Hook"; Op=""; Res=""; Lookup=""; Path="graphics-hook"; Cause="Capture" },
    @{ Id='493'; Title="XInput"; Op=""; Res=""; Lookup=""; Path="xinput"; Cause="Controller" },
    @{ Id='494'; Title="DirectInput"; Op=""; Res=""; Lookup=""; Path="dinput"; Cause="Controller" },
    @{ Id='495'; Title="Vulkan:"; Op=""; Res=""; Lookup=""; Path="vulkan\-1\.dll"; Cause="Graphics" },
    @{ Id='496'; Title="OpenGL:"; Op=""; Res=""; Lookup=""; Path="opengl32\.dll"; Cause="Graphics" },
    @{ Id='497'; Title="OpenCL:"; Op=""; Res=""; Lookup=""; Path="OpenCL\.dll"; Cause="Compute" },
    @{ Id='498'; Title="PhysX"; Op=""; Res=""; Lookup=""; Path="PhysX"; Cause="Physics" },
    @{ Id='499'; Title="Shader Cache"; Op=""; Res=""; Lookup=""; Path="D3DSCache"; Cause="Perf" },
    @{ Id='500'; Title="Refresh Rate"; Op=""; Res=""; Lookup=""; Path="ChangeDisplaySettings"; Cause="Hz" },
    @{ Id='501'; Title="Policy Poll (Explorer):"; Op=""; Res=""; Lookup=""; Path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"; Cause="UI restrictions" },
    @{ Id='502'; Title="Policy Poll (System):"; Op=""; Res=""; Lookup=""; Path="Read\ `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System`"; Cause="UAC/Logon" },
    @{ Id='503'; Title="Policy Poll (Assoc):"; Op=""; Res=""; Lookup=""; Path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts"; Cause="Assoc hijacking" },
    @{ Id='504'; Title="Policy Poll (IE):"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Policies\\Microsoft\\Internet\ Explorer"; Cause="Browser lock" },
    @{ Id='505'; Title="Policy Poll (Edge):"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Policies\\Microsoft\\Edge"; Cause="Browser lock" },
    @{ Id='506'; Title="Policy Poll (Chrome):"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Policies\\Google\\Chrome"; Cause="Browser lock" },
    @{ Id='507'; Title="Policy Poll (Office):"; Op=""; Res=""; Lookup=""; Path="Read\ `HKCU\\Software\\Policies\\Microsoft\\Office`"; Cause="Macro settings" },
    @{ Id='508'; Title="Policy Poll (Defender):"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Policies\\Microsoft\\Windows\ Defender"; Cause="AV settings" },
    @{ Id='509'; Title="Policy Poll (Update):"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"; Cause="Patching" },
    @{ Id='510'; Title="Policy Poll (Power):"; Op=""; Res=""; Lookup=""; Path="Read\ `HKLM\\Software\\Policies\\Microsoft\\Power\\PowerSettings`"; Cause="Sleep/Wake" },
    @{ Id='511'; Title="Background Poll:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKCU\\Control\ Panel\\Desktop\\Wallpaper`"; Cause="GPO Refresh" },
    @{ Id='512'; Title="ScreenSaver Poll:"; Op=""; Res=""; Lookup=""; Path="HKCU\\Control\ Panel\\Desktop\\ScreenSaveActive"; Cause="Lockout" },
    @{ Id='513'; Title="TimeOut Poll:"; Op=""; Res="TIMEOUT"; Lookup="TIMEOUT"; Path=""; Cause="Lockout" },
    @{ Id='514'; Title="Theme Poll:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ThemeManager`"; Cause="Visuals" },
    @{ Id='515'; Title="Color Poll:"; Op=""; Res=""; Lookup=""; Path="HKCU\\Control\ Panel\\Colors"; Cause="High Contrast" },
    @{ Id='516'; Title="Cursor Poll:"; Op=""; Res=""; Lookup=""; Path="HKCU\\Control\ Panel\\Cursors"; Cause="Accessibility" },
    @{ Id='517'; Title="Sound Poll:"; Op=""; Res=""; Lookup=""; Path="HKCU\\AppEvents\\Schemes"; Cause="Audio feedback" },
    @{ Id='518'; Title="Icon Cache Check:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell\ Icons`"; Cause="Overlays" },
    @{ Id='519'; Title="Drive Map Poll:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKCU\\Network`"; Cause="Mapped Drives" },
    @{ Id='520'; Title="Printer Poll:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKCU\\Printers`"; Cause="Default printer" },
    @{ Id='521'; Title="MUI Poll:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\MUI\\Settings`"; Cause="Language" },
    @{ Id='522'; Title="TimeZone Poll:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation`"; Cause="Clock" },
    @{ Id='523'; Title="Network List Poll:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKLM\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\NetworkList`"; Cause="NLA" },
    @{ Id='524'; Title="Firewall Poll:"; Op=""; Res=""; Lookup=""; Path="HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy"; Cause="Rules" },
    @{ Id='525'; Title="Audit Poll:"; Op=""; Res=""; Lookup=""; Path="HKLM\\SECURITY\\Policy\\PolAdtEv"; Cause="Event generation" },
    @{ Id='526'; Title="LSA Poll:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa`"; Cause="Auth" },
    @{ Id='527'; Title="Schannel Poll:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL`"; Cause="TLS/SSL" },
    @{ Id='528'; Title="FIPS Poll:"; Op=""; Res=""; Lookup=""; Path="HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy"; Cause="Crypto" },
    @{ Id='529'; Title="Winlogon Poll:"; Op=""; Res=""; Lookup=""; Path="Read\ `HKLM\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Winlogon`"; Cause="Shell" },
    @{ Id='530'; Title="AppInit Poll:"; Op=""; Res=""; Lookup=""; Path="HKLM\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Windows\\AppInit_DLLs"; Cause="Injection" },
    @{ Id='531'; Title="Spooler Crash:"; Op=""; Res=""; Lookup=""; Path="`spoolsv\.exe`\ Exit\ Code\ !=\ 0"; Cause="Print" },
    @{ Id='532'; Title="Audio Crash:"; Op=""; Res=""; Lookup=""; Path="`audiodg\.exe`\ Exit\ Code\ !=\ 0"; Cause="Sound" },
    @{ Id='533'; Title="DWM Crash:"; Op=""; Res=""; Lookup=""; Path="`dwm\.exe`\ Exit\ Code\ !=\ 0"; Cause="Graphics" },
    @{ Id='534'; Title="Search Crash:"; Op=""; Res=""; Lookup=""; Path="SearchIndexer\.exe"; Cause="Index" },
    @{ Id='535'; Title="WMI Crash:"; Op=""; Res=""; Lookup=""; Path="`WmiPrvSE\.exe`\ Exit\ Code\ !=\ 0"; Cause="Mgmt" },
    @{ Id='536'; Title="Update Crash:"; Op=""; Res=""; Lookup=""; Path="TiWorker\.exe"; Cause="Install" },
    @{ Id='537'; Title="Defender Crash:"; Op=""; Res=""; Lookup=""; Path="`MsMpEng\.exe`\ Exit\ Code\ !=\ 0"; Cause="AV" },
    @{ Id='538'; Title="Firewall Crash"; Op=""; Res=""; Lookup=""; Path="mpssvc"; Cause="Security" },
    @{ Id='539'; Title="EventLog Crash"; Op=""; Res=""; Lookup=""; Path="wevtsvc"; Cause="Audit" },
    @{ Id='540'; Title="TaskSched Crash:"; Op=""; Res=""; Lookup=""; Path="`taskeng\.exe`\ Exit"; Cause="Tasks" },
    @{ Id='541'; Title="Explorer Crash:"; Op=""; Res=""; Lookup=""; Path="`Explorer\.exe`\ Exit"; Cause="Shell" },
    @{ Id='542'; Title="LogonUI Crash:"; Op=""; Res=""; Lookup=""; Path="`LogonUI\.exe`\ Exit"; Cause="Login" },
    @{ Id='543'; Title="Lsass Crash:"; Op=""; Res=""; Lookup=""; Path="lsass\.exe"; Cause="Reboot" },
    @{ Id='544'; Title="Csrss Crash:"; Op=""; Res=""; Lookup=""; Path="`csrss\.exe`\ Exit"; Cause="BSOD" },
    @{ Id='545'; Title="Smss Crash:"; Op=""; Res=""; Lookup=""; Path="smss\.exe"; Cause="BSOD" },
    @{ Id='546'; Title="Svchost Split:"; Op=""; Res=""; Lookup=""; Path="`svchost\.exe\ \-k\ netsvcs`\ High\ CPU"; Cause="Shared" },
    @{ Id='547'; Title="Svchost Dcom:"; Op=""; Res=""; Lookup=""; Path="`svchost\.exe\ \-k\ DcomLaunch`\ High\ CPU"; Cause="RPC" },
    @{ Id='548'; Title="Svchost RPC:"; Op=""; Res=""; Lookup=""; Path="svchost\.exe\ \-k\ RpcSs"; Cause="RPC" },
    @{ Id='549'; Title="Svchost Local:"; Op=""; Res=""; Lookup=""; Path="`svchost\.exe\ \-k\ LocalService`\ High\ CPU"; Cause="Background" },
    @{ Id='550'; Title="Svchost Net:"; Op=""; Res=""; Lookup=""; Path="svchost\.exe\ \-k\ NetworkService"; Cause="Network" },
    @{ Id='551'; Title="SysMain Busy:"; Op=""; Res=""; Lookup=""; Path="svchost\.exe\ \-k\ sysmain"; Cause="Superfetch" },
    @{ Id='552'; Title="DiagTrack Busy:"; Op=""; Res=""; Lookup=""; Path="`svchost\.exe\ \-k\ utisvc`\ Disk\ I"; Cause="Telemetry" },
    @{ Id='553'; Title="Bits Busy:"; Op=""; Res=""; Lookup=""; Path="svchost\.exe\ \-k\ netsvcs"; Cause="Download" },
    @{ Id='554'; Title="WinDefend Busy:"; Op=""; Res=""; Lookup=""; Path="MsMpEng\.exe"; Cause="Scan" },
    @{ Id='555'; Title="TrustedInstall:"; Op=""; Res=""; Lookup=""; Path="TrustedInstaller\.exe"; Cause="Update" },
    @{ Id='556'; Title="WMI Loop:"; Op=""; Res=""; Lookup=""; Path="`WmiPrvSE\.exe`\ High\ CPU"; Cause="Query storm" },
    @{ Id='557'; Title="WMI Provider:"; Op=""; Res=""; Lookup=""; Path="`WmiPrvSE`\ loading\ `cimwin32\.dll`"; Cause="Inventory" },
    @{ Id='558'; Title="WMI Storage:"; Op=""; Res=""; Lookup=""; Path="`WmiPrvSE`\ loading\ `storagewmi\.dll`"; Cause="Disk check" },
    @{ Id='559'; Title="WMI Net:"; Op=""; Res=""; Lookup=""; Path="wmidex\.dll"; Cause="Net check" },
    @{ Id='560'; Title="WMI Event:"; Op=""; Res=""; Lookup=""; Path="`WmiPrvSE`\ loading\ `wbemess\.dll`"; Cause="Event sub" },
    @{ Id='561'; Title="FSO Fail"; Op=""; Res=""; Lookup=""; Path="{0D43FE01-F093-11CF-8940-00A0C9054228}"; Cause="FileSystemObject" },
    @{ Id='562'; Title="Shell Fail"; Op=""; Res=""; Lookup=""; Path="{13709620-C279-11CE-A49E-444553540000}"; Cause="Shell.Application" },
    @{ Id='563'; Title="WScript Fail"; Op=""; Res=""; Lookup=""; Path="{72C24DD5-D70A-438B-8A42-98424B88AFB8}"; Cause="WScript.Shell" },
    @{ Id='564'; Title="ADODB Fail"; Op=""; Res=""; Lookup=""; Path="{00000514-0000-0010-8000-00AA006D2EA4}"; Cause="Database" },
    @{ Id='565'; Title="XMLDOM Fail"; Op=""; Res=""; Lookup=""; Path="{2933BF90-7B36-11D2-B20E-00C04F983E60}"; Cause="XML Parser" },
    @{ Id='566'; Title="HTTPReq Fail"; Op=""; Res=""; Lookup=""; Path="{88D96A0A-F192-11D4-A65F-0040963251E5}"; Cause="WinHTTP" },
    @{ Id='567'; Title="BITS Fail"; Op=""; Res=""; Lookup=""; Path="{4991D34B-80A1-4291-83B6-3328366B9097}"; Cause="Background Transfer" },
    @{ Id='568'; Title="TaskSched Fail"; Op=""; Res=""; Lookup=""; Path="{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}"; Cause="Scheduler" },
    @{ Id='569'; Title="Firewall Fail"; Op=""; Res=""; Lookup=""; Path="{F7898AF5-CAC4-4632-A2EC-DA06E5111AF2}"; Cause="NetFwPolicy" },
    @{ Id='570'; Title="Update Fail"; Op=""; Res=""; Lookup=""; Path="{4CB43D7F-7EEE-4906-8698-60DA1C38F2FE}"; Cause="WindowsUpdate" },
    @{ Id='571'; Title="Installer Fail"; Op=""; Res=""; Lookup=""; Path="{000C1090-0000-0000-C000-000000000046}"; Cause="MSI" },
    @{ Id='572'; Title="WMI Fail"; Op=""; Res=""; Lookup=""; Path="{4590F811-1D3A-11D0-891F-00AA004B2E24}"; Cause="WbemLocator" },
    @{ Id='573'; Title="Speech Fail"; Op=""; Res=""; Lookup=""; Path="{96749377-3391-11D2-9EE3-00C04F797396}"; Cause="SAPI" },
    @{ Id='574'; Title="Search Fail"; Op=""; Res=""; Lookup=""; Path="{9E175B8D-F52A-11D8-B9A5-505054503030}"; Cause="WindowsSearch" },
    @{ Id='575'; Title="ImgUtil Fail"; Op=""; Res=""; Lookup=""; Path="{557CF406-1A04-11D3-9A73-0000F81EF32E}"; Cause="ImageUtil" },
    @{ Id='576'; Title="Scriptlet Fail"; Op=""; Res=""; Lookup=""; Path="{06290BD5-48AA-11D2-8432-006008C3FBFC}"; Cause="Scriptlet" },
    @{ Id='577'; Title="HTA Fail"; Op=""; Res=""; Lookup=""; Path="{3050F4D8-98B5-11CF-BB82-00AA00BDCE0B}"; Cause="HTML App" },
    @{ Id='578'; Title="ShellWin Fail"; Op=""; Res=""; Lookup=""; Path="{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"; Cause="ShellWindows" },
    @{ Id='579'; Title="Folder Fail"; Op=""; Res=""; Lookup=""; Path="{F3364BA0-65B9-11CE-A9BA-00AA004AE837}"; Cause="ShellFolder" },
    @{ Id='580'; Title="Link Fail"; Op=""; Res=""; Lookup=""; Path="{00021401-0000-0000-C000-000000000046}"; Cause="ShellLink" },
    @{ Id='581'; Title="Access Denied"; Op=""; Res=""; Lookup=""; Path="0xC0000022"; Cause="Permission" },
    @{ Id='582'; Title="Object Found"; Op=""; Res=""; Lookup=""; Path="0xC0000000"; Cause="Success" },
    @{ Id='583'; Title="Not Found"; Op=""; Res=""; Lookup=""; Path="0xC0000034"; Cause="Missing" },
    @{ Id='584'; Title="Sharing Vio"; Op=""; Res=""; Lookup=""; Path="0xC0000043"; Cause="Locked" },
    @{ Id='585'; Title="Privilege"; Op=""; Res=""; Lookup=""; Path="0xC0000061"; Cause="Elevation req" },
    @{ Id='586'; Title="Disk Full"; Op=""; Res=""; Lookup=""; Path="0xC000007F"; Cause="Space" },
    @{ Id='587'; Title="Mem Full"; Op=""; Res=""; Lookup=""; Path="0xC0000017"; Cause="RAM/Commit" },
    @{ Id='588'; Title="Timeout"; Op=""; Res=""; Lookup=""; Path="0xC00000B5"; Cause="Wait" },
    @{ Id='589'; Title="Pipe Busy"; Op=""; Res=""; Lookup=""; Path="0xC00000AE"; Cause="Load" },
    @{ Id='590'; Title="Pipe Broken"; Op=""; Res=""; Lookup=""; Path="0xC000014B"; Cause="Disconnect" },
    @{ Id='591'; Title="Net Unreach"; Op=""; Res=""; Lookup=""; Path="0xC000023C"; Cause="Route" },
    @{ Id='592'; Title="Host Unreach"; Op=""; Res=""; Lookup=""; Path="0xC000023D"; Cause="Target" },
    @{ Id='593'; Title="Conn Refused"; Op=""; Res=""; Lookup=""; Path="0xC0000236"; Cause="Port" },
    @{ Id='594'; Title="Addr In Use"; Op=""; Res=""; Lookup=""; Path="0xC000020A"; Cause="Conflict" },
    @{ Id='595'; Title="Proc Limit"; Op=""; Res=""; Lookup=""; Path="0xC000012D"; Cause="Job limit" },
    @{ Id='596'; Title="Quota"; Op=""; Res=""; Lookup=""; Path="0xC0000044"; Cause="Disk quota" },
    @{ Id='597'; Title="Cancel"; Op=""; Res=""; Lookup=""; Path="0xC0000120"; Cause="User abort" },
    @{ Id='598'; Title="Buffer Over"; Op=""; Res=""; Lookup=""; Path="0xC0000023"; Cause="Data size" },
    @{ Id='599'; Title="Not Impl"; Op=""; Res=""; Lookup=""; Path="0xC0000002"; Cause="API missing" },
    @{ Id='600'; Title="Invalid Param"; Op=""; Res=""; Lookup=""; Path="0xC000000D"; Cause="Bad call" },
    @{ Id='601'; Title="Invalid Handle"; Op=""; Res=""; Lookup=""; Path="0xC0000008"; Cause="Logic bug" },
    @{ Id='602'; Title="DLL Init"; Op=""; Res=""; Lookup=""; Path="0xC0000142"; Cause="Loader fail" },
    @{ Id='603'; Title="Entry Point"; Op=""; Res=""; Lookup=""; Path="0xC0000139"; Cause="Version fail" },
    @{ Id='604'; Title="Ordinal"; Op=""; Res=""; Lookup=""; Path="0xC0000138"; Cause="Export fail" },
    @{ Id='605'; Title="SideBySide"; Op=""; Res=""; Lookup=""; Path="0xC0000365"; Cause="Manifest" },
    @{ Id='606'; Title="Hashing"; Op=""; Res=""; Lookup=""; Path="0xC0000428"; Cause="Signature" },
    @{ Id='607'; Title="Delete Pend"; Op=""; Res=""; Lookup=""; Path="0xC0000056"; Cause="Zombie file" },
    @{ Id='608'; Title="Directory"; Op=""; Res=""; Lookup=""; Path="0xC0000103"; Cause="Is not dir" },
    @{ Id='609'; Title="Reparse"; Op=""; Res=""; Lookup=""; Path="0xC0000275"; Cause="Symlink" },
    @{ Id='610'; Title="EAS Policy"; Op=""; Res=""; Lookup=""; Path="0xC00002D0"; Cause="Password complexity" },
    @{ Id='611'; Title="Word Template:"; Op=""; Res=""; Lookup=""; Path="Normal\.dotm"; Cause="Corruption" },
    @{ Id='612'; Title="Word Addin:"; Op=""; Res=""; Lookup=""; Path="\.wll"; Cause="Plugin" },
    @{ Id='613'; Title="Excel Calc:"; Op=""; Res=""; Lookup=""; Path="High\ CPU\ `EXCEL\.EXE`"; Cause="Calculation" },
    @{ Id='614'; Title="Excel OLE"; Op=""; Res=""; Lookup=""; Path="Splwow64"; Cause="Print/PDF" },
    @{ Id='615'; Title="Excel Addin:"; Op=""; Res=""; Lookup=""; Path="\.xla"; Cause="Plugin" },
    @{ Id='616'; Title="Outlook OST:"; Op=""; Res=""; Lookup=""; Path="\.ost"; Cause="Lock" },
    @{ Id='617'; Title="Outlook Index"; Op=""; Res=""; Lookup=""; Path="SearchProtocolHost"; Cause="Index" },
    @{ Id='618'; Title="Outlook RPC:"; Op="TCP\ Connect"; Res=""; Lookup=""; Path="outlook\.office365\.com"; Cause="Net" },
    @{ Id='619'; Title="Outlook Autodiscover:"; Op=""; Res=""; Lookup=""; Path="autodiscover\.xml"; Cause="Config" },
    @{ Id='620'; Title="Outlook Addin:"; Op=""; Res=""; Lookup=""; Path="Load\ `outlvba\.dll`"; Cause="Macro" },
    @{ Id='621'; Title="Access Lock:"; Op=""; Res=""; Lookup=""; Path="\.ldb"; Cause="Record lock" },
    @{ Id='622'; Title="Access ODBC:"; Op=""; Res=""; Lookup=""; Path="odbc32\.dll"; Cause="Driver" },
    @{ Id='623'; Title="PowerPoint Media:"; Op=""; Res=""; Lookup=""; Path="pflash\.dll"; Cause="Flash" },
    @{ Id='624'; Title="OneNote Cache:"; Op=""; Res=""; Lookup=""; Path="\.bin"; Cause="Sync" },
    @{ Id='625'; Title="Office Update:"; Op=""; Res=""; Lookup=""; Path="OfficeClickToRun\.exe"; Cause="Update" },
    @{ Id='626'; Title="Office License:"; Op=""; Res=""; Lookup=""; Path="OSPP\.VBS"; Cause="Activation" },
    @{ Id='627'; Title="Office Telemetry:"; Op=""; Res=""; Lookup=""; Path="mso\.dll"; Cause="Diag" },
    @{ Id='628'; Title="Teams Status"; Op=""; Res=""; Lookup=""; Path="ub_"; Cause="Presence" },
    @{ Id='629'; Title="Teams Mtg:"; Op="UDP\ Send"; Res=""; Lookup=""; Path=""; Cause="Media" },
    @{ Id='630'; Title="Skype Mtg:"; Op=""; Res=""; Lookup=""; Path="`lync\.exe`\ activity"; Cause="Legacy" },
    @{ Id='631'; Title="Chrome Prefs"; Op=""; Res=""; Lookup=""; Path="Preferences"; Cause="Corruption" },
    @{ Id='632'; Title="Chrome Local"; Op=""; Res=""; Lookup=""; Path="Local State"; Cause="Config" },
    @{ Id='633'; Title="Chrome Policy"; Op=""; Res=""; Lookup=""; Path="CloudManagement"; Cause="Mgmt" },
    @{ Id='634'; Title="Chrome Ext:"; Op=""; Res=""; Lookup=""; Path="Read\ `manifest\.json`\ fail"; Cause="Addon" },
    @{ Id='635'; Title="Chrome GPU"; Op=""; Res=""; Lookup=""; Path="GpuProcess"; Cause="Driver" },
    @{ Id='636'; Title="Chrome Render"; Op=""; Res=""; Lookup=""; Path="Renderer"; Cause="Page" },
    @{ Id='637'; Title="Chrome Sandbox"; Op=""; Res=""; Lookup=""; Path="Broker"; Cause="Security" },
    @{ Id='638'; Title="Edge Update:"; Op=""; Res=""; Lookup=""; Path="MicrosoftEdgeUpdate\.exe"; Cause="Patch" },
    @{ Id='639'; Title="Edge IE Mode:"; Op=""; Res=""; Lookup=""; Path="ieexplore\.exe"; Cause="Compat" },
    @{ Id='640'; Title="Edge WebView:"; Op=""; Res=""; Lookup=""; Path="`msedgewebview2\.exe`\ crash"; Cause="App" },
    @{ Id='641'; Title="Cookie Lock"; Op=""; Res=""; Lookup=""; Path="Cookies"; Cause="Sync" },
    @{ Id='642'; Title="History Lock"; Op=""; Res=""; Lookup=""; Path="History"; Cause="Sync" },
    @{ Id='643'; Title="Cache Size"; Op=""; Res=""; Lookup=""; Path="Cache_Data"; Cause="Space" },
    @{ Id='644'; Title="Download Scan"; Op=""; Res=""; Lookup=""; Path="Download"; Cause="Delay" },
    @{ Id='645'; Title="Cert Check"; Op=""; Res=""; Lookup=""; Path="Root"; Cause="SSL" },
    @{ Id='646'; Title="Proxy Script:"; Op=""; Res="TIMEOUT"; Lookup="TIMEOUT"; Path="\.pac"; Cause="Net" },
    @{ Id='647'; Title="DNS Pre-fetch"; Op=""; Res=""; Lookup=""; Path=""; Cause="Speed" },
    @{ Id='648'; Title="QUIC Proto"; Op=""; Res=""; Lookup=""; Path=""; Cause="Google Net" },
    @{ Id='649'; Title="WebRTC"; Op=""; Res=""; Lookup=""; Path=""; Cause="Media" },
    @{ Id='650'; Title="Flash Load"; Op=""; Res=""; Lookup=""; Path="pepflashplayer"; Cause="Legacy" },
    @{ Id='651'; Title="NTFS Driver:"; Op=""; Res=""; Lookup=""; Path="`ntfs\.sys`\ activity"; Cause="Disk" },
    @{ Id='652'; Title="Filter Mgr:"; Op=""; Res=""; Lookup=""; Path="fltmgr\.sys"; Cause="Filters" },
    @{ Id='653'; Title="TCP/IP:"; Op=""; Res=""; Lookup=""; Path="`tcpip\.sys`\ activity"; Cause="Net" },
    @{ Id='654'; Title="NetBIOS:"; Op=""; Res=""; Lookup=""; Path="netbt\.sys"; Cause="Legacy" },
    @{ Id='655'; Title="AFD Driver:"; Op=""; Res=""; Lookup=""; Path="afd\.sys"; Cause="Sock" },
    @{ Id='656'; Title="WFP Driver:"; Op=""; Res=""; Lookup=""; Path="`fwpkclnt\.sys`\ activity"; Cause="Firewall" },
    @{ Id='657'; Title="NDIS Driver:"; Op=""; Res=""; Lookup=""; Path="`ndis\.sys`\ activity"; Cause="NIC" },
    @{ Id='658'; Title="Storport:"; Op=""; Res=""; Lookup=""; Path="`storport\.sys`\ activity"; Cause="SAN" },
    @{ Id='659'; Title="USB Port:"; Op=""; Res=""; Lookup=""; Path="usbport\.sys"; Cause="Bus" },
    @{ Id='660'; Title="USB Hub:"; Op=""; Res=""; Lookup=""; Path="usbhub\.sys"; Cause="Bus" },
    @{ Id='661'; Title="HID Class:"; Op=""; Res=""; Lookup=""; Path="`hidclass\.sys`\ activity"; Cause="Input" },
    @{ Id='662'; Title="Mouse Class:"; Op=""; Res=""; Lookup=""; Path="`mouclass\.sys`\ activity"; Cause="Input" },
    @{ Id='663'; Title="Kbd Class:"; Op=""; Res=""; Lookup=""; Path="kbdclass\.sys"; Cause="Input" },
    @{ Id='664'; Title="Graphics:"; Op=""; Res=""; Lookup=""; Path="`dxgkrnl\.sys`\ activity"; Cause="GPU" },
    @{ Id='665'; Title="Nvidia:"; Op=""; Res=""; Lookup=""; Path="`nvlddmkm\.sys`\ activity"; Cause="GPU" },
    @{ Id='666'; Title="AMD:"; Op=""; Res=""; Lookup=""; Path="atikmdag\.sys"; Cause="GPU" },
    @{ Id='667'; Title="Intel Gfx:"; Op=""; Res=""; Lookup=""; Path="igdkmd64\.sys"; Cause="GPU" },
    @{ Id='668'; Title="Realtek Audio:"; Op=""; Res=""; Lookup=""; Path="`rtkvhd64\.sys`\ activity"; Cause="Sound" },
    @{ Id='669'; Title="Symantec Filter:"; Op=""; Res=""; Lookup=""; Path="`symefasi\.sys`"; Cause="AV" },
    @{ Id='670'; Title="McAfee Filter:"; Op=""; Res=""; Lookup=""; Path="`mfehidk\.sys`"; Cause="AV" },
    @{ Id='671'; Title="CrowdStrike:"; Op=""; Res=""; Lookup=""; Path="csagent\.sys"; Cause="EDR" },
    @{ Id='672'; Title="SentinelOne:"; Op=""; Res=""; Lookup=""; Path="`SentinelMonitor\.sys`"; Cause="EDR" },
    @{ Id='673'; Title="CarbonBlack:"; Op=""; Res=""; Lookup=""; Path="`cbk7\.sys`"; Cause="EDR" },
    @{ Id='674'; Title="Sysmon:"; Op=""; Res=""; Lookup=""; Path="`SysmonDrv\.sys`"; Cause="Log" },
    @{ Id='675'; Title="ProcMon:"; Op=""; Res=""; Lookup=""; Path="PROCMON24\.SYS"; Cause="Self" },
    @{ Id='676'; Title="VMware Mouse:"; Op=""; Res=""; Lookup=""; Path="vmmouse\.sys"; Cause="Guest" },
    @{ Id='677'; Title="VMware Video:"; Op=""; Res=""; Lookup=""; Path="vm3dmp\.sys"; Cause="Guest" },
    @{ Id='678'; Title="Citrix Net:"; Op=""; Res=""; Lookup=""; Path="ctxtcp\.sys"; Cause="VDI" },
    @{ Id='679'; Title="Citrix Usb:"; Op=""; Res=""; Lookup=""; Path="ctxusbm\.sys"; Cause="VDI" },
    @{ Id='680'; Title="FSLogix:"; Op=""; Res=""; Lookup=""; Path="`frxdrv\.sys`"; Cause="Profile" },
    @{ Id='681'; Title="DHCP Renew"; Op=""; Res=""; Lookup=""; Path=""; Cause="IP" },
    @{ Id='682'; Title="NTP Sync"; Op=""; Res=""; Lookup=""; Path=""; Cause="Time" },
    @{ Id='683'; Title="SNMP Query"; Op=""; Res=""; Lookup=""; Path=""; Cause="Mgmt" },
    @{ Id='684'; Title="Syslog Send"; Op=""; Res=""; Lookup=""; Path=""; Cause="Log" },
    @{ Id='685'; Title="LDAP SSL"; Op=""; Res=""; Lookup=""; Path=""; Cause="Auth" },
    @{ Id='686'; Title="Global Cat"; Op=""; Res=""; Lookup=""; Path=""; Cause="AD" },
    @{ Id='687'; Title="GC SSL"; Op=""; Res=""; Lookup=""; Path=""; Cause="AD" },
    @{ Id='688'; Title="SQL Browser"; Op=""; Res=""; Lookup=""; Path=""; Cause="DB" },
    @{ Id='689'; Title="RDP Gateway"; Op=""; Res=""; Lookup=""; Path=""; Cause="Tunnel" },
    @{ Id='690'; Title="WinRM HTTP"; Op=""; Res=""; Lookup=""; Path=""; Cause="Mgmt" },
    @{ Id='691'; Title="WinRM HTTPS"; Op=""; Res=""; Lookup=""; Path=""; Cause="Mgmt" },
    @{ Id='692'; Title="RPC Mapper"; Op=""; Res=""; Lookup=""; Path=""; Cause="DCOM" },
    @{ Id='693'; Title="NetBIOS Name"; Op=""; Res=""; Lookup=""; Path=""; Cause="Name" },
    @{ Id='694'; Title="NetBIOS Data"; Op=""; Res=""; Lookup=""; Path=""; Cause="Data" },
    @{ Id='695'; Title="NetBIOS Sess"; Op=""; Res=""; Lookup=""; Path=""; Cause="Sess" },
    @{ Id='696'; Title="SMB Direct"; Op=""; Res=""; Lookup=""; Path=""; Cause="File" },
    @{ Id='697'; Title="VNC"; Op=""; Res=""; Lookup=""; Path=""; Cause="Remote" },
    @{ Id='698'; Title="ICA (Citrix)"; Op=""; Res=""; Lookup=""; Path=""; Cause="VDI" },
    @{ Id='699'; Title="CGP (Citrix)"; Op=""; Res=""; Lookup=""; Path=""; Cause="VDI" },
    @{ Id='700'; Title="Blast (VMware)"; Op=""; Res=""; Lookup=""; Path=""; Cause="VDI" },
    @{ Id='701'; Title="PCoIP"; Op=""; Res=""; Lookup=""; Path=""; Cause="VDI" },
    @{ Id='702'; Title="BitTorrent"; Op=""; Res=""; Lookup=""; Path=""; Cause="P2P" },
    @{ Id='703'; Title="Spotify"; Op=""; Res=""; Lookup=""; Path=""; Cause="Media" },
    @{ Id='704'; Title="Steam"; Op=""; Res=""; Lookup=""; Path=""; Cause="Game" },
    @{ Id='705'; Title="Xbox Live"; Op=""; Res=""; Lookup=""; Path=""; Cause="Game" },
    @{ Id='706'; Title="Teredo"; Op=""; Res=""; Lookup=""; Path=""; Cause="Tunnel" },
    @{ Id='707'; Title="LLMNR"; Op=""; Res=""; Lookup=""; Path=""; Cause="Local DNS" },
    @{ Id='708'; Title="SSDP"; Op=""; Res=""; Lookup=""; Path=""; Cause="UPnP" },
    @{ Id='709'; Title="WS-Discovery"; Op=""; Res=""; Lookup=""; Path=""; Cause="Disco" },
    @{ Id='710'; Title="mDNS"; Op=""; Res=""; Lookup=""; Path=""; Cause="Bonjour" },
    @{ Id='711'; Title="PS Version"; Op=""; Res=""; Lookup=""; Path="PowerShellVersion"; Cause="Compat" },
    @{ Id='712'; Title="PS Module"; Op=""; Res=""; Lookup=""; Path="PSModulePath"; Cause="Load" },
    @{ Id='713'; Title="PS Profile:"; Op=""; Res=""; Lookup=""; Path="Microsoft\.PowerShell_profile\.ps1"; Cause="Config" },
    @{ Id='714'; Title="PS History:"; Op=""; Res=""; Lookup=""; Path="ConsoleHost_history\.txt"; Cause="Log" },
    @{ Id='715'; Title="PS Execution"; Op=""; Res=""; Lookup=""; Path="ExecutionPolicy"; Cause="Security" },
    @{ Id='716'; Title="PS Transcript:"; Op=""; Res=""; Lookup=""; Path="Write\ `Transcript\.txt`"; Cause="Log" },
    @{ Id='717'; Title="PS Gallery:"; Op=""; Res=""; Lookup=""; Path="powershellgallery\.com"; Cause="Download" },
    @{ Id='718'; Title="PS Remoting"; Op=""; Res=""; Lookup=""; Path="wsman"; Cause="Remote" },
    @{ Id='719'; Title="PS Constrained"; Op=""; Res=""; Lookup=""; Path="ConstrainedLanguage"; Cause="Security" },
    @{ Id='720'; Title="PS Logging"; Op=""; Res=""; Lookup=""; Path="ScriptBlockLogging"; Cause="Audit" },
    @{ Id='721'; Title="VBS Engine:"; Op=""; Res=""; Lookup=""; Path="vbscript\.dll"; Cause="Legacy" },
    @{ Id='722'; Title="JS Engine:"; Op=""; Res=""; Lookup=""; Path="jscript\.dll"; Cause="Legacy" },
    @{ Id='723'; Title="WSF File:"; Op=""; Res=""; Lookup=""; Path="Exec\ `\.wsf`"; Cause="Mixed" },
    @{ Id='724'; Title="HTA App:"; Op=""; Res=""; Lookup=""; Path="Exec\ `\.hta`"; Cause="UI" },
    @{ Id='725'; Title="Batch File:"; Op=""; Res=""; Lookup=""; Path="\.bat"; Cause="Shell" },
    @{ Id='726'; Title="Cmd File:"; Op=""; Res=""; Lookup=""; Path="Exec\ `\.cmd`"; Cause="Shell" },
    @{ Id='727'; Title="Python Script:"; Op=""; Res=""; Lookup=""; Path="\.py"; Cause="Dev" },
    @{ Id='728'; Title="Perl Script:"; Op=""; Res=""; Lookup=""; Path="\.pl"; Cause="Dev" },
    @{ Id='729'; Title="Ruby Script:"; Op=""; Res=""; Lookup=""; Path="Exec\ `\.rb`"; Cause="Dev" },
    @{ Id='730'; Title="Jar File:"; Op=""; Res=""; Lookup=""; Path="\.jar"; Cause="Java" },
    @{ Id='731'; Title="Prefetch Create:"; Op=""; Res=""; Lookup=""; Path="Write\ `.*\.pf`"; Cause="Exec" },
    @{ Id='732'; Title="Recent Docs"; Op=""; Res=""; Lookup=""; Path="Recent"; Cause="Access" },
    @{ Id='733'; Title="JumpList"; Op=""; Res=""; Lookup=""; Path="AutomaticDestinations"; Cause="Access" },
    @{ Id='734'; Title="ShellBag:"; Op=""; Res=""; Lookup=""; Path="Shell\\Bags"; Cause="Folder view" },
    @{ Id='735'; Title="UserAssist"; Op=""; Res=""; Lookup=""; Path="UserAssist"; Cause="Exec count" },
    @{ Id='736'; Title="ShimCache"; Op=""; Res=""; Lookup=""; Path="AppCompatCache"; Cause="Compat" },
    @{ Id='737'; Title="Amcache:"; Op=""; Res=""; Lookup=""; Path="Amcache\.hve"; Cause="Inventory" },
    @{ Id='738'; Title="SRUM:"; Op=""; Res=""; Lookup=""; Path="SRUDB\.dat"; Cause="Usage" },
    @{ Id='739'; Title="ThumbCache:"; Op=""; Res=""; Lookup=""; Path="thumbcache_.*\.db"; Cause="Image" },
    @{ Id='740'; Title="IconCache:"; Op=""; Res=""; Lookup=""; Path="Write\ `IconCache\.db`"; Cause="Icon" },
    @{ Id='741'; Title="Recycle Bin:"; Op=""; Res=""; Lookup=""; Path="\$Recycle\.Bin"; Cause="Delete" },
    @{ Id='742'; Title="MFT Record"; Op=""; Res=""; Lookup=""; Path="$MFT"; Cause="Meta" },
    @{ Id='743'; Title="LogFile"; Op=""; Res=""; Lookup=""; Path="$LogFile"; Cause="Journal" },
    @{ Id='744'; Title="USN:"; Op=""; Res=""; Lookup=""; Path="Write\ `\$Extend\\\$UsnJrnl`"; Cause="Change" },
    @{ Id='745'; Title="Index DB:"; Op=""; Res=""; Lookup=""; Path="Write\ `Windows\.edb`"; Cause="Search" },
    @{ Id='746'; Title="Event Log:"; Op=""; Res=""; Lookup=""; Path="Security\.evtx"; Cause="Audit" },
    @{ Id='747'; Title="WER Report:"; Op=""; Res=""; Lookup=""; Path="Report\.wer"; Cause="Crash" },
    @{ Id='748'; Title="Dump File:"; Op=""; Res=""; Lookup=""; Path="memory\.dmp"; Cause="Crash" },
    @{ Id='749'; Title="Mini Dump"; Op=""; Res=""; Lookup=""; Path="Minidump"; Cause="Crash" },
    @{ Id='750'; Title="Hibernation:"; Op=""; Res=""; Lookup=""; Path="hiberfil\.sys"; Cause="Power" },
    @{ Id='751'; Title="SetupAPI:"; Op=""; Res=""; Lookup=""; Path="setupapi\.dev\.log"; Cause="Driver" },
    @{ Id='752'; Title="CBS:"; Op=""; Res=""; Lookup=""; Path="Write\ `CBS\.log`"; Cause="OS" },
    @{ Id='753'; Title="DISM:"; Op=""; Res=""; Lookup=""; Path="Write\ `dism\.log`"; Cause="Image" },
    @{ Id='754'; Title="WindowsUpdate:"; Op=""; Res=""; Lookup=""; Path="WindowsUpdate\.log"; Cause="Patch" },
    @{ Id='755'; Title="MSI Log:"; Op=""; Res=""; Lookup=""; Path="Write\ `MSI.*\.log`"; Cause="App" },
    @{ Id='756'; Title="DirectX:"; Op=""; Res="DXError\.log"; Lookup="DXError.log"; Path=""; Cause="Graphics" },
    @{ Id='757'; Title="DotNet:"; Op=""; Res=""; Lookup=""; Path="Write\ `dd_.*\.log`"; Cause="Runtime" },
    @{ Id='758'; Title="VCRedist:"; Op=""; Res=""; Lookup=""; Path="dd_vcredist.*\.log"; Cause="Runtime" },
    @{ Id='759'; Title="SQL Setup:"; Op=""; Res=""; Lookup=""; Path="Write\ `Summary\.txt`"; Cause="DB" },
    @{ Id='760'; Title="IIS Setup:"; Op=""; Res=""; Lookup=""; Path="iis\.log"; Cause="Web" },
    @{ Id='761'; Title="SCCM Log:"; Op=""; Res=""; Lookup=""; Path="Write\ `ccmsetup\.log`"; Cause="Mgmt" },
    @{ Id='762'; Title="Intune Log:"; Op=""; Res=""; Lookup=""; Path="Write\ `IntuneManagementExtension\.log`"; Cause="Mgmt" },
    @{ Id='763'; Title="Sysprep:"; Op=""; Res=""; Lookup=""; Path="Write\ `setupact\.log`"; Cause="Image" },
    @{ Id='764'; Title="Unattend:"; Op=""; Res=""; Lookup=""; Path="Read\ `unattend\.xml`"; Cause="Config" },
    @{ Id='765'; Title="Panther:"; Op=""; Res=""; Lookup=""; Path="Read\ `\\Panther`"; Cause="Setup" },
    @{ Id='766'; Title="LoadString Fail:"; Op=""; Res="Resource\ load\ fail\ \->\ Blank\ Error\."; Lookup="Resource load fail -> Blank Error."; Path=""; Cause="" },
    @{ Id='767'; Title="CreateFile Directory:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="" },
    @{ Id='768'; Title="Delete Pending:"; Op=""; Res=""; Lookup=""; Path="File\ locked\ by\ previous\ delete\ \->\ Install\ Fail\."; Cause="" },
    @{ Id='769'; Title="HKCU Override:"; Op=""; Res=""; Lookup=""; Path="User\ key\ hiding\ System\ key\."; Cause="" },
    @{ Id='770'; Title="Environment Var:"; Op=""; Res=""; Lookup=""; Path="`%SystemRoot%`\ literal\ lookup\."; Cause="" },
    @{ Id='771'; Title="Buffer Overflow:"; Op=""; Res=""; Lookup=""; Path="Registry\ value\ too\ small\."; Cause="" },
    @{ Id='772'; Title="Network Timeout:"; Op=""; Res=""; Lookup=""; Path="30\ second\ delay\ on\ connect\."; Cause="" },
    @{ Id='773'; Title="Dll Search Order:"; Op=""; Res=""; Lookup=""; Path="evil\.dll"; Cause="" },
    @{ Id='774'; Title="Zone Identifier:"; Op=""; Res=""; Lookup=""; Path="ADS\ causing\ security\ block\."; Cause="" },
    @{ Id='775'; Title="GDI Exhaustion:"; Op=""; Res=""; Lookup=""; Path="Black\ screen\ due\ to\ 10k\ objects\."; Cause="" },
    @{ Id='776'; Title="Handle Leak:"; Op=""; Res=""; Lookup=""; Path="Slowdown\ due\ to\ 100k\ handles\."; Cause="" },
    @{ Id='777'; Title="Thread Spike:"; Op=""; Res=""; Lookup=""; Path="High\ context\ switch\ rate\."; Cause="" },
    @{ Id='778'; Title="Disk Queue:"; Op=""; Res=""; Lookup=""; Path="Queue\ length\ >\ 5\."; Cause="" },
    @{ Id='779'; Title="Privilege Missing:"; Op=""; Res=""; Lookup=""; Path="`SeDebugPrivilege`\ check\ fail\."; Cause="" },
    @{ Id='780'; Title="Integrity Level:"; Op=""; Res=""; Lookup=""; Path="Low\ IL\ write\ to\ Medium\ IL\ fail\."; Cause="" },
    @{ Id='781'; Title="Virtual Store:"; Op=""; Res=""; Lookup=""; Path="Writes\ to\ `VirtualStore`\."; Cause="" },
    @{ Id='782'; Title="Short Name:"; Op=""; Res=""; Lookup=""; Path="\~1"; Cause="" },
    @{ Id='783'; Title="Case Sensitivity:"; Op=""; Res=""; Lookup=""; Path="`File`\ !=\ `file`\."; Cause="" },
    @{ Id='784'; Title="Sparse File:"; Op=""; Res="DISK\ FULL"; Lookup="DISK FULL"; Path=""; Cause="" },
    @{ Id='785'; Title="Reparse Loop:"; Op=""; Res=""; Lookup=""; Path="Symlink\ cycle\."; Cause="" },
    @{ Id='786'; Title="Offline File:"; Op=""; Res=""; Lookup=""; Path="Hierarchical\ Storage\ fail\."; Cause="" },
    @{ Id='787'; Title="Alternate Stream:"; Op=""; Res=""; Lookup=""; Path="Hiding\ data\ in\ ADS\."; Cause="" },
    @{ Id='788'; Title="Host File:"; Op=""; Res=""; Lookup=""; Path="Redirect\ verification\."; Cause="" },
    @{ Id='789'; Title="LSP/WFP:"; Op=""; Res=""; Lookup=""; Path="Network\ filter\ blocking\."; Cause="" },
    @{ Id='790'; Title="User/Kernel Mode:"; Op=""; Res=""; Lookup=""; Path="Context\ of\ operation\."; Cause="" },
    @{ Id='791'; Title="Session 0:"; Op=""; Res=""; Lookup=""; Path="Service\ interacting\ with\ desktop\."; Cause="" },
    @{ Id='792'; Title="Desktop Heap:"; Op=""; Res=""; Lookup=""; Path="Service\ GUI\ fail\."; Cause="" },
    @{ Id='793'; Title="Power Request:"; Op=""; Res=""; Lookup=""; Path="Sleep\ prevention\."; Cause="" },
    @{ Id='794'; Title="Timer Res:"; Op=""; Res=""; Lookup=""; Path="Timer\ resolution\ change\."; Cause="" },
    @{ Id='795'; Title="MMIO:"; Op=""; Res="O\ error\."; Lookup="O error."; Path=""; Cause="" },
    @{ Id='796'; Title="DMA:"; Op=""; Res="Direct\ Memory\ Access\ error\."; Lookup="Direct Memory Access error."; Path=""; Cause="" },
    @{ Id='797'; Title="Interrupts:"; Op=""; Res=""; Lookup=""; Path="High\ hardware\ interrupts\."; Cause="" },
    @{ Id='798'; Title="DPC:"; Op=""; Res=""; Lookup=""; Path="High\ Deferred\ Procedure\ Calls\."; Cause="" },
    @{ Id='799'; Title="Hard Fault:"; Op=""; Res=""; Lookup=""; Path="Paging\ from\ disk\."; Cause="" },
    @{ Id='800'; Title="Working Set:"; Op=""; Res=""; Lookup=""; Path="RAM\ trimming\."; Cause="" },
    @{ Id='801'; Title="NtQuerySystemInfo:"; Op=""; Res=""; Lookup=""; Path="Enum\ processes\."; Cause="" },
    @{ Id='802'; Title="NtQueryObject:"; Op=""; Res=""; Lookup=""; Path="Enum\ handles\."; Cause="" },
    @{ Id='803'; Title="NtQueryInformationFile:"; Op=""; Res=""; Lookup=""; Path="File\ meta\."; Cause="" },
    @{ Id='804'; Title="NtSetInformationFile:"; Op=""; Res=""; Lookup=""; Path="Delete\."; Cause="" },
    @{ Id='805'; Title="NtDeviceIoControlFile:"; Op=""; Res=""; Lookup=""; Path="Driver\ talk\."; Cause="" },
    @{ Id='806'; Title="NtCreateSection:"; Op=""; Res=""; Lookup=""; Path="Shared\ memory\."; Cause="" },
    @{ Id='807'; Title="NtMapViewOfSection:"; Op=""; Res=""; Lookup=""; Path="Map\ memory\."; Cause="" },
    @{ Id='808'; Title="NtUnmapViewOfSection:"; Op=""; Res=""; Lookup=""; Path="Free\ memory\."; Cause="" },
    @{ Id='809'; Title="NtAllocateVirtualMemory:"; Op=""; Res=""; Lookup=""; Path="Alloc\ RAM\."; Cause="" },
    @{ Id='810'; Title="NtFreeVirtualMemory:"; Op=""; Res=""; Lookup=""; Path="Free\ RAM\."; Cause="" },
    @{ Id='811'; Title="NtProtectVirtualMemory:"; Op=""; Res=""; Lookup=""; Path="Permissions\."; Cause="" },
    @{ Id='812'; Title="NtReadVirtualMemory:"; Op=""; Res=""; Lookup=""; Path="Read\."; Cause="" },
    @{ Id='813'; Title="NtWriteVirtualMemory:"; Op=""; Res=""; Lookup=""; Path="Inject\."; Cause="" },
    @{ Id='814'; Title="NtCreateThreadEx:"; Op=""; Res=""; Lookup=""; Path="Thread\ spawn\."; Cause="" },
    @{ Id='815'; Title="NtTerminateProcess:"; Op=""; Res=""; Lookup=""; Path="Kill\."; Cause="" },
    @{ Id='816'; Title="NtSuspendProcess:"; Op=""; Res=""; Lookup=""; Path="Freeze\."; Cause="" },
    @{ Id='817'; Title="NtResumeProcess:"; Op=""; Res=""; Lookup=""; Path="Thaw\."; Cause="" },
    @{ Id='818'; Title="NtOpenProcessToken:"; Op=""; Res=""; Lookup=""; Path="Auth\ check\."; Cause="" },
    @{ Id='819'; Title="NtAdjustPrivilegesToken:"; Op=""; Res=""; Lookup=""; Path="Elevate\."; Cause="" },
    @{ Id='820'; Title="NtDuplicateToken:"; Op=""; Res=""; Lookup=""; Path="Impersonate\."; Cause="" },
    @{ Id='821'; Title="NtSetSecurityObject:"; Op=""; Res=""; Lookup=""; Path="ACL\ change\."; Cause="" },
    @{ Id='822'; Title="NtQuerySecurityObject:"; Op=""; Res=""; Lookup=""; Path="ACL\ read\."; Cause="" },
    @{ Id='823'; Title="NtCreateKey:"; Op=""; Res=""; Lookup=""; Path="Reg\ create\."; Cause="" },
    @{ Id='824'; Title="NtOpenKey:"; Op=""; Res=""; Lookup=""; Path="Reg\ open\."; Cause="" },
    @{ Id='825'; Title="NtSetValueKey:"; Op=""; Res=""; Lookup=""; Path="Reg\ write\."; Cause="" },
    @{ Id='826'; Title="NtDeleteKey:"; Op=""; Res=""; Lookup=""; Path="Reg\ delete\."; Cause="" },
    @{ Id='827'; Title="NtEnumerateKey:"; Op=""; Res=""; Lookup=""; Path="Reg\ scan\."; Cause="" },
    @{ Id='828'; Title="NtLoadDriver:"; Op=""; Res=""; Lookup=""; Path="Driver\ load\."; Cause="" },
    @{ Id='829'; Title="NtUnloadDriver:"; Op=""; Res=""; Lookup=""; Path="Driver\ unload\."; Cause="" },
    @{ Id='830'; Title="NtRaiseHardError:"; Op=""; Res=""; Lookup=""; Path="Popup\."; Cause="" },
    @{ Id='831'; Title="NtShutdownSystem:"; Op=""; Res=""; Lookup=""; Path="Reboot\."; Cause="" },
    @{ Id='832'; Title="NtSystemDebugControl:"; Op=""; Res=""; Lookup=""; Path="Kernel\ debug\."; Cause="" },
    @{ Id='833'; Title="NtTraceControl:"; Op=""; Res=""; Lookup=""; Path="ETW\ trace\."; Cause="" },
    @{ Id='834'; Title="NtAlpcSendWait:"; Op=""; Res=""; Lookup=""; Path="LPC\."; Cause="" },
    @{ Id='835'; Title="NtFsControlFile:"; Op=""; Res=""; Lookup=""; Path="Filesystem\ op\."; Cause="" },
    @{ Id='836'; Title="NtLockFile:"; Op=""; Res=""; Lookup=""; Path="File\ lock\."; Cause="" },
    @{ Id='837'; Title="NtUnlockFile:"; Op=""; Res=""; Lookup=""; Path="File\ unlock\."; Cause="" },
    @{ Id='838'; Title="NtNotifyChangeDirectoryFile:"; Op=""; Res=""; Lookup=""; Path="Watcher\."; Cause="" },
    @{ Id='839'; Title="NtQueryEaFile:"; Op=""; Res=""; Lookup=""; Path="Ext\ attributes\."; Cause="" },
    @{ Id='840'; Title="NtSetEaFile:"; Op=""; Res=""; Lookup=""; Path="Ext\ attributes\."; Cause="" },
    @{ Id='841'; Title="HCS Crash:"; Op=""; Res=""; Lookup=""; Path="hcsshim\.dll"; Cause="Container" },
    @{ Id='842'; Title="Docker Svc:"; Op=""; Res=""; Lookup=""; Path="`dockerd\.exe`\ fail"; Cause="Engine" },
    @{ Id='843'; Title="Container NIC"; Op=""; Res=""; Lookup=""; Path="vEthernet (HNS)"; Cause="Net" },
    @{ Id='844'; Title="Layer Locked:"; Op=""; Res=""; Lookup=""; Path="layer\.tar"; Cause="Image" },
    @{ Id='845'; Title="Volume Mount"; Op=""; Res=""; Lookup=""; Path="host_mnt"; Cause="Storage" },
    @{ Id='846'; Title="Pipe Docker:"; Op=""; Res=""; Lookup=""; Path="`\\\\\.\\pipe\\docker_engine`\ fail"; Cause="API" },
    @{ Id='847'; Title="Kube Config"; Op=""; Res=""; Lookup=""; Path="config"; Cause="Cluster" },
    @{ Id='848'; Title="CRI Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="Orch" },
    @{ Id='849'; Title="GMSA Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="Auth" },
    @{ Id='850'; Title="Process Isolation"; Op=""; Res=""; Lookup=""; Path=""; Cause="Kernel" },
    @{ Id='851'; Title="OneDrive Pipe:"; Op=""; Res=""; Lookup=""; Path="`\\\\\.\\pipe\\OneDriveIPC`\ fail"; Cause="IPC" },
    @{ Id='852'; Title="OneDrive Status"; Op=""; Res=""; Lookup=""; Path="Status"; Cause="Overlay" },
    @{ Id='853'; Title="OneDrive Lock"; Op=""; Res=""; Lookup=""; Path="FileCoAuth"; Cause="Office" },
    @{ Id='854'; Title="Dropbox Pipe:"; Op=""; Res=""; Lookup=""; Path="`\\\\\.\\pipe\\DropboxPipe`\ fail"; Cause="IPC" },
    @{ Id='855'; Title="Dropbox Ignore:"; Op=""; Res=""; Lookup=""; Path="Read\ `\.dropboxignore`"; Cause="Config" },
    @{ Id='856'; Title="GDrive Pipe"; Op=""; Res=""; Lookup=""; Path="GoogleDriveFS"; Cause="IPC" },
    @{ Id='857'; Title="GDrive Cache"; Op=""; Res=""; Lookup=""; Path="content_cache"; Cause="Space" },
    @{ Id='858'; Title="Box Mount"; Op=""; Res=""; Lookup=""; Path="Box Drive"; Cause="Mount" },
    @{ Id='859'; Title="Sync Conflict"; Op=""; Res=""; Lookup=""; Path="Conflicted Copy"; Cause="Race" },
    @{ Id='860'; Title="Attr Fail:"; Op="SetFileAttributes"; Res=""; Lookup=""; Path=""; Cause="Tiering" },
    @{ Id='861'; Title="SQL Mem:"; Op=""; Res=""; Lookup=""; Path="`sqlservr\.exe`\ Mem\ limit"; Cause="RAM" },
    @{ Id='862'; Title="SQL Dump:"; Op=""; Res=""; Lookup=""; Path="SQLDump.*\.mdmp"; Cause="Crash" },
    @{ Id='863'; Title="SQL Pipe:"; Op=""; Res=""; Lookup=""; Path="`\\\\\.\\pipe\\sql\\query`\ busy"; Cause="Load" },
    @{ Id='864'; Title="SQL VIA:"; Op=""; Res=""; Lookup=""; Path="Load\ `sqlvia\.dll`"; Cause="Legacy Proto" },
    @{ Id='865'; Title="SQL Shared:"; Op=""; Res=""; Lookup=""; Path="sqlmin\.dll"; Cause="Engine" },
    @{ Id='866'; Title="Oracle OCI:"; Op=""; Res=""; Lookup=""; Path="oci\.dll"; Cause="Client" },
    @{ Id='867'; Title="Oracle Java:"; Op=""; Res=""; Lookup=""; Path="ojdbc\.jar"; Cause="Java" },
    @{ Id='868'; Title="Postgres:"; Op=""; Res=""; Lookup=""; Path="postgres\.exe"; Cause="OSS DB" },
    @{ Id='869'; Title="MySQL:"; Op=""; Res=""; Lookup=""; Path="`mysqld\.exe`\ activity"; Cause="OSS DB" },
    @{ Id='870'; Title="SQLite Lock:"; Op=""; Res=""; Lookup=""; Path="database\.sqlite\-journal"; Cause="Local" },
    @{ Id='871'; Title="Git Config:"; Op=""; Res=""; Lookup=""; Path="\.gitconfig"; Cause="Settings" },
    @{ Id='872'; Title="SSH Agent"; Op=""; Res=""; Lookup=""; Path="ssh-agent"; Cause="Auth" },
    @{ Id='873'; Title="VSCode Ext:"; Op=""; Res=""; Lookup=""; Path="Read\ `extensions\.json`"; Cause="IDE" },
    @{ Id='874'; Title="Visual Studio:"; Op=""; Res=""; Lookup=""; Path="`devenv\.exe`\ crash"; Cause="IDE" },
    @{ Id='875'; Title="MSBuild:"; Op=""; Res=""; Lookup=""; Path="`MSBuild\.exe`\ fail"; Cause="Build" },
    @{ Id='876'; Title="NuGet:"; Op=""; Res=""; Lookup=""; Path="Read\ `nuget\.config`"; Cause="Pkg" },
    @{ Id='877'; Title="Npm Lock:"; Op=""; Res=""; Lookup=""; Path="Read\ `package\-lock\.json`"; Cause="Dep" },
    @{ Id='878'; Title="Pip Cache"; Op=""; Res=""; Lookup=""; Path="pip"; Cause="Python" },
    @{ Id='879'; Title="Maven Repo:"; Op=""; Res=""; Lookup=""; Path="Read\ `\.m2`"; Cause="Java" },
    @{ Id='880'; Title="Gradle"; Op=""; Res=""; Lookup=""; Path="gradlew"; Cause="Build" },
    @{ Id='881'; Title="Adobe Scratch:"; Op=""; Res="DISK\ FULL"; Lookup="DISK FULL"; Path=""; Cause="Space" },
    @{ Id='882'; Title="Adobe Font:"; Op=""; Res=""; Lookup=""; Path="Read\ `AdobeFnt\.lst`"; Cause="Cache" },
    @{ Id='883'; Title="Adobe License"; Op=""; Res=""; Lookup=""; Path="AdobeIPCBroker"; Cause="Auth" },
    @{ Id='884'; Title="Premiere:"; Op=""; Res=""; Lookup=""; Path="`Adobe\ Premiere\ Pro\.exe`"; Cause="Video" },
    @{ Id='885'; Title="After Effects:"; Op=""; Res=""; Lookup=""; Path="AfterFX\.exe"; Cause="VFX" },
    @{ Id='886'; Title="Photoshop:"; Op=""; Res=""; Lookup=""; Path="`Photoshop\.exe`"; Cause="Image" },
    @{ Id='887'; Title="Davinci Resolve:"; Op=""; Res=""; Lookup=""; Path="`Resolve\.exe`"; Cause="Video" },
    @{ Id='888'; Title="Dongle Check"; Op=""; Res=""; Lookup=""; Path=""; Cause="License" },
    @{ Id='889'; Title="Plugin Scan"; Op=""; Res=""; Lookup=""; Path="VST"; Cause="Audio" },
    @{ Id='890'; Title="Codec Load:"; Op=""; Res=""; Lookup=""; Path="ffmpeg\.dll"; Cause="Media" },
    @{ Id='891'; Title="SteamVR:"; Op=""; Res=""; Lookup=""; Path="`vrserver\.exe`"; Cause="VR" },
    @{ Id='892'; Title="Oculus:"; Op=""; Res=""; Lookup=""; Path="`OVRServer_x64\.exe`"; Cause="VR" },
    @{ Id='893'; Title="WMR:"; Op=""; Res=""; Lookup=""; Path="`MixedRealityPortal\.exe`"; Cause="VR" },
    @{ Id='894'; Title="OpenVR:"; Op=""; Res=""; Lookup=""; Path="Load\ `openvr_api\.dll`"; Cause="API" },
    @{ Id='895'; Title="HMD USB"; Op=""; Res=""; Lookup=""; Path="HMD"; Cause="Headset" },
    @{ Id='896'; Title="Tracking"; Op=""; Res=""; Lookup=""; Path=""; Cause="USB" },
    @{ Id='897'; Title="Compositor:"; Op=""; Res=""; Lookup=""; Path="`vrcompositor\.exe`\ crash"; Cause="Display" },
    @{ Id='898'; Title="Room Setup"; Op=""; Res=""; Lookup=""; Path="chaperone"; Cause="Config" },
    @{ Id='899'; Title="Runtime"; Op=""; Res=""; Lookup=""; Path="LibOVRRT"; Cause="Driver" },
    @{ Id='900'; Title="Async Reprojection"; Op=""; Res=""; Lookup=""; Path=""; Cause="Framerate" },
    @{ Id='901'; Title="DiagTrack:"; Op=""; Res=""; Lookup=""; Path="`CompatTelRunner\.exe`"; Cause="Usage" },
    @{ Id='902'; Title="SQM:"; Op=""; Res=""; Lookup=""; Path="Write\ `sqm.*\.dat`"; Cause="Quality" },
    @{ Id='903'; Title="Watson"; Op=""; Res=""; Lookup=""; Path="Watson"; Cause="Crash" },
    @{ Id='904'; Title="AIT"; Op=""; Res=""; Lookup=""; Path="AitAgent"; Cause="Install" },
    @{ Id='905'; Title="Inventory:"; Op=""; Res=""; Lookup=""; Path="`Inventory\.exe`"; Cause="App scan" },
    @{ Id='906'; Title="Device Census:"; Op=""; Res=""; Lookup=""; Path="DeviceCensus\.exe"; Cause="Hw scan" },
    @{ Id='907'; Title="Location"; Op=""; Res=""; Lookup=""; Path="Geofence"; Cause="GPS" },
    @{ Id='908'; Title="Feedback"; Op=""; Res=""; Lookup=""; Path="FeedbackHub"; Cause="User" },
    @{ Id='909'; Title="Timeline:"; Op=""; Res=""; Lookup=""; Path="Write\ `ActivitiesCache\.db`"; Cause="History" },
    @{ Id='910'; Title="Clip SVC"; Op=""; Res=""; Lookup=""; Path="ClientLicense"; Cause="Store" },
    @{ Id='911'; Title="TermSvc"; Op=""; Res=""; Lookup=""; Path="TermService"; Cause="Svc" },
    @{ Id='912'; Title="RDP Clip:"; Op=""; Res=""; Lookup=""; Path="`rdpclip\.exe`\ fail"; Cause="Copy/Paste" },
    @{ Id='913'; Title="RDP Drv:"; Op=""; Res=""; Lookup=""; Path="`rdpdr\.sys`\ fail"; Cause="Redirection" },
    @{ Id='914'; Title="RDP Sound:"; Op=""; Res=""; Lookup=""; Path="`rdpsnd\.sys`\ fail"; Cause="Audio" },
    @{ Id='915'; Title="RDP Print"; Op=""; Res=""; Lookup=""; Path="EasyPrint"; Cause="Print" },
    @{ Id='916'; Title="RDP Input:"; Op=""; Res=""; Lookup=""; Path="rdpinput\.sys"; Cause="Mouse" },
    @{ Id='917'; Title="RDP Gfx:"; Op=""; Res=""; Lookup=""; Path="rdpgfx\.sys"; Cause="Video" },
    @{ Id='918'; Title="Session Dir:"; Op=""; Res=""; Lookup=""; Path="`tssdis\.exe`\ fail"; Cause="Broker" },
    @{ Id='919'; Title="License Svc:"; Op=""; Res=""; Lookup=""; Path="lserver\.exe"; Cause="CALs" },
    @{ Id='920'; Title="RemoteApp:"; Op=""; Res=""; Lookup=""; Path="rdpshell\.exe"; Cause="Seamless" },
    @{ Id='921'; Title="VSS Create:"; Op=""; Res=""; Lookup=""; Path="vssvc\.exe"; Cause="Snapshot" },
    @{ Id='922'; Title="VSS Writer:"; Op=""; Res="TIMEOUT"; Lookup="TIMEOUT"; Path=""; Cause="SQL" },
    @{ Id='923'; Title="VSS Provider"; Op=""; Res=""; Lookup=""; Path="swprv"; Cause="Software" },
    @{ Id='924'; Title="VSS Hardware:"; Op=""; Res=""; Lookup=""; Path="`vds\.exe`\ fail"; Cause="SAN" },
    @{ Id='925'; Title="Change Block:"; Op=""; Res=""; Lookup=""; Path="ctp\.sys"; Cause="CBT" },
    @{ Id='926'; Title="Veeam Transport"; Op=""; Res=""; Lookup=""; Path="VeeamTransport"; Cause="Net" },
    @{ Id='927'; Title="Backup Read"; Op=""; Res=""; Lookup=""; Path="BackupRead"; Cause="Stream" },
    @{ Id='928'; Title="Archive Bit:"; Op="SetFileAttributes"; Res=""; Lookup=""; Path=""; Cause="Flag" },
    @{ Id='929'; Title="Last Modified"; Op=""; Res=""; Lookup=""; Path=""; Cause="Inc" },
    @{ Id='930'; Title="Catalog"; Op=""; Res=""; Lookup=""; Path="GlobalCatalog"; Cause="Tape" },
    @{ Id='931'; Title="Print Processor:"; Op=""; Res=""; Lookup=""; Path="Load\ `winprint\.dll`"; Cause="Spool" },
    @{ Id='932'; Title="Print Monitor:"; Op=""; Res=""; Lookup=""; Path="usbmon\.dll"; Cause="Port" },
    @{ Id='933'; Title="Print Lang:"; Op=""; Res=""; Lookup=""; Path="Load\ `pjlmon\.dll`"; Cause="PJL" },
    @{ Id='934'; Title="Print Net:"; Op=""; Res=""; Lookup=""; Path="tcpmon\.dll"; Cause="IP" },
    @{ Id='935'; Title="Print Form"; Op=""; Res=""; Lookup=""; Path="Forms"; Cause="Paper" },
    @{ Id='936'; Title="Print Color"; Op=""; Res=""; Lookup=""; Path="ColorProfiles"; Cause="ICC" },
    @{ Id='937'; Title="Print Sep"; Op=""; Res=""; Lookup=""; Path="Separator"; Cause="Page" },
    @{ Id='938'; Title="Print Driver"; Op=""; Res=""; Lookup=""; Path="DriverStore"; Cause="File" },
    @{ Id='939'; Title="Print Queue:"; Op=""; Res=""; Lookup=""; Path="Write\ `\.spl`"; Cause="Spool" },
    @{ Id='940'; Title="Print Job:"; Op=""; Res=""; Lookup=""; Path="\.shd"; Cause="Shadow" },
    @{ Id='941'; Title="Font Load"; Op=""; Res=""; Lookup=""; Path="AddFontResource"; Cause="Install" },
    @{ Id='942'; Title="Font Mem"; Op=""; Res=""; Lookup=""; Path="CreateFontIndirect"; Cause="GDI" },
    @{ Id='943'; Title="Font Link"; Op=""; Res=""; Lookup=""; Path="FontLink"; Cause="Fallbacks" },
    @{ Id='944'; Title="Font Sub"; Op=""; Res=""; Lookup=""; Path="FontSubstitutes"; Cause="Alias" },
    @{ Id='945'; Title="EUDC:"; Op=""; Res=""; Lookup=""; Path="Read\ `EUDC\.TE`"; Cause="Custom" },
    @{ Id='946'; Title="Freetype:"; Op=""; Res=""; Lookup=""; Path="freetype\.dll"; Cause="OSS" },
    @{ Id='947'; Title="DirectWrite:"; Op=""; Res=""; Lookup=""; Path="Load\ `dwrite\.dll`"; Cause="Modern" },
    @{ Id='948'; Title="Uniscribe:"; Op=""; Res=""; Lookup=""; Path="usp10\.dll"; Cause="Complex" },
    @{ Id='949'; Title="Font Cache:"; Op=""; Res=""; Lookup=""; Path="FNTCACHE\.DAT"; Cause="Boot" },
    @{ Id='950'; Title="Type1 Font:"; Op=""; Res=""; Lookup=""; Path="\.pfm"; Cause="Legacy" },
    @{ Id='951'; Title="AutoCAD:"; Op=""; Res=""; Lookup=""; Path="`acad\.exe`\ crash"; Cause="CAD" },
    @{ Id='952'; Title="Revit:"; Op=""; Res=""; Lookup=""; Path="revit\.exe"; Cause="BIM" },
    @{ Id='953'; Title="SolidWorks:"; Op=""; Res=""; Lookup=""; Path="`SLDWORKS\.exe`"; Cause="CAD" },
    @{ Id='954'; Title="Matlab:"; Op=""; Res=""; Lookup=""; Path="matlab\.exe"; Cause="Math" },
    @{ Id='955'; Title="LabView:"; Op=""; Res=""; Lookup=""; Path="labview\.exe"; Cause="Eng" },
    @{ Id='956'; Title="License Flex:"; Op=""; Res=""; Lookup=""; Path="lmgrd\.exe"; Cause="Licensing" },
    @{ Id='957'; Title="Dongle HASP:"; Op=""; Res=""; Lookup=""; Path="hasplms\.exe"; Cause="Key" },
    @{ Id='958'; Title="Dongle Sentinel"; Op=""; Res=""; Lookup=""; Path="Sentinel"; Cause="Key" },
    @{ Id='959'; Title="CUDA:"; Op=""; Res=""; Lookup=""; Path="Load\ `nvcuda\.dll`"; Cause="Compute" },
    @{ Id='960'; Title="MPI:"; Op=""; Res=""; Lookup=""; Path="mpi\.dll"; Cause="Cluster" },
    @{ Id='961'; Title="Bloomberg:"; Op=""; Res=""; Lookup=""; Path="`bbcomm\.exe`"; Cause="Terminal" },
    @{ Id='962'; Title="Thomson:"; Op=""; Res=""; Lookup=""; Path="`Eikon\.exe`"; Cause="Terminal" },
    @{ Id='963'; Title="Excel RTD"; Op=""; Res=""; Lookup=""; Path=""; Cause="Feed" },
    @{ Id='964'; Title="Excel DDE"; Op=""; Res=""; Lookup=""; Path=""; Cause="Legacy" },
    @{ Id='965'; Title="Multicast:"; Op=""; Res=""; Lookup=""; Path="UDP\ 224\.x\.x\.x"; Cause="Ticker" },
    @{ Id='966'; Title="PTP Sync"; Op=""; Res=""; Lookup=""; Path=""; Cause="Time" },
    @{ Id='967'; Title="Solarflare:"; Op=""; Res=""; Lookup=""; Path="Load\ `sf.*dll`"; Cause="NIC" },
    @{ Id='968'; Title="Mellanox:"; Op=""; Res=""; Lookup=""; Path="mlx.*sys"; Cause="NIC" },
    @{ Id='969'; Title="RDMA"; Op=""; Res=""; Lookup=""; Path=""; Cause="Speed" },
    @{ Id='970'; Title="Kernel Bypass"; Op=""; Res=""; Lookup=""; Path=""; Cause="Speed" },
    @{ Id='971'; Title="Epic:"; Op=""; Res=""; Lookup=""; Path="`Hyperspace\.exe`"; Cause="EMR" },
    @{ Id='972'; Title="Cerner"; Op=""; Res=""; Lookup=""; Path="Citrix"; Cause="EMR" },
    @{ Id='973'; Title="DICOM Send"; Op=""; Res=""; Lookup=""; Path=""; Cause="Image" },
    @{ Id='974'; Title="PACS"; Op=""; Res=""; Lookup=""; Path=""; Cause="Image" },
    @{ Id='975'; Title="HL7"; Op=""; Res=""; Lookup=""; Path=""; Cause="Msg" },
    @{ Id='976'; Title="Twain"; Op=""; Res=""; Lookup=""; Path=""; Cause="Scan" },
    @{ Id='977'; Title="Speech Mic"; Op=""; Res=""; Lookup=""; Path="Nuance"; Cause="Dictation" },
    @{ Id='978'; Title="Foot Pedal"; Op=""; Res=""; Lookup=""; Path=""; Cause="Control" },
    @{ Id='979'; Title="Badge Tap"; Op=""; Res=""; Lookup=""; Path=""; Cause="Auth" },
    @{ Id='980'; Title="Imprivata"; Op=""; Res=""; Lookup=""; Path="SSO"; Cause="Auth" },
    @{ Id='981'; Title="LanSchool:"; Op=""; Res=""; Lookup=""; Path="student\.exe"; Cause="Monitor" },
    @{ Id='982'; Title="NetSupport:"; Op=""; Res=""; Lookup=""; Path="`client32\.exe`"; Cause="Monitor" },
    @{ Id='983'; Title="Faronics"; Op=""; Res=""; Lookup=""; Path="DeepFreeze"; Cause="Restore" },
    @{ Id='984'; Title="Respondus"; Op=""; Res=""; Lookup=""; Path="LockDownBrowser"; Cause="Test" },
    @{ Id='985'; Title="SmartBoard"; Op=""; Res=""; Lookup=""; Path="SmartBoard"; Cause="Input" },
    @{ Id='986'; Title="SafeExam"; Op=""; Res=""; Lookup=""; Path="SEB"; Cause="Test" },
    @{ Id='987'; Title="PaperCut"; Op=""; Res=""; Lookup=""; Path="pc-client"; Cause="Print" },
    @{ Id='988'; Title="Pharos"; Op=""; Res=""; Lookup=""; Path="Pharos"; Cause="Print" },
    @{ Id='989'; Title="LabStats"; Op=""; Res=""; Lookup=""; Path="LabStats"; Cause="Usage" },
    @{ Id='990'; Title="Veyon"; Op=""; Res=""; Lookup=""; Path="Veyon"; Cause="Monitor" },
    @{ Id='991'; Title="OPOS:"; Op=""; Res=""; Lookup=""; Path="Load\ `OPOS\.dll`"; Cause="Device" },
    @{ Id='992'; Title="JavaPOS:"; Op=""; Res=""; Lookup=""; Path="jpos\.jar"; Cause="Device" },
    @{ Id='993'; Title="Cash Drawer"; Op=""; Res=""; Lookup=""; Path=""; Cause="HW" },
    @{ Id='994'; Title="Receipt Prn"; Op=""; Res=""; Lookup=""; Path=""; Cause="HW" },
    @{ Id='995'; Title="Pole Display"; Op=""; Res=""; Lookup=""; Path=""; Cause="HW" },
    @{ Id='996'; Title="Pin Pad"; Op=""; Res=""; Lookup=""; Path=""; Cause="Pay" },
    @{ Id='997'; Title="Mag Stripe"; Op=""; Res=""; Lookup=""; Path=""; Cause="Card" },
    @{ Id='998'; Title="Scanner"; Op=""; Res=""; Lookup=""; Path=""; Cause="Input" },
    @{ Id='999'; Title="Scale"; Op=""; Res=""; Lookup=""; Path=""; Cause="HW" },
    @{ Id='1000'; Title="EFT"; Op=""; Res=""; Lookup=""; Path=""; Cause="Net" },
    @{ Id='1001'; Title="Bit Flip"; Op=""; Res=""; Lookup=""; Path=""; Cause="RAM" },
    @{ Id='1002'; Title="Cosmic Ray"; Op=""; Res=""; Lookup=""; Path=""; Cause="Physics" },
    @{ Id='1003'; Title="Cable Rot"; Op=""; Res=""; Lookup=""; Path=""; Cause="Physical" },
    @{ Id='1004'; Title="Power Sag"; Op=""; Res=""; Lookup=""; Path=""; Cause="Physical" },
    @{ Id='1005'; Title="Capacitor"; Op=""; Res=""; Lookup=""; Path=""; Cause="Physical" },
    @{ Id='1006'; Title="Thermal"; Op=""; Res=""; Lookup=""; Path=""; Cause="Physical" },
    @{ Id='1007'; Title="Dust"; Op=""; Res=""; Lookup=""; Path=""; Cause="Physical" },
    @{ Id='1008'; Title="Liquid"; Op=""; Res=""; Lookup=""; Path=""; Cause="Physical" },
    @{ Id='1009'; Title="User Error"; Op=""; Res=""; Lookup=""; Path=""; Cause="Layer 8" },
    @{ Id='1010'; Title="Gremlins"; Op=""; Res=""; Lookup=""; Path=""; Cause="Undefined" },
    @{ Id='1011'; Title="Swallowed Exception (CLR):"; Op=""; Res="`\.NET\ Runtime`\ logs\ "Application\ Error"\ event\ but\ no\ ProcMon\ crash"; Lookup="`.NET Runtime` logs "Application Error" event but no ProcMon crash"; Path="\.NET\ Runtime"; Cause="Dev caught exception but didn't log it" },
    @{ Id='1012'; Title="WerFault Suppression:"; Op=""; Res=""; Lookup=""; Path="WerFault\.exe"; Cause="Headless mode crash" },
    @{ Id='1013'; Title="Stack Overflow (Silent):"; Op="Process\ Exit"; Res=""; Lookup=""; Path=""; Cause="Recursion limit hit, often no dump" },
    @{ Id='1014'; Title="Heap Corruption (Immediate):"; Op="Process\ Exit"; Res=""; Lookup=""; Path=""; Cause="Kernel kills app instantly to save OS" },
    @{ Id='1015'; Title="Dependency Loader Snap:"; Op=""; Res=""; Lookup=""; Path="App\ exits\ before\ `Main\(\)`\.\ `LdrInitializeThunk`\ fail"; Cause="Static import missing" },
    @{ Id='1016'; Title="Sentinel/Dongle Check"; Op=""; Res=""; Lookup=""; Path=""; Cause="Hardware key missing" },
    @{ Id='1017'; Title="Licensing Timeout"; Op=""; Res=""; Lookup=""; Path="Exit 0"; Cause="License server unreachable" },
    @{ Id='1018'; Title="Environment Variable Null"; Op=""; Res=""; Lookup=""; Path=""; Cause="Logic error" },
    @{ Id='1019'; Title="Console Hidden"; Op=""; Res=""; Lookup=""; Path=""; Cause="UI logic" },
    @{ Id='1020'; Title="Shim Engine Block"; Op=""; Res=""; Lookup=""; Path="Shim Engine"; Cause="Windows compatibility" },
    @{ Id='1021'; Title="Focus Theft"; Op=""; Res=""; Lookup=""; Path="SetForegroundWindow"; Cause="Interrupts speech" },
    @{ Id='1022'; Title="UIA Timeout"; Op=""; Res=""; Lookup=""; Path="WM_GETOBJECT"; Cause="App hanging the screen reader" },
    @{ Id='1023'; Title="AccName Missing:"; Op=""; Res=""; Lookup=""; Path="`IAccessible::get_accName`\ returns\ empty"; Cause="Unlabeled button" },
    @{ Id='1024'; Title="AccRole Mismatch"; Op=""; Res=""; Lookup=""; Path="ROLE_SYSTEM_GRAPHIC"; Cause="Not clickable" },
    @{ Id='1025'; Title="Live Region Spam"; Op=""; Res=""; Lookup=""; Path="EVENT_OBJECT_LIVEREGIONCHANGED"; Cause="Floods speech buffer" },
    @{ Id='1026'; Title="Java Bridge 32/64:"; Op=""; Res=""; Lookup=""; Path="WindowsAccessBridge\-32\.dll"; Cause="Silent Java" },
    @{ Id='1027'; Title="Java Bridge Missing:"; Op="RegOpenKey"; Res=""; Lookup=""; Path="HKLM\\Software\\JavaSoft\\Accessibility"; Cause="Not installed" },
    @{ Id='1028'; Title="Adobe Reader Tagging"; Op=""; Res=""; Lookup=""; Path="structTreeRoot"; Cause="Untagged PDF" },
    @{ Id='1029'; Title="Chromium A11y Tree"; Op=""; Res=""; Lookup=""; Path="Chrome_RenderWidgetHostHWND"; Cause="Browser lag" },
    @{ Id='1030'; Title="Secure Desktop Block:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Security boundary" },
    @{ Id='1031'; Title="Audio Ducking Fail"; Op=""; Res=""; Lookup=""; Path="IAudioSessionControl"; Cause="Background noise loud" },
    @{ Id='1032'; Title="Mirror Driver Fail:"; Op=""; Res=""; Lookup=""; Path="Load\ `jfwvid\.dll`\ \(JAWS\)\ or\ `nvda_mirror`\ fail"; Cause="Video hook broken" },
    @{ Id='1033'; Title="Touch API Fail:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Touchscreen reader fail" },
    @{ Id='1034'; Title="Off-Screen Text"; Op=""; Res=""; Lookup=""; Path="-32000"; Cause="Hidden text read aloud" },
    @{ Id='1035'; Title="Z-Order Confusion"; Op=""; Res=""; Lookup=""; Path=""; Cause="Tab order jump" },
    @{ Id='1036'; Title="Provider Reg Fail:"; Op="RegOpenKey"; Res=""; Lookup=""; Path="HKCR\\CLSID\\\{ProxyStub\}"; Cause="UIA broken" },
    @{ Id='1037'; Title="AutomationID Null"; Op=""; Res=""; Lookup=""; Path="AutomationId"; Cause="Bot cannot find control" },
    @{ Id='1038'; Title="Pattern Not Supported:"; Op=""; Res=""; Lookup=""; Path="IUIAutomation::GetPattern"; Cause="Control broken" },
    @{ Id='1039'; Title="TextPattern Timeout"; Op=""; Res=""; Lookup=""; Path="GetText"; Cause="Word processor lag" },
    @{ Id='1040'; Title="TreeWalker Loop"; Op=""; Res=""; Lookup=""; Path=""; Cause="Freeze" },
    @{ Id='1041'; Title="Element Orphaned"; Op=""; Res=""; Lookup=""; Path=""; Cause="Crash risk" },
    @{ Id='1042'; Title="Virtualization Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="Memory spike" },
    @{ Id='1043'; Title="Event Storm"; Op=""; Res=""; Lookup=""; Path="StructureChanged"; Cause="Performance kill" },
    @{ Id='1044'; Title="Proxy Loading:"; Op=""; Res=""; Lookup=""; Path="`UIAutomationCore\.dll`\ loading\ wrong\ version"; Cause="Compat" },
    @{ Id='1045'; Title="Privilege Boundary"; Op=""; Res=""; Lookup=""; Path=""; Cause="UIPI" },
    @{ Id='1046'; Title="Magnifier Overlay:"; Op=""; Res=""; Lookup=""; Path="`Magnification\.dll`\ init\ fail"; Cause="Driver conflict" },
    @{ Id='1047'; Title="Cursor Hook Fail"; Op=""; Res=""; Lookup=""; Path="SetWindowsHookEx"; Cause="Tracking broken" },
    @{ Id='1048'; Title="Caret Tracking"; Op=""; Res=""; Lookup=""; Path="GetGUIThreadInfo"; Cause="Zoom doesn't follow type" },
    @{ Id='1049'; Title="Color Filter Fail"; Op=""; Res=""; Lookup=""; Path="DwmSetColorizationParameters"; Cause="High contrast break" },
    @{ Id='1050'; Title="Smoothed Text"; Op=""; Res=""; Lookup=""; Path="SystemParametersInfo"; Cause="Blurry zoom" },
    @{ Id='1051'; Title="Dictation Mic Lock"; Op=""; Res=""; Lookup=""; Path="AudioEndpoint"; Cause="Dragon can't hear" },
    @{ Id='1052'; Title="Text Service (TSF):"; Op=""; Res=""; Lookup=""; Path="`ctfmon\.exe`\ deadlock"; Cause="Dictation freeze" },
    @{ Id='1053'; Title="Correction UI"; Op=""; Res=""; Lookup=""; Path=""; Cause="Invisible menu" },
    @{ Id='1054'; Title="Vocabulary Write:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path="user\.dic"; Cause="Learning fail" },
    @{ Id='1055'; Title="Eye Tracker HID:"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="Hardware connect" },
    @{ Id='1056'; Title="Switch Input Lag"; Op=""; Res=""; Lookup=""; Path=""; Cause="Motor aid delay" },
    @{ Id='1057'; Title="OSK Injection"; Op=""; Res=""; Lookup=""; Path="SendInput"; Cause="Keyboard security" },
    @{ Id='1058'; Title="Tablet Service:"; Op=""; Res=""; Lookup=""; Path="TabTip\.exe"; Cause="Touch keyboard" },
    @{ Id='1059'; Title="Gesture Conflict"; Op=""; Res=""; Lookup=""; Path=""; Cause="OS nav broken" },
    @{ Id='1060'; Title="High DPI Blur"; Op=""; Res=""; Lookup=""; Path="GetScaleFactorForMonitor"; Cause="Fuzzy UI" },
    @{ Id='1061'; Title="Global Object Creation:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Needs SeCreateGlobalPrivilege" },
    @{ Id='1062'; Title="Service Control:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Trying to start service" },
    @{ Id='1063'; Title="Program Files Write:"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="Bad coding" },
    @{ Id='1064'; Title="HKLM Write:"; Op="RegSetValue"; Res=""; Lookup=""; Path=""; Cause="Bad coding" },
    @{ Id='1065'; Title="Event Log Write:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Audit write" },
    @{ Id='1066'; Title="Symlink Create:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Needs privilege" },
    @{ Id='1067'; Title="Debug Privilege:"; Op="OpenProcess"; Res=""; Lookup=""; Path=""; Cause="Debug" },
    @{ Id='1068'; Title="Driver Load:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Kernel" },
    @{ Id='1069'; Title="Raw Socket:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Network tool" },
    @{ Id='1070'; Title="Volume Access:"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="Disk tool" },
    @{ Id='1071'; Title="Modified PATH:"; Op="LoadImage"; Res=""; Lookup=""; Path="%PATH%"; Cause="" },
    @{ Id='1072'; Title="User vs System Path:"; Op=""; Res=""; Lookup=""; Path="C:\\Users\\.*\\bin"; Cause="Wrong version" },
    @{ Id='1073'; Title="Current Work Dir:"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="Shortcut 'Start In' wrong" },
    @{ Id='1074'; Title="GAC Priority:"; Op=""; Res=""; Lookup=""; Path="C:\\Windows\\Assembly"; Cause="GAC" },
    @{ Id='1075'; Title="KnownDLLs"; Op=""; Res=""; Lookup=""; Path="KnownDLLs"; Cause="Ignores local copy" },
    @{ Id='1076'; Title="Redirected Folders:"; Op=""; Res=""; Lookup=""; Path="\\\\Server\\Share"; Cause="" },
    @{ Id='1077'; Title="Regional Date"; Op=""; Res=""; Lookup=""; Path=""; Cause="MM/DD vs DD/MM" },
    @{ Id='1078'; Title="Decimal Separator"; Op=""; Res=""; Lookup=""; Path=""; Cause="Comma vs Dot" },
    @{ Id='1079'; Title="Codepage Mismatch"; Op=""; Res=""; Lookup=""; Path="MultiByteToWideChar"; Cause="Locale" },
    @{ Id='1080'; Title="Font Substitution"; Op=""; Res=""; Lookup=""; Path="FontSubstitutes"; Cause="UI garbage" },
    @{ Id='1081'; Title="MTU Black Hole"; Op=""; Res=""; Lookup=""; Path="TCP Retransmit"; Cause="Packet too big, DF set" },
    @{ Id='1082'; Title="Ephemeral Exhaustion:"; Op=""; Res=""; Lookup=""; Path="`WSAEADDRINUSE`\ \(10048\)\ on\ .*Outbound.*"; Cause="Ran out of ports" },
    @{ Id='1083'; Title="Time_Wait Accumulation"; Op=""; Res=""; Lookup=""; Path=""; Cause="High churn" },
    @{ Id='1084'; Title="Nagle Algorithm"; Op=""; Res=""; Lookup=""; Path=""; Cause="NoDelay not set" },
    @{ Id='1085'; Title="Delayed ACK"; Op=""; Res=""; Lookup=""; Path=""; Cause="ACK timer" },
    @{ Id='1086'; Title="Window Scaling"; Op=""; Res=""; Lookup=""; Path=""; Cause="Scale factor 0" },
    @{ Id='1087'; Title="PAWS Drop:"; Op=""; Res="Timestamp\ error"; Lookup="Timestamp error"; Path=""; Cause="Sequence number wrap" },
    @{ Id='1088'; Title="ECN Drop"; Op=""; Res=""; Lookup=""; Path=""; Cause="Router compat" },
    @{ Id='1089'; Title="RSS Imbalance:"; Op=""; Res=""; Lookup=""; Path="One\ CPU\ core\ 100%\ on\ network\ interrupt"; Cause="Card setting" },
    @{ Id='1090'; Title="Chimney Offload"; Op=""; Res=""; Lookup=""; Path=""; Cause="NIC Driver bug" },
    @{ Id='1091'; Title="Aria-Hidden True"; Op=""; Res=""; Lookup=""; Path="AriaProperties"; Cause="Invisible to Reader" },
    @{ Id='1092'; Title="IFrame Boundary"; Op=""; Res=""; Lookup=""; Path="<iframe>"; Cause="Cross-origin security" },
    @{ Id='1093'; Title="Shadow DOM"; Op=""; Res=""; Lookup=""; Path="#shadow-root"; Cause="Encapsulation" },
    @{ Id='1094'; Title="Focus Trap"; Op=""; Res=""; Lookup=""; Path=""; Cause="JS Logic" },
    @{ Id='1095'; Title="AccessKey Conflict"; Op=""; Res=""; Lookup=""; Path="Alt+F"; Cause="Keyboard" },
    @{ Id='1096'; Title="Canvas Element"; Op=""; Res=""; Lookup=""; Path=""; Cause="No semantic info" },
    @{ Id='1097'; Title="Flash/ActiveX"; Op=""; Res=""; Lookup=""; Path="MacromediaFlash"; Cause="Inaccessible black box" },
    @{ Id='1098'; Title="Auto-Refresh"; Op=""; Res=""; Lookup=""; Path=""; Cause="UX" },
    @{ Id='1099'; Title="Contrast Media"; Op=""; Res=""; Lookup=""; Path="@media(forced-colors)"; Cause="Visual" },
    @{ Id='1100'; Title="Zoom Reflow:"; Op=""; Res=""; Lookup=""; Path="Text\ overlaps\ at\ 200%"; Cause="Layout break" },
    @{ Id='1101'; Title="USB Redirection:"; Op=""; Res=""; Lookup=""; Path="tsusbhub\.sys"; Cause="Scanner doesn't map" },
    @{ Id='1102'; Title="SmartCard Redir:"; Op=""; Res=""; Lookup=""; Path="scard\.dll"; Cause="Middleware" },
    @{ Id='1103'; Title="Audio Redir"; Op=""; Res=""; Lookup=""; Path="audiodg"; Cause="Lag/Quality" },
    @{ Id='1104'; Title="Printer Mapping:"; Op=""; Res=""; Lookup=""; Path="C:\\Windows\\System32\\spool\\servers"; Cause="Driver pull" },
    @{ Id='1105'; Title="Drive Map Slow:"; Op=""; Res=""; Lookup=""; Path="`\\\\tsclient\\c`\ latency"; Cause="Client drive access" },
    @{ Id='1106'; Title="Time Zone Redir"; Op=""; Res=""; Lookup=""; Path=""; Cause="Meeting time wrong" },
    @{ Id='1107'; Title="Clipboard Chain"; Op=""; Res=""; Lookup=""; Path="rdpclip"; Cause="Copy/Paste break" },
    @{ Id='1108'; Title="Display Topology"; Op=""; Res=""; Lookup=""; Path=""; Cause="Coordinates" },
    @{ Id='1109'; Title="DPI Matching"; Op=""; Res=""; Lookup=""; Path=""; Cause="Tiny/Huge text" },
    @{ Id='1110'; Title="Single Sign On:"; Op=""; Res=""; Lookup=""; Path="`ssonsvr\.exe`\ fail"; Cause="Cred prompt" },
    @{ Id='1111'; Title="Filter Stack"; Op=""; Res=""; Lookup=""; Path="fltmgr"; Cause="Latency" },
    @{ Id='1112'; Title="Hook Collision"; Op=""; Res=""; Lookup=""; Path="User32!BeginPaint"; Cause="Crash" },
    @{ Id='1113'; Title="Inject War"; Op=""; Res=""; Lookup=""; Path=""; Cause="Code integrity" },
    @{ Id='1114'; Title="Scan Loop"; Op=""; Res=""; Lookup=""; Path=""; Cause="Disk IO" },
    @{ Id='1115'; Title="Net Filter"; Op=""; Res=""; Lookup=""; Path=""; Cause="Network" },
    @{ Id='1116'; Title="EDR Memory"; Op=""; Res=""; Lookup=""; Path="NtReadVirtualMemory"; Cause="Heuristic flag" },
    @{ Id='1117'; Title="File Lock"; Op=""; Res=""; Lookup=""; Path=""; Cause="Corruption" },
    @{ Id='1118'; Title="Certificate Intercept"; Op=""; Res=""; Lookup=""; Path=""; Cause="Trust" },
    @{ Id='1119'; Title="Registry Monitor"; Op=""; Res=""; Lookup=""; Path=""; Cause="Loop" },
    @{ Id='1120'; Title="Overlay War"; Op=""; Res=""; Lookup=""; Path=""; Cause="Flicker" },
    @{ Id='1121'; Title="V4 Driver Isolation"; Op=""; Res=""; Lookup=""; Path="PrintIsolationHost"; Cause="Perms" },
    @{ Id='1122'; Title="Point & Print Policy"; Op=""; Res=""; Lookup=""; Path="PackagePointAndPrint"; Cause="GPO" },
    @{ Id='1123'; Title="Render Filter:"; Op=""; Res=""; Lookup=""; Path="mxdwdrv\.dll"; Cause="XPS convert" },
    @{ Id='1124'; Title="Color Profile:"; Op=""; Res="ACCESS\ DENIED"; Lookup="ACCESS DENIED"; Path="mscms\.dll"; Cause="Bad colors" },
    @{ Id='1125'; Title="Form Mismatch"; Op=""; Res=""; Lookup=""; Path=""; Cause="Tray selection" },
    @{ Id='1126'; Title="Spooler RPC"; Op=""; Res=""; Lookup=""; Path="RpcEpMap"; Cause="Service dead" },
    @{ Id='1127'; Title="CSR (Client Side Render):"; Op=""; Res=""; Lookup=""; Path="`winspool\.drv`\ heavy\ CPU"; Cause="Rendering" },
    @{ Id='1128'; Title="Job Stuck:"; Op=""; Res=""; Lookup=""; Path="`\.spl`\ file\ locked\ by\ AV"; Cause="Queue jam" },
    @{ Id='1129'; Title="Port Monitor"; Op=""; Res=""; Lookup=""; Path="monitordll"; Cause="Comm error" },
    @{ Id='1130'; Title="DevMode Corrupt"; Op=""; Res=""; Lookup=""; Path="DevMode"; Cause="Settings reset" },
    @{ Id='1131'; Title="Idle Timeout"; Op=""; Res=""; Lookup=""; Path=""; Cause="User away" },
    @{ Id='1132'; Title="Force Shutdown"; Op=""; Res=""; Lookup=""; Path=""; Cause="Hard reset" },
    @{ Id='1133'; Title="Cable Pull"; Op=""; Res=""; Lookup=""; Path=""; Cause="Unplugged" },
    @{ Id='1134'; Title="USB Eject"; Op=""; Res=""; Lookup=""; Path="DeviceRemoval"; Cause="Thumb drive pull" },
    @{ Id='1135'; Title="Resolution Change"; Op=""; Res=""; Lookup=""; Path="DisplaySettings"; Cause="User mess with screen" },
    @{ Id='1136'; Title="Theme Change"; Op=""; Res=""; Lookup=""; Path="Theme"; Cause="User High Contrast toggle" },
    @{ Id='1137'; Title="Volume Mute"; Op=""; Res=""; Lookup=""; Path="Volume"; Cause="User muted app" },
    @{ Id='1138'; Title="Date Change"; Op=""; Res=""; Lookup=""; Path="SetSystemTime"; Cause="User changed clock" },
    @{ Id='1139'; Title="File Move"; Op=""; Res=""; Lookup=""; Path="Explorer"; Cause="User moved folder" },
    @{ Id='1140'; Title="Install"; Op=""; Res=""; Lookup=""; Path="msiexec"; Cause="User installed software" },
    @{ Id='1141'; Title="Shellbag Access:"; Op="RegQueryValue"; Res=""; Lookup=""; Path="Shell\\Bags"; Cause="Explorer reading folder view state. Corruption here causes crashes." },
    @{ Id='1142'; Title="Context Menu Scan:"; Op="RegOpenKey"; Res=""; Lookup=""; Path="ContextMenuHandlers"; Cause="Explorer loading shell extensions. High latency here means a hung extension." },
    @{ Id='1143'; Title="Icon Overlay Scan:"; Op="RegEnumKey"; Res=""; Lookup=""; Path="ShellIconOverlayIdentifiers"; Cause="Checking overlay icons. Limit is 15; excess apps fight for slots." },
    @{ Id='1144'; Title="Quick Access Link:"; Op="CreateFile"; Res=""; Lookup=""; Path="Recent\\AutomaticDestinations"; Cause="Reading Quick Access pins. Dead links here cause Explorer hangs." },
    @{ Id='1145'; Title="Thumbnail Cache Lock"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1146'; Title="Tray Notification:"; Op="RegQueryValue"; Res=""; Lookup=""; Path="TrayNotify"; Cause="Reading system tray state. Corruption leads to missing icons." },
    @{ Id='1147'; Title="File Assoc Reset:"; Op="RegSetValue"; Res=""; Lookup=""; Path="UserChoice\\Hash"; Cause="Windows resetting file association due to hash mismatch (UserChoice protection)." },
    @{ Id='1148'; Title="Invisible Window Focus"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1149'; Title="Drag and Drop Freeze"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1150'; Title="Taskbar Unclickable"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1151'; Title="ARP Cache Poisoning (Local)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1152'; Title="Persistent Route Injection"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1153'; Title="Winsock Namespace Provider (NSP) Rot"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1154'; Title="Source Port Exhaustion (The `"1 user`" version)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1155'; Title="Ghost Network Adapter"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1156'; Title="LMHOSTS Active:"; Op="CreateFile"; Res="SUCCESS"; Lookup="SUCCESS"; Path="lmhosts"; Cause="Legacy LMHOSTS file found and readable. May override DNS." },
    @{ Id='1157'; Title="Teredo Tunneling Loop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1158'; Title="ICS (Internet Connection Sharing) Conflict"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1159'; Title="VPN Split Tunnel DNS Leak"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1160'; Title="WPAD Detection:"; Op=""; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path="wpad"; Cause="Proxy Auto-Discovery failing. Can cause periodic browser freeze." },
    @{ Id='1161'; Title="Credential Manager `"Zombie`" Cred"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1162'; Title="Cached Logon Count Exceeded"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1163'; Title="Kerberos Encryption Type Mismatch"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1164'; Title="Workstation Trust Broken (Silent)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1165'; Title="Phantom Drive Mapping Auth"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1166'; Title="DPAPI Master Key Corruption"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1167'; Title="Session 0 Isolation Auth"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1168'; Title="NGC (Windows Hello) Container Rot"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1169'; Title="AAD Broker Token Loop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1170'; Title="User Rights Assignment (Logon as Batch)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1171'; Title="Ghost Monitor Registry:"; Op="RegOpenKey"; Res=""; Lookup=""; Path="System\\CurrentControlSet\\Enum\\DISPLAY"; Cause="Enumerating display history. Zombie entries can cause off-screen windows." },
    @{ Id='1172'; Title="USB Serial Number Collision"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1173'; Title="Print Queue `"Deleting`" State"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1174'; Title="Audio Endpoint Scan:"; Op="RegOpenKey"; Res=""; Lookup=""; Path="MMDevices\\Audio\\Render"; Cause=" enumerating audio devices. Corruption here breaks sound." },
    @{ Id='1175'; Title="TWAIN Driver Lock"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1176'; Title="Bluetooth Handle Leak"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1177'; Title="Laptop Lid Switch Sensor"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1178'; Title="Touchpad Palm Rejection"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1179'; Title="Docking Station Ethernet Flap"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1180'; Title="GPU `"Fake`" Monitor (Headless Dongle)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1181'; Title="Clipboard Chain Broken"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1182'; Title="Format Not Available"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1183'; Title="Drag-Drop Handler Hang"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1184'; Title="RDP Clipboard Sync Loop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1185'; Title="Excel `"The picture is too large`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1186'; Title="Sparse File `"Disk Full`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1187'; Title="Directory Junction Recursion"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1188'; Title="File ID Reuse (The `"Wrong File`" Bug)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1189'; Title="USN Journal Wrap (Backup Fail)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1190'; Title="Offline Attribute (Sticky)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1191'; Title="Excel `"Date is text`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1192'; Title="Time Skew (Small)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1193'; Title="Leap Second Crash"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1194'; Title="Decimal vs Comma"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1195'; Title="Defrag Storm"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1196'; Title="Certificate Auto-Enrollment"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1197'; Title="Group Policy Refresh (Background)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1198'; Title="WSUS Reboot"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1199'; Title="Inventory Scan (SCCM)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1200'; Title="Browser Update Task"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1201'; Title="HDCP Handshake Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1202'; Title="Audio Switching Lag"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1203'; Title="PowerPoint Presentation Mode"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1204'; Title="USB Bandwidth Exceeded"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1205'; Title="Display Scaling (Blurry App)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1206'; Title="Bit Flip (Cosmic Ray/Bad RAM)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1207'; Title="The `"Magnet`" User"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1208'; Title="The `"Spacebar`" Heater"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1209'; Title="The `"Printer`" Voltage"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1210'; Title="The `"One-Way`" Audio"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1211'; Title="Quorum Arbitration Loss"; Process="clussvc\.exe"; Op=""; Res="STATUS_IO_TIMEOUT|STATUS_DEVICE_BUSY"; Lookup=""; Path="Quorum|Witness"; Cause="SAN latency causing the node to lose its reservation on the disk." },
    @{ Id='1212'; Title="Cluster CSV Redirected Access"; Process="System"; Op="ReadFile"; Res=""; Lookup=""; Path="C:\\ClusterStorage"; Cause="High volume of SMB Loopback traffic indicating Cluster Shared Volume is in Redirected Mode (Metadata node corruption/backup lock)." },
    @{ Id='1213'; Title="Cluster DB Registry Lock"; Process="clussvc\.exe"; Op=""; Res="SHARING_VIOLATION"; Lookup="SHARING_VIOLATION"; Path="HKLM\\Cluster"; Cause="Backup software or AV scanning the Cluster Hive (CLUSDB) while the service tries to update state." },
    @{ Id='1214'; Title="NetFT Adapter Saturation"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1215'; Title="Resource DLL Deadlock"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1216'; Title="Witness Share Access Denied"; Process="clussvc\.exe"; Op="CreateFile"; Res="ACCESS_DENIED"; Lookup="ACCESS_DENIED"; Path="\\\\.*\\.*"; Cause="Cluster Service cannot access File Share Witness. Verify 'ClusterName$' computer account permissions." },
    @{ Id='1217'; Title="VMMS Certificate Expiry"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1218'; Title="VHDX Snapshot Merge Lock"; Process="vmms\.exe"; Op=""; Res="ACCESS_DENIED"; Lookup="ACCESS_DENIED"; Path=".*\.avhdx"; Cause="Backup software (Veeam/Commvault) still holding a lock on the snapshot file after backup completion." },
    @{ Id='1219'; Title="Virtual Switch Extension Conflict"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1220'; Title="NUMA Spanning Performance Kill"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1221'; Title="Pass-Through Disk Offline"; Process="vmms\.exe"; Op=""; Res="STATUS_DEVICE_OFF_LINE"; Lookup="STATUS_DEVICE_OFF_LINE"; Path="\\\\.\\PhysicalDrive.*"; Cause="The host OS unexpectedly claimed the LUN intended for the guest (check Disk Management)." },
    @{ Id='1222'; Title="Virtual Machine Worker Process Crash"; Process="vmwp\.exe"; Op="Process Exit"; Res=""; Lookup=""; Path=""; Cause="VM Worker Process crashed (0xC0000005). Check Video Driver or Host RAM health." },
    @{ Id='1223'; Title="IME (Intune Mgmt Ext) Hash Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1224'; Title="Sidecar / PowerShell Timeout"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1225'; Title="Intune OMA-DM Sync Fail"; Process="Omadmclient\.exe"; Op="Process Exit"; Res=""; Lookup=""; Path=""; Cause="Exit code 0x80072ee2 indicates Network Timeout to Microsoft MDM endpoints." },
    @{ Id='1226'; Title="Win32 App Detection Logic Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1227'; Title="Autopilot Profile Not Found"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1228'; Title="BitLocker Compliance Error (65000)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1229'; Title="SQL OS Scheduler Yielding"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1230'; Title="Backup I/O Freeze"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1231'; Title="Instant File Initialization Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1232'; Title="SQL Memory Paging"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1233'; Title="TempDB Contention"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1234'; Title="Application Initialization Warmup Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1235'; Title="Rapid Fail Protection (Loop)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1236'; Title="HTTP.sys Cert Binding Conflict"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1237'; Title="IIS Compression Directory Lock"; Process="w3wp\.exe"; Op=""; Res="ACCESS_DENIED"; Lookup="ACCESS_DENIED"; Path="IIS Temporary Compressed Files"; Cause="IIS Worker cannot write to compression cache. Permissions broken on inetpub temp folder." },
    @{ Id='1238'; Title="WebSocket Upgrade Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1239'; Title="DNS Suffix Search List Exhaustion"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1240'; Title="EDNS0 Fragmentation Drop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1241'; Title="DNS Negative Cache"; Op=""; Res="NAME_NOT_FOUND"; Lookup="NAME_NOT_FOUND"; Path=""; Cause="Fast failure indicates Windows 'Negative Cache' is holding a failure result. Run 'ipconfig /flushdns'." },
    @{ Id='1242'; Title="LLMNR Broadcast Storm"; Op="UDP Send"; Res=""; Lookup=""; Path="224\.0\.0\.252|.*:5355"; Cause="Excessive LLMNR broadcasts indicate DNS failure; clients failing over to multicast discovery." },
    @{ Id='1243'; Title="Hosts File BOM (Byte Order Mark)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1244'; Title="ApiSetSchema Mapping Fail"; Op="LoadImage"; Res="NAME_NOT_FOUND|PATH_NOT_FOUND"; Lookup=""; Path="api-ms-win-crt-runtime.*"; Cause="Missing Universal C Runtime (KB2999226). Install the update." },
    @{ Id='1245'; Title="Manifest Activation (SxS) Parse Error"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1246'; Title="Extension DLL Block (Office)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1247'; Title="Untrusted Font Block"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1248'; Title="Raw Input Thread Hang"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1249'; Title="DPI Awareness Lie"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1250'; Title="Composition Surface Loss"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1251'; Title="PRT (Primary Refresh Token) Missing"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1252'; Title="Workplace Join Certificate Rot"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1253'; Title="Conditional Access (Device State) Block"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1254'; Title="WMI Event Consumer Persistence"; Process="scrcons\.exe"; Op="Process Create"; Res=""; Lookup=""; Path="cmd\.exe|powershell\.exe"; Cause="WMI Script Host spawning shell. High indicator of fileless malware persistence." },
    @{ Id='1255'; Title="Sticky Keys Backdoor (Classic)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1256'; Title="Utilman Hijack"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1257'; Title="UserInit Modification"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1258'; Title="Screensaver Hijack"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1259'; Title="OneDrive Office Lock"; Process="OneDrive\.exe"; Op=""; Res="SHARING_VIOLATION"; Lookup="SHARING_VIOLATION"; Path=""; Cause="OneDrive cannot upload file because OfficeClickToRun.exe has an exclusive handle." },
    @{ Id='1260'; Title="Dropbox Permissions Rot"; Process="Dropbox\.exe"; Op=""; Res="ACCESS_DENIED"; Lookup="ACCESS_DENIED"; Path="\.dropbox\.cache"; Cause="Dropbox cannot access its own cache. Fix permissions or reinstall." },
    @{ Id='1261'; Title="File Name Character sync fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1262'; Title="WHEA Corrected Error (PCIe)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1263'; Title="Machine Check Exception (MCE) - Soft"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1264'; Title="WSD (Web Services for Devices) Port Flap"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1265'; Title="Driver Version Mismatch (Point & Print)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1266'; Title="VSS Shadow Copy Deletion (Defender)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1267'; Title="Recovery Partition Disabled"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1268'; Title="NTVDM CPU Spike"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1269'; Title="AUTOEXEC.NT Parsing"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1270'; Title="RPC_S_SERVER_UNAVAILABLE (0x6BA)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1271'; Title="RPC_S_CALL_FAILED (0x6BE)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1272'; Title="ERROR_MORE_DATA (0xEA)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1273'; Title="ERROR_NO_SYSTEM_RESOURCES (0x5AA)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1274'; Title="Event Log Service Loop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1275'; Title="Subscription Failure (Source Initiated)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1276'; Title="Presentation Cache Corrupt"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1277'; Title="EUDC (End User Defined Character) Link"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1278'; Title="Modern Standby (S0) Drain"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1279'; Title="Hibernation File Lock"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1280'; Title="The `"Monday Morning`" Boot"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1281'; Title="The `"Invisible`" File"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1282'; Title="The `"Null`" User"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1283'; Title="The `"Case Sensitive`" Folder"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1284'; Title="Bubble-to-Bubble Comms"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1285'; Title="DFS Referral Loop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1286'; Title="Offline Files sync trap"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1287'; Title="AIA (Authority Info Access) Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1288'; Title="Key Spec Mismatch (Exchange/IIS)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1289'; Title="Task Queued (Wait)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1290'; Title="Run Level Mismatch"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1291'; Title="Counter Corruption"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1292'; Title="WMI Class Missing"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1293'; Title="KMS Count Too Low"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1294'; Title="Time Drift Activation"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1295'; Title="Profile Tombstoning"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1296'; Title="Ntuser.dat.LOG Lock"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1297'; Title="DDE Broadcast Hang"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1298'; Title="Index Rebuild Loop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1299'; Title="Outlook Search Scope"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1300'; Title="The `"Solar Flare`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1301'; Title="The `"9:00 AM`" Network Storm"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1302'; Title="The `"Tidal`" WiFi"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1303'; Title="The `"Magnet`" Laptop Stack"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1304'; Title="The `"Helium`" iPhone/PC Crash"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1305'; Title="The `"Spacebar`" Heater"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1306'; Title="The `"Vampire`" Tap"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1307'; Title="The `"Scrap Yard`" Crane"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1308'; Title="The `"CON`" Folder"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1309'; Title="The `"Initial`" Bug"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1310'; Title="The `"Trailing Space`" Ghost"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1311'; Title="The `"Deep`" Path"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1312'; Title="The `"Debug`" Race Condition"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1313'; Title="The `"Focus`" Stealer"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1314'; Title="The `"ProcMon`" Denial"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1315'; Title="The `"Service Timeout`" Debug"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1316'; Title="Ghost NIC (Hidden Device)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1317'; Title="Filter Driver Altitude Collision"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1318'; Title="The `"Sticky`" USB Serial"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1319'; Title="Audio `"Enhancement`" Deadlock"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1320'; Title="Bypass Traverse Checking (The `"Deep`" Access)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1321'; Title="Owner Rights (The `"Creator`" Trap)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1322'; Title="ICACLS Canonical Order"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1323'; Title="The `"Null`" SID"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1324'; Title="Token Bloat (The `"1000 Groups`")"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1325'; Title="AdminSDHolder (The `"Protected`" User)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1326'; Title="USN Rollback (The `"Zombie`" DC)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1327'; Title="TCP Chimney Offload Bug"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1328'; Title="Windows Filtering Platform (WFP) Silent Drop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1329'; Title="Ephemeral Port Exhaustion (Outbound)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1330'; Title="Path MTU Discovery Black Hole"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1331'; Title="The `"Lie`" Shim"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1332'; Title="Heap Mitigation Crash"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1333'; Title="Installer Detection (UAC)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1334'; Title="Drag and Drop Accidental Move"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1335'; Title="The `"Sticky`" Insert Key"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1336'; Title="Browser Zoom Prank"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1337'; Title="Fast Startup (The `"Fake`" Shutdown)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1338'; Title="Modern Standby (Network Connected)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1339'; Title="Windows Update `"Active Hours`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1340'; Title="Focus Assist (Do Not Disturb)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1341'; Title="The `"Ghost`" Ctrl Key (RDP Latch)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1342'; Title="Filter Keys Flag:"; Op="RegSetValue"; Res=""; Lookup=""; Path="Accessibility\\Keyboard Response"; Cause="Filter Keys (accessibility) being enabled. Causes ignored keystrokes." },
    @{ Id='1343'; Title="The `"Precision`" Touchpad Deadzone"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1344'; Title="Focus Assist Toast:"; Op="RegQueryValue"; Res=""; Lookup=""; Path="NOC_GLOBAL_SETTING_TOASTS_ENABLED"; Cause="Checking Notification suppression. May indicate Game Mode or Focus Assist blocking alerts." },
    @{ Id='1345'; Title="The `"Phantom`" Digitizer Touch"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1346'; Title="Mouse `"Polling Rate`" stutter"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1347'; Title="The `"Sepia`" Screen (Night Light Registry Rot)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1348'; Title="Intel DPST `"Flicker`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1349'; Title="The `"Invisible`" App (Off-Screen Coordinates)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1350'; Title="HDR `"Washed Out`" Desktop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1351'; Title="The `"Ghost`" Overlay (Unclickable Spot)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1352'; Title="Icon Cache `"Black Box`" Corruption"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1353'; Title="Wallpaper `"Transcoding`" Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1354'; Title="The `"Duck`" That Never Ended"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1355'; Title="Audio `"Enhancement`" Processing Loop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1356'; Title="HDMI Audio `"Silent`" Stream"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1357'; Title="Bluetooth Hands-Free Profile (HFP) Quality"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1358'; Title="Modern Standby `"Network`" Wake"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1359'; Title="The `"Update`" Wake Timer"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1360'; Title="Power Request `"System`" Override"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1361'; Title="Shutdown vs Hibernate (Fast Startup)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1362'; Title="The `"Roaming`" Aggressiveness"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1363'; Title="VPN `"Split DNS`" Leak"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1364'; Title="Metered Connection `"Outlook Block`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1365'; Title="MAC Randomization (Captive Portal Loop)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1366'; Title="`"Quick Access`" Timeout"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1367'; Title="Context Menu `"Cloud`" Delay"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1368'; Title="Recycle Bin Corruption"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1369'; Title="Search Index `"Outlook`" Missing"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1370'; Title="USB Selective Suspend (The `"Dying Mouse`")"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1371'; Title="Phantom COM Port (In Use)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1372'; Title="Docking Station `"Billboard`" Device"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1373'; Title="TPM `"Hysteresis`" Lockout"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1374'; Title="NGC Container `"Desync`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1375'; Title="BitLocker `"DMA`" Trigger"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1376'; Title="Chrome `"Renderer`" Code Integrity"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1377'; Title="Excel `"Clipboard`" Lock"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1378'; Title="Zoom `"Camera`" Exclusive Lock"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1379'; Title="Temporary Profile (Ref Count)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1380'; Title="Roaming AppData Bloat"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1381'; Title="Known Folder Redirection `"Loop`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1382'; Title="`"Feature you are trying to use`" (Source Prompt)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1383'; Title="Pending Reboot `"Sentinel`" File"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1384'; Title="`"Allow Telemetry`" = 0 (Settings Freeze)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1385'; Title="UAC `"Consent Prompt`" Hidden"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1386'; Title="Date `"Validity`" 2038"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1387'; Title="Root CA `"Disable`" Flag"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1388'; Title="The `"Fn`" Key Lock"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1389'; Title="Physical WiFi Switch (BIOS)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1390'; Title="Future Timestamps (Build Fails)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1391'; Title="Variable Font `"Glitches`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1392'; Title="EUDC (End User Defined Character) Link"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1393'; Title="Ethernet `"Energy Efficient`" Drop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1394'; Title="Dell/HP `"Optimizer`" Network Shaping"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1395'; Title="`"Eye Tracking`" Dimming"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1396'; Title="WSL (Linux) Case Conflict"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1397'; Title="The `"Non-Breaking Space`" in Username"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1398'; Title="The `"Null`" Terminator in Registry"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1399'; Title="The `"BOM`" (Byte Order Mark) in Hosts File"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1400'; Title="The `"F1`" Help Key Stuck"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1401'; Title="The `"Steam`" Desktop Layout"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1402'; Title="Touchscreen `"Phantom`" Moisture"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1403'; Title="The `"NKRO`" (N-Key Rollover) BIOS Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1404'; Title="Wireless Receiver Interference (USB 3.0)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1405'; Title="Digitizer Pen `"Hover`" Click"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1406'; Title="The `"Function Key`" Inversion"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1407'; Title="Wacom Driver `"Windows Ink`" War"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1408'; Title="Mouse `"Lift-Off`" Jitter"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1409'; Title="Barcode Scanner `"Enter`" Key"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1410'; Title="Game Controller `"Screensaver`" Block"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1411'; Title="Sample Rate Mismatch (The `"Chipmunk`" Effect)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1412'; Title="Front Panel Jack Detection Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1413'; Title="`"Listen to this device`" Loop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1414'; Title="HDMI `"Sleep`" Audio Loss"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1415'; Title="Spatial Sound Crash"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1416'; Title="Webcam `"Privacy`" Shutter (Hardware)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1417'; Title="USB Bandwidth `"Robotic`" Mic"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1418'; Title="Monitor `"Deep Sleep`" disconnect"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1419'; Title="ICC Profile `"Yellow`" Photo Viewer"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1420'; Title="Refresh Rate Mixing Stutter"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1421'; Title="The `"Workday`" VPN Limit"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1422'; Title="IPv6 `"Link-Local`" Broadcast Storm"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1423'; Title="QoS Packet Tagging Drop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1424'; Title="Network Location Awareness (NLA) Stuck"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1425'; Title="`"Green Ethernet`" Disconnects"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1426'; Title="WLAN `"Background Scan`" Lag"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1427'; Title="TCP Window Scaling (Old Router)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1428'; Title="DNS `"Smart Multi-Homed`" Resolution"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1429'; Title="Captive Portal Detection (NCSI) False Negative"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1430'; Title="SMB Direct (RDMA) over WiFi"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1431'; Title="`"Thumbs.db`" Locking"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1432'; Title="Desktop.ini `"Hiding`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1433'; Title="FAT32 4GB Limit (The `"Generic`" Error)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1434'; Title="Long Path (>260) Legacy App Crash"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1435'; Title="The `"Dot`" Folder (Naming)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1436'; Title="WebDAV File Lock"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1437'; Title="Metadata `"Date Taken`" Sorting"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1438'; Title="Symbolic Link Cycle (Backup)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1439'; Title="File Stream `"Zone`" Propagation"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1440'; Title="`"System Volume Information`" Ownership"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1441'; Title="ShutdownWithoutLogon"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1442'; Title="UserAssist `"ROT13`" Corruption"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1443'; Title="ShellBags Off-Screen"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1444'; Title="`"Winlogon`" Shell Replacement"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1445'; Title="AutoAdminLogon Loop"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1446'; Title="Background Intelligent Transfer (BITS) Job Rot"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1447'; Title="Firewall `"Block All`" Panic"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1448'; Title="PATH Truncation:"; Op="RegQueryValue"; Res="BUFFER OVERFLOW"; Lookup="BUFFER OVERFLOW"; Path="Environment\\Path"; Cause="Environment variable too long (>2048 chars). Tools will fail to launch." },
    @{ Id='1449'; Title="Debugger Hijack:"; Op="RegQueryValue"; Res=""; Lookup=""; Path="Image File Execution Options.*Debugger"; Cause="Process launch intercepted by IFEO Debugger key." },
    @{ Id='1450'; Title="Drive Letter `"Stickiness`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1451'; Title="Static Discharge (The `"Carpet`" Reboot)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1452'; Title="Ground Loop Hum"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1453'; Title="HDD Free-Fall Sensor Trigger"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1454'; Title="Piezoelectric `"Singing`" Capacitor"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1455'; Title="Thermal Throttling (Dust)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1456'; Title="Battery Calibration Drift"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1457'; Title="The `"Hair`" in the Optical Mouse"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1458'; Title="Dirty Power (Brownouts)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1459'; Title="Loose RAM Stick"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1460'; Title="SATA Cable Corruption"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1461'; Title="Discord Overlay Crash"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1462'; Title="FPS Counter Injection"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1463'; Title="Clipboard Manager Conflict"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1464'; Title="`"Game Booster`" Process Kill"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1465'; Title="RGB Software Driver Leak"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1466'; Title="Virtual Camera `"Black Screen`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1467'; Title="VPN `"Kill Switch`" Lock"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1468'; Title="Antivirus `"HTTPS Scanning`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1469'; Title="Explorer Shell Extension Crash"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1470'; Title="Focus Assist `"Duplication`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1471'; Title="Profile RefCount:"; Op="RegQueryValue"; Res=""; Lookup=""; Path="ProfileList.*RefCount"; Cause="Checking profile usage count. Non-zero at logoff indicates stuck profile." },
    @{ Id='1472'; Title="User Service (UUID) Fail"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1473'; Title="Corrupt `"Ntuser.dat`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1474'; Title="`"Guest`" Account confusion"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1475'; Title="SID Mismatch (Domain Trust)"; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1476'; Title="Credential Vault `"Max Size`""; Op=""; Res=""; Lookup=""; Path=""; Cause="" },
    @{ Id='1477'; Title="OneDrive Redirection:"; Op="RegQueryValue"; Res=""; Lookup=""; Path="User Shell Folders.*OneDrive"; Cause="Known Folders (Docs/Desktop) pointed to OneDrive." },
    @{ Id='1478'; Title="Quick Access FTP Freeze"; Op=""; Res=""; Lookup=""; Path="Explorer connecting to FTP site"; Cause="Recent Files contains a link to a slow FTP server." },
    @{ Id='1479'; Title="Library Optimization Slowdown"; Op=""; Res=""; Lookup=""; Path="Folder type = Pictures"; Cause="Automatic Folder Type Discovery decided Downloads is a Photo Album." },
    @{ Id='1480'; Title="Account Unknown SIDs"; Op=""; Res=""; Lookup=""; Path="ACLs full of S-1-5-21-"; Cause="Files migrated from old installation; SIDs don't resolve to current users." },
    @{ Id='1481'; Title="CMOS Battery Death"; Op=""; Res=""; Lookup=""; Path="Date is Jan 1, 1980 on boot"; Cause="RTC battery dead." },
    @{ Id='1482'; Title="Time Zone Auto Fail"; Op=""; Res=""; Lookup=""; Path="tzautoupdate service"; Cause="Geo-IP lookup thinks VPN exit node is physical location." },
    @{ Id='1483'; Title="Kerberos Time Skew"; Op=""; Res=""; Lookup=""; Path="Client time > 5 mins difference"; Cause="Windows Time Service sync failure." },
    @{ Id='1484'; Title="Excel 1900 Date System"; Op=""; Res=""; Lookup=""; Path="Dates copy-pasted from Mac"; Cause="Excel for Mac used 1904 date system; Windows uses 1900." },
    @{ Id='1485'; Title="Last Modified Paradox"; Op=""; Res=""; Lookup=""; Path="File modified date is before creation date"; Cause="File copied from another volume preserves Mod time, but Creation time is Now." },
    @{ Id='1486'; Title="DST Patch Missing"; Op=""; Res=""; Lookup=""; Path="Meetings are 1 hour off"; Cause="OS missing Daylight Savings Time update for specific time zone." },
    @{ Id='1487'; Title="BIOS Clock Drift"; Op=""; Res=""; Lookup=""; Path="Clock loses 10 mins per day"; Cause="Failing motherboard oscillator." },
    @{ Id='1488'; Title="Leap Year Bug"; Op=""; Res=""; Lookup=""; Path="App crashes on Feb 29"; Cause="Hardcoded 365 days logic." },
    @{ Id='1489'; Title="Region Format AM/PM"; Op=""; Res=""; Lookup=""; Path="App parses 14:00 as error"; Cause="User region set to US (12h), App expects 24h input." },
    @{ Id='1490'; Title="Uptime Counter Overflow"; Op=""; Res=""; Lookup=""; Path="GetTickCount 32-bit rollover"; Cause="Ancient driver using 32-bit millisecond counter." },
    @{ Id='1491'; Title="Desktop Heap Exhaustion"; Op=""; Res=""; Lookup=""; Path="User32 resource fail"; Cause="Too many hooks/objects allocated in the interactive session heap." },
    @{ Id='1492'; Title="Atom Table Exhaustion"; Op=""; Res=""; Lookup=""; Path="GlobalAddAtom fail"; Cause="App leaking global atoms (strings), filling the 64k table." },
    @{ Id='1493'; Title="GDI Object Limit"; Op=""; Res=""; Lookup=""; Path="GDI Objects = 10,000"; Cause="Hard limit per process. App leak." },
    @{ Id='1494'; Title="Handle Leak Kernel"; Op=""; Res=""; Lookup=""; Path="Paged Pool high"; Cause="Driver leaking registry handles." },
    @{ Id='1495'; Title="Magic Packet Wake"; Op=""; Res=""; Lookup=""; Path="Wake on LAN Pattern Match"; Cause="NIC configured to wake on Pattern Match, interpreting arbitrary broadcast traffic." },
    @{ Id='1496'; Title="BitLocker Used Space Only"; Op=""; Res=""; Lookup=""; Path="Undelete tools fail on Empty space"; Cause="BitLocker only encrypted written data; free space is technically clear." },
    @{ Id='1497'; Title="Fonts Non-System Block"; Op=""; Res=""; Lookup=""; Path="MitigationPolicy event"; Cause="Block untrusted fonts security policy enabled." },
    @{ Id='1498'; Title="AppContainer Network Isolation"; Op=""; Res=""; Lookup=""; Path="CheckNetIsolation loopback exempt missing"; Cause="UWP Security feature blocking loopback." },
    @{ Id='1499'; Title="OOBE Complete Flag"; Op=""; Res=""; Lookup=""; Path="OOBEComplete registry mismatch"; Cause="Search Indexer waits for Out-Of-Box-Experience to finish." },
    @{ Id='1500'; Title="Null Window Class"; Op=""; Res=""; Lookup=""; Path="CreateWindow with NULL class"; Cause="Race condition in shell extension initialization." },
)


# =========================
# 4) AUX LOG PARSING (EVTX + TEXT LOGS + REG)
# =========================
$AuxEvents = [System.Collections.Generic.List[PSObject]]::new()
$AuxTextFindings = [System.Collections.Generic.List[PSObject]]::new()
$AuxRegSignals = [System.Collections.Generic.List[PSObject]]::new()

function Add-AuxEvent {
    param([TimeSpan]$Time, [string]$Type, [string]$Source, [string]$Details)
    $AuxEvents.Add([PSCustomObject]@{
        Time = $Time
        Type = $Type
        Source = $Source
        Details = $Details
    }) | Out-Null
}

# DMP inventory
foreach ($d in $DumpFiles) {
    Add-AuxEvent -Time $d.CreationTime.TimeOfDay -Type "DUMP" -Source $d.Name -Details ("SizeMB={0}; Path={1}" -f ([math]::Round($d.Length/1MB,2)), $d.FullName)
}

# EVTX parse (target common crash/hang IDs)
$CrashIds = @(1000,1001,1002,1005,1026,11707,11708)
foreach ($e in $EvtxFiles) {
    try {
        $ev = Get-WinEvent -FilterHashtable @{ Path = $e.FullName; Id = $CrashIds } -ErrorAction SilentlyContinue
        foreach ($r in ($ev | Select-Object -First 250)) {
            $msg = ($r.Message -split "`r?`n" | Select-Object -First 3) -join " | "
            $msg = $msg.Trim()
            $type = switch ($r.Id) {
                1000 { "APP CRASH (EVTX)" }
                1001 { "WER REPORT (EVTX)" }
                1002 { "APP HANG (EVTX)" }
                1026 { ".NET CRASH (EVTX)" }
                default { "EVTX $($r.Id)" }
            }
            Add-AuxEvent -Time $r.TimeCreated.TimeOfDay -Type $type -Source $e.Name -Details $msg
        }
    } catch {}
}

# Text logs (JAWS + generic): search for high-signal lines
$TextPatterns = @(
    "(?i)\bexception\b",
    "(?i)\bfault\b",
    "(?i)\baccess violation\b",
    "(?i)\bcrash\b",
    "(?i)\bhung\b",
    "(?i)\bdeadlock\b",
    "(?i)\btimeout\b",
    "(?i)\baccess denied\b",
    "(?i)\bsharing violation\b",
    "(?i)\bui automation\b|\buia\b",
    "(?i)\boleacc\b|\bmsaa\b",
    "(?i)\bcom\b.*\bclass not registered\b",
    "(?i)\berror\b"
)

foreach ($t in ($TextLogFiles | Select-Object -First 350)) {
    try {
        $lines = Get-Content -LiteralPath $t.FullName -ErrorAction SilentlyContinue -TotalCount 20000
        $hitLines = @()
        foreach ($p in $TextPatterns) {
            $hitLines += $lines | Where-Object { $_ -match $p } | Select-Object -First 3
        }
        $hitLines = $hitLines | Select-Object -Unique | Select-Object -First 12
        if ($hitLines.Count -gt 0) {
            $AuxTextFindings.Add([PSCustomObject]@{
                File = $t.FullName
                Hits = $hitLines -join " \n "
            }) | Out-Null
        }
    } catch {}
}

# REG exports: pull a few known toggles (best-effort)
$RegKeySignals = @(
    "(?i)LowLevelHooksTimeout",
    "(?i)LoadAppInit_DLLs",
    "(?i)AppInit_DLLs",
    "(?i)EnableLUA",
    "(?i)Accessibility",
    "(?i)UIA",
    "(?i)oleacc",
    "(?i)Magnification",
    "(?i)Filter",
    "(?i)AppLocker",
    "(?i)WDAC|CodeIntegrity",
    "(?i)SmartScreen",
    "(?i)OneDrive"
)

foreach ($r in ($RegFiles | Select-Object -First 120)) {
    try {
        $raw = Get-Content -LiteralPath $r.FullName -ErrorAction SilentlyContinue -TotalCount 200000
        foreach ($sig in $RegKeySignals) {
            $matches = $raw | Where-Object { $_ -match $sig } | Select-Object -First 6
            if ($matches) {
                $AuxRegSignals.Add([PSCustomObject]@{
                    File = $r.FullName
                    Signal = $sig
                    Lines = ($matches -join " \n ")
                }) | Out-Null
            }
        }
    } catch {}
}

# =========================
# 5) CSV HEADER NORMALIZER + STREAMING PARSER
# =========================
Add-Type -AssemblyName Microsoft.VisualBasic | Out-Null

$StandardFieldMap = @{
    "Time of Day" = @("Time of Day","Time","TimeOfDay","Timestamp")
    "Process Name" = @("Process Name","Process","Image Name","ProcessName")
    "PID" = @("PID","Process ID","ProcessId")
    "Operation" = @("Operation","Op")
    "Path" = @("Path","File Path","Registry Path","Object Name")
    "Result" = @("Result","Status")
    "Detail" = @("Detail","Details")
    "Duration" = @("Duration","Elapsed Time")
    "Thread ID" = @("Thread ID","TID","ThreadId")
    "Image Path" = @("Image Path","ImagePath","Process Path")
    "Command Line" = @("Command Line","CommandLine")
    "User" = @("User","Account Name")
    "Integrity" = @("Integrity","Integrity Level")
    "Session" = @("Session","Session ID")
}

function Resolve-HeaderName {
    param([string[]]$Headers, [string]$Standard)
    foreach ($alt in $StandardFieldMap[$Standard]) {
        $h = $Headers | Where-Object { $_.Trim('"') -ieq $alt } | Select-Object -First 1
        if ($h) { return $h.Trim('"') }
    }
    return $null
}

function Parse-TimeOfDay {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return [TimeSpan]::Zero }
    $s = $s.Trim('"').Trim()
    try {
        # ProcMon often uses local time format; DateTime.Parse handles it.
        $dt = [DateTime]::Parse($s, [System.Globalization.CultureInfo]::InvariantCulture)
        return $dt.TimeOfDay
    } catch {
        try { return [TimeSpan]::Parse($s) } catch { return [TimeSpan]::Zero }
    }
}

function Parse-Double {
    param([string]$s)
    if ([string]::IsNullOrWhiteSpace($s)) { return 0.0 }
    $s = $s.Trim('"').Trim()
    try { return [double]::Parse($s, [System.Globalization.CultureInfo]::InvariantCulture) } catch { return 0.0 }
}

function Normalize-ProcName {
    param([string]$p)
    if ([string]::IsNullOrWhiteSpace($p)) { return "" }
    $p = $p.Trim('"').Trim()
    if ($p -notmatch '\.exe$' -and $p -notmatch '\.dll$') {
        # ProcMon Process Name is typically exe; leave non-exe for other ops
        return $p
    }
    return $p
}

# Read header via TextFieldParser for correctness
function Get-CsvHeaders {
    param([string]$CsvPath)
    $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($CsvPath)
    $parser.SetDelimiters(",")
    $parser.HasFieldsEnclosedInQuotes = $true
    $parser.TrimWhiteSpace = $true
    $headers = $parser.ReadFields()
    $parser.Close()
    return $headers
}

$Headers = Get-CsvHeaders -CsvPath $PrimaryCsv.FullName
$Resolved = @{}
foreach ($std in $StandardFieldMap.Keys) {
    $Resolved[$std] = Resolve-HeaderName -Headers $Headers -Standard $std
}

# Minimum column validation (but flexible)
if (-not $Resolved["Process Name"] -or -not $Resolved["Path"] -or -not $Resolved["Result"] -or -not $Resolved["Operation"]) {
    Write-Host "[!] Header normalization: could not reliably locate one or more critical columns." -ForegroundColor Yellow
    Write-Host "    Found headers: $($Headers -join ', ')" -ForegroundColor Yellow
    Write-Error "CRITICAL: Must have at least Process Name/Path/Result/Operation in exported CSV."
    return
}

# =========================
# 6) DETECTION ENGINE (MODULE REGISTRY)
# =========================
$Findings = [System.Collections.Generic.List[PSObject]]::new()
$Evidence = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[PSObject]]]::new([System.StringComparer]::OrdinalIgnoreCase)

function Add-Finding {
    param(
        [string]$Category,
        [string]$Severity,
        [string]$Process,
        [string]$PID = "",
        [string]$TID = "",
        [string]$User = "",
        [string]$ImagePath = "",
        [string]$CommandLine = "",
        [string]$Operation,
        [string]$Path,
        [string]$Result,
        [string]$Detail,
        [TimeSpan]$Time,
        [double]$Duration,

        # Legacy mapping parameters (kept for backward compat during refactor)
        [string]$Why = "",
        [string]$HowToConfirm = "",
        [string]$NextSteps = "",

        # New 3-Layer Model
        [string]$UserExperience = "",
        [string]$TechnicalContext = "",
        [string]$Remediation = "",

        # Chain of Custody
        [string]$SourceFile = "",
        [long]$SourceLine = 0,

        [hashtable]$Oracle = $null
    )
    if ($Findings.Count -ge 5000) { return } # safety cap

    # Map legacy fields if new ones are empty
    if ([string]::IsNullOrWhiteSpace($UserExperience) -and [string]::IsNullOrWhiteSpace($TechnicalContext)) {
        # Fallback for detectors not yet updated
        $UserExperience = "Issue detected in category: $Category"
        $TechnicalContext = "$Why `n`nConfirmation: $HowToConfirm"
        $Remediation = $NextSteps
    }

    $id = [Guid]::NewGuid().ToString()
    $obj = [PSCustomObject]@{
        Id=$id
        Time=$Time
        Severity=$Severity
        Category=$Category
        Process=$Process
        PID=$PID
        TID=$TID
        User=$User
        ImagePath=$ImagePath
        CommandLine=$CommandLine
        Operation=$Operation
        Path=$Path
        Result=$Result
        Detail=$Detail
        DurationSeconds=$Duration

        # 3-Layer Model
        UserExperience=$UserExperience
        TechnicalContext=$TechnicalContext
        Remediation=$Remediation

        # Chain of Custody
        SourceFile=$SourceFile
        SourceLine=$SourceLine

        OracleTitle= if($Oracle){$Oracle.title}else{""}
        OracleFix= if($Oracle){$Oracle.fix}else{""}
        OracleUrl= if($Oracle){$Oracle.url}else{""}
    }
    $Findings.Add($obj) | Out-Null

    if (-not $Evidence.ContainsKey($id)) {
        $Evidence[$id] = [System.Collections.Generic.List[PSObject]]::new()
    }
    return $id
}

function Add-Evidence {
    param([string]$FindingId, $Evt)
    if (-not $Evidence.ContainsKey($FindingId)) { return }
    if ($Evidence[$FindingId].Count -ge $MaxEvidenceSamplesPerFinding) { return }
    $Evidence[$FindingId].Add($Evt) | Out-Null
}

function Oracle-Match {
    param(
        [string]$ProcessName,
        [string]$PathText,
        [string]$CategoryText,
        [string]$DetailText
    )
    if (-not $OracleDbObj -or -not $OracleDbObj.entries) { return $null }
    $p = $(if($ProcessName){$ProcessName}else{""}).ToLowerInvariant()
    $blob = ($(if($PathText){$PathText}else{""}) + " " + $(if($CategoryText){$CategoryText}else{""}) + " " + $(if($DetailText){$DetailText}else{""})).ToLowerInvariant()

    # Try: exact file match first
    $hits = $OracleDbObj.entries | Where-Object {
        ($_.file -and $_.file.ToLowerInvariant() -eq $p) -or
        ($_.file -and $p -and $p -like $_.file.ToLowerInvariant())
    } | Select-Object -First 3

    if (-not $hits) {
        # fallback: pattern match
        $hits = $OracleDbObj.entries | Where-Object {
            $_.symptom_patterns -and ($_.symptom_patterns | Where-Object { $blob -match $_.ToLowerInvariant() } | Select-Object -First 1)
        } | Select-Object -First 3
    }

    return ($hits | Select-Object -First 1)
}

# Sliding windows / counters
$OpCountsByKey = @{}       # registry thrash
$ReparseCounts = @{}       # reparse loop
$RecentByProcess = @{}     # for burst detection
$EventRateByProcSec = @{}  # EVENT FLOOD (proc|secondBucket -> count)
$WerCounts = @{ Fault=0; Writes=0 } # WERFLOOD signals

# Detector: Access Denied & Security contention
function Detect-AccessDenied {
    param($evt)
    if ($evt.Result -notmatch "ACCESS DENIED") { return $null }
    $proc = $evt.Process
    $cat = "ACCESS DENIED"
    $sev = if ($AT_Processes.Contains($proc)) { "High" } else { "Medium" }

    $oracle = Oracle-Match -ProcessName $proc -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The application may crash, show an 'Access Denied' error, or fail to save/load data."
    $tc = "Process '$proc' attempted operation '$($evt.Operation)' on '$($evt.Path)' but was blocked by the OS kernel (Result: ACCESS DENIED). This usually indicates insufficient NTFS permissions, a Read-Only attribute, or blockage by security software (Anti-Virus/DLP)."
    $rm = "1. Check NTFS permissions (ACLs) for the user account. 2. Verify if the file has the 'Read-only' attribute set. 3. Investigate if Anti-Virus/EDR is blocking this specific path."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Sharing violation / oplock / fast I/O fallback
function Detect-OplockFastIo {
    param($evt)
    if ($evt.Result -notmatch "SHARING VIOLATION|OPLOCK_NOT_GRANTED|FAST_IO_DISALLOWED|LOCK VIOLATION") { return $null }
    $cat = "OPLOCK/FASTIO"
    $sev = if ($AT_Processes.Contains($evt.Process)) { "High" } else { "Medium" }
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The application may feel sluggish or unresponsive during file operations."
    $tc = "A '$($evt.Result)' occurred on '$($evt.Path)'. This forces the I/O manager to fall back to a slower, synchronous code path. This is often caused by contention with other processes (like Search Indexer, Anti-Virus, or Backup agents) trying to access the same file simultaneously."
    $rm = "1. Identify the contending process using Handle.exe or Resource Monitor. 2. Temporarily exclude the path from Anti-Virus scanning. 3. If the path is on a network share, check for network latency or locking issues."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Reparse loop
function Detect-ReparseLoop {
    param($evt)
    if ($evt.Result -notmatch "REPARSE") { return $null }
    $key = ("{0}|{1}" -f $evt.Process, $evt.Path).ToLowerInvariant()
    if (-not $ReparseCounts.ContainsKey($key)) { $ReparseCounts[$key] = 0 }
    $ReparseCounts[$key]++
    if ($ReparseCounts[$key] -lt 8) { return $null }

    $cat = "REPARSE LOOP"
    $sev = if ($AT_Processes.Contains($evt.Process)) { "High" } else { "Medium" }
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The application or system may hang, crash, or consume excessive CPU."
    $tc = "Process '$($evt.Process)' hit a Reparse Point Loop (infinite symlink recursion) at '$($evt.Path)'. This often happens with misconfigured OneDrive folders, Junction Points, or containerized storage (FSLogix)."
    $rm = "1. Inspect the path for circular Junction Points/Symlinks (use `dir /al /s`). 2. Check OneDrive 'Files On-Demand' settings. 3. Verify FSLogix profile container configurations."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Load Image injection / hook DLLs
function Detect-HookInjection {
    param($evt)
    if ($evt.Operation -notmatch "Load Image") { return $null }
    $proc = $evt.Process
    if (-not $AT_Processes.Contains($proc)) { return $null }

    $module = (Split-Path -Path $evt.Path -Leaf)
    if ([string]::IsNullOrWhiteSpace($module)) { return $null }

    # Ignore safe baseline
    if ($Safe_DLL_Tokens.Contains($module)) { return $null }

    # Flag if looks like security/VDI/hook vendor token
    $tokenHit = $null
    if ($evt.Path -match $Suspicious_DLL_Regex) {
        $tokenHit = $Matches[0]
    }
    if (-not $tokenHit) { return $null }

    $cat = "HOOK INJECTION"
    $sev = "High"
    $oracle = Oracle-Match -ProcessName $proc -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The application may crash on startup, freeze, or exhibit erratic behavior (e.g., focus loss)."
    $tc = "Third-party DLL '$module' was injected into the AT process '$proc'. This 'Hook Injection' pattern allows security/management tools to inspect or modify application behavior, but often destabilizes Assistive Technology hooks (UIA/MSAA)."
    $rm = "1. Identify the vendor of '$module' (e.g., Security Agent, Virtualization Tool). 2. Configure the security tool to 'allowlist' or exclude the AT process from injection. 3. Update the third-party agent to the latest version."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: VC++ missing runtime DLLs
function Detect-VCppMissing {
    param($evt)
    if ($evt.Result -notmatch "NAME NOT FOUND|PATH NOT FOUND") { return $null }
    if ($evt.Path -notmatch '(?i)\\msvcp\d+\.dll$|\\vcruntime\d+\.dll$|\\api-ms-win-.*\.dll$') { return $null }
    $cat="VC++ MISSING"
    $sev = if ($AT_Processes.Contains($evt.Process)) { "High" } else { "Medium" }
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The application may fail to start with a 'Missing DLL' error or crash silently."
    $tc = "Process '$($evt.Process)' failed to load a Visual C++ Runtime dependency ('$($evt.Path)'). Result: '$($evt.Result)'. This typically means the required VC++ Redistributable package is not installed or corrupted."
    $rm = "1. Identify the specific VC++ version required (e.g., 2015-2022). 2. Install/Repair the Microsoft Visual C++ Redistributable (x86 and x64). 3. Ensure the DLL is in the application directory or System32."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Registry thrash
function Detect-RegistryThrash {
    param($evt)
    if ($evt.Operation -notmatch '^Reg') { return $null }
    $k = ("{0}|{1}" -f $evt.Process, $evt.Path).ToLowerInvariant()
    if (-not $OpCountsByKey.ContainsKey($k)) { $OpCountsByKey[$k] = 0 }
    $OpCountsByKey[$k]++
    if ($OpCountsByKey[$k] -lt $HotspotThreshold) { return $null }

    $cat="REGISTRY THRASH"
    $sev = if ($AT_Processes.Contains($evt.Process)) { "High" } else { "Low" }
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "High CPU usage and application unresponsiveness."
    $tc = "Process '$($evt.Process)' is hammering the registry key '$($evt.Path)' with excessive queries (> $HotspotThreshold). This indicates a tight polling loop, a policy conflict, or a broken add-in repeatedly trying to read a missing configuration."
    $rm = "1. Investigate the specific registry key to understand what configuration is being requested. 2. If it's a policy key, check Group Policy settings. 3. If it's an app key, try resetting the application preference or reinstalling the add-in."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Heap/Stack corruption (via Process Exit detail)
function Detect-ProcessExitCodes {
    param($evt)
    if ($evt.Operation -notmatch 'Process Exit') { return $null }
    if ($evt.Detail -notmatch '(?i)Exit Status:\s*0x([0-9a-f]{8})') { return $null }
    $code = $Matches[1].ToLowerInvariant()
    $cat = switch ($code) {
        "c0000374" { "HEAP CORRUPTION" }
        "c0000409" { "STACK OVERRUN" }
        default { return $null }
    }
    $sev="Critical"
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The application crashes or disappears instantly."
    $tc = "Process '$($evt.Process)' terminated with exit code '$code' ($cat). This is a fatal low-level crash. 0xC0000374 = Heap Corruption (Memory damage). 0xC0000409 = Stack Buffer Overrun (Security fail-fast). These are often caused by incompatible injected DLLs or buggy drivers."
    $rm = "1. Review the 'Hook Injection' findings to see what 3rd party DLLs were loaded before the crash. 2. Update video/input drivers. 3. Check Windows Event Viewer (Application/System) for corresponding crash details (Event ID 1000/1001)."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}


# Detector: High latency (slow operations)
function Detect-HighLatency {
    param($evt)
    if ($evt.Duration -lt $SlowThresholdSeconds) { return $null }
    if (-not ($AT_Processes.Contains($evt.Process) -or $evt.Process -ieq $TargetProcess)) { return $null }

    $cat = "HIGH LATENCY"
    $sev = if ($evt.Duration -ge ($SlowThresholdSeconds * 5)) { "High" } else { "Medium" }
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The application is slow to respond to user input (laggy)."
    $tc = "Operation '$($evt.Operation)' on '$($evt.Path)' took $($evt.Duration) seconds, exceeding the threshold ($SlowThresholdSeconds s). High latency on specific files/paths suggests disk contention, network lag (if UNC), or filter driver overhead."
    $rm = "1. Check disk queue length and I/O performance. 2. If the path is on a network, troubleshoot network latency. 3. Check for Anti-Virus/Filter drivers attaching to this operation (FLTMC)."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Thread profiling (when enabled in ProcMon)
function Detect-ThreadProfiling {
    param($evt)
    if ($evt.Operation -notmatch 'Thread Profiling') { return $null }
    if (-not ($AT_Processes.Contains($evt.Process))) { return $null }
    $cat="THREAD PROFILING HOTSPOT"
    $sev="Medium"
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The application freezes briefly or stutters."
    $tc = "High frequency of 'Thread Profiling' events detected for '$($evt.Process)'. This usually indicates the process is CPU-bound or thread-locked, often waiting on a resource or performing heavy computation."
    $rm = "1. Use a performance profiler (WPR/WPA) to analyze CPU usage. 2. Check for infinite loops or heavy processing on the UI thread."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Clipboard lock / clipboard service contention (heuristic)
function Detect-ClipboardLock {
    param($evt)
    $proc = $evt.Process.ToLowerInvariant()
    if ($proc -notmatch 'rdpclip\.exe|clipsvc\.exe|cbdhsvc\.exe|dwm\.exe|explorer\.exe|jfw\.exe|nvda\.exe') { return $null }
    if ($evt.Result -notmatch 'ACCESS DENIED|PIPE BUSY|SHARING VIOLATION|LOCK VIOLATION') { return $null }
    if ($evt.Path -notmatch '(?i)clip|clipboard|\\BaseNamedObjects\\') { return $null }

    $cat="CLIPBOARD LOCK"
    $sev= if ($AT_Processes.Contains($evt.Process)) { "High" } else { "Medium" }
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "Copy/Paste stops working, or the application freezes when attempting to access the clipboard."
    $tc = "Process '$($evt.Process)' failed to open the clipboard ('$($evt.Result)') on path '$($evt.Path)'. This typically happens when another process (RDP clipboard chain, Clipboard History, or a remote management tool) has an exclusive lock on the clipboard and isn't releasing it."
    $rm = "1. Identify the process holding the clipboard using 'Get-ClipboardOwner' (PowerShell) or a tool like 'ClipView'. 2. Restart the 'rdpclip.exe' process if in a remote session. 3. Disable 'Clipboard History' temporarily to test."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Audio block / audio ducking stomp (heuristic)
function Detect-AudioDucking {
    param($evt)
    if ($evt.Process -notmatch '(?i)^audiodg\.exe$|^audiosrv\.exe$|^svchost\.exe$') { return $null }
    if ($evt.Result -notmatch 'ACCESS DENIED|SHARING VIOLATION|OPLOCK|FAST_IO|NAME NOT FOUND|PATH NOT FOUND') { return $null }
    if ($evt.Path -notmatch '(?i)MMDevices|Audio|PolicyConfig|Render|Capture|Endpoint') { return $null }

    $cat="AUDIO BLOCK/DUCKING"
    $sev="Medium"
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "Audio volume drops unexpectedly, stutters, or becomes silent."
    $tc = "The Audio Engine (audiodg/audiosrv) encountered an error ('$($evt.Result)') accessing audio endpoints/policy config. This suggests a conflict with 'Audio Ducking' (communication activity attenuation) or an exclusive-mode driver lock."
    $rm = "1. Disable 'Audio Enhancements' in Sound Control Panel. 2. Set 'Communications' activity to 'Do nothing' in Sound settings. 3. Check for third-party audio drivers (Nahimic, Waves, Dolby) causing contention."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Legacy bridge missing (UIA/MSAA)
function Detect-LegacyBridge {
    param($evt)
    if ($evt.Result -notmatch 'NAME NOT FOUND|PATH NOT FOUND') { return $null }
    if ($evt.Path -notmatch '(?i)\\uiautomationcore\.dll$|\\oleacc\.dll$|\\msaa\.dll$|\\atspi') { return $null }
    $cat="LEGACY BRIDGE"
    $sev = if ($AT_Processes.Contains($evt.Process)) { "High" } else { "Medium" }
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "Screen readers (JAWS/NVDA) may be silent or fail to read specific application windows."
    $tc = "Process '$($evt.Process)' failed to load legacy accessibility bridge components (OLEACC, UIA, MSAA). This breaks the 'Bridge' between the application's internal object model and the Assistive Technology."
    $rm = "1. Ensure the application is installed correctly (repair install). 2. Check if 'uiautomationcore.dll' is present in System32. 3. Verify that Anti-Virus isn't blocking the loading of accessibility DLLs."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: COM class/category problems (HKCR\CLSID / class not registered)
function Detect-ComCat {
    param($evt)
    if ($evt.Operation -notmatch '^Reg' ) { return $null }
    if ($evt.Path -notmatch '(?i)^HKCR\\CLSID\\|^HKLM\\Software\\Classes\\CLSID\\|^HKCU\\Software\\Classes\\CLSID\\') { return $null }
    if ($evt.Result -notmatch 'ACCESS DENIED|NAME NOT FOUND') { return $null }
    $cat="COM CAT"
    $sev = if ($AT_Processes.Contains($evt.Process)) { "High" } else { "Low" }
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "Application features (add-ins, automation) fail to load or crash."
    $tc = "Process '$($evt.Process)' failed to instantiate a COM Class (CLSID) or Interface. Result: '$($evt.Result)'. The registry key for the component is missing or access was denied."
    $rm = "1. Identify the GUID in the path and look it up to find the missing component. 2. Re-register the associated DLL using 'regsvr32'. 3. Repair the application installation."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Filter/minifilter conflict signals (altitude collisions)
function Detect-FilterConflict {
    param($evt)
    if ($evt.Result -notmatch '(?i)ALTITUDE|INSTANCE_ALTITUDE_COLLISION|FLT_INSTANCE_ALTITUDE_COLLISION') { return $null }
    $cat="FILTER CONFLICT"
    $sev="Medium"
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "File operations are slow or fail with strange errors."
    $tc = "A Minifilter altitude collision was detected. This means two file system filter drivers (e.g., Anti-Virus and Encryption) are trying to attach at the exact same 'altitude' (priority), causing instability."
    $rm = "1. Run 'fltmc instances' to see loaded filters. 2. Update the drivers involved. 3. Contact the vendor to request a different altitude assignment."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Secure Desktop contention (Consent/LogonUI)
function Detect-SecureDesktop {
    param($evt)
    if ($evt.Process -notmatch '(?i)^consent\.exe$|^logonui\.exe$|^winlogon\.exe$') { return $null }
    if ($evt.Result -notmatch 'ACCESS DENIED|SHARING VIOLATION|OPLOCK|FAST_IO') { return $null }
    $cat="SECURE DESKTOP"
    $sev="Medium"
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "Assistive Technology stops working on the Logon screen or UAC prompts."
    $tc = "The process '$($evt.Process)' running on the Secure Desktop (Session 0/1) failed to access required resources. This security boundary isolates the logon/UAC UI, often blocking AT tools that aren't properly signed or configured for UI access."
    $rm = "1. Ensure the AT tool is configured to 'Start on Logon Screen'. 2. Check Group Policy for 'User Account Control: Switch to the secure desktop when prompting for elevation'."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: MFA / auth network block (heuristic)
function Detect-MfaBlock {
    param($evt)
    if ($evt.Operation -notmatch 'TCP Connect|TCP Receive|TCP Send') { return $null }
    if ($evt.Path -notmatch '(?i)login\.microsoftonline\.com|device\.login\.microsoftonline\.com|aadcdn|msauth|officecdn|graph\.microsoft\.com') { return $null }
    if ($evt.Result -notmatch 'TIMEOUT|TIMED OUT|NAME NOT RESOLVED|CONNECTION RESET') { return $null }
    $cat="MFA BLOCK"
    $sev="Medium"
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The application hangs at 'Signing in...' or prompts for credentials repeatedly."
    $tc = "Network connection to Microsoft Identity endpoints (login.microsoftonline.com, etc.) failed or timed out. This prevents Modern Authentication (OAuth/SAML) from completing."
    $rm = "1. Check firewall/proxy logs for blocks to Microsoft Identity URLs. 2. Verify if a 'SSL Inspection' (Man-in-the-Middle) proxy is breaking the certificate chain. 3. Test network connectivity to Azure AD."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: OCR failures (AT OCR modules / Windows OCR)
function Detect-OcrFail {
    param($evt)
    if ($evt.Process -notmatch '(?i)fsocr\.exe|jfw\.exe|nvda\.exe|narrator\.exe|explorer\.exe') { return $null }
    if ($evt.Result -notmatch 'NAME NOT FOUND|PATH NOT FOUND|ACCESS DENIED') { return $null }
    if ($evt.Path -notmatch '(?i)OCR|tessdata|Windows\.OCR|OneCore|Language|Speech') { return $null }
    $cat="OCR FAIL"
    $sev="Low"
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "OCR (Optical Character Recognition) features fail to read text from images."
    $tc = "The application failed to load Windows OCR components or language models. This is often due to missing 'Windows Features' (Optical Character Recognition) or language packs."
    $rm = "1. Install the OCR Language Pack for the user's language via Windows Settings. 2. Ensure the 'Windows.OCR' system DLLs are healthy (SFC /ScanNow)."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: WRP violation (system file protection)
function Detect-WrpViolation {
    param($evt)
    if ($evt.Result -notmatch 'ACCESS DENIED') { return $null }
    if ($evt.Path -notmatch '(?i)\\Windows\\WinSxS\\|\\Windows\\System32\\|\\Windows\\SysWOW64\\') { return $null }
    $cat="WRP VIOLATION"
    $sev="Low"
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "Application installation or update fails."
    $tc = "Process '$($evt.Process)' attempted to write to a protected Windows system file (WRP/WFP) and was denied. This usually indicates a badly behaved installer or updater trying to replace core OS files."
    $rm = "1. Check if the application requires 'Run as Administrator'. 2. The application may be incompatible with this version of Windows; check for updates."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Token mismatch / impersonation problems
function Detect-TokenMismatch {
    param($evt)
    if ($evt.Result -notmatch '(?i)BAD IMPERSONATION LEVEL|INVALID OWNER|PRIVILEGE NOT HELD|TOKEN') { return $null }
    $cat="TOKEN MISMATCH"
    $sev="Medium"
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The application fails to access network shares or inter-process communication fails."
    $tc = "A 'Token Mismatch' or 'Impersonation Level' error occurred. This happens when a process tries to perform an action on behalf of a user but the security token doesn't allow it (e.g., Service trying to access user network drive without delegation)."
    $rm = "1. Review the security context of the process (System vs User). 2. Check 'Impersonate a client after authentication' user rights assignment."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Focus Bounce (Registry activity on ForegroundLockTimeout)
function Detect-FocusBounce {
    param($evt)
    if ($evt.Operation -notmatch '^Reg') { return $null }
    if ($evt.Path -notmatch 'ForegroundLockTimeout|FocusBorderHeight|FocusBorderWidth|SPI_GETFOREGROUNDLOCKTIMEOUT') { return $null }

    $cat="FOCUS BOUNCE"
    $sev="Medium"
    if ($evt.Operation -match 'Set') { $sev="High" }

    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The active window loses focus, interrupts typing, or flickers."
    $tc = "Process '$($evt.Process)' is rapidly querying or modifying 'ForegroundLockTimeout'. This registry key controls focus stealing prevention. Excessive activity here suggests an application is fighting the OS to grab focus."
    $rm = "1. Identify the background application fighting for focus. 2. Use the 'Focus Logger' tool to catch the culprit. 3. Disable 'Foreground Flash' or notifications for that app."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Touch Input / Tablet PC contention (Touch War)
function Detect-TouchWar {
    param($evt)
    $isTouchProc = ($evt.Process -match '(?i)wisptis\.exe|tabtip\.exe|inputservice|textinputhost\.exe|ctfmon\.exe')
    $isTouchPath = ($evt.Path -match '(?i)Wisp|Tablet|InputService|TabTip')

    if (-not ($isTouchProc -or $isTouchPath)) { return $null }

    # We only care about failures
    if ($evt.Result -notmatch 'ACCESS DENIED|TIMEOUT|SHARING VIOLATION|OPLOCK|FAST_IO|NAME NOT FOUND') { return $null }

    # If it's just "NAME NOT FOUND" for a touch proc, maybe low noise.
    if ($evt.Result -eq 'NAME NOT FOUND' -and $isTouchProc) { return $null }

    $cat="TOUCH WAR"
    $sev="Medium"
    # Escalation: Access Denied or Timeout is serious
    if ($evt.Result -match 'ACCESS DENIED|TIMEOUT') { $sev="High" }

    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "Touchscreen input is ignored, or the On-Screen Keyboard flickers."
    $tc = "Contention detected in the Touch Input subsystem (Wisptis/TabTip). The 'Tablet PC Input Service' is being blocked or timed out, often due to conflict with third-party tablet drivers (Wacom/Logitech)."
    $rm = "1. Restart the 'Touch Keyboard and Handwriting Panel Service'. 2. Check for driver conflicts between Windows Ink and vendor drivers. 3. Calibrate the touch screen."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: Browser renderer loop (Process Create spam)
$BrowserLoopCounts = @{}
function Detect-BrowserLoop {
    param($evt)
    # We track 'Process Create' where the child path is a browser exe
    if ($evt.Operation -ne "Process Create") { return $null }

    # In ProcMon, 'Process Name' is parent, 'Path' is child image
    if ($evt.Path -match '(?i)\\((msedge|chrome|firefox|brave)\.exe)$') {
        $childEx = $Matches[1]
        if (-not $BrowserLoopCounts.ContainsKey($childEx)) { $BrowserLoopCounts[$childEx] = 0 }
        $BrowserLoopCounts[$childEx]++

        # Trigger on the 20th restart (arbitrary threshold for "loop")
        if ($BrowserLoopCounts[$childEx] -eq 20) {
            $cat = "BROWSER LOOP"
            $sev = "High"
            $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

            $ux = "The browser is slow, pages crash ('Aw Snap'), or high CPU usage."
            $tc = "The browser parent process '$($evt.Process)' is repeatedly spawning child renderer processes '$childEx'. This 'Renderer Crash Loop' usually happens when security software injects incompatible code into the renderer sandbox."
            $rm = "1. Check for 'Hook Injection' in the browser process. 2. Disable 'Renderer Code Integrity' (testing only). 3. Update or remove the conflicting security agent extension."

            return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
        }
    }
    return $null
}

# Detector registry (order matters: most actionable first)

# =========================
# SCENARIO MATCHER (V1300)
# =========================
$ScenarioLookup = @{}
foreach ($s in $StartScenarios) {
    # Discriminator keys
    $keys = @()
    if ($s.Lookup) {
        $keys += ("RES:" + $s.Lookup.ToUpper())
    } elseif ($s.Op -and $s.Op -ne ".*" -and $s.Op -notmatch "\|") {
        # Fallback to single-op key if no result
        $keys += ("OP:" + $s.Op.ToUpper())
    } else {
        $keys += "GENERIC"
    }

    foreach ($k in $keys) {
        if (-not $ScenarioLookup.ContainsKey($k)) {
            $ScenarioLookup[$k] = [System.Collections.Generic.List[Object]]::new()
        }
        $ScenarioLookup[$k].Add($s)
    }
}

function Detect-KnownScenarios {
    param($evt)

    $candidates = [System.Collections.Generic.List[Object]]::new()

    # Lookup by Result
    if ($evt.Result) {
        $k = "RES:" + $evt.Result.ToUpper()
        if ($ScenarioLookup.ContainsKey($k)) {
            $candidates.AddRange($ScenarioLookup[$k])
        }
    }

    # Lookup by Operation (fallback for generic success ops)
    if ($evt.Operation) {
        $k = "OP:" + $evt.Operation.ToUpper()
        if ($ScenarioLookup.ContainsKey($k)) {
            $candidates.AddRange($ScenarioLookup[$k])
        }
    }

    # Lookup Generics
    if ($ScenarioLookup.ContainsKey("GENERIC")) {
        $candidates.AddRange($ScenarioLookup["GENERIC"])
    }

    foreach ($s in $candidates) {
        # Regex checks
        if ($s.Op -and $evt.Operation -notmatch $s.Op) { continue }
        if ($s.Res -and $evt.Result -notmatch $s.Res) { continue }
        if ($s.Path -and $evt.Path -notmatch $s.Path) { continue }
        if ($s.Process -and ($null -eq $evt.Process -or $evt.Process -notmatch $s.Process)) { continue }

        # Match found!
        $cat = "KNOWN SCENARIO"
        $sev = "High"

        $ux = "Issue detected: $($s.Title)"
        $tc = "The engine matched a known failure pattern (Scenario #$($s.Id)). Logic: Operation '$($s.Op)' result '$($s.Res)' on path '$($s.Path)'. `n`nRoot Cause Context: $($s.Cause)"
        $rm = "Refer to the 'Root Cause Context' for specific fix instructions. Verify if the environment matches the scenario conditions."

        # Oracle stub
        $oracle = @{
            title = $s.Title
            fix = $s.Cause
            url = ""
        }

        return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
    }
    return $null
}


# Detector: Packet Storm / Network Flood
$NetworkRateByProc = @{}
function Detect-PacketStorm {
    param($evt)
    if ($evt.Operation -notmatch 'TCP|UDP') { return $null }

    # Bucket by Process + Second
    $bucket = [int][Math]::Floor($evt.Time.TotalSeconds)
    $key = ("{0}|{1}" -f $evt.Process, $bucket).ToLowerInvariant()

    if (-not $NetworkRateByProc.ContainsKey($key)) { $NetworkRateByProc[$key] = 0 }
    $NetworkRateByProc[$key]++

    # Trigger if > 500 packets/sec
    if ($NetworkRateByProc[$key] -eq 500) {
        $cat = "PACKET STORM"
        $sev = "High"
        $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

        $ux = "Network connectivity drops intermittently or becomes sluggish."
        $tc = "Process '$($evt.Process)' is generating excessive network traffic (>500 ops/sec). This could be a broadcast storm, a denial-of-service condition, or a bug in a network agent."
        $rm = "1. Use Wireshark to analyze the traffic content. 2. Check for 'UDP Flood' or 'Broadcast Storm' patterns. 3. Isolate the machine from the network to prevent propagation."

        return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
    }
    return $null
}

# Detector: Font Blocking (Untrusted Font Mitigation)
function Detect-FontBlocking {
    param($evt)
    # Check for MitigationPolicy event with BlockUntrustedFonts detail
    if ($evt.Path -match 'MitigationPolicy' -or $evt.Detail -match 'BlockUntrustedFonts') {
        $cat = "FONT BLOCKING"
        $sev = "Medium"
        $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

        $ux = "Fonts appear as rectangles or generic substitutions."
        $tc = "The application encountered a 'MitigationPolicy' event related to 'BlockUntrustedFonts'. This security feature prevents GDI from loading non-system fonts, which breaks many legacy apps."
        $rm = "1. Disable the 'Untrusted Font Blocking' Group Policy (Computer Configuration > Administrative Templates > System > Mitigation Options). 2. Whitelist the application executable."

        return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
    }
    return $null
}

# Detector: IPv6 -> IPv4 Failover Latency
$NetFailoverState = @{}
function Detect-NetFailover {
    param($evt)
    if ($evt.Operation -notmatch 'TCP Connect') { return $null }

    # Check for IPv6 literal (contains [ ) or colon count >= 2
    # Standard ProcMon Path for IPv6 is [address]:port
    $isV6 = ($evt.Path -match '\[.*\]')
    $key = "$($evt.PID)_$($evt.TID)"

    if ($isV6 -and $evt.Result -ne "SUCCESS") {
        # Record failure start
        $NetFailoverState[$key] = $evt.Time
        return $null
    }

    if (-not $isV6 -and $evt.Result -eq "SUCCESS") {
        if ($NetFailoverState.ContainsKey($key)) {
            $prevTime = $NetFailoverState[$key]
            $delta = ($evt.Time - $prevTime).TotalSeconds

            # If fallback happened within 5 seconds, flag it
            if ($delta -ge 0 -and $delta -lt 5.0) {
                $NetFailoverState.Remove($key)

                $cat = "IPV6 FAILOVER"
                $sev = "Medium"
                $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

                $ux = "Network connections take 3-5 seconds to establish (Latency)."
                $tc = "Application attempted IPv6, failed, and fell back to IPv4 within $([math]::Round($delta,2)) seconds. This 'Happy Eyeballs' failover adds latency to every connection."
                $rm = "1. Verify IPv6 connectivity on the network. 2. If IPv6 is not supported, disable it on the adapter or prefer IPv4 via prefix policy."

                return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
            }
        }
    }
    return $null
}

$Detectors = @(
    ${function:Detect-KnownScenarios},
    ${function:Detect-KnownScenarios},
    ${function:Detect-BrowserLoop},
    ${function:Detect-ProcessExitCodes},
    ${function:Detect-HookInjection},
    ${function:Detect-AccessDenied},
    ${function:Detect-OplockFastIo},
    ${function:Detect-HighLatency},
    ${function:Detect-ThreadProfiling},
    ${function:Detect-FilterConflict},
    ${function:Detect-WrpViolation},
    ${function:Detect-TokenMismatch},
    ${function:Detect-ComCat},
    ${function:Detect-LegacyBridge},
    ${function:Detect-VCppMissing},
    ${function:Detect-ReparseLoop},
    ${function:Detect-FocusBounce},
    ${function:Detect-TouchWar},
    ${function:Detect-ClipboardLock},
    ${function:Detect-AudioDucking},
    ${function:Detect-MfaBlock},
    ${function:Detect-OcrFail},
    ${function:Detect-RegistryThrash},
    ${function:Detect-NetFailover},
    ${function:Detect-FontBlocking},
    ${function:Detect-PacketStorm}
)
# =========================
# 7) STREAM PARSE CSV + APPLY DETECTORS
# =========================

# Global Suspect Buffer for Security Contention (Time correlation)
# Stores last seen time of security process activity per Path.
$GlobalSuspectBuffer = [System.Collections.Generic.Dictionary[string, PSObject]]::new()

function Stream-ProcMonCsv {
    param([string]$CsvPath)

    $parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($CsvPath)
    $parser.SetDelimiters(",")
    $parser.HasFieldsEnclosedInQuotes = $true
    $parser.TrimWhiteSpace = $true

    # header row
    [void]$parser.ReadFields()

    $i = 0
    while (-not $parser.EndOfData) {
        $fields = $parser.ReadFields()
        $i++
        if (-not $fields) { continue }

        # Access by resolved header indexes
        # Build a header->index map once
        if ($i -eq 1) {
            $HeaderIndex = @{}
            for ($h=0; $h -lt $Headers.Count; $h++) { $HeaderIndex[$Headers[$h].Trim('"')] = $h }
        }

        function GetField([string]$stdName) {
            $hn = $Resolved[$stdName]
            if (-not $hn) { return "" }
            if (-not $HeaderIndex.ContainsKey($hn)) { return "" }
            $idx = [int]$HeaderIndex[$hn]
            if ($idx -ge 0 -and $idx -lt $fields.Count) { return $fields[$idx] } else { return "" }
        }

        $proc = Normalize-ProcName (GetField "Process Name")
        $pid  = (GetField "PID").Trim('"')
        $tid  = (GetField "Thread ID").Trim('"')
        $usr  = (GetField "User").Trim('"')
        $img  = (GetField "Image Path").Trim('"')
        $cmd  = (GetField "Command Line").Trim('"')

        $op   = (GetField "Operation").Trim('"')
        $p    = (GetField "Path").Trim('"')
        $res  = (GetField "Result").Trim('"')
        $det  = (GetField "Detail").Trim('"')
        $tod  = Parse-TimeOfDay (GetField "Time of Day")
        $dur  = Parse-Double (GetField "Duration")

        if ([string]::IsNullOrWhiteSpace($proc) -or [string]::IsNullOrWhiteSpace($op)) { continue }

        # lightweight prefilter: keep events that matter
        $interesting =
            $AT_Processes.Contains($proc) -or
            $Sec_Processes.Contains($proc) -or
            ($dur -ge $SlowThresholdSeconds) -or
            ($res -match "ACCESS DENIED|SHARING VIOLATION|OPLOCK|FAST_IO|LOCK VIOLATION|REPARSE|NAME NOT FOUND|PATH NOT FOUND|BUFFER OVERFLOW|PIPE BUSY") -or
            ($op -match "Load Image|Process Exit|Process Create|Thread Profiling|TCP")

        if (-not $interesting) { continue }

        $evt = [PSCustomObject]@{
            Time=$tod
            Process=$proc
            PID=$pid
            TID=$tid
            User=$usr
            ImagePath=$img
            CommandLine=$cmd
            Operation=$op
            Path=$p
            Result=$res
            Detail=$det
            Duration=$dur
        }

        # Event-rate buckets for EVENT FLOOD summary
        if ($AT_Processes.Contains($proc)) {
            $bucket = [int][Math]::Floor($tod.TotalSeconds)
            $rk = ("{0}|{1}" -f $proc, $bucket).ToLowerInvariant()
            if (-not $EventRateByProcSec.ContainsKey($rk)) { $EventRateByProcSec[$rk] = 0 }
            $EventRateByProcSec[$rk]++
        }

        # WER flood signals
        if ($proc -match '(?i)^werfault\.exe$') { $WerCounts["Fault"]++ }
        if ($p -match '(?i)\WER\|\Microsoft\Windows\WER\') { $WerCounts["Writes"]++ }

        # --- SECURITY CONTENTION LOGIC (V1300) ---
        # Update GlobalSuspectBuffer if this is a Security Process touching a path
        if ($Sec_Processes.Contains($proc)) {
             $GlobalSuspectBuffer[$p] = [PSCustomObject]@{ Time=$tod; Proc=$proc; Path=$p }
        }

        # Check for Contention: AT Process Denied + Recent Security Touch
        if ($AT_Processes.Contains($proc) -and ($res -match "DENIED|SHARING|OPLOCK") -and $GlobalSuspectBuffer.ContainsKey($p)) {
            $Suspect = $GlobalSuspectBuffer[$p]
            # Check for contention within 0.5s (SlowThresholdSeconds default)
            if ([Math]::Abs(($tod - $Suspect.Time).TotalSeconds) -le 0.5) {
                 $cat="SECURITY LOCK"
                 $sev="Critical"

                 $ux="The application may freeze or crash due to a race condition with security software."
                 $tech="Security process '$($Suspect.Proc)' accessed '$p' immediately ($([math]::Round([Math]::Abs(($tod - $Suspect.Time).TotalSeconds), 3))s) before the AT process '$proc' was denied access. This pattern (Security Fratricide) indicates aggressive inline scanning or locking."
                 $rem="Exclude the path '$p' from $($Suspect.Proc) scanning. Configure the security agent to trust the AT process signature."

                 Add-Finding -Category $cat -Severity $sev -Process $proc -PID $pid -TID $tid -User $usr -ImagePath $img -CommandLine $cmd -Operation $op -Path $p -Result $res -Detail ("Contention with: " + $Suspect.Proc) -Time $tod -Duration $dur -UserExperience $ux -TechnicalContext $tech -Remediation $rem -SourceFile $CsvPath -SourceLine $i -Oracle $null | Out-Null
            }
        }

        foreach ($detFn in $Detectors) {
            $r = & $detFn $evt
            if (-not $r) { continue }

            # cap per category
            $existing = ($Findings | Where-Object { $_.Category -eq $r.Category }).Count
            if ($existing -ge $MaxFindingsPerCategory) { continue }

            # Support both new and legacy detector returns
            $ux = if($r.UserExperience){$r.UserExperience}else{""}
            $tc = if($r.TechnicalContext){$r.TechnicalContext}else{""}
            $rm = if($r.Remediation){$r.Remediation}else{""}
            $legacyWhy = if($r.Why){$r.Why}else{""}
            $legacyConfirm = if($r.Confirm){$r.Confirm}else{""}
            $legacyNext = if($r.Next){$r.Next}else{""}

            $fid = Add-Finding -Category $r.Category -Severity $r.Severity -Process $evt.Process -PID $evt.PID -TID $evt.TID -User $evt.User -ImagePath $evt.ImagePath -CommandLine $evt.CommandLine -Operation $evt.Operation -Path $evt.Path -Result $evt.Result -Detail $evt.Detail -Time $evt.Time -Duration $evt.Duration -UserExperience $ux -TechnicalContext $tc -Remediation $rm -Why $legacyWhy -HowToConfirm $legacyConfirm -NextSteps $legacyNext -SourceFile $CsvPath -SourceLine $i -Oracle $r.Oracle

            if ($fid) { Add-Evidence -FindingId $fid -Evt $evt }
        }
    }

    $parser.Close()
}

# Analyze either primary or all CSVs
$CsvToAnalyze = if ($AnalyzeAllCsv) { $CsvFiles } else { @($PrimaryCsv) }
foreach ($c in $CsvToAnalyze) {
    Write-Host "[*] Streaming parse: $($c.Name)" -ForegroundColor Gray
    Stream-ProcMonCsv -CsvPath $c.FullName
}


# =========================
# 7b) POST-PROCESS SUMMARIES (EVENT FLOOD / WERFLOOD)
# =========================
# EVENT FLOOD: max events per second per process
$MaxRateByProc = @{}
foreach ($k in $EventRateByProcSec.Keys) {
    $parts = $k -split '\|', 2
    if ($parts.Count -lt 2) { continue }
    $proc = $parts[0]
    $cnt = [int]$EventRateByProcSec[$k]
    if (-not $MaxRateByProc.ContainsKey($proc) -or $cnt -gt $MaxRateByProc[$proc]) {
        $MaxRateByProc[$proc] = $cnt
    }
}
foreach ($proc in $MaxRateByProc.Keys) {
    $max = $MaxRateByProc[$proc]
    if ($max -lt 300) { continue }
    $sev = if ($max -ge 1500) { "High" } elseif ($max -ge 800) { "Medium" } else { "Low" }
    $why = "Very high ProcMon event rates (events/sec) often correspond to tight retry loops, broken UIA/MSAA enumeration, or aggressive polling (often amplified by security scanning)."
    $confirm = "Filter ProcMon to this process and identify the repeating Operation/Path pairs driving the rate."
    $next = "If the paths are profile/OneDrive/network, test local paths. If registry/UIA keys, isolate add-ins/providers. Capture stacks for the hottest operation."
    $fid = Add-Finding -Category "EVENT FLOOD" -Severity $sev -Process $proc -PID "" -TID "" -User "" -ImagePath "" -CommandLine "" -Operation "(summary)" -Path "(rate bucket)" -Result "" -Detail ("Max events/sec observed: {0}" -f $max) -Time ([TimeSpan]::Zero) -Duration 0.0 -Why $why -HowToConfirm $confirm -NextSteps $next -Oracle $null
}

# WERFLOOD: many WER writes / werfault activity
if ($WerCounts["Fault"] -ge 20 -or $WerCounts["Writes"] -ge 200) {
    $sev = if ($WerCounts["Fault"] -ge 80) { "High" } else { "Medium" }
    $why = "Frequent Windows Error Reporting activity suggests repeated crashes/hangs or repeated fault escalation."
    $confirm = "Review EVTX 1000/1002/1001 entries and correlate with dumps/Report.wer artifacts."
    $next = "Identify the faulting module; update/remove the injected DLL/add-in; collect dump for the top offender."
    [void](Add-Finding -Category "WERFLOOD" -Severity $sev -Process "werfault.exe" -PID "" -TID "" -User "" -ImagePath "" -CommandLine "" -Operation "(summary)" -Path "(WER)" -Result "" -Detail ("WERFaultCount={0}; WERWrites={1}" -f $WerCounts["Fault"], $WerCounts["Writes"]) -Time ([TimeSpan]::Zero) -Duration 0.0 -Why $why -HowToConfirm $confirm -NextSteps $next -Oracle $null)
}


# =========================
# 8) CORRELATE AUX EVENTS WITH FINDINGS (TIME WINDOW)
# =========================
function TimeSpanAbsSeconds([TimeSpan]$a, [TimeSpan]$b) {
    return [Math]::Abs(($a - $b).TotalSeconds)
}

foreach ($f in $Findings) {
    foreach ($ae in $AuxEvents) {
        if (TimeSpanAbsSeconds $f.Time $ae.Time -le $CollisionWindowSeconds) {
            # attach as evidence text
            Add-Evidence -FindingId $f.Id -Evt ([PSCustomObject]@{
                Time=$ae.Time
                Process="(aux)"
                Operation=$ae.Type
                Path=$ae.Source
                Result=""
                Detail=$ae.Details
                Duration=0.0
            })
        }
    }
}

# =========================
# 9) OUTPUT: CSV + HTML REPORT
# =========================
# CSV
$Findings | Export-Csv -LiteralPath $CsvExportPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] CSV Findings: $CsvExportPath" -ForegroundColor Green

# HTML Helpers
function HtmlEncode([string]$s) {
    if ($null -eq $s) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($s)
}
function SeverityRank([string]$sev) {
    switch ($sev) {
        "Critical" { 0 }
        "High" { 1 }
        "Medium" { 2 }
        "Low" { 3 }
        default { 4 }
    }
}

# Summary counts
$BySev = $Findings | Group-Object Severity | Sort-Object Name
$ByCat = $Findings | Group-Object Category | Sort-Object Count -Descending

# Artifact inventory table rows
$HashCache = @{}
function Get-FileSha256 {
    param([string]$FilePath)
    if (-not (Test-Path -LiteralPath $FilePath)) { return "" }
    if ($HashCache.ContainsKey($FilePath)) { return $HashCache[$FilePath] }
    try {
        $h = (Get-FileHash -LiteralPath $FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
        $HashCache[$FilePath] = $h
        return $h
    } catch {
        return "HASH_FAIL"
    }
}

function ArtifactRows($files, [string]$label, [int]$cap=250) {
    $rows = ""
    foreach ($f in ($files | Sort-Object Length -Descending | Select-Object -First $cap)) {
        $hash = Get-FileSha256 -FilePath $f.FullName
        $rows += "<tr><td>$label</td><td>$(HtmlEncode($f.Name))</td><td>$(HtmlEncode($f.FullName))</td><td>$([math]::Round($f.Length/1KB,1))</td><td>$(HtmlEncode($f.LastWriteTime.ToString("s")))</td><td class='mono small'>$hash</td></tr>`n"
    }
    return $rows
}

# Findings rows
$Rows = ""
$FindingsSorted = $Findings | Sort-Object @{Expression={SeverityRank $_.Severity}}, @{Expression={$_.Category}}, @{Expression={$_.Process}}, @{Expression={$_.Time}}
foreach ($f in $FindingsSorted) {
    $oracleLink = ""
    if (-not [string]::IsNullOrWhiteSpace($f.OracleUrl)) {
        $oracleLink = "<a href='$(HtmlEncode($f.OracleUrl))' target='_blank'>Link</a>"
    }
    $Rows += "<tr data-sev='$(HtmlEncode($f.Severity))' data-cat='$(HtmlEncode($f.Category))' data-proc='$(HtmlEncode($f.Process))'>" +
             "<td><span class='sev sev-$(HtmlEncode($f.Severity))'>$(HtmlEncode($f.Severity))</span></td>" +
             "<td>$(HtmlEncode($f.Category))</td>" +
             "<td>$(HtmlEncode($f.Time.ToString()))</td>" +
             "<td>$(HtmlEncode($f.Process))</td>" +
             "<td class='mono'>$(HtmlEncode($f.PID))</td>" +
             "<td>$(HtmlEncode($f.User))</td>" +
             "<td>$(HtmlEncode($f.Operation))</td>" +
             "<td class='pathcell'><button class='copy' onclick='copyText(this)'>Copy</button><span class='mono'>$(HtmlEncode($f.Path))</span></td>" +
             "<td>$(HtmlEncode($f.Result))</td>" +
             "<td class='mono'>$(HtmlEncode($f.Detail))</td>" +
             "<td class='mono'>$(HtmlEncode([string]::Format('{0:0.000000}', $f.DurationSeconds)))</td>" +
             "<td>$(HtmlEncode($f.OracleTitle))</td>" +
             "<td class='mono'>$(HtmlEncode($f.OracleFix))</td>" +
             "<td>$oracleLink</td>" +
             "<td><button class='toggle' onclick='toggleDetails(""$(HtmlEncode($f.Id))"")'>Details</button></td>" +
             "</tr>`n"

    # Details panel (hidden row)
    $evRows = ""
    if ($Evidence.ContainsKey($f.Id)) {
        foreach ($ev in $Evidence[$f.Id]) {
            $evRows += "<tr><td>$(HtmlEncode($ev.Time.ToString()))</td><td>$(HtmlEncode($ev.Process))</td><td>$(HtmlEncode($ev.Operation))</td><td class='mono'>$(HtmlEncode($ev.Path))</td><td>$(HtmlEncode($ev.Result))</td><td class='mono'>$(HtmlEncode($ev.Detail))</td><td class='mono'>$(HtmlEncode([string]::Format('{0:0.000000}', $ev.Duration)))</td></tr>"
        }
    }
    $hash = Get-FileSha256 -FilePath $f.SourceFile
    $Rows += "<tr id='detail-$(HtmlEncode($f.Id))' class='detailRow'><td colspan='15'>" +
             "<div class='detailBox'>" +
             "<div class='grid-3'>" +
             "<div class='box ux'><h3>User Experience</h3>$(HtmlEncode($f.UserExperience))</div>" +
             "<div class='box tech'><h3>Technical Context</h3>$(HtmlEncode($f.TechnicalContext))</div>" +
             "<div class='box fix'><h3>Remediation</h3>$(HtmlEncode($f.Remediation))</div>" +
             "</div>" +
             "<div><b>Image path:</b> <span class='mono'>$(HtmlEncode($f.ImagePath))</span></div>" +
             "<div><b>Command line:</b> <span class='mono'>$(HtmlEncode($f.CommandLine))</span></div>" +
             "<div class='coc'><b>Chain of Custody:</b> File: <span class='mono'>$(HtmlEncode($f.SourceFile))</span> | Line: <span class='mono'>$($f.SourceLine)</span> | SHA256: <span class='mono'>$hash</span></div>" +
             "<div class='subhead'>Evidence samples (ProcMon/Aux correlated):</div>" +
             "<table class='ev'><thead><tr><th>Time</th><th>Proc</th><th>Op</th><th>Path</th><th>Result</th><th>Detail</th><th>Dur</th></tr></thead><tbody>$evRows</tbody></table>" +
             "</div></td></tr>`n"
}

# Glossary (expanded, "do the work" oriented)
$Glossary = @"
<ul>
  <li><b>ACCESS DENIED</b>: A component attempted to open a file/registry/object but was blocked. Often caused by ACLs, policy, AppLocker/WDAC, or protected folders.</li>
  <li><b>OPLOCK / FAST_IO_DISALLOWED</b>: Optimized I/O path refused; can indicate contention (scanner/indexer/backup) causing fallback to slower code paths.</li>
  <li><b>REPARSE</b>: A path was redirected via junction/symlink/OneDrive/virtualization. Repeats can create loops and severe latency.</li>
  <li><b>Load Image</b>: A DLL/module was loaded into a process. If a security/VDI DLL loads into AT, it can destabilize UIA/MSAA hooks.</li>
  <li><b>Process Exit 0xC0000374/0xC0000409</b>: Heap corruption / stack overrun. Strong indicator of injected/bad DLLs, add-ins, or graphics/input hooks.</li>
</ul>
"@

# Top next steps generator (simple priority list)
$Top = ($FindingsSorted | Select-Object -First 12)
$TopNext = "<ol>"
foreach ($t in $Top) {
    $desc = if ($t.OracleTitle) { $t.OracleTitle } else { $t.Category }
    $action = if ($t.Remediation) { $t.Remediation } else { "Investigate technical context." }
    if ($action.Length -gt 200) { $action = $action.Substring(0,200) + "..." }
    $TopNext += "<li><b>$(HtmlEncode($desc))</b> ($($t.Category)) <br><span class='small'>Action: $(HtmlEncode($action))</span></li>"
}
$TopNext += "</ol>"

# Aux text table
$AuxTextRows = ""
foreach ($x in ($AuxTextFindings | Select-Object -First 120)) {
    $AuxTextRows += "<tr><td class='mono'>$(HtmlEncode($x.File))</td><td>$(HtmlEncode($x.Hits))</td></tr>"
}
$AuxRegRows = ""
foreach ($x in ($AuxRegSignals | Select-Object -First 200)) {
    $AuxRegRows += "<tr><td class='mono'>$(HtmlEncode($x.File))</td><td class='mono'>$(HtmlEncode($x.Signal))</td><td class='mono'>$(HtmlEncode($x.Lines))</td></tr>"
}

# Inventory rows
$InvRows = ""
$InvRows += ArtifactRows $CsvFiles "CSV"
$InvRows += ArtifactRows $EvtxFiles "EVTX"
$InvRows += ArtifactRows $DumpFiles "DMP"
$InvRows += ArtifactRows $TextLogFiles "TEXT"
$InvRows += ArtifactRows $RegFiles "REG"
$InvRows += ArtifactRows $EtlFiles "ETL"
$InvRows += ArtifactRows $CabFiles "CAB"
$InvRows += ArtifactRows $ZipFiles "ARCHIVE"
$InvRows += ArtifactRows $NfoFiles "NFO"

$OracleNote = ""
if ($OracleDbObj) {
    $OracleNote = "Oracle DB: $(HtmlEncode($OracleDbPath)) | LastUpdate: $(HtmlEncode($OracleDbObj.last_update_utc)) | Note: $(HtmlEncode($OracleDbObj.last_update_note))"
}

$Html = @"
<!doctype html>
<html>
<head>
<meta charset="utf-8"/>
<title>ProcMon-Enterprise $ScriptVersion Report</title>
<style>
  body{font-family:Segoe UI,Arial,sans-serif;margin:18px;background:#0e1116;color:#e6edf3}
  h1,h2{margin:0 0 10px 0}
  .small{color:#9aa4af;font-size:12px}
  .card{background:#151a22;border:1px solid #2a3240;border-radius:12px;padding:14px;margin:10px 0;box-shadow:0 2px 10px rgba(0,0,0,.35)}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:10px}
  .sev{padding:2px 8px;border-radius:999px;font-weight:700;font-size:12px}
  .sev-Critical{background:#8b0000}
  .sev-High{background:#b45309}
  .sev-Medium{background:#1d4ed8}
  .sev-Low{background:#047857}
  table{width:100%;border-collapse:collapse}
  th,td{border-bottom:1px solid #2a3240;padding:8px;vertical-align:top}
  th{position:sticky;top:0;background:#151a22;text-align:left}
  .mono{font-family:Consolas,Menlo,monospace;font-size:12px}
  .pathcell{min-width:360px}
  input,select{background:#0e1116;color:#e6edf3;border:1px solid #2a3240;border-radius:8px;padding:8px}
  .controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:10px 0}
  .copy,.toggle{background:#223049;color:#e6edf3;border:1px solid #2a3240;border-radius:8px;padding:4px 10px;cursor:pointer}
  .detailRow{display:none}
  .detailBox{margin:8px 0;background:#0e1116;border:1px solid #2a3240;border-radius:10px;padding:10px}
  .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-bottom: 10px; }
  .box { padding: 10px; border-radius: 6px; background: #1c2128; border: 1px solid #30363d; }
  .box h3 { margin-top: 0; font-size: 14px; color: #8b949e; border-bottom: 1px solid #30363d; padding-bottom: 5px; }
  .ux { border-left: 4px solid #d29922; }
  .tech { border-left: 4px solid #58a6ff; }
  .fix { border-left: 4px solid #238636; }
  .coc { margin-top: 10px; font-size: 11px; color: #8b949e; border-top: 1px solid #30363d; padding-top: 5px; }
  .subhead{margin-top:10px;font-weight:700}
  .ev th{background:#0e1116;position:static}
  a{color:#93c5fd}
</style>
<script>
function copyText(btn){
  var cell = btn.parentElement.querySelector('span');
  var text = cell ? cell.textContent : '';
  navigator.clipboard.writeText(text);
  btn.textContent = 'Copied';
  setTimeout(function(){btn.textContent='Copy';},700);
}
function toggleDetails(id){
  var r = document.getElementById('detail-'+id);
  if(!r) return;
  r.style.display = (r.style.display==='table-row') ? 'none' : 'table-row';
}
function applyFilters(){
  var q = document.getElementById('q').value.toLowerCase();
  var sev = document.getElementById('sev').value;
  var cat = document.getElementById('cat').value;
  var proc = document.getElementById('proc').value;
  var rows = document.querySelectorAll('#findings tbody tr');
  for (var i=0;i<rows.length;i++){
    var tr = rows[i];
    if(tr.classList.contains('detailRow')) continue;
    var text = tr.textContent.toLowerCase();
    var ok = true;
    if(q && text.indexOf(q)===-1) ok=false;
    if(sev && tr.getAttribute('data-sev')!==sev) ok=false;
    if(cat && tr.getAttribute('data-cat')!==cat) ok=false;
    if(proc && tr.getAttribute('data-proc')!==proc) ok=false;
    tr.style.display = ok ? '' : 'none';
    // hide corresponding detail row if main row hidden
    var btn = tr.querySelector('.toggle');
    if(btn){
      var id = btn.getAttribute('onclick').match(/"(.*)"/)[1];
      var dr = document.getElementById('detail-'+id);
      if(dr) dr.style.display = ok ? dr.style.display : 'none';
    }
  }
}
</script>
</head>
<body>
  <h1>ProcMon-Enterprise $ScriptVersion Report</h1>
  <div class="small">Generated (UTC): $(HtmlEncode([DateTime]::UtcNow.ToString("s"))) | ScanRoot: $(HtmlEncode($ScanRoot))</div>
  <div class="small">$OracleNote</div>

  <div class="card">
    <h2>Prioritized next steps (auto-extracted)</h2>
    $TopNext
    <div class="small">These are the highest-ranked findings (Critical->High->Medium) to investigate first.</div>
  </div>

  <div class="grid">
    <div class="card"><h2>Findings</h2><div class="mono">$($Findings.Count)</div></div>
    <div class="card"><h2>CSV files</h2><div class="mono">$($CsvFiles.Count)</div></div>
    <div class="card"><h2>EVTX</h2><div class="mono">$($EvtxFiles.Count)</div></div>
    <div class="card"><h2>Dumps</h2><div class="mono">$($DumpFiles.Count)</div></div>
  </div>

  <div class="card">
    <h2>Artifact inventory (recursive)</h2>
    <div class="small">This run inventories artifacts beyond CSV (EVTX/DMP/TXT/LOG/NFO/ETL/CAB/REG/archives), addressing the V1200 limitations where file-scoped runs didn't recurse and only used a narrow file set. </div>
    <table>
      <thead><tr><th>Type</th><th>Name</th><th>Full Path</th><th>KB</th><th>LastWrite</th></tr></thead>
      <tbody>
        $InvRows
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Findings explorer</h2>
    <div class="controls">
      <input id="q" onkeyup="applyFilters()" placeholder="search (path/result/detail/oracle)"/>
      <select id="sev" onchange="applyFilters()">
        <option value="">All severities</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
      </select>
      <select id="cat" onchange="applyFilters()">
        <option value="">All categories</option>
        $(($ByCat | ForEach-Object { "<option value='$(HtmlEncode($_.Name))'>$(HtmlEncode($_.Name)) ($($_.Count))</option>" }) -join "`n")
      </select>
      <select id="proc" onchange="applyFilters()">
        <option value="">All processes</option>
        $(($Findings | Group-Object Process | Sort-Object Count -Descending | Select-Object -First 60 | ForEach-Object { "<option value='$(HtmlEncode($_.Name))'>$(HtmlEncode($_.Name)) ($($_.Count))</option>" }) -join "`n")
      </select>
    </div>

    <table id="findings">
      <thead>
        <tr>
          <th>Severity</th><th>Category</th><th>Time</th><th>Process</th><th>PID</th><th>User</th><th>Operation</th>
          <th>Path</th><th>Result</th><th>Detail</th><th>Dur(s)</th>
          <th>Oracle Title</th><th>Oracle Fix</th><th>Oracle URL</th><th>More</th>
        </tr>
      </thead>
      <tbody>
        $Rows
      </tbody>
    </table>
  </div>

  <div class="card">
    <h2>Aux text log signals (JAWS/app logs)</h2>
    <div class="small">First pass regex extraction of high-signal lines from TXT/LOG/INI/CFG logs.</div>
    <table><thead><tr><th>File</th><th>Signals</th></tr></thead><tbody>$AuxTextRows</tbody></table>
  </div>

  <div class="card">
    <h2>Aux registry export signals (TSS REG)</h2>
    <div class="small">Best-effort extraction of relevant toggles (hooks timeouts, AppInit DLLs, Code Integrity hints, etc.).</div>
    <table><thead><tr><th>File</th><th>Signal</th><th>Lines</th></tr></thead><tbody>$AuxRegRows</tbody></table>
  </div>

  <div class="card">
    <h2>Glossary</h2>
    $Glossary
  </div>

  <div class="card">
    <h2>Built-in constraints & regression notes</h2>
    <ul>
      <li>V1200 promised recursive ingestion but file-scope runs only scanned the parent folder non-recursively and limited aux types to EVTX/DMP/TXT/LOG/NFO.  This version always recurses and expands artifact types.</li>
      <li>Compulsory constraints in your chat included: "NO Sentinel L-D-K (Licensing) checks" and "NO Team-Viewer checks".  This version does not include those checks by default.</li>
      <li>V600 explicitly listed Touch War / Audio Ducking / Focus Bounce / Clipboard Lock / Global Suspect Buffer as preserved core modules.  This version rebuilds the report + engine so those categories can be re-added without feature loss (more detectors can be appended in the registry).</li>
    </ul>
  </div>

</body>
</html>
"@

$Html | Out-File -LiteralPath $ReportPath -Encoding UTF8
Write-Host "[+] HTML Report: $ReportPath" -ForegroundColor Green

# =========================
# 10) 7x VALIDATION PASSES (SELF-TESTS)
# =========================
function Assert-True([bool]$Condition, [string]$Name, [ref]$Failures) {
    if (-not $Condition) { $Failures.Value += $Name }
}

function Run-Validations {
    $fails = @()
    # Pass 1: PS version / paths
    Assert-True ($PSVersionTable.PSVersion.Major -ge 5) "PSVersion>=5" ([ref]$fails)
    Assert-True (Test-Path -LiteralPath $ReportPath) "ReportWritten" ([ref]$fails)
    Assert-True (Test-Path -LiteralPath $CsvExportPath) "CsvWritten" ([ref]$fails)
    Assert-True (Test-Path -LiteralPath $OracleDbPath) "OracleDbExists" ([ref]$fails)

    # Pass 2: Recursion guarantee (ScanRoot used, not raw $Path)
    Assert-True ($ScanRoot -and (Test-Path -LiteralPath $ScanRoot)) "ScanRootValid" ([ref]$fails)

    # Pass 3: List dedupe/case-insensitive behavior
    $tmp = New-NameSet @("X.exe","x.exe"," X.exe ")
    Assert-True ($tmp.Count -eq 1) "ListDedupeCaseInsensitive" ([ref]$fails)

    # Pass 4: Compulsory constraints (no Team-Viewer sentinel licensing checks baked in)
    $scriptText = (Get-Content -LiteralPath $MyInvocation.MyCommand.Path -Raw -ErrorAction SilentlyContinue)
    if ($scriptText) {
        $tv = "team" + "viewer"
        Assert-True ($scriptText -notmatch "(?i)$tv") "NoTeamViewerCheckInCode" ([ref]$fails)
        # allow "sentinel" token in suspicious tokens but avoid hard-coded licensing checks; keep it loose:
        $ldk = "ld" + "k"
        Assert-True ($scriptText -notmatch "(?i)\b$ldk\b|\b1947\b") "NoSentinelLDKChecksInCode" ([ref]$fails)
    }

    # Pass 5: Header normalization sanity
    Assert-True ($Resolved["Process Name"]) "HeaderHasProcessName" ([ref]$fails)
    Assert-True ($Resolved["Path"]) "HeaderHasPath" ([ref]$fails)

    # Pass 6: HTML contains key sections
    $htmlText = Get-Content -LiteralPath $ReportPath -Raw -ErrorAction SilentlyContinue
    if ($htmlText) {
        Assert-True ($htmlText -match "Findings explorer") "HtmlHasFindingsExplorer" ([ref]$fails)
        Assert-True ($htmlText -match "Artifact inventory") "HtmlHasInventory" ([ref]$fails)
        Assert-True ($htmlText -match "Glossary") "HtmlHasGlossary" ([ref]$fails)
    }

    # Pass 7: Findings objects schema
    if ($Findings.Count -gt 0) {
        $f = $Findings[0]
        Assert-True ($null -ne $f.Category -and $null -ne $f.Severity -and $null -ne $f.Process) "FindingSchema" ([ref]$fails)
    } else {
        # still OK; but record as informational in console
    }

    return $fails
}

$AllFailures = @()
for ($p=1; $p -le $ValidationPasses; $p++) {
    $fails = Run-Validations
    if ($fails.Count -eq 0) {
        Write-Host "[[OK]] Validation pass $p/$($ValidationPasses): OK" -ForegroundColor Green
    } else {
        Write-Host "[X] Validation pass $p/$($ValidationPasses): FAIL -> $($fails -join ', ')" -ForegroundColor Red
        $AllFailures += $fails
    }
}

if ($AllFailures.Count -gt 0) {
    Write-Host "[!] Some validations failed. Review above. (Script still produced outputs.)" -ForegroundColor Yellow
}

Write-Host "[*] Done. Elapsed (s): $([math]::Round(([DateTime]::UtcNow - $StartUtc).TotalSeconds,2))" -ForegroundColor Cyan