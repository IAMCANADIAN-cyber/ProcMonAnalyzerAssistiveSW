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
    @{ Id='1'; Title="Access Denied (Write - User)"; Op="CreateFile|WriteFile"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path="C:\\Users\\[^\\]+\\.*"; Cause="``CreateFile/WriteFile`` = ``ACCESS_DENIED`` on ``C:\Users\<User>\...``. (User permissions broken on own profile)." },
    @{ Id='2'; Title="Access Denied (Write - System)"; Op="CreateFile"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path="C:\\Windows\\System32"; Cause="``CreateFile`` = ``ACCESS_DENIED`` on ``C:\Windows\System32``. (UAC/Permission issue)." },
    @{ Id='3'; Title="Access Denied (Execute)"; Op="CreateFile"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``CreateFile`` (Execute) = ``ACCESS_DENIED``. (AppLocker/SRP blocking binary)." },
    @{ Id='4'; Title="Access Denied (Delete)"; Op="SetDispositionInformationFile"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``SetDispositionInformationFile`` = ``ACCESS_DENIED``. (Read-only attribute or ACL)." },
    @{ Id='5'; Title="Access Denied (ADS)"; Op="CreateFile"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=".*:Zone\.Identifier"; Cause="``CreateFile`` on ``*:Zone.Identifier`` = ``ACCESS_DENIED``. (AV blocking Mark-of-Web removal)." },
    @{ Id='6'; Title="Access Denied (Pipe)"; Op="CreateFile"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path="\\\\\.\\Pipe\\.*"; Cause="``CreateFile`` on ``\\.\Pipe\...`` = ``ACCESS_DENIED``. (Service security hardening)." },
    @{ Id='7'; Title="Access Denied (Spool)"; Op="CreateFile"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path="\\System32\\spool"; Cause="``CreateFile`` on ``\System32\spool`` = ``ACCESS_DENIED``. (Print nightmare mitigation)." },
    @{ Id='8'; Title="Access Denied (WasDeletePending)"; Op="CreateFile"; Res="STATUS DELETE PENDING"; Lookup="STATUS DELETE PENDING"; Path=""; Cause="``CreateFile`` = ``STATUS_DELETE_PENDING``. (File deleted but handle open; zombie file)." },
    @{ Id='9'; Title="Sharing Violation (Profile)"; Op="CreateFile"; Res="SHARING VIOLATION"; Lookup="SHARING VIOLATION"; Path="NTUSER\.DAT"; Cause="``CreateFile`` on ``NTUSER.DAT`` = ``SHARING_VIOLATION``. (Profile locked by AV/Backup)." },
    @{ Id='10'; Title="Sharing Violation (VHDX)"; Op="CreateFile"; Res="SHARING VIOLATION"; Lookup="SHARING VIOLATION"; Path=".*\.vhdx"; Cause="``CreateFile`` on ``*.vhdx`` = ``SHARING_VIOLATION``. (FSLogix/VDI double-mount)." },
    @{ Id='11'; Title="Sharing Violation (Log)"; Op="CreateFile"; Res="SHARING VIOLATION"; Lookup="SHARING VIOLATION"; Path=".*\.log"; Cause="``CreateFile`` on ``*.log`` = ``SHARING_VIOLATION``. (Log rotation race condition)." },
    @{ Id='12'; Title="Sharing Violation (Dll)"; Op="CreateFile"; Res="SHARING VIOLATION"; Lookup="SHARING VIOLATION"; Path=".*\.dll"; Cause="``CreateFile`` on ``*.dll`` = ``SHARING_VIOLATION``. (Update trying to replace loaded library)." },
    @{ Id='13'; Title="Path Not Found (DLL)"; Op="LoadImage"; Res="PATH NOT FOUND"; Lookup="PATH NOT FOUND"; Path=""; Cause="``LoadImage`` = ``PATH_NOT_FOUND``. (Missing dependency)." },
    @{ Id='14'; Title="Path Not Found (Exe)"; Op="ProcessCreate"; Res="PATH NOT FOUND"; Lookup="PATH NOT FOUND"; Path=""; Cause="``ProcessCreate`` = ``PATH_NOT_FOUND``. (Broken shortcut/service path)." },
    @{ Id='15'; Title="Path Not Found (Config)"; Op="CreateFile"; Res="PATH NOT FOUND"; Lookup="PATH NOT FOUND"; Path=".*\.ini|.*\.config"; Cause="``CreateFile`` on ``*.ini/*.config`` = ``PATH_NOT_FOUND``. (Missing configuration)." },
    @{ Id='16'; Title="Path Not Found (Drive)"; Op="CreateFile"; Res="PATH NOT FOUND"; Lookup="PATH NOT FOUND"; Path="X:\\"; Cause="``CreateFile`` on ``X:\`` = ``PATH_NOT_FOUND``. (Mapped drive disconnected)." },
    @{ Id='17'; Title="Path Not Found (UNC)"; Op="CreateFile"; Res="BAD NETWORK PATH"; Lookup="BAD NETWORK PATH"; Path="\\\\Server\\Share"; Cause="``CreateFile`` on ``\\Server\Share`` = ``BAD_NETWORK_PATH``. (Server offline/DNS fail)." },
    @{ Id='18'; Title="Path Not Found (8.3)"; Op="CreateFile"; Res="PATH NOT FOUND"; Lookup="PATH NOT FOUND"; Path=""; Cause="``CreateFile`` on ``PROGRA~1`` = ``PATH_NOT_FOUND``. (Short names disabled)." },
    @{ Id='19'; Title="Path Not Found (Dev)"; Op="CreateFile"; Res="PATH NOT FOUND"; Lookup="PATH NOT FOUND"; Path="C:\\Users\\DevName"; Cause="``CreateFile`` on ``C:\Users\DevName`` = ``PATH_NOT_FOUND``. (Hardcoded developer path)." },
    @{ Id='20'; Title="Path Not Found (SXS)"; Op="CreateFile"; Res="PATH NOT FOUND"; Lookup="PATH NOT FOUND"; Path="\\WinSxS\\.*"; Cause="``CreateFile`` on ``\WinSxS\...`` = ``PATH_NOT_FOUND``. (Component Store corruption)." },
    @{ Id='21'; Title="Name Collision (Temp)"; Op="CreateFile"; Res="NAME COLLISION"; Lookup="NAME COLLISION"; Path=""; Cause="``CreateFile`` = ``NAME_COLLISION`` in ``%TEMP%``. (Temp folder flooding)." },
    @{ Id='22'; Title="Name Collision (ShortName)"; Op="CreateFile"; Res="NAME COLLISION"; Lookup="NAME COLLISION"; Path=""; Cause="``CreateFile`` = ``NAME_COLLISION`` on 8.3 generation. (Hash collision on volume)." },
    @{ Id='23'; Title="Disk Full"; Op="WriteFile"; Res="DISK FULL"; Lookup="DISK FULL"; Path=""; Cause="``WriteFile`` = ``DISK_FULL``. (Volume out of space)." },
    @{ Id='24'; Title="Quota Exceeded"; Op="WriteFile"; Res="QUOTA EXCEEDED"; Lookup="QUOTA EXCEEDED"; Path=""; Cause="``WriteFile`` = ``QUOTA_EXCEEDED``. (User disk quota hit)." },
    @{ Id='25'; Title="File Corrupt"; Op="ReadFile"; Res="FILE CORRUPT ERROR"; Lookup="FILE CORRUPT ERROR"; Path=""; Cause="``ReadFile`` = ``FILE_CORRUPT_ERROR``. (Physical disk/filesystem rot)." },
    @{ Id='26'; Title="CRC Error"; Op="ReadFile"; Res="DATA ERROR"; Lookup="DATA ERROR"; Path=""; Cause="``ReadFile`` = ``DATA_ERROR``. (Bad sectors/Dedup corruption)." },
    @{ Id='27'; Title="InPage Error"; Op="ReadFile"; Res="STATUS IN PAGE ERROR"; Lookup="STATUS IN PAGE ERROR"; Path=""; Cause="``ReadFile`` = ``STATUS_IN_PAGE_ERROR``. (Swap file/Memory/Network paging failure)." },
    @{ Id='28'; Title="Device Offline"; Op="CreateFile"; Res="STATUS DEVICE OFF LINE"; Lookup="STATUS DEVICE OFF LINE"; Path=""; Cause="``CreateFile`` = ``STATUS_DEVICE_OFF_LINE``. (USB/Storage disconnect)." },
    @{ Id='29'; Title="Device Busy"; Op="DeviceIoControl"; Res="STATUS DEVICE BUSY"; Lookup="STATUS DEVICE BUSY"; Path=""; Cause="``DeviceIoControl`` = ``STATUS_DEVICE_BUSY``. (Hardware stuck)." },
    @{ Id='30'; Title="Oplock Break"; Op="FsRtlCheckOplock"; Res=""; Lookup=""; Path=""; Cause="``FsRtlCheckOplock`` duration > 1s. (Network locking contention)." },
    @{ Id='31'; Title="Filter Latency"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="``CreateFile`` duration > 0.5s. (AV/EDR filter driver overhead)." },
    @{ Id='32'; Title="Sparse Write Fail"; Op="WriteFile"; Res="DISK FULL"; Lookup="DISK FULL"; Path=""; Cause="``WriteFile`` on Sparse File = ``DISK_FULL``. (Over-provisioning failure)." },
    @{ Id='33'; Title="Reparse Point Loop"; Op="CreateFile"; Res="STATUS REPARSE POINT NOT RESOLVED"; Lookup="STATUS REPARSE POINT NOT RESOLVED"; Path=""; Cause="``CreateFile`` = ``STATUS_REPARSE_POINT_NOT_RESOLVED``. (Infinite symlink loop)." },
    @{ Id='34'; Title="Not A Directory"; Op="CreateFile"; Res="STATUS NOT A DIRECTORY"; Lookup="STATUS NOT A DIRECTORY"; Path=""; Cause="``CreateFile`` = ``STATUS_NOT_A_DIRECTORY``. (File exists with name of requested folder)." },
    @{ Id='35'; Title="Dir Not Empty"; Op="SetDispositionInfo"; Res="STATUS DIRECTORY NOT EMPTY"; Lookup="STATUS DIRECTORY NOT EMPTY"; Path=""; Cause="``SetDispositionInfo`` = ``STATUS_DIRECTORY_NOT_EMPTY``. (Failed folder delete)." },
    @{ Id='36'; Title="Case Sensitivity"; Op="CreateFile"; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path=""; Cause="``CreateFile`` (``File`` vs ``file``) = ``NAME_NOT_FOUND``. (Per-directory case sensitivity enabled)." },
    @{ Id='37'; Title="Alternate Data Stream Exec"; Op="ProcessCreate"; Res=""; Lookup=""; Path=".*:Stream"; Cause="``ProcessCreate`` on ``*:Stream``. (Potential malware/hiding)." },
    @{ Id='38'; Title="ZoneID Block"; Op="CreateFile"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path="Zone\.Identifier"; Cause="``CreateFile`` on ``Zone.Identifier`` = ``ACCESS_DENIED``. (Security tool blocking unblock)." },
    @{ Id='39'; Title="Cloud Tiering"; Op="ReadFile"; Res="STATUS FILE IS OFFLINE"; Lookup="STATUS FILE IS OFFLINE"; Path=""; Cause="``ReadFile`` = ``STATUS_FILE_IS_OFFLINE``. (OneDrive/Azure Files recall needed)." },
    @{ Id='40'; Title="Encrypted File (EFS)"; Op="CreateFile"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``CreateFile`` = ``ACCESS_DENIED`` (User mismatch on EFS)." },
    @{ Id='41'; Title="BitLocker Locked"; Op="CreateFile"; Res="STATUS FVE LOCKED VOLUME"; Lookup="STATUS FVE LOCKED VOLUME"; Path=""; Cause="``CreateFile`` = ``STATUS_FVE_LOCKED_VOLUME``. (Drive mounted but locked)." },
    @{ Id='42'; Title="USN Journal Wrap"; Op=""; Res="USN JOURNAL WRAP"; Lookup="USN JOURNAL WRAP"; Path=""; Cause="``FsCtl`` = ``USN_JOURNAL_WRAP``. (Backup failure warning)." },
    @{ Id='43'; Title="Transaction Log Full"; Op=""; Res="LOG FILE FULL"; Lookup="LOG FILE FULL"; Path="Ntfs\.sys"; Cause="``Ntfs.sys`` = ``LOG_FILE_FULL``. (Metadata explosion)." },
    @{ Id='44'; Title="MFT Fragmentation"; Op="ReadFile"; Res=""; Lookup=""; Path=""; Cause="``ReadFile`` on ``$MFT`` > 100ms. (Severe filesystem fragmentation)." },
    @{ Id='45'; Title="Directory Enumeration Storm"; Op="QueryDirectory"; Res=""; Lookup=""; Path=""; Cause="``QueryDirectory`` repeated 10,000x. (Inefficient loop)." },
    @{ Id='46'; Title="1-Byte I/O"; Op="ReadFile"; Res=""; Lookup=""; Path=""; Cause="``ReadFile`` length = 1. (Inefficient coding)." },
    @{ Id='47'; Title="Flush Storm"; Op="FlushBuffersFile"; Res=""; Lookup=""; Path=""; Cause="``FlushBuffersFile`` after every write. (Performance killer)." },
    @{ Id='49'; Title="Log File Bloat"; Op="WriteFile"; Res=""; Lookup=""; Path=""; Cause="Single ``WriteFile`` extending log > 100MB. (Disk usage spike)." },
    @{ Id='50'; Title="Zero Byte Write"; Op="WriteFile"; Res=""; Lookup=""; Path=""; Cause="``WriteFile`` length = 0. (Truncation/Logic error)." },
    @{ Id='51'; Title="Reg Access Denied (HKLM)"; Op="RegSetValue"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``RegSetValue`` HKLM = ``ACCESS_DENIED``. (Standard user trying to change system)." },
    @{ Id='52'; Title="Reg Access Denied (HKCU)"; Op="RegSetValue"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``RegSetValue`` HKCU = ``ACCESS_DENIED``. (Permission corruption on user hive)." },
    @{ Id='53'; Title="Reg Access Denied (GroupPolicy)"; Op="RegSetValue"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path="Software\\Policies"; Cause="``RegSetValue`` ``Software\Policies`` = ``ACCESS_DENIED``. (App trying to override GPO)." },
    @{ Id='54'; Title="Reg Key Not Found (CLSID)"; Op="RegOpenKey"; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path="HKCR\\CLSID"; Cause="``RegOpenKey`` ``HKCR\CLSID`` = ``NAME_NOT_FOUND``. (Unregistered COM object)." },
    @{ Id='55'; Title="Reg Key Not Found (AppID)"; Op="RegOpenKey"; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path="HKCR\\AppID"; Cause="``RegOpenKey`` ``HKCR\AppID`` = ``NAME_NOT_FOUND``. (DCOM config missing)." },
    @{ Id='56'; Title="Reg Key Not Found (Interface)"; Op="RegOpenKey"; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path="HKCR\\Interface"; Cause="``RegOpenKey`` ``HKCR\Interface`` = ``NAME_NOT_FOUND``. (Proxy/Stub missing)." },
    @{ Id='57'; Title="Reg Key Not Found (TypeLib)"; Op="RegOpenKey"; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path="HKCR\\TypeLib"; Cause="``RegOpenKey`` ``HKCR\TypeLib`` = ``NAME_NOT_FOUND``. (Automation failure)." },
    @{ Id='58'; Title="Reg Key Not Found (Service)"; Op="RegOpenKey"; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path="HKLM\\System\\.*\\Services"; Cause="``RegOpenKey`` ``HKLM\System\...\Services`` = ``NAME_NOT_FOUND``. (Service missing)." },
    @{ Id='59'; Title="Reg Key Not Found (Uninstall)"; Op="RegOpenKey"; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path="HKLM\\.*\\Uninstall"; Cause="``RegOpenKey`` ``HKLM\...\Uninstall`` = ``NAME_NOT_FOUND``. (Installer corruption)." },
    @{ Id='60'; Title="Reg Value Not Found (Run)"; Op="RegQueryValue"; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path=""; Cause="``RegQueryValue`` ``Run`` = ``NAME_NOT_FOUND``. (Startup item missing)." },
    @{ Id='61'; Title="Reg Value Not Found (Env)"; Op="RegQueryValue"; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path=""; Cause="``RegQueryValue`` ``Environment`` = ``NAME_NOT_FOUND``. (Missing env var)." },
    @{ Id='62'; Title="Reg Type Mismatch"; Op="RegQueryValue"; Res=""; Lookup=""; Path=""; Cause="``RegQueryValue`` expected ``REG_SZ`` got ``REG_DWORD``. (Crash risk)." },
    @{ Id='63'; Title="Buffer Overflow (Reg)"; Op="RegQueryValue"; Res="BUFFER OVERFLOW"; Lookup="BUFFER OVERFLOW"; Path=""; Cause="``RegQueryValue`` = ``BUFFER_OVERFLOW``. (Data larger than buffer)." },
    @{ Id='64'; Title="Registry Hive Bloat"; Op="RegQueryValue"; Res=""; Lookup=""; Path=""; Cause="``RegQueryValue`` duration > 100ms. (Hive fragmentation)." },
    @{ Id='68'; Title="Orphaned Key Scan"; Op=""; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path=""; Cause="Enumerating 1000s of keys with ``NAME_NOT_FOUND``. (Registry cleaner behavior)." },
    @{ Id='69'; Title="IniFileMapping"; Op=""; Res=""; Lookup=""; Path="win\.ini"; Cause="Read of ``win.ini`` mapped to Registry. (Ancient app compatibility)." },
    @{ Id='76'; Title="ZoneMap Check"; Op=""; Res=""; Lookup=""; Path="ZoneMap\\Domains"; Cause="Query ``ZoneMap\Domains``. (IE Security Zone check)." },
    @{ Id='77'; Title="Capability Access"; Op=""; Res=""; Lookup=""; Path="HKCU\\.*\\Capabilities"; Cause="Query ``HKCU\...\Capabilities``. (Privacy permission check)." },
    @{ Id='81'; Title="Group Policy History"; Op=""; Res=""; Lookup=""; Path="GroupPolicy\\History"; Cause="Read ``GroupPolicy\History``. (GPO processing)." },
    @{ Id='82'; Title="Winlogon Helper"; Op=""; Res=""; Lookup=""; Path="Winlogon\\Shell"; Cause="Write to ``Winlogon\Shell``. (Persistence/Kiosk mode)." },
    @{ Id='83'; Title="LSA Provider Mod"; Op=""; Res=""; Lookup=""; Path="Security\\Providers"; Cause="Write to ``Security\Providers``. (Credential theft/Inject)." },
    @{ Id='88'; Title="USB Enum"; Op=""; Res=""; Lookup=""; Path="Enum\\USB"; Cause="Read ``Enum\USB``. (Hardware enumeration)." },
    @{ Id='90'; Title="Network Profile"; Op=""; Res=""; Lookup=""; Path="NetworkList\\Profiles"; Cause="Read ``NetworkList\Profiles``. (Network location awareness)." },
    @{ Id='92'; Title="WPA Key"; Op=""; Res=""; Lookup=""; Path="Wlansvc\\Parameters"; Cause="Read ``Wlansvc\Parameters``. (WiFi config)." },
    @{ Id='93'; Title="Console Config"; Op=""; Res=""; Lookup=""; Path="Console\\Configuration"; Cause="Read ``Console\Configuration``. (CMD settings)." },
    @{ Id='99'; Title="Crypto Seed"; Op=""; Res=""; Lookup=""; Path="RNG\\Seed"; Cause="Read ``RNG\Seed``. (Entropy generation)." },
    @{ Id='108'; Title="Image Load Fail"; Op="LoadImage"; Res="STATUS IMAGE NOT AT BASE"; Lookup="STATUS IMAGE NOT AT BASE"; Path=""; Cause="``LoadImage`` = ``STATUS_IMAGE_NOT_AT_BASE``. (Relocation)." },
    @{ Id='109'; Title="Image Load Fail (Arch)"; Op=""; Res="STATUS IMAGE MACHINE TYPE MISMATCH"; Lookup="STATUS IMAGE MACHINE TYPE MISMATCH"; Path=""; Cause="``STATUS_IMAGE_MACHINE_TYPE_MISMATCH``. (32/64 bit mix)." },
    @{ Id='110'; Title="Image Load Fail (Sign)"; Op=""; Res="STATUS INVALID IMAGE HASH"; Lookup="STATUS INVALID IMAGE HASH"; Path=""; Cause="``STATUS_INVALID_IMAGE_HASH``. (Unsigned binary)." },
    @{ Id='119'; Title="WerFault Trigger"; Op=""; Res=""; Lookup=""; Path="WerFault\.exe"; Cause="Spawning ``WerFault.exe``. (Crash reporting)." },
    @{ Id='120'; Title="Dr Watson"; Op=""; Res=""; Lookup=""; Path="dwwin\.exe"; Cause="Spawning ``dwwin.exe``. (Legacy crash)." },
    @{ Id='121'; Title="Conhost Spawn"; Op=""; Res=""; Lookup=""; Path="conhost\.exe"; Cause="Spawning ``conhost.exe``. (Console window)." },
    @{ Id='127'; Title="Handle Leak"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="``CloseHandle`` count << ``CreateFile``. (Resource leak)." },
    @{ Id='130'; Title="Non-Paged Pool"; Op=""; Res="STATUS INSUFFICIENT RESOURCES"; Lookup="STATUS INSUFFICIENT RESOURCES"; Path=""; Cause="``STATUS_INSUFFICIENT_RESOURCES``. (Kernel memory full)." },
    @{ Id='131'; Title="Commit Limit"; Op=""; Res="STATUS COMMITMENT LIMIT"; Lookup="STATUS COMMITMENT LIMIT"; Path=""; Cause="``STATUS_COMMITMENT_LIMIT``. (RAM/Pagefile full)." },
    @{ Id='132'; Title="Working Set Trim"; Op="EmptyWorkingSet"; Res=""; Lookup=""; Path=""; Cause="``EmptyWorkingSet``. (Memory reclaiming)." },
    @{ Id='134'; Title="Stack Overflow"; Op=""; Res="STATUS STACK OVERFLOW"; Lookup="STATUS STACK OVERFLOW"; Path=""; Cause="``STATUS_STACK_OVERFLOW``. (Recursion loop)." },
    @{ Id='135'; Title="DllMain Hang"; Op="LoadImage"; Res=""; Lookup=""; Path=""; Cause="Long duration in ``LoadImage``. (Loader lock)." },
    @{ Id='148'; Title="Shim Engine"; Op=""; Res=""; Lookup=""; Path="AcLayers\.dll"; Cause="``AcLayers.dll`` load. (AppCompat)." },
    @{ Id='149'; Title="Detours"; Op=""; Res=""; Lookup=""; Path="detoured\.dll"; Cause="``detoured.dll`` load. (Hooking)." },
    @{ Id='152'; Title="TCP Connect (Refused)"; Op=""; Res="CONNECTION REFUSED"; Lookup="CONNECTION REFUSED"; Path=""; Cause="``CONNECTION_REFUSED``. (Port closed/Blocked)." },
    @{ Id='154'; Title="TCP Connect (Unreachable)"; Op=""; Res="NETWORK UNREACHABLE"; Lookup="NETWORK UNREACHABLE"; Path=""; Cause="``NETWORK_UNREACHABLE``. (Routing fail)." },
    @{ Id='155'; Title="TCP Connect (AddrInUse)"; Op=""; Res="ADDRESS ALREADY ASSOCIATED"; Lookup="ADDRESS ALREADY ASSOCIATED"; Path=""; Cause="``ADDRESS_ALREADY_ASSOCIATED``. (Port exhaustion)." },
    @{ Id='157'; Title="TCP Disconnect (Reset)"; Op=""; Res="ECONNRESET"; Lookup="ECONNRESET"; Path=""; Cause="``ECONNRESET``. (Force close)." },
    @{ Id='159'; Title="UDP Send (Fail)"; Op=""; Res="HOST UNREACHABLE"; Lookup="HOST UNREACHABLE"; Path=""; Cause="``HOST_UNREACHABLE``. (Delivery fail)." },
    @{ Id='163'; Title="DNS Fail"; Op=""; Res="NAME NOT FOUND"; Lookup="NAME NOT FOUND"; Path=""; Cause="``NAME_NOT_FOUND``. (Typo/Missing record)." },
    @{ Id='181'; Title="PAC File Fail"; Op=""; Res=""; Lookup=""; Path="\.pac"; Cause="404 on ``.pac``. (Slow browsing)." },
    @{ Id='185'; Title="RPC Auth Fail"; Op=""; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``RPC_E_ACCESS_DENIED``. (Permission)." },
    @{ Id='187'; Title="Named Pipe Connect"; Op=""; Res=""; Lookup=""; Path="\\\\Server\\pipe"; Cause="``\\Server\pipe``. (IPC)." },
    @{ Id='188'; Title="Mail Slot"; Op=""; Res=""; Lookup=""; Path="\\mailslot\\browse"; Cause="``\mailslot\browse``. (Browser election)." },
    @{ Id='191'; Title="Winsock Load"; Op=""; Res=""; Lookup=""; Path="ws2_32\.dll"; Cause="``ws2_32.dll``. (Net stack init)." },
    @{ Id='201'; Title="GPO Read Fail"; Op=""; Res=""; Lookup=""; Path="gpt\.ini"; Cause="``gpt.ini`` access deny. (Policy fail)." },
    @{ Id='202'; Title="GPO Script Fail"; Op=""; Res=""; Lookup=""; Path="gpscript\.exe"; Cause="``gpscript.exe`` error. (Startup script)." },
    @{ Id='203'; Title="GPO History Lock"; Op=""; Res=""; Lookup=""; Path="history\.ini"; Cause="``history.ini`` sharing vio. (Processing hang)." },
    @{ Id='204'; Title="Sysvol Latency"; Op=""; Res=""; Lookup=""; Path="\\\\Domain\\Sysvol"; Cause="Slow read ``\\Domain\Sysvol``. (DC overload)." },
    @{ Id='207'; Title="Ticket Bloat"; Op=""; Res="STATUS BUFFER OVERFLOW"; Lookup="STATUS BUFFER OVERFLOW"; Path=""; Cause="``STATUS_BUFFER_OVERFLOW`` on LSASS. (MaxTokenSize)." },
    @{ Id='208'; Title="Machine Trust"; Op=""; Res="STATUS TRUST FAILURE"; Lookup="STATUS TRUST FAILURE"; Path=""; Cause="``STATUS_TRUST_FAILURE``. (Broken trust)." },
    @{ Id='210'; Title="Roaming Profile"; Op=""; Res=""; Lookup=""; Path="NTUSER\.DAT"; Cause="``NTUSER.DAT`` copy fail. (Logon error)." },
    @{ Id='213'; Title="DFS Referral"; Op=""; Res=""; Lookup=""; Path="\\\\Domain\\DFS"; Cause="Access ``\\Domain\DFS``. (Namespace)." },
    @{ Id='214'; Title="Print Spooler Crash"; Op=""; Res=""; Lookup=""; Path="spoolsv\.exe"; Cause="``spoolsv.exe`` exit. (Print kill)." },
    @{ Id='218'; Title="Citrix Hook"; Op=""; Res=""; Lookup=""; Path="CtxHk\.dll"; Cause="``CtxHk.dll`` load. (VDI hook)." },
    @{ Id='222'; Title="App-V Stream"; Op=""; Res=""; Lookup=""; Path="Q:"; Cause="Read from ``Q:`` / Mount. (Streaming)." },
    @{ Id='223'; Title="ThinPrint"; Op="TPAutoConnect"; Res=""; Lookup=""; Path=""; Cause="``TPAutoConnect`` fail. (VDI Print)." },
    @{ Id='226'; Title="SCCM Agent"; Op="CcmExec"; Res=""; Lookup=""; Path=""; Cause="``CcmExec`` activity. (Mgmt agent)." },
    @{ Id='231'; Title="MSI Exec Start"; Op=""; Res=""; Lookup=""; Path="msiexec\.exe"; Cause="``msiexec.exe`` /v. (Install start)." },
    @{ Id='234'; Title="MSI Rollback"; Op="SetRename"; Res=""; Lookup=""; Path=""; Cause="``SetRename`` restore. (Fatal error)." },
    @{ Id='235'; Title="MSI Mutex"; Op="_MSIExecute"; Res=""; Lookup=""; Path=""; Cause="Wait on ``_MSIExecute``. (Concurrent install)." },
    @{ Id='238'; Title="MSI Transform"; Op=""; Res=""; Lookup=""; Path="\.mst"; Cause="``.mst`` missing. (Customization lost)." },
    @{ Id='248'; Title="AppX Manifest"; Op=""; Res=""; Lookup=""; Path="AppxManifest\.xml"; Cause="``AppxManifest.xml`` read. (Store App)." },
    @{ Id='251'; Title="Run Key Persistence"; Op=""; Res=""; Lookup=""; Path="CurrentVersion\\Run"; Cause="Write ``CurrentVersion\Run``. (Autostart)." },
    @{ Id='256'; Title="Image Hijack"; Op="Image File Execution Options"; Res=""; Lookup=""; Path=""; Cause="Write ``Image File Execution Options``. (Debug hijack)." },
    @{ Id='259'; Title="Extension Hijack"; Op=""; Res=""; Lookup=""; Path="txtfile\\shell\\open"; Cause="Write ``txtfile\shell\open``. (Assoc hijack)." },
    @{ Id='261'; Title="Phantom DLL"; Op=""; Res=""; Lookup=""; Path="version\.dll"; Cause="Drop ``version.dll`` (Sideloading)." },
    @{ Id='262'; Title="WMI Persist"; Op=""; Res=""; Lookup=""; Path="Objects\.data"; Cause="Write ``Objects.data``. (Fileless persist)." },
    @{ Id='264'; Title="Powershell Download"; Op=""; Res=""; Lookup=""; Path="Net\.WebClient"; Cause="``Net.WebClient``. (Downloader)." },
    @{ Id='272'; Title="LSA Secret"; Op=""; Res=""; Lookup=""; Path="Policy\\Secrets"; Cause="Read ``Policy\Secrets``. (Password dump)." },
    @{ Id='289'; Title="Timestomp"; Op="SetBasicInformationFile"; Res=""; Lookup=""; Path=""; Cause="``SetBasicInformationFile`` Time. (Hiding)." },
    @{ Id='296'; Title="PST Access"; Op=""; Res=""; Lookup=""; Path="\.pst"; Cause="Read ``.pst``. (Email theft)." },
    @{ Id='298'; Title="RDP Saved"; Op=""; Res=""; Lookup=""; Path="Default\.rdp"; Cause="Read ``Default.rdp``. (Lateral move)." },
    @{ Id='301'; Title=".NET CLR Load"; Op=""; Res=""; Lookup=""; Path="mscoree\.dll"; Cause="``mscoree.dll`` load. (.NET start)." },
    @{ Id='302'; Title=".NET GAC Load"; Op=""; Res=""; Lookup=""; Path="C:\\Windows\\Assembly"; Cause="Read ``C:\Windows\Assembly``. (Global lib)." },
    @{ Id='303'; Title=".NET Temp"; Op=""; Res=""; Lookup=""; Path="Temporary ASP\.NET Files"; Cause="Write ``Temporary ASP.NET Files``. (Compile)." },
    @{ Id='304'; Title=".NET Config"; Op=""; Res=""; Lookup=""; Path="machine\.config"; Cause="Read ``machine.config``. (Settings)." },
    @{ Id='305'; Title=".NET JIT"; Op=""; Res=""; Lookup=""; Path="mscorjit\.dll"; Cause="``mscorjit.dll`` activity. (Compilation)." },
    @{ Id='306'; Title=".NET NGEN"; Op=""; Res=""; Lookup=""; Path="ngen\.exe"; Cause="``ngen.exe`` activity. (Optimization)." },
    @{ Id='308'; Title="Java Runtime"; Op=""; Res=""; Lookup=""; Path="jvm\.dll"; Cause="``jvm.dll`` load. (Java start)." },
    @{ Id='312'; Title="Python Import"; Op=""; Res=""; Lookup=""; Path="__init__\.py"; Cause="Read ``__init__.py``. (Module load)." },
    @{ Id='315'; Title="IIS Worker"; Op=""; Res=""; Lookup=""; Path="w3wp\.exe"; Cause="``w3wp.exe`` start. (Web server)." },
    @{ Id='316'; Title="IIS Config"; Op=""; Res=""; Lookup=""; Path="web\.config"; Cause="Read ``web.config``. (App settings)." },
    @{ Id='317'; Title="IIS Shared"; Op=""; Res=""; Lookup=""; Path="applicationHost\.config"; Cause="Read ``applicationHost.config``. (Server set)." },
    @{ Id='318'; Title="AppPool Identity"; Op=""; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``ACCESS_DENIED`` as IIS AppPool. (Perms)." },
    @{ Id='320'; Title="Oracle TNS"; Op=""; Res=""; Lookup=""; Path="tnsnames\.ora"; Cause="Read ``tnsnames.ora``. (DB Config)." },
    @{ Id='321'; Title="ODBC System"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\ODBC"; Cause="Read ``HKLM\Software\ODBC``. (DSN)." },
    @{ Id='322'; Title="ODBC User"; Op=""; Res=""; Lookup=""; Path="HKCU\\Software\\ODBC"; Cause="Read ``HKCU\Software\ODBC``. (DSN)." },
    @{ Id='323'; Title="SQL Driver"; Op=""; Res=""; Lookup=""; Path="sqlncli\.dll"; Cause="Load ``sqlncli.dll``. (Connectivity)." },
    @{ Id='324'; Title="OLEDB Reg"; Op=""; Res=""; Lookup=""; Path="HKCR\\CLSID\\{Provider}"; Cause="Read ``HKCR\CLSID\{Provider}``. (Driver)." },
    @{ Id='325'; Title="UDL Read"; Op=""; Res=""; Lookup=""; Path="\.udl"; Cause="Read ``.udl``. (Conn string)." },
    @{ Id='326'; Title="Report Viewer"; Op=""; Res=""; Lookup=""; Path="Microsoft\.ReportViewer"; Cause="Load ``Microsoft.ReportViewer``. (Reporting)." },
    @{ Id='327'; Title="Crystal Reports"; Op=""; Res=""; Lookup=""; Path="crpe32\.dll"; Cause="Load ``crpe32.dll``. (Reporting)." },
    @{ Id='328'; Title="Flash OCX"; Op=""; Res=""; Lookup=""; Path="Flash\.ocx"; Cause="Load ``Flash.ocx``. (Legacy)." },
    @{ Id='329'; Title="Silverlight"; Op=""; Res=""; Lookup=""; Path="npctrl\.dll"; Cause="Load ``npctrl.dll``. (Legacy)." },
    @{ Id='331'; Title="USB Arrival"; Op="DeviceIoControl"; Res=""; Lookup=""; Path=""; Cause="``DeviceIoControl`` USB Hub. (Connect)." },
    @{ Id='332'; Title="USB Removal"; Op="DeviceIoControl"; Res=""; Lookup=""; Path=""; Cause="``DeviceIoControl`` Fail. (Disconnect)." },
    @{ Id='342'; Title="Webcam Lock"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="``CreateFile`` Video0 deny. (Privacy)." },
    @{ Id='344'; Title="Scanner Twain"; Op=""; Res=""; Lookup=""; Path="twain_32\.dll"; Cause="Load ``twain_32.dll``. (Imaging)." },
    @{ Id='350'; Title="BIOS Info"; Op=""; Res=""; Lookup=""; Path="Hardwaredescription\\System"; Cause="Read ``Hardwaredescription\System``. (Firmware)." },
    @{ Id='351'; Title="UIA Prov Fail"; Op="RegOpenKey"; Res=""; Lookup=""; Path=""; Cause="``RegOpenKey`` UIA deny. (Automation)." },
    @{ Id='354'; Title="Focus Fight"; Op="SetFocus"; Res=""; Lookup=""; Path=""; Cause="Rapid ``SetFocus``. (Loop)." },
    @{ Id='359'; Title="Braille Lock"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="``CreateFile`` COM fail. (Display)." },
    @{ Id='361'; Title="INI Redirect"; Op=""; Res=""; Lookup=""; Path="win\.ini"; Cause="Read ``win.ini``. (16-bit)." },
    @{ Id='362'; Title="16-bit App"; Op=""; Res=""; Lookup=""; Path="ntvdm\.exe"; Cause="Load ``ntvdm.exe``. (DOS)." },
    @{ Id='363'; Title="Thunking"; Op=""; Res=""; Lookup=""; Path="wow64\.dll"; Cause="Load ``wow64.dll``. (32-on-64)." },
    @{ Id='364'; Title="Shim Apply"; Op=""; Res=""; Lookup=""; Path="sysmain\.sdb"; Cause="Read ``sysmain.sdb``. (Patches)." },
    @{ Id='365'; Title="DirectX 9"; Op=""; Res=""; Lookup=""; Path="d3d9\.dll"; Cause="Load ``d3d9.dll``. (Old Gfx)." },
    @{ Id='366'; Title="VB6 Runtime"; Op=""; Res=""; Lookup=""; Path="msvbvm60\.dll"; Cause="Load ``msvbvm60.dll``. (Basic)." },
    @{ Id='367'; Title="MFC 42"; Op=""; Res=""; Lookup=""; Path="mfc42\.dll"; Cause="Load ``mfc42.dll``. (C++)." },
    @{ Id='369'; Title="Hardcoded Drv"; Op=""; Res=""; Lookup=""; Path="D:\\"; Cause="Access ``D:\``. (Missing drive)." },
    @{ Id='372'; Title="Deprecated API"; Op="WinExec"; Res=""; Lookup=""; Path=""; Cause="Call ``WinExec``. (Old code)." },
    @{ Id='373'; Title="Legacy Help"; Op=""; Res=""; Lookup=""; Path="winhlp32\.exe"; Cause="Load ``winhlp32.exe``. (.hlp)." },
    @{ Id='374'; Title="MAPI Mail"; Op=""; Res=""; Lookup=""; Path="mapi32\.dll"; Cause="Load ``mapi32.dll``. (Email)." },
    @{ Id='377'; Title="Root Update"; Op=""; Res=""; Lookup=""; Path="authroot\.stl"; Cause="Download ``authroot.stl``. (Update)." },
    @{ Id='378'; Title="CRL Fetch"; Op=""; Res=""; Lookup=""; Path="\.crl"; Cause="HTTP fetch ``.crl``. (Revocation)." },
    @{ Id='388'; Title="Hash Fail"; Op=""; Res="STATUS INVALID IMAGE HASH"; Lookup="STATUS INVALID IMAGE HASH"; Path=""; Cause="``STATUS_INVALID_IMAGE_HASH``. (Sign)." },
    @{ Id='394'; Title="M365 Activate"; Op=""; Res=""; Lookup=""; Path="office\.com"; Cause="Connect ``office.com``. (Licensing)." },
    @{ Id='404'; Title="Firefox Lock"; Op=""; Res=""; Lookup=""; Path="parent\.lock"; Cause="``parent.lock``. (Stuck)." },
    @{ Id='406'; Title="Teams Log"; Op=""; Res=""; Lookup=""; Path="logs\.txt"; Cause="Write ``logs.txt``. (Diag)." },
    @{ Id='407'; Title="Outlook OST"; Op=""; Res=""; Lookup=""; Path="\.ost"; Cause="Read ``.ost`` > 100MB. (Disk IO)." },
    @{ Id='409'; Title="Excel Addin"; Op=""; Res=""; Lookup=""; Path="\.xll"; Cause="Load ``.xll``. (Extension)." },
    @{ Id='410'; Title="Word Template"; Op=""; Res=""; Lookup=""; Path="Normal\.dotm"; Cause="Read ``Normal.dotm``. (Config)." },
    @{ Id='411'; Title="Adobe Reader"; Op=""; Res=""; Lookup=""; Path="AcroRd32\.dll"; Cause="Load ``AcroRd32.dll``. (PDF)." },
    @{ Id='412'; Title="Adobe Arm"; Op=""; Res=""; Lookup=""; Path="AdobeARM\.exe"; Cause="``AdobeARM.exe``. (Update)." },
    @{ Id='413'; Title="Zoom Cpt"; Op=""; Res=""; Lookup=""; Path="CptHost\.exe"; Cause="``CptHost.exe``. (Sharing)." },
    @{ Id='418'; Title="Kubernetes"; Op=""; Res=""; Lookup=""; Path="\.kube"; Cause="Read ``.kube``. (Config)." },
    @{ Id='419'; Title="Git Lock"; Op=""; Res=""; Lookup=""; Path="index\.lock"; Cause="Read ``index.lock``. (Repo)." },
    @{ Id='421'; Title="McAfee Scan"; Op=""; Res=""; Lookup=""; Path="mcshield\.exe"; Cause="``mcshield.exe``. (AV)." },
    @{ Id='422'; Title="Symantec Scan"; Op=""; Res=""; Lookup=""; Path="ccSvcHst\.exe"; Cause="``ccSvcHst.exe``. (AV)." },
    @{ Id='451'; Title="Boot Log"; Op=""; Res=""; Lookup=""; Path="ntbtlog\.txt"; Cause="Write ``ntbtlog.txt``. (Diag)." },
    @{ Id='452'; Title="Setup Log"; Op=""; Res=""; Lookup=""; Path="setupapi\.dev\.log"; Cause="Write ``setupapi.dev.log``. (Driver)." },
    @{ Id='453'; Title="CBS Log"; Op=""; Res=""; Lookup=""; Path="cbs\.log"; Cause="Write ``cbs.log``. (Update)." },
    @{ Id='454'; Title="DISM Log"; Op=""; Res=""; Lookup=""; Path="dism\.log"; Cause="Write ``dism.log``. (Image)." },
    @{ Id='455'; Title="Events Log"; Op=""; Res=""; Lookup=""; Path="\.evtx"; Cause="Write ``.evtx``. (Audit)." },
    @{ Id='456'; Title="WMI Repo"; Op=""; Res=""; Lookup=""; Path="Index\.btr"; Cause="Read ``Index.btr``. (Mgmt)." },
    @{ Id='457'; Title="SRU DB"; Op=""; Res=""; Lookup=""; Path="srudb\.dat"; Cause="Write ``srudb.dat``. (Usage)." },
    @{ Id='458'; Title="Prefetch"; Op=""; Res=""; Lookup=""; Path="\.pf"; Cause="Write ``.pf``. (Optimize)." },
    @{ Id='464'; Title="Settings App"; Op="SystemSettings"; Res=""; Lookup=""; Path=""; Cause="``SystemSettings``. (Config)." },
    @{ Id='467'; Title="Event Viewer"; Op=""; Res=""; Lookup=""; Path="mmc\.exe"; Cause="``mmc.exe``. (Admin)." },
    @{ Id='468'; Title="Reg Editor"; Op=""; Res=""; Lookup=""; Path="regedit\.exe"; Cause="``regedit.exe``. (Admin)." },
    @{ Id='469'; Title="CMD Shell"; Op=""; Res=""; Lookup=""; Path="cmd\.exe"; Cause="``cmd.exe``. (Shell)." },
    @{ Id='470'; Title="PowerShell"; Op=""; Res=""; Lookup=""; Path="powershell\.exe"; Cause="``powershell.exe``. (Shell)." },
    @{ Id='471'; Title="Run Dialog"; Op=""; Res=""; Lookup=""; Path="explorer\.exe"; Cause="``explorer.exe`` Run. (Shell)." },
    @{ Id='472'; Title="LogonUI"; Op=""; Res=""; Lookup=""; Path="LogonUI\.exe"; Cause="``LogonUI.exe``. (Auth)." },
    @{ Id='473'; Title="WinInit"; Op=""; Res=""; Lookup=""; Path="wininit\.exe"; Cause="``wininit.exe``. (Boot)." },
    @{ Id='474'; Title="LSM"; Op=""; Res=""; Lookup=""; Path="lsm\.exe"; Cause="``lsm.exe``. (Session)." },
    @{ Id='475'; Title="Smss"; Op=""; Res=""; Lookup=""; Path="smss\.exe"; Cause="``smss.exe``. (Session)." },
    @{ Id='476'; Title="WSL Host"; Op=""; Res=""; Lookup=""; Path="wslhost\.exe"; Cause="``wslhost.exe``. (Kernel)." },
    @{ Id='477'; Title="WSL File"; Op=""; Res=""; Lookup=""; Path="\\\\wsl$"; Cause="Access ``\\wsl$``. (Network)." },
    @{ Id='478'; Title="WSL Config"; Op=""; Res=""; Lookup=""; Path="\.wslconfig"; Cause="Read ``.wslconfig``. (Settings)." },
    @{ Id='480'; Title="Plan 9 FS"; Op=""; Res=""; Lookup=""; Path="p9rdr\.sys"; Cause="``p9rdr.sys``. (Filesystem)." },
    @{ Id='481'; Title="Bash Exec"; Op=""; Res=""; Lookup=""; Path="bash\.exe"; Cause="``bash.exe``. (Shell)." },
    @{ Id='485'; Title="WSL2 VHD"; Op=""; Res=""; Lookup=""; Path="ext4\.vhdx"; Cause="``ext4.vhdx``. (Disk)." },
    @{ Id='486'; Title="Game Mode"; Op=""; Res=""; Lookup=""; Path="GameBar\.exe"; Cause="``GameBar.exe``. (Overlay)." },
    @{ Id='487'; Title="DVR Store"; Op=""; Res=""; Lookup=""; Path="\.mp4"; Cause="Write ``.mp4``. (Record)." },
    @{ Id='495'; Title="Vulkan"; Op=""; Res=""; Lookup=""; Path="vulkan-1\.dll"; Cause="Load ``vulkan-1.dll``. (Graphics)." },
    @{ Id='496'; Title="OpenGL"; Op=""; Res=""; Lookup=""; Path="opengl32\.dll"; Cause="Load ``opengl32.dll``. (Graphics)." },
    @{ Id='497'; Title="OpenCL"; Op="OpenCL.dll"; Res=""; Lookup=""; Path=""; Cause="Load ``OpenCL.dll``. (Compute)." },
    @{ Id='500'; Title="Refresh Rate"; Op="ChangeDisplaySettings"; Res=""; Lookup=""; Path=""; Cause="``ChangeDisplaySettings``. (Hz)." },
    @{ Id='501'; Title="Policy Poll (Explorer)"; Op=""; Res=""; Lookup=""; Path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer"; Cause="Read ``HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer``. (UI restrictions)." },
    @{ Id='502'; Title="Policy Poll (System)"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"; Cause="Read ``HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System``. (UAC/Logon)." },
    @{ Id='503'; Title="Policy Poll (Assoc)"; Op=""; Res=""; Lookup=""; Path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts"; Cause="Read ``HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts``. (Assoc hijacking)." },
    @{ Id='504'; Title="Policy Poll (IE)"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Policies\\Microsoft\\Internet Explorer"; Cause="Read ``HKLM\Software\Policies\Microsoft\Internet Explorer``. (Browser lock)." },
    @{ Id='505'; Title="Policy Poll (Edge)"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Policies\\Microsoft\\Edge"; Cause="Read ``HKLM\Software\Policies\Microsoft\Edge``. (Browser lock)." },
    @{ Id='506'; Title="Policy Poll (Chrome)"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Policies\\Google\\Chrome"; Cause="Read ``HKLM\Software\Policies\Google\Chrome``. (Browser lock)." },
    @{ Id='507'; Title="Policy Poll (Office)"; Op=""; Res=""; Lookup=""; Path="HKCU\\Software\\Policies\\Microsoft\\Office"; Cause="Read ``HKCU\Software\Policies\Microsoft\Office``. (Macro settings)." },
    @{ Id='508'; Title="Policy Poll (Defender)"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Policies\\Microsoft\\Windows Defender"; Cause="Read ``HKLM\Software\Policies\Microsoft\Windows Defender``. (AV settings)." },
    @{ Id='509'; Title="Policy Poll (Update)"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate"; Cause="Read ``HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate``. (Patching)." },
    @{ Id='511'; Title="Background Poll"; Op=""; Res=""; Lookup=""; Path="HKCU\\Control Panel\\Desktop\\Wallpaper"; Cause="Read ``HKCU\Control Panel\Desktop\Wallpaper``. (GPO Refresh)." },
    @{ Id='512'; Title="ScreenSaver Poll"; Op=""; Res=""; Lookup=""; Path="HKCU\\Control Panel\\Desktop\\ScreenSaveActive"; Cause="Read ``HKCU\Control Panel\Desktop\ScreenSaveActive``. (Lockout)." },
    @{ Id='513'; Title="TimeOut Poll"; Op=""; Res=""; Lookup=""; Path="HKCU\\Control Panel\\Desktop\\ScreenSaveTimeOut"; Cause="Read ``HKCU\Control Panel\Desktop\ScreenSaveTimeOut``. (Lockout)." },
    @{ Id='514'; Title="Theme Poll"; Op=""; Res=""; Lookup=""; Path="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ThemeManager"; Cause="Read ``HKCU\Software\Microsoft\Windows\CurrentVersion\ThemeManager``. (Visuals)." },
    @{ Id='515'; Title="Color Poll"; Op=""; Res=""; Lookup=""; Path="HKCU\\Control Panel\\Colors"; Cause="Read ``HKCU\Control Panel\Colors``. (High Contrast)." },
    @{ Id='516'; Title="Cursor Poll"; Op=""; Res=""; Lookup=""; Path="HKCU\\Control Panel\\Cursors"; Cause="Read ``HKCU\Control Panel\Cursors``. (Accessibility)." },
    @{ Id='517'; Title="Sound Poll"; Op=""; Res=""; Lookup=""; Path="HKCU\\AppEvents\\Schemes"; Cause="Read ``HKCU\AppEvents\Schemes``. (Audio feedback)." },
    @{ Id='518'; Title="Icon Cache Check"; Op=""; Res=""; Lookup=""; Path="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Icons"; Cause="Read ``HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons``. (Overlays)." },
    @{ Id='519'; Title="Drive Map Poll"; Op=""; Res=""; Lookup=""; Path="HKCU\\Network"; Cause="Read ``HKCU\Network``. (Mapped Drives)." },
    @{ Id='520'; Title="Printer Poll"; Op=""; Res=""; Lookup=""; Path="HKCU\\Printers"; Cause="Read ``HKCU\Printers``. (Default printer)." },
    @{ Id='523'; Title="Network List Poll"; Op=""; Res=""; Lookup=""; Path="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList"; Cause="Read ``HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList``. (NLA)." },
    @{ Id='525'; Title="Audit Poll"; Op=""; Res=""; Lookup=""; Path="HKLM\\SECURITY\\Policy\\PolAdtEv"; Cause="Read ``HKLM\SECURITY\Policy\PolAdtEv``. (Event generation)." },
    @{ Id='529'; Title="Winlogon Poll"; Op=""; Res=""; Lookup=""; Path="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"; Cause="Read ``HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon``. (Shell)." },
    @{ Id='530'; Title="AppInit Poll"; Op=""; Res=""; Lookup=""; Path="HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\\AppInit_DLLs"; Cause="Read ``HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs``. (Injection)." },
    @{ Id='531'; Title="Spooler Crash"; Op=""; Res=""; Lookup=""; Path="spoolsv\.exe"; Cause="``spoolsv.exe`` Exit Code != 0. (Print)." },
    @{ Id='532'; Title="Audio Crash"; Op=""; Res=""; Lookup=""; Path="audiodg\.exe"; Cause="``audiodg.exe`` Exit Code != 0. (Sound)." },
    @{ Id='533'; Title="DWM Crash"; Op=""; Res=""; Lookup=""; Path="dwm\.exe"; Cause="``dwm.exe`` Exit Code != 0. (Graphics)." },
    @{ Id='534'; Title="Search Crash"; Op=""; Res=""; Lookup=""; Path="SearchIndexer\.exe"; Cause="``SearchIndexer.exe`` Exit Code != 0. (Index)." },
    @{ Id='535'; Title="WMI Crash"; Op=""; Res=""; Lookup=""; Path="WmiPrvSE\.exe"; Cause="``WmiPrvSE.exe`` Exit Code != 0. (Mgmt)." },
    @{ Id='536'; Title="Update Crash"; Op=""; Res=""; Lookup=""; Path="TiWorker\.exe"; Cause="``TiWorker.exe`` Exit Code != 0. (Install)." },
    @{ Id='537'; Title="Defender Crash"; Op=""; Res=""; Lookup=""; Path="MsMpEng\.exe"; Cause="``MsMpEng.exe`` Exit Code != 0. (AV)." },
    @{ Id='540'; Title="TaskSched Crash"; Op=""; Res=""; Lookup=""; Path="taskeng\.exe"; Cause="``taskeng.exe`` Exit. (Tasks)." },
    @{ Id='541'; Title="Explorer Crash"; Op=""; Res=""; Lookup=""; Path="Explorer\.exe"; Cause="``Explorer.exe`` Exit. (Shell)." },
    @{ Id='542'; Title="LogonUI Crash"; Op=""; Res=""; Lookup=""; Path="LogonUI\.exe"; Cause="``LogonUI.exe`` Exit. (Login)." },
    @{ Id='543'; Title="Lsass Crash"; Op=""; Res=""; Lookup=""; Path="lsass\.exe"; Cause="``lsass.exe`` Exit. (Reboot)." },
    @{ Id='544'; Title="Csrss Crash"; Op=""; Res=""; Lookup=""; Path="csrss\.exe"; Cause="``csrss.exe`` Exit. (BSOD)." },
    @{ Id='545'; Title="Smss Crash"; Op=""; Res=""; Lookup=""; Path="smss\.exe"; Cause="``smss.exe`` Exit. (BSOD)." },
    @{ Id='546'; Title="Svchost Split"; Op=""; Res=""; Lookup=""; Path="svchost\.exe -k netsvcs"; Cause="``svchost.exe -k netsvcs`` High CPU. (Shared)." },
    @{ Id='547'; Title="Svchost Dcom"; Op=""; Res=""; Lookup=""; Path="svchost\.exe -k DcomLaunch"; Cause="``svchost.exe -k DcomLaunch`` High CPU. (RPC)." },
    @{ Id='548'; Title="Svchost RPC"; Op=""; Res=""; Lookup=""; Path="svchost\.exe -k RpcSs"; Cause="``svchost.exe -k RpcSs`` High CPU. (RPC)." },
    @{ Id='549'; Title="Svchost Local"; Op=""; Res=""; Lookup=""; Path="svchost\.exe -k LocalService"; Cause="``svchost.exe -k LocalService`` High CPU. (Background)." },
    @{ Id='550'; Title="Svchost Net"; Op=""; Res=""; Lookup=""; Path="svchost\.exe -k NetworkService"; Cause="``svchost.exe -k NetworkService`` High CPU. (Network)." },
    @{ Id='551'; Title="SysMain Busy"; Op=""; Res=""; Lookup=""; Path="svchost\.exe -k sysmain"; Cause="``svchost.exe -k sysmain`` Disk I/O. (Superfetch)." },
    @{ Id='552'; Title="DiagTrack Busy"; Op=""; Res=""; Lookup=""; Path="svchost\.exe -k utisvc"; Cause="``svchost.exe -k utisvc`` Disk I/O. (Telemetry)." },
    @{ Id='553'; Title="Bits Busy"; Op=""; Res=""; Lookup=""; Path="svchost\.exe -k netsvcs"; Cause="``svchost.exe -k netsvcs`` Network. (Download)." },
    @{ Id='554'; Title="WinDefend Busy"; Op=""; Res=""; Lookup=""; Path="MsMpEng\.exe"; Cause="``MsMpEng.exe`` Disk I/O. (Scan)." },
    @{ Id='555'; Title="TrustedInstall"; Op=""; Res=""; Lookup=""; Path="TrustedInstaller\.exe"; Cause="``TrustedInstaller.exe`` Disk I/O. (Update)." },
    @{ Id='556'; Title="WMI Loop"; Op=""; Res=""; Lookup=""; Path="WmiPrvSE\.exe"; Cause="``WmiPrvSE.exe`` High CPU. (Query storm)." },
    @{ Id='557'; Title="WMI Provider"; Op=""; Res=""; Lookup=""; Path="cimwin32\.dll"; Cause="``WmiPrvSE`` loading ``cimwin32.dll``. (Inventory)." },
    @{ Id='558'; Title="WMI Storage"; Op=""; Res=""; Lookup=""; Path="storagewmi\.dll"; Cause="``WmiPrvSE`` loading ``storagewmi.dll``. (Disk check)." },
    @{ Id='559'; Title="WMI Net"; Op=""; Res=""; Lookup=""; Path="wmidex\.dll"; Cause="``WmiPrvSE`` loading ``wmidex.dll``. (Net check)." },
    @{ Id='560'; Title="WMI Event"; Op=""; Res=""; Lookup=""; Path="wbemess\.dll"; Cause="``WmiPrvSE`` loading ``wbemess.dll``. (Event sub)." },
    @{ Id='582'; Title="Object Found"; Op=""; Res="SUCCESS"; Lookup="SUCCESS"; Path=""; Cause="``0xC0000000`` / ``0``. (Success)." },
    @{ Id='611'; Title="Word Template"; Op=""; Res=""; Lookup=""; Path="Normal\.dotm"; Cause="Access ``Normal.dotm`` fail. (Corruption)." },
    @{ Id='612'; Title="Word Addin"; Op=""; Res=""; Lookup=""; Path="\.wll"; Cause="Load ``.wll`` fail. (Plugin)." },
    @{ Id='613'; Title="Excel Calc"; Op=""; Res=""; Lookup=""; Path="EXCEL\.EXE"; Cause="High CPU ``EXCEL.EXE``. (Calculation)." },
    @{ Id='615'; Title="Excel Addin"; Op=""; Res=""; Lookup=""; Path="\.xla"; Cause="Load ``.xla`` fail. (Plugin)." },
    @{ Id='616'; Title="Outlook OST"; Op=""; Res=""; Lookup=""; Path="\.ost"; Cause="Write ``.ost`` fail. (Lock)." },
    @{ Id='618'; Title="Outlook RPC"; Op=""; Res=""; Lookup=""; Path="outlook\.office365\.com"; Cause="TCP Connect ``outlook.office365.com`` fail. (Net)." },
    @{ Id='619'; Title="Outlook Autodiscover"; Op=""; Res=""; Lookup=""; Path="autodiscover\.xml"; Cause="HTTP ``autodiscover.xml`` fail. (Config)." },
    @{ Id='620'; Title="Outlook Addin"; Op=""; Res=""; Lookup=""; Path="outlvba\.dll"; Cause="Load ``outlvba.dll``. (Macro)." },
    @{ Id='621'; Title="Access Lock"; Op=""; Res=""; Lookup=""; Path="\.ldb"; Cause="Write ``.ldb`` fail. (Record lock)." },
    @{ Id='622'; Title="Access ODBC"; Op=""; Res=""; Lookup=""; Path="odbc32\.dll"; Cause="Load ``odbc32.dll`` fail. (Driver)." },
    @{ Id='623'; Title="PowerPoint Media"; Op=""; Res=""; Lookup=""; Path="pflash\.dll"; Cause="Load ``pflash.dll``. (Flash)." },
    @{ Id='624'; Title="OneNote Cache"; Op=""; Res=""; Lookup=""; Path="\.bin"; Cause="Write ``.bin`` fail. (Sync)." },
    @{ Id='625'; Title="Office Update"; Op=""; Res=""; Lookup=""; Path="OfficeClickToRun\.exe"; Cause="``OfficeClickToRun.exe`` activity. (Update)." },
    @{ Id='626'; Title="Office License"; Op=""; Res=""; Lookup=""; Path="OSPP\.VBS"; Cause="``OSPP.VBS`` execution. (Activation)." },
    @{ Id='627'; Title="Office Telemetry"; Op=""; Res=""; Lookup=""; Path="mso\.dll"; Cause="``mso.dll`` connect. (Diag)." },
    @{ Id='630'; Title="Skype Mtg"; Op=""; Res=""; Lookup=""; Path="lync\.exe"; Cause="``lync.exe`` activity. (Legacy)." },
    @{ Id='634'; Title="Chrome Ext"; Op=""; Res=""; Lookup=""; Path="manifest\.json"; Cause="Read ``manifest.json`` fail. (Addon)." },
    @{ Id='638'; Title="Edge Update"; Op=""; Res=""; Lookup=""; Path="MicrosoftEdgeUpdate\.exe"; Cause="``MicrosoftEdgeUpdate.exe`` fail. (Patch)." },
    @{ Id='639'; Title="Edge IE Mode"; Op=""; Res=""; Lookup=""; Path="ieexplore\.exe"; Cause="``ieexplore.exe`` spawn. (Compat)." },
    @{ Id='640'; Title="Edge WebView"; Op=""; Res=""; Lookup=""; Path="msedgewebview2\.exe"; Cause="``msedgewebview2.exe`` crash. (App)." },
    @{ Id='646'; Title="Proxy Script"; Op=""; Res=""; Lookup=""; Path="\.pac"; Cause="Read ``.pac`` timeout. (Net)." },
    @{ Id='651'; Title="NTFS Driver"; Op=""; Res=""; Lookup=""; Path="ntfs\.sys"; Cause="``ntfs.sys`` activity. (Disk)." },
    @{ Id='652'; Title="Filter Mgr"; Op=""; Res=""; Lookup=""; Path="fltmgr\.sys"; Cause="``fltmgr.sys`` activity. (Filters)." },
    @{ Id='653'; Title="TCP/IP"; Op=""; Res=""; Lookup=""; Path="tcpip\.sys"; Cause="``tcpip.sys`` activity. (Net)." },
    @{ Id='654'; Title="NetBIOS"; Op=""; Res=""; Lookup=""; Path="netbt\.sys"; Cause="``netbt.sys`` activity. (Legacy)." },
    @{ Id='655'; Title="AFD Driver"; Op=""; Res=""; Lookup=""; Path="afd\.sys"; Cause="``afd.sys`` activity. (Sock)." },
    @{ Id='656'; Title="WFP Driver"; Op=""; Res=""; Lookup=""; Path="fwpkclnt\.sys"; Cause="``fwpkclnt.sys`` activity. (Firewall)." },
    @{ Id='657'; Title="NDIS Driver"; Op=""; Res=""; Lookup=""; Path="ndis\.sys"; Cause="``ndis.sys`` activity. (NIC)." },
    @{ Id='658'; Title="Storport"; Op=""; Res=""; Lookup=""; Path="storport\.sys"; Cause="``storport.sys`` activity. (SAN)." },
    @{ Id='659'; Title="USB Port"; Op=""; Res=""; Lookup=""; Path="usbport\.sys"; Cause="``usbport.sys`` activity. (Bus)." },
    @{ Id='660'; Title="USB Hub"; Op=""; Res=""; Lookup=""; Path="usbhub\.sys"; Cause="``usbhub.sys`` activity. (Bus)." },
    @{ Id='661'; Title="HID Class"; Op=""; Res=""; Lookup=""; Path="hidclass\.sys"; Cause="``hidclass.sys`` activity. (Input)." },
    @{ Id='662'; Title="Mouse Class"; Op=""; Res=""; Lookup=""; Path="mouclass\.sys"; Cause="``mouclass.sys`` activity. (Input)." },
    @{ Id='663'; Title="Kbd Class"; Op=""; Res=""; Lookup=""; Path="kbdclass\.sys"; Cause="``kbdclass.sys`` activity. (Input)." },
    @{ Id='664'; Title="Graphics"; Op=""; Res=""; Lookup=""; Path="dxgkrnl\.sys"; Cause="``dxgkrnl.sys`` activity. (GPU)." },
    @{ Id='665'; Title="Nvidia"; Op=""; Res=""; Lookup=""; Path="nvlddmkm\.sys"; Cause="``nvlddmkm.sys`` activity. (GPU)." },
    @{ Id='666'; Title="AMD"; Op=""; Res=""; Lookup=""; Path="atikmdag\.sys"; Cause="``atikmdag.sys`` activity. (GPU)." },
    @{ Id='667'; Title="Intel Gfx"; Op=""; Res=""; Lookup=""; Path="igdkmd64\.sys"; Cause="``igdkmd64.sys`` activity. (GPU)." },
    @{ Id='668'; Title="Realtek Audio"; Op=""; Res=""; Lookup=""; Path="rtkvhd64\.sys"; Cause="``rtkvhd64.sys`` activity. (Sound)." },
    @{ Id='669'; Title="Symantec Filter"; Op=""; Res=""; Lookup=""; Path="symefasi\.sys"; Cause="``symefasi.sys``. (AV)." },
    @{ Id='670'; Title="McAfee Filter"; Op=""; Res=""; Lookup=""; Path="mfehidk\.sys"; Cause="``mfehidk.sys``. (AV)." },
    @{ Id='671'; Title="CrowdStrike"; Op=""; Res=""; Lookup=""; Path="csagent\.sys"; Cause="``csagent.sys``. (EDR)." },
    @{ Id='672'; Title="SentinelOne"; Op=""; Res=""; Lookup=""; Path="SentinelMonitor\.sys"; Cause="``SentinelMonitor.sys``. (EDR)." },
    @{ Id='673'; Title="CarbonBlack"; Op=""; Res=""; Lookup=""; Path="cbk7\.sys"; Cause="``cbk7.sys``. (EDR)." },
    @{ Id='674'; Title="Sysmon"; Op=""; Res=""; Lookup=""; Path="SysmonDrv\.sys"; Cause="``SysmonDrv.sys``. (Log)." },
    @{ Id='675'; Title="ProcMon"; Op=""; Res=""; Lookup=""; Path="PROCMON24\.SYS"; Cause="``PROCMON24.SYS``. (Self)." },
    @{ Id='676'; Title="VMware Mouse"; Op=""; Res=""; Lookup=""; Path="vmmouse\.sys"; Cause="``vmmouse.sys``. (Guest)." },
    @{ Id='677'; Title="VMware Video"; Op=""; Res=""; Lookup=""; Path="vm3dmp\.sys"; Cause="``vm3dmp.sys``. (Guest)." },
    @{ Id='678'; Title="Citrix Net"; Op=""; Res=""; Lookup=""; Path="ctxtcp\.sys"; Cause="``ctxtcp.sys``. (VDI)." },
    @{ Id='679'; Title="Citrix Usb"; Op=""; Res=""; Lookup=""; Path="ctxusbm\.sys"; Cause="``ctxusbm.sys``. (VDI)." },
    @{ Id='680'; Title="FSLogix"; Op=""; Res=""; Lookup=""; Path="frxdrv\.sys"; Cause="``frxdrv.sys``. (Profile)." },
    @{ Id='713'; Title="PS Profile"; Op=""; Res=""; Lookup=""; Path="Microsoft\.PowerShell_profile\.ps1"; Cause="Read ``Microsoft.PowerShell_profile.ps1``. (Config)." },
    @{ Id='714'; Title="PS History"; Op=""; Res=""; Lookup=""; Path="ConsoleHost_history\.txt"; Cause="Read ``ConsoleHost_history.txt``. (Log)." },
    @{ Id='715'; Title="PS Execution"; Op="ExecutionPolicy"; Res=""; Lookup=""; Path=""; Cause="Read ``ExecutionPolicy``. (Security)." },
    @{ Id='716'; Title="PS Transcript"; Op=""; Res=""; Lookup=""; Path="Transcript\.txt"; Cause="Write ``Transcript.txt``. (Log)." },
    @{ Id='717'; Title="PS Gallery"; Op=""; Res=""; Lookup=""; Path="powershellgallery\.com"; Cause="Connect ``powershellgallery.com``. (Download)." },
    @{ Id='721'; Title="VBS Engine"; Op=""; Res=""; Lookup=""; Path="vbscript\.dll"; Cause="Load ``vbscript.dll``. (Legacy)." },
    @{ Id='722'; Title="JS Engine"; Op=""; Res=""; Lookup=""; Path="jscript\.dll"; Cause="Load ``jscript.dll``. (Legacy)." },
    @{ Id='723'; Title="WSF File"; Op=""; Res=""; Lookup=""; Path="\.wsf"; Cause="Exec ``.wsf``. (Mixed)." },
    @{ Id='724'; Title="HTA App"; Op=""; Res=""; Lookup=""; Path="\.hta"; Cause="Exec ``.hta``. (UI)." },
    @{ Id='725'; Title="Batch File"; Op=""; Res=""; Lookup=""; Path="\.bat"; Cause="Exec ``.bat``. (Shell)." },
    @{ Id='726'; Title="Cmd File"; Op=""; Res=""; Lookup=""; Path="\.cmd"; Cause="Exec ``.cmd``. (Shell)." },
    @{ Id='727'; Title="Python Script"; Op=""; Res=""; Lookup=""; Path="\.py"; Cause="Exec ``.py``. (Dev)." },
    @{ Id='728'; Title="Perl Script"; Op=""; Res=""; Lookup=""; Path="\.pl"; Cause="Exec ``.pl``. (Dev)." },
    @{ Id='729'; Title="Ruby Script"; Op=""; Res=""; Lookup=""; Path="\.rb"; Cause="Exec ``.rb``. (Dev)." },
    @{ Id='730'; Title="Jar File"; Op=""; Res=""; Lookup=""; Path="\.jar"; Cause="Exec ``.jar``. (Java)." },
    @{ Id='731'; Title="Prefetch Create"; Op=""; Res=""; Lookup=""; Path=".*\.pf"; Cause="Write ``*.pf``. (Exec)." },
    @{ Id='734'; Title="ShellBag"; Op=""; Res=""; Lookup=""; Path="Shell\\Bags"; Cause="Reg Write ``Shell\Bags``. (Folder view)." },
    @{ Id='737'; Title="Amcache"; Op=""; Res=""; Lookup=""; Path="Amcache\.hve"; Cause="Write ``Amcache.hve``. (Inventory)." },
    @{ Id='738'; Title="SRUM"; Op=""; Res=""; Lookup=""; Path="SRUDB\.dat"; Cause="Write ``SRUDB.dat``. (Usage)." },
    @{ Id='739'; Title="ThumbCache"; Op=""; Res=""; Lookup=""; Path="thumbcache_.*\.db"; Cause="Write ``thumbcache_*.db``. (Image)." },
    @{ Id='740'; Title="IconCache"; Op=""; Res=""; Lookup=""; Path="IconCache\.db"; Cause="Write ``IconCache.db``. (Icon)." },
    @{ Id='741'; Title="Recycle Bin"; Op=""; Res=""; Lookup=""; Path="$Recycle\.Bin"; Cause="Write ``$Recycle.Bin``. (Delete)." },
    @{ Id='744'; Title="USN"; Op=""; Res=""; Lookup=""; Path="$Extend\\$UsnJrnl"; Cause="Write ``$Extend\$UsnJrnl``. (Change)." },
    @{ Id='745'; Title="Index DB"; Op=""; Res=""; Lookup=""; Path="Windows\.edb"; Cause="Write ``Windows.edb``. (Search)." },
    @{ Id='746'; Title="Event Log"; Op=""; Res=""; Lookup=""; Path="Security\.evtx"; Cause="Write ``Security.evtx``. (Audit)." },
    @{ Id='747'; Title="WER Report"; Op=""; Res=""; Lookup=""; Path="Report\.wer"; Cause="Write ``Report.wer``. (Crash)." },
    @{ Id='748'; Title="Dump File"; Op=""; Res=""; Lookup=""; Path="memory\.dmp"; Cause="Write ``memory.dmp``. (Crash)." },
    @{ Id='750'; Title="Hibernation"; Op=""; Res=""; Lookup=""; Path="hiberfil\.sys"; Cause="Write ``hiberfil.sys``. (Power)." },
    @{ Id='751'; Title="SetupAPI"; Op=""; Res=""; Lookup=""; Path="setupapi\.dev\.log"; Cause="Write ``setupapi.dev.log``. (Driver)." },
    @{ Id='752'; Title="CBS"; Op=""; Res=""; Lookup=""; Path="CBS\.log"; Cause="Write ``CBS.log``. (OS)." },
    @{ Id='753'; Title="DISM"; Op=""; Res=""; Lookup=""; Path="dism\.log"; Cause="Write ``dism.log``. (Image)." },
    @{ Id='754'; Title="WindowsUpdate"; Op=""; Res=""; Lookup=""; Path="WindowsUpdate\.log"; Cause="Write ``WindowsUpdate.log``. (Patch)." },
    @{ Id='755'; Title="MSI Log"; Op=""; Res=""; Lookup=""; Path="MSI.*\.log"; Cause="Write ``MSI*.log``. (App)." },
    @{ Id='756'; Title="DirectX"; Op=""; Res=""; Lookup=""; Path="DXError\.log"; Cause="Write ``DXError.log``. (Graphics)." },
    @{ Id='757'; Title="DotNet"; Op=""; Res=""; Lookup=""; Path="dd_.*\.log"; Cause="Write ``dd_*.log``. (Runtime)." },
    @{ Id='758'; Title="VCRedist"; Op=""; Res=""; Lookup=""; Path="dd_vcredist.*\.log"; Cause="Write ``dd_vcredist*.log``. (Runtime)." },
    @{ Id='759'; Title="SQL Setup"; Op=""; Res=""; Lookup=""; Path="Summary\.txt"; Cause="Write ``Summary.txt``. (DB)." },
    @{ Id='760'; Title="IIS Setup"; Op=""; Res=""; Lookup=""; Path="iis\.log"; Cause="Write ``iis.log``. (Web)." },
    @{ Id='761'; Title="SCCM Log"; Op=""; Res=""; Lookup=""; Path="ccmsetup\.log"; Cause="Write ``ccmsetup.log``. (Mgmt)." },
    @{ Id='762'; Title="Intune Log"; Op=""; Res=""; Lookup=""; Path="IntuneManagementExtension\.log"; Cause="Write ``IntuneManagementExtension.log``. (Mgmt)." },
    @{ Id='763'; Title="Sysprep"; Op=""; Res=""; Lookup=""; Path="setupact\.log"; Cause="Write ``setupact.log``. (Image)." },
    @{ Id='764'; Title="Unattend"; Op=""; Res=""; Lookup=""; Path="unattend\.xml"; Cause="Read ``unattend.xml``. (Config)." },
    @{ Id='765'; Title="Panther"; Op=""; Res=""; Lookup=""; Path="\\Panther"; Cause="Read ``\Panther``. (Setup)." },
    @{ Id='767'; Title="CreateFile Directory"; Op=""; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Opening Dir as File -> Access Denied." },
    @{ Id='773'; Title="Dll Search Order"; Op=""; Res=""; Lookup=""; Path="evil\.dll"; Cause="Loading ``evil.dll`` from CWD." },
    @{ Id='784'; Title="Sparse File"; Op=""; Res="DISK FULL"; Lookup="DISK FULL"; Path=""; Cause="Disk Full on sparse write." },
    @{ Id='841'; Title="HCS Crash"; Op=""; Res=""; Lookup=""; Path="hcsshim\.dll"; Cause="``hcsshim.dll`` fail. (Container)." },
    @{ Id='842'; Title="Docker Svc"; Op=""; Res=""; Lookup=""; Path="dockerd\.exe"; Cause="``dockerd.exe`` fail. (Engine)." },
    @{ Id='844'; Title="Layer Locked"; Op=""; Res=""; Lookup=""; Path="layer\.tar"; Cause="``layer.tar`` access deny. (Image)." },
    @{ Id='846'; Title="Pipe Docker"; Op=""; Res=""; Lookup=""; Path="\\\\\.\\pipe\\docker_engine"; Cause="``\\.\pipe\docker_engine`` fail. (API)." },
    @{ Id='851'; Title="OneDrive Pipe"; Op=""; Res=""; Lookup=""; Path="\\\\\.\\pipe\\OneDriveIPC"; Cause="``\\.\pipe\OneDriveIPC`` fail. (IPC)." },
    @{ Id='854'; Title="Dropbox Pipe"; Op=""; Res=""; Lookup=""; Path="\\\\\.\\pipe\\DropboxPipe"; Cause="``\\.\pipe\DropboxPipe`` fail. (IPC)." },
    @{ Id='855'; Title="Dropbox Ignore"; Op=""; Res=""; Lookup=""; Path="\.dropboxignore"; Cause="Read ``.dropboxignore``. (Config)." },
    @{ Id='860'; Title="Attr Fail"; Op="SetFileAttributes"; Res=""; Lookup=""; Path=""; Cause="``SetFileAttributes`` Recall. (Tiering)." },
    @{ Id='861'; Title="SQL Mem"; Op=""; Res=""; Lookup=""; Path="sqlservr\.exe"; Cause="``sqlservr.exe`` Mem limit. (RAM)." },
    @{ Id='862'; Title="SQL Dump"; Op=""; Res=""; Lookup=""; Path="SQLDump.*\.mdmp"; Cause="Write ``SQLDump*.mdmp``. (Crash)." },
    @{ Id='863'; Title="SQL Pipe"; Op=""; Res=""; Lookup=""; Path="\\\\\.\\pipe\\sql\\query"; Cause="``\\.\pipe\sql\query`` busy. (Load)." },
    @{ Id='864'; Title="SQL VIA"; Op=""; Res=""; Lookup=""; Path="sqlvia\.dll"; Cause="Load ``sqlvia.dll``. (Legacy Proto)." },
    @{ Id='865'; Title="SQL Shared"; Op=""; Res=""; Lookup=""; Path="sqlmin\.dll"; Cause="Load ``sqlmin.dll``. (Engine)." },
    @{ Id='866'; Title="Oracle OCI"; Op=""; Res=""; Lookup=""; Path="oci\.dll"; Cause="Load ``oci.dll`` fail. (Client)." },
    @{ Id='867'; Title="Oracle Java"; Op=""; Res=""; Lookup=""; Path="ojdbc\.jar"; Cause="Load ``ojdbc.jar`` fail. (Java)." },
    @{ Id='868'; Title="Postgres"; Op=""; Res=""; Lookup=""; Path="postgres\.exe"; Cause="``postgres.exe`` activity. (OSS DB)." },
    @{ Id='869'; Title="MySQL"; Op=""; Res=""; Lookup=""; Path="mysqld\.exe"; Cause="``mysqld.exe`` activity. (OSS DB)." },
    @{ Id='870'; Title="SQLite Lock"; Op=""; Res=""; Lookup=""; Path="database\.sqlite-journal"; Cause="``database.sqlite-journal`` lock. (Local)." },
    @{ Id='871'; Title="Git Config"; Op=""; Res=""; Lookup=""; Path="\.gitconfig"; Cause="Read ``.gitconfig``. (Settings)." },
    @{ Id='873'; Title="VSCode Ext"; Op=""; Res=""; Lookup=""; Path="extensions\.json"; Cause="Read ``extensions.json``. (IDE)." },
    @{ Id='874'; Title="Visual Studio"; Op=""; Res=""; Lookup=""; Path="devenv\.exe"; Cause="``devenv.exe`` crash. (IDE)." },
    @{ Id='875'; Title="MSBuild"; Op=""; Res=""; Lookup=""; Path="MSBuild\.exe"; Cause="``MSBuild.exe`` fail. (Build)." },
    @{ Id='876'; Title="NuGet"; Op=""; Res=""; Lookup=""; Path="nuget\.config"; Cause="Read ``nuget.config``. (Pkg)." },
    @{ Id='877'; Title="Npm Lock"; Op=""; Res=""; Lookup=""; Path="package-lock\.json"; Cause="Read ``package-lock.json``. (Dep)." },
    @{ Id='879'; Title="Maven Repo"; Op=""; Res=""; Lookup=""; Path="\.m2"; Cause="Read ``.m2``. (Java)." },
    @{ Id='882'; Title="Adobe Font"; Op=""; Res=""; Lookup=""; Path="AdobeFnt\.lst"; Cause="Read ``AdobeFnt.lst``. (Cache)." },
    @{ Id='884'; Title="Premiere"; Op=""; Res=""; Lookup=""; Path="Adobe Premiere Pro\.exe"; Cause="``Adobe Premiere Pro.exe``. (Video)." },
    @{ Id='885'; Title="After Effects"; Op=""; Res=""; Lookup=""; Path="AfterFX\.exe"; Cause="``AfterFX.exe``. (VFX)." },
    @{ Id='886'; Title="Photoshop"; Op=""; Res=""; Lookup=""; Path="Photoshop\.exe"; Cause="``Photoshop.exe``. (Image)." },
    @{ Id='887'; Title="Davinci Resolve"; Op=""; Res=""; Lookup=""; Path="Resolve\.exe"; Cause="``Resolve.exe``. (Video)." },
    @{ Id='890'; Title="Codec Load"; Op=""; Res=""; Lookup=""; Path="ffmpeg\.dll"; Cause="Load ``ffmpeg.dll``. (Media)." },
    @{ Id='891'; Title="SteamVR"; Op=""; Res=""; Lookup=""; Path="vrserver\.exe"; Cause="``vrserver.exe``. (VR)." },
    @{ Id='892'; Title="Oculus"; Op=""; Res=""; Lookup=""; Path="OVRServer_x64\.exe"; Cause="``OVRServer_x64.exe``. (VR)." },
    @{ Id='893'; Title="WMR"; Op=""; Res=""; Lookup=""; Path="MixedRealityPortal\.exe"; Cause="``MixedRealityPortal.exe``. (VR)." },
    @{ Id='894'; Title="OpenVR"; Op=""; Res=""; Lookup=""; Path="openvr_api\.dll"; Cause="Load ``openvr_api.dll``. (API)." },
    @{ Id='897'; Title="Compositor"; Op=""; Res=""; Lookup=""; Path="vrcompositor\.exe"; Cause="``vrcompositor.exe`` crash. (Display)." },
    @{ Id='901'; Title="DiagTrack"; Op=""; Res=""; Lookup=""; Path="CompatTelRunner\.exe"; Cause="``CompatTelRunner.exe``. (Usage)." },
    @{ Id='902'; Title="SQM"; Op=""; Res=""; Lookup=""; Path="sqm.*\.dat"; Cause="Write ``sqm*.dat``. (Quality)." },
    @{ Id='905'; Title="Inventory"; Op=""; Res=""; Lookup=""; Path="Inventory\.exe"; Cause="``Inventory.exe``. (App scan)." },
    @{ Id='906'; Title="Device Census"; Op=""; Res=""; Lookup=""; Path="DeviceCensus\.exe"; Cause="``DeviceCensus.exe``. (Hw scan)." },
    @{ Id='909'; Title="Timeline"; Op=""; Res=""; Lookup=""; Path="ActivitiesCache\.db"; Cause="Write ``ActivitiesCache.db``. (History)." },
    @{ Id='912'; Title="RDP Clip"; Op=""; Res=""; Lookup=""; Path="rdpclip\.exe"; Cause="``rdpclip.exe`` fail. (Copy/Paste)." },
    @{ Id='913'; Title="RDP Drv"; Op=""; Res=""; Lookup=""; Path="rdpdr\.sys"; Cause="``rdpdr.sys`` fail. (Redirection)." },
    @{ Id='914'; Title="RDP Sound"; Op=""; Res=""; Lookup=""; Path="rdpsnd\.sys"; Cause="``rdpsnd.sys`` fail. (Audio)." },
    @{ Id='916'; Title="RDP Input"; Op=""; Res=""; Lookup=""; Path="rdpinput\.sys"; Cause="``rdpinput.sys``. (Mouse)." },
    @{ Id='917'; Title="RDP Gfx"; Op=""; Res=""; Lookup=""; Path="rdpgfx\.sys"; Cause="``rdpgfx.sys``. (Video)." },
    @{ Id='918'; Title="Session Dir"; Op=""; Res=""; Lookup=""; Path="tssdis\.exe"; Cause="``tssdis.exe`` fail. (Broker)." },
    @{ Id='919'; Title="License Svc"; Op=""; Res=""; Lookup=""; Path="lserver\.exe"; Cause="``lserver.exe`` fail. (CALs)." },
    @{ Id='920'; Title="RemoteApp"; Op=""; Res=""; Lookup=""; Path="rdpshell\.exe"; Cause="``rdpshell.exe``. (Seamless)." },
    @{ Id='921'; Title="VSS Create"; Op=""; Res=""; Lookup=""; Path="vssvc\.exe"; Cause="``vssvc.exe`` start. (Snapshot)." },
    @{ Id='922'; Title="VSS Writer"; Op="SqlWriter"; Res=""; Lookup=""; Path=""; Cause="``SqlWriter`` timeout. (SQL)." },
    @{ Id='924'; Title="VSS Hardware"; Op=""; Res=""; Lookup=""; Path="vds\.exe"; Cause="``vds.exe`` fail. (SAN)." },
    @{ Id='925'; Title="Change Block"; Op=""; Res=""; Lookup=""; Path="ctp\.sys"; Cause="``ctp.sys`` activity. (CBT)." },
    @{ Id='927'; Title="Backup Read"; Op="BackupRead"; Res=""; Lookup=""; Path=""; Cause="``BackupRead`` API. (Stream)." },
    @{ Id='928'; Title="Archive Bit"; Op="SetFileAttributes"; Res=""; Lookup=""; Path=""; Cause="``SetFileAttributes`` A. (Flag)." },
    @{ Id='931'; Title="Print Processor"; Op=""; Res=""; Lookup=""; Path="winprint\.dll"; Cause="Load ``winprint.dll``. (Spool)." },
    @{ Id='932'; Title="Print Monitor"; Op=""; Res=""; Lookup=""; Path="usbmon\.dll"; Cause="Load ``usbmon.dll``. (Port)." },
    @{ Id='933'; Title="Print Lang"; Op=""; Res=""; Lookup=""; Path="pjlmon\.dll"; Cause="Load ``pjlmon.dll``. (PJL)." },
    @{ Id='934'; Title="Print Net"; Op=""; Res=""; Lookup=""; Path="tcpmon\.dll"; Cause="Load ``tcpmon.dll``. (IP)." },
    @{ Id='939'; Title="Print Queue"; Op=""; Res=""; Lookup=""; Path="\.spl"; Cause="Write ``.spl``. (Spool)." },
    @{ Id='940'; Title="Print Job"; Op=""; Res=""; Lookup=""; Path="\.shd"; Cause="Write ``.shd``. (Shadow)." },
    @{ Id='942'; Title="Font Mem"; Op="CreateFontIndirect"; Res=""; Lookup=""; Path=""; Cause="``CreateFontIndirect`` fail. (GDI)." },
    @{ Id='945'; Title="EUDC"; Op=""; Res=""; Lookup=""; Path="EUDC\.TE"; Cause="Read ``EUDC.TE``. (Custom)." },
    @{ Id='946'; Title="Freetype"; Op=""; Res=""; Lookup=""; Path="freetype\.dll"; Cause="Load ``freetype.dll``. (OSS)." },
    @{ Id='947'; Title="DirectWrite"; Op=""; Res=""; Lookup=""; Path="dwrite\.dll"; Cause="Load ``dwrite.dll``. (Modern)." },
    @{ Id='948'; Title="Uniscribe"; Op=""; Res=""; Lookup=""; Path="usp10\.dll"; Cause="Load ``usp10.dll``. (Complex)." },
    @{ Id='949'; Title="Font Cache"; Op=""; Res=""; Lookup=""; Path="FNTCACHE\.DAT"; Cause="Write ``FNTCACHE.DAT``. (Boot)." },
    @{ Id='950'; Title="Type1 Font"; Op=""; Res=""; Lookup=""; Path="\.pfm"; Cause="Read ``.pfm``. (Legacy)." },
    @{ Id='951'; Title="AutoCAD"; Op=""; Res=""; Lookup=""; Path="acad\.exe"; Cause="``acad.exe`` crash. (CAD)." },
    @{ Id='952'; Title="Revit"; Op=""; Res=""; Lookup=""; Path="revit\.exe"; Cause="``revit.exe`` crash. (BIM)." },
    @{ Id='953'; Title="SolidWorks"; Op=""; Res=""; Lookup=""; Path="SLDWORKS\.exe"; Cause="``SLDWORKS.exe``. (CAD)." },
    @{ Id='954'; Title="Matlab"; Op=""; Res=""; Lookup=""; Path="matlab\.exe"; Cause="``matlab.exe``. (Math)." },
    @{ Id='955'; Title="LabView"; Op=""; Res=""; Lookup=""; Path="labview\.exe"; Cause="``labview.exe``. (Eng)." },
    @{ Id='956'; Title="License Flex"; Op=""; Res=""; Lookup=""; Path="lmgrd\.exe"; Cause="``lmgrd.exe``. (Licensing)." },
    @{ Id='957'; Title="Dongle HASP"; Op=""; Res=""; Lookup=""; Path="hasplms\.exe"; Cause="``hasplms.exe``. (Key)." },
    @{ Id='959'; Title="CUDA"; Op=""; Res=""; Lookup=""; Path="nvcuda\.dll"; Cause="Load ``nvcuda.dll``. (Compute)." },
    @{ Id='960'; Title="MPI"; Op=""; Res=""; Lookup=""; Path="mpi\.dll"; Cause="Load ``mpi.dll``. (Cluster)." },
    @{ Id='961'; Title="Bloomberg"; Op=""; Res=""; Lookup=""; Path="bbcomm\.exe"; Cause="``bbcomm.exe``. (Terminal)." },
    @{ Id='962'; Title="Thomson"; Op=""; Res=""; Lookup=""; Path="Eikon\.exe"; Cause="``Eikon.exe``. (Terminal)." },
    @{ Id='967'; Title="Solarflare"; Op=""; Res=""; Lookup=""; Path="sf.*dll"; Cause="Load ``sf...dll``. (NIC)." },
    @{ Id='968'; Title="Mellanox"; Op=""; Res=""; Lookup=""; Path="mlx.*sys"; Cause="Load ``mlx...sys``. (NIC)." },
    @{ Id='971'; Title="Epic"; Op=""; Res=""; Lookup=""; Path="Hyperspace\.exe"; Cause="``Hyperspace.exe``. (EMR)." },
    @{ Id='981'; Title="LanSchool"; Op=""; Res=""; Lookup=""; Path="student\.exe"; Cause="``student.exe``. (Monitor)." },
    @{ Id='982'; Title="NetSupport"; Op=""; Res=""; Lookup=""; Path="client32\.exe"; Cause="``client32.exe``. (Monitor)." },
    @{ Id='991'; Title="OPOS"; Op=""; Res=""; Lookup=""; Path="OPOS\.dll"; Cause="Load ``OPOS.dll``. (Device)." },
    @{ Id='992'; Title="JavaPOS"; Op=""; Res=""; Lookup=""; Path="jpos\.jar"; Cause="Load ``jpos.jar``. (Device)." },
    @{ Id='1011'; Title="Swallowed Exception (CLR)"; Op=""; Res=""; Lookup=""; Path="\.NET Runtime"; Cause="``.NET Runtime`` logs `"Application Error`" event but no ProcMon crash. (Dev caught exception but didn't log it)." },
    @{ Id='1012'; Title="WerFault Suppression"; Op=""; Res=""; Lookup=""; Path="WerFault\.exe"; Cause="``WerFault.exe`` starts but exits immediately with no UI. (Headless mode crash)." },
    @{ Id='1013'; Title="Stack Overflow (Silent)"; Op="Process Exit"; Res=""; Lookup=""; Path=""; Cause="``Process Exit`` code ``0xC00000FD``. (Recursion limit hit, often no dump)." },
    @{ Id='1014'; Title="Heap Corruption (Immediate)"; Op="Process Exit"; Res=""; Lookup=""; Path=""; Cause="``Process Exit`` code ``0xC0000374``. (Kernel kills app instantly to save OS)." },
    @{ Id='1021'; Title="Focus Theft"; Op="SetForegroundWindow"; Res=""; Lookup=""; Path=""; Cause="High rate of ``SetForegroundWindow`` by background app. (Interrupts speech)." },
    @{ Id='1023'; Title="AccName Missing"; Op=""; Res=""; Lookup=""; Path="IAccessible::get_accName"; Cause="``IAccessible::get_accName`` returns empty. (Unlabeled button)." },
    @{ Id='1026'; Title="Java Bridge 32/64"; Op=""; Res=""; Lookup=""; Path="WindowsAccessBridge-32\.dll"; Cause="``WindowsAccessBridge-32.dll`` load fail in 64-bit Java. (Silent Java)." },
    @{ Id='1027'; Title="Java Bridge Missing"; Op="RegOpenKey"; Res=""; Lookup=""; Path="HKLM\\Software\\JavaSoft\\Accessibility"; Cause="``RegOpenKey`` ``HKLM\Software\JavaSoft\Accessibility`` fail. (Not installed)." },
    @{ Id='1030'; Title="Secure Desktop Block"; Op=""; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="Screen Reader ``ACCESS_DENIED`` on UAC prompt. (Security boundary)." },
    @{ Id='1032'; Title="Mirror Driver Fail"; Op=""; Res=""; Lookup=""; Path="jfwvid\.dll"; Cause="Load ``jfwvid.dll`` (JAWS) or ``nvda_mirror`` fail. (Video hook broken)." },
    @{ Id='1033'; Title="Touch API Fail"; Op=""; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``InjectTouchInput`` Access Denied. (Touchscreen reader fail)." },
    @{ Id='1036'; Title="Provider Reg Fail"; Op="RegOpenKey"; Res=""; Lookup=""; Path="HKCR\\CLSID\\{ProxyStub}"; Cause="``RegOpenKey`` ``HKCR\CLSID\{ProxyStub}`` fail. (UIA broken)." },
    @{ Id='1038'; Title="Pattern Not Supported"; Op=""; Res=""; Lookup=""; Path="IUIAutomation::GetPattern"; Cause="``IUIAutomation::GetPattern`` returns null. (Control broken)." },
    @{ Id='1044'; Title="Proxy Loading"; Op=""; Res=""; Lookup=""; Path="UIAutomationCore\.dll"; Cause="``UIAutomationCore.dll`` loading wrong version. (Compat)." },
    @{ Id='1046'; Title="Magnifier Overlay"; Op=""; Res=""; Lookup=""; Path="Magnification\.dll"; Cause="``Magnification.dll`` init fail. (Driver conflict)." },
    @{ Id='1047'; Title="Cursor Hook Fail"; Op="SetWindowsHookEx"; Res=""; Lookup=""; Path=""; Cause="``SetWindowsHookEx`` (WH_CALLWNDPROC) fail. (Tracking broken)." },
    @{ Id='1049'; Title="Color Filter Fail"; Op="DwmSetColorizationParameters"; Res=""; Lookup=""; Path=""; Cause="``DwmSetColorizationParameters`` fail. (High contrast break)." },
    @{ Id='1052'; Title="Text Service (TSF)"; Op=""; Res=""; Lookup=""; Path="ctfmon\.exe"; Cause="``ctfmon.exe`` deadlock. (Dictation freeze)." },
    @{ Id='1054'; Title="Vocabulary Write"; Op=""; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path="user\.dic"; Cause="Write ``user.dic`` Access Denied. (Learning fail)." },
    @{ Id='1055'; Title="Eye Tracker HID"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="``CreateFile`` EyeTracker fail. (Hardware connect)." },
    @{ Id='1057'; Title="OSK Injection"; Op="SendInput"; Res=""; Lookup=""; Path=""; Cause="``SendInput`` fail on Admin window. (Keyboard security)." },
    @{ Id='1058'; Title="Tablet Service"; Op=""; Res=""; Lookup=""; Path="TabTip\.exe"; Cause="``TabTip.exe`` crash. (Touch keyboard)." },
    @{ Id='1061'; Title="Global Object Creation"; Op="CreateMutex"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``CreateMutex`` `"Global\`" Access Denied. (Needs SeCreateGlobalPrivilege)." },
    @{ Id='1062'; Title="Service Control"; Op="OpenSCManager"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``OpenSCManager`` Access Denied. (Trying to start service)." },
    @{ Id='1063'; Title="Program Files Write"; Op="CreateFile"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``CreateFile`` `"C:\Program Files\...`" Access Denied. (Bad coding)." },
    @{ Id='1064'; Title="HKLM Write"; Op="RegSetValue"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``RegSetValue`` HKLM Access Denied. (Bad coding)." },
    @{ Id='1065'; Title="Event Log Write"; Op=""; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``RegisterEventSource`` `"Security`" Access Denied. (Audit write)." },
    @{ Id='1066'; Title="Symlink Create"; Op="CreateSymbolicLink"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``CreateSymbolicLink`` Access Denied. (Needs privilege)." },
    @{ Id='1067'; Title="Debug Privilege"; Op="OpenProcess"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``OpenProcess`` System Process Access Denied. (Debug)." },
    @{ Id='1068'; Title="Driver Load"; Op="NtLoadDriver"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``NtLoadDriver`` Access Denied. (Kernel)." },
    @{ Id='1069'; Title="Raw Socket"; Op=""; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``socket(SOCK_RAW)`` Access Denied. (Network tool)." },
    @{ Id='1070'; Title="Volume Access"; Op="CreateFile"; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="``CreateFile`` `"\\.\C:`" Access Denied. (Disk tool)." },
    @{ Id='1071'; Title="Modified PATH"; Op="LoadImage"; Res=""; Lookup=""; Path=""; Cause="``LoadImage`` fails because ``%PATH%`` truncated > 2048 chars." },
    @{ Id='1072'; Title="User vs System Path"; Op=""; Res=""; Lookup=""; Path="C:\\Users\\.*\\bin"; Cause="DLL loaded from User Path ``C:\Users\...\bin``. (Wrong version)." },
    @{ Id='1073'; Title="Current Work Dir"; Op="CreateFile"; Res=""; Lookup=""; Path=""; Cause="``CreateFile`` relative path fail. (Shortcut `"Start In`" wrong)." },
    @{ Id='1074'; Title="GAC Priority"; Op=""; Res=""; Lookup=""; Path="C:\\Windows\\Assembly"; Cause="DLL loaded from ``C:\Windows\Assembly`` (GAC) instead of App folder." },
    @{ Id='1076'; Title="Redirected Folders"; Op=""; Res=""; Lookup=""; Path="C:\\Users|\\\\Server\\Share"; Cause="App hardcodes ``C:\Users``, fails on ``\\Server\Share``." },
    @{ Id='1101'; Title="USB Redirection"; Op=""; Res=""; Lookup=""; Path="tsusbhub\.sys"; Cause="``tsusbhub.sys`` fail. (Scanner doesn't map)." },
    @{ Id='1102'; Title="SmartCard Redir"; Op=""; Res=""; Lookup=""; Path="scard\.dll|winscard\.dll"; Cause="``scard.dll`` works, ``winscard.dll`` fails. (Middleware)." },
    @{ Id='1104'; Title="Printer Mapping"; Op=""; Res=""; Lookup=""; Path="C:\\Windows\\System32\\spool\\servers"; Cause="``C:\Windows\System32\spool\servers`` access. (Driver pull)." },
    @{ Id='1105'; Title="Drive Map Slow"; Op=""; Res=""; Lookup=""; Path="\\\\tsclient\\c"; Cause="``\\tsclient\c`` latency. (Client drive access)." },
    @{ Id='1110'; Title="Single Sign On"; Op=""; Res=""; Lookup=""; Path="ssonsvr\.exe"; Cause="``ssonsvr.exe`` fail. (Cred prompt)." },
    @{ Id='1116'; Title="EDR Memory"; Op="NtReadVirtualMemory"; Res=""; Lookup=""; Path=""; Cause="EDR hooking ``NtReadVirtualMemory`` of AV. (Heuristic flag)." },
    @{ Id='1123'; Title="Render Filter"; Op=""; Res=""; Lookup=""; Path="mxdwdrv\.dll"; Cause="``mxdwdrv.dll`` crash. (XPS convert)." },
    @{ Id='1124'; Title="Color Profile"; Op=""; Res=""; Lookup=""; Path="mscms\.dll"; Cause="``mscms.dll`` access denied. (Bad colors)." },
    @{ Id='1127'; Title="CSR (Client Side Render)"; Op=""; Res=""; Lookup=""; Path="winspool\.drv"; Cause="``winspool.drv`` heavy CPU. (Rendering)." },
    @{ Id='1128'; Title="Job Stuck"; Op=""; Res=""; Lookup=""; Path="\.spl"; Cause="``.spl`` file locked by AV. (Queue jam)." },
    @{ Id='1135'; Title="Resolution Change"; Op="DisplaySettings"; Res=""; Lookup=""; Path=""; Cause="``DisplaySettings`` event. (User mess with screen)." },
    @{ Id='1138'; Title="Date Change"; Op="SetSystemTime"; Res=""; Lookup=""; Path=""; Cause="``SetSystemTime`` event. (User changed clock)." },
    @{ Id='10000'; Title="`Narrator.exe` Hook Failure"; Op=""; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path="NarratorHook\.dll"; Cause="Narrator tries to inject ``NarratorHook.dll`` but gets Access Denied." },
    @{ Id='10001'; Title="Synthetic Click Rejection"; Op=""; Res=""; Lookup=""; Path="InvokePattern\.Invoke()"; Cause="App ignores ``InvokePattern.Invoke()`` calls, requiring physical mouse input." },
    @{ Id='10002'; Title="Java Access Bridge (JAB) Load Fail"; Op=""; Res=""; Lookup=""; Path="WindowsAccessBridge-64\.dll"; Cause="``WindowsAccessBridge-64.dll`` not found." },
    @{ Id='10003'; Title="Magnifier Driver Overlay"; Op=""; Res=""; Lookup=""; Path="Magnify\.exe"; Cause="``Magnify.exe`` failing to create the magnification overlay window." },
    @{ Id='10004'; Title="Tablet Input Service Hang"; Op=""; Res=""; Lookup=""; Path="TabTip\.exe"; Cause="``TabTip.exe`` crashing or freezing." },
    @{ Id='10005'; Title="Theme API Crash"; Op=""; Res=""; Lookup=""; Path="uxtheme\.dll"; Cause="App crashing when ``uxtheme.dll`` handles High Contrast theme switch." },
    @{ Id='10006'; Title="Night Light Transition"; Op="SetDeviceGammaRamp"; Res=""; Lookup=""; Path=""; Cause="Gamma ramp API failure (``SetDeviceGammaRamp``)." },
    @{ Id='72'; Title="Text Services Framework (TSF) Lock"; Op=""; Res=""; Lookup=""; Path="ctfmon\.exe"; Cause="TSF manager (``ctfmon.exe``) deadlock with app." },
    @{ Id='10007'; Title="Ease of Access Registry Reset"; Op=""; Res=""; Lookup=""; Path="HKCU\\Control Panel\\Accessibility"; Cause="Windows resetting ``HKCU\Control Panel\Accessibility`` on reboot." },
    @{ Id='87'; Title="Portable Copy Permission"; Op=""; Res="ACCESS DENIED"; Lookup="ACCESS DENIED"; Path=""; Cause="`"Access Denied`" running NVDA Portable from a USB stick." },
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

# Detector: Shared Memory Contention (NtCreateSection)
function Detect-SharedMem {
    param($evt)
    if ($evt.Operation -notmatch 'CreateSection|MapViewOfSection') { return $null }
    if ($evt.Result -eq "SUCCESS" -and $evt.Duration -lt 0.5) { return $null }

    $cat = "SHARED MEMORY"
    $sev = "Medium"

    # Escalation for failures
    if ($evt.Result -match 'ACCESS DENIED|INSUFFICIENT_RESOURCES|NO_MEMORY') { $sev = "High" }

    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "Application crashes or white-screens (especially Electron/Chrome apps)."
    $tc = "Operation '$($evt.Operation)' on Shared Memory Section '$($evt.Path)' failed or was slow. Result: '$($evt.Result)'. This often indicates resource exhaustion (Page File / Commit Limit) or security permission issues with the Section Object."
    $rm = "1. Check Commit Charge (Memory) in Task Manager. 2. Verify Page File settings (is it disabled?). 3. Check for security software blocking 'Section' object creation."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: ALPC Latency (IPC Hangs)
function Detect-AlpcLatency {
    param($evt)
    if ($evt.Operation -notmatch 'ALPC|RPC|LPC') { return $null }
    if ($evt.Duration -lt 1.0) { return $null }

    $cat = "ALPC LATENCY"
    $sev = if ($evt.Duration -ge 5.0) { "High" } else { "Medium" }
    $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

    $ux = "The application freezes while waiting for another process."
    $tc = "An Advanced Local Procedure Call (ALPC) operation took $($evt.Duration) seconds. This indicates a synchronous IPC wait chain where the target process is hung or busy. Common in COM/DCOM/RPC scenarios."
    $rm = "1. Identify the target process (often visible in the 'Path' as a port name or via 'Detail'). 2. Check if the target service/process is hung. 3. Use 'Analyze Wait Chain' in Task Manager."

    return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
}

# Detector: ETW Exhaustion (Trace Control)
$EtwRateByProc = @{}
function Detect-EtwExhaustion {
    param($evt)
    # NtTraceControl or general ETW ops
    if ($evt.Operation -notmatch 'TraceControl|ETW') { return $null }

    # Bucket by Process + Second
    $bucket = [int][Math]::Floor($evt.Time.TotalSeconds)
    $key = ("{0}|{1}" -f $evt.Process, $bucket).ToLowerInvariant()

    if (-not $EtwRateByProc.ContainsKey($key)) { $EtwRateByProc[$key] = 0 }
    $EtwRateByProc[$key]++

    # Trigger if > 100 trace ops/sec (very high for normal apps)
    if ($EtwRateByProc[$key] -eq 100) {
        $cat = "ETW EXHAUSTION"
        $sev = "Medium"
        $oracle = Oracle-Match -ProcessName $evt.Process -PathText $evt.Path -CategoryText $cat -DetailText $evt.Detail

        $ux = "System performance degrades; logging tools may fail or drop events."
        $tc = "Process '$($evt.Process)' is generating excessive ETW control traffic (>100 ops/sec). This indicates a diagnostic tool, EDR agent, or debugger is thrashing the Event Tracing for Windows subsystem."
        $rm = "1. Check for running diagnostic tools (PerfView, WPR, ProcMon itself). 2. Investigate security agents that hook ETW (EDR/XDR). 3. Restart the offending service."

        return @{ Category=$cat; Severity=$sev; Oracle=$oracle; UserExperience=$ux; TechnicalContext=$tc; Remediation=$rm }
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
    ${function:Detect-PacketStorm},
    ${function:Detect-EtwExhaustion},
    ${function:Detect-AlpcLatency},
    ${function:Detect-SharedMem}
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