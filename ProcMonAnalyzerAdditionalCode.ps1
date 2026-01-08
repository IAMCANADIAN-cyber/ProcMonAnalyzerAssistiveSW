<#
.SYNOPSIS
    ProcMon-Reporter V1300: The Overseer Edition.
    A complete, zero-regression forensic architect for Enterprise AT Interoperability.
    
    COMPATIBILITY: PowerShell 5.1 (Enterprise Standard)
    VERSION: V1300 (January 2026)
#>

param (
    [Parameter(Mandatory=$true)]
    [string]$Path,                   # Directory or File
    [string]$TargetProcess = "",     # Primary app to watch
    [string]$ReportPath = ".\ProcMon_V1300_Overseer_Report.html",
    [string]$CsvExportPath = ".\ProcMon_V1300_Findings.csv",
    [double]$SlowThresholdSeconds = 0.5,
    [int]$HotspotThreshold = 2000
)

# --- 1. THE OVERSEER KNOWLEDGE BASE (2019 - 2026) ---
$OverseerDB = @{
    "msedge.exe" = @{
        "134.0.0" = @{ Cause="Chromium v134 Copy/Paste Bug"; Fix="Update JAWS to April 2025 Release or newer."; Link="https://blog.freedomscientific.com/install-software-updates-to-resolve-jaws-and-zoomtext-issues/" }
        "24H2" = @{ Cause="Windows 11 24H2 WebView2 Corruption"; Fix="Run 'sfc /scannow' or update WebView2 Runtime."; Link="" }
    }
    "WINWORD.EXE" = @{
        "dgnword.dll" = @{ Cause="Dragon Add-in Disabled"; Fix="Re-enable Dragon Add-in in Word Options > Add-ins."; Link="" }
        "ModernComments" = @{ Cause="M365 Modern Comments Deadlock"; Fix="Ensure Office Build > 16.0.14000 for UIA fixes."; Link="" }
    }
    "jfw.exe" = @{
        "0xC0000374" = @{ Cause="Security DLL Heap Corruption"; Fix="Identify the third-party DLL causing 0xC0000374 in the 'Hook Injection' table."; Link="" }
        "AI_Labeler" = @{ Cause="AI Labeler Focus Hang"; Fix="Update JAWS 2026 to December 2025 Enhancement patch."; Link="" }
    }
}

# --- 2. INTELLIGENT RECURSION & DEDUPLICATION ---
Write-Host "[*] Booting V1300 Overseer Engine..." -ForegroundColor Cyan

$ProcMonFiles = @()
$AuxData = [System.Collections.Generic.List[PSObject]]::new()
$HistoricalPatterns = [System.Collections.Generic.HashSet[string]]::new() 

if (Test-Path $Path -PathType Container) {
    Write-Host "[-] TSS Directory Detected. Starting Recursive Ingestion..." -ForegroundColor Gray
    $ProcMonFiles = Get-ChildItem -Path $Path -Filter "*.csv" -Recurse
    $AllAux = Get-ChildItem -Path $Path -Include "*.evtx","*.dmp","*.txt","*.log","*.reg","*.nfo" -Recurse
} else {
    $ProcMonFiles = @(Get-Item $Path)
    $AllAux = Get-ChildItem -Path $ProcMonFiles[0].DirectoryName -Include "*.evtx","*.dmp","*.log","*.txt","*.reg","*.nfo"
}

# Pre-parse Auxiliary Logs for Patterns
foreach ($File in $AllAux) {
    if ($File.Extension -eq ".evtx") {
        try {
            $Events = Get-WinEvent -Path $File.FullName -FilterXPath "*[System[(EventID=1000 or EventID=1002)]]" -ErrorAction SilentlyContinue
            foreach ($E in $Events) {
                if ($E.Message -match "Faulting module name: (.*?),") { $HistoricalPatterns.Add($Matches[1]) | Out-Null }
                $AuxData.Add([PSCustomObject]@{ Time=$E.TimeCreated.TimeOfDay; Type="EVTX"; Source=$File.Name; Detail=$E.Message })
            }
        } catch {}
    } elseif ($File.Extension -eq ".dmp") {
        $AuxData.Add([PSCustomObject]@{ Time=$File.CreationTime.TimeOfDay; Type="DUMP"; Source=$File.Name; Detail="Crash Dump Captured" })
    }
}

# Lists & Deduplication Pass
$AT_Raw = @("jfw.exe", "zoomtext.exe", "fusion.exe", "nvda.exe", "natspeak.exe", "WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "msedge.exe", "chrome.exe", "audiodg.exe", "fontdrvhost.exe", "LogonUI.exe", "Consent.exe")
if ($TargetProcess) { $AT_Raw += $TargetProcess }
$AT_Processes = [System.Collections.Generic.HashSet[string]]::new(($AT_Raw | Select-Object -Unique), [System.StringComparer]::OrdinalIgnoreCase)

$Sec_Raw = @("MsMpEng.exe", "CsFalconService.exe", "SentinelAgent.exe", "edpa.exe", "ZSATunnel.exe", "ccSvcHst.exe", "RepMgr.exe", "mfeesp.exe", "CylanceSvc.exe", "CyveraService.exe")
$Sec_Processes = [System.Collections.Generic.HashSet[string]]::new(($Sec_Raw | Select-Object -Unique), [System.StringComparer]::OrdinalIgnoreCase)

# --- 3. THE ANALYSIS ENGINE ---
$Findings = [System.Collections.Generic.List[PSObject]]::new()
$GlobalSuspectBuffer = [System.Collections.Generic.Dictionary[string, PSObject]]::new()
$EdgeBuffer = [System.Collections.Generic.List[PSObject]]::new()
$PathHotspots = [System.Collections.Generic.Dictionary[string, int]]::new()
$TotalLinesScanned = 0

foreach ($File in $ProcMonFiles) {
    Write-Host "[+] Analyzing Primary Log: $($File.Name)" -ForegroundColor Green
    $RawHeader = Get-Content $File.FullName -TotalCount 1
    $StandardHeaders = "Time of Day,Process Name,PID,Operation,Path,Result,Detail,Duration,Completion Time,Sequence"
    $ImportParams = @{ Path=$File.FullName; ReadCount=10000 }
    if ($RawHeader -notmatch "Process Name") { $ImportParams["Header"] = $StandardHeaders.Split(',') }

    Import-Csv @ImportParams | ForEach-Object {
        $Batch = $_
        $CurrentBatchClean = [System.Collections.Generic.List[PSObject]]::new()

        foreach ($Row in $Batch) {
            $Proc = if ($Row."Process Name") { $Row."Process Name" } else { $Row.Process }
            if (-not $Proc -or $Proc -eq "Process Name") { continue }
            $Res = $Row.Result; $Op = $Row.Operation; $PathVal = $Row.Path; $Det = $Row.Detail
            
            $Dur = 0.0
            if ($Row.PSObject.Properties.Match("Duration").Count -gt 0 -and $Row.Duration) {
                $Dur = [double]($Row.Duration -replace ',','.')
            }

            $ParsedTime = $null
            try { $ParsedTime = [TimeSpan]::Parse($Row."Time of Day") } catch { }

            # --- A. ORACLE KNOWLEDGE MATCH ---
            if ($OverseerDB.ContainsKey($Proc)) {
                $Issues = $OverseerDB[$Proc]
                foreach ($Key in $Issues.Keys) {
                    if ($Det -match $Key -or $PathVal -match $Key) {
                        $Info = $Issues[$Key]
                        $Findings.Add([PSCustomObject]@{ Cat="ORACLE MATCH"; Sev="High"; Proc=$Proc; UserX="Known Software Bug"; Tech=$Info.Cause; Dev="Matched Key: $Key"; Guidance=$Info.Fix; Path=$PathVal; Chain="Oracle"; Syntax=$Info.Link; Context="KnowledgeBase" })
                    }
                }
            }

            # --- B. SECURITY CONTENION ---
            if ($Sec_Processes.Contains($Proc)) { 
                $GlobalSuspectBuffer[$PathVal] = [PSCustomObject]@{ Time=$ParsedTime; Proc=$Proc; Path=$PathVal }
            }
            if ($AT_Processes.Contains($Proc) -and ($Res -match "DENIED|SHARING|OPLOCK") -and $GlobalSuspectBuffer.ContainsKey($PathVal)) {
                $Suspect = $GlobalSuspectBuffer[$PathVal]
                if ([Math]::Abs(($ParsedTime - $Suspect.Time).TotalSeconds) -lt 0.5) {
                    $Findings.Add([PSCustomObject]@{ Cat="SECURITY LOCK"; Sev="Critical"; Proc=$Proc; UserX="System Freeze / Lag"; Tech="Interference from $($Suspect.Proc)"; Dev="Race Condition on $PathVal"; Guidance="Exclude Path from Scan"; Path=$PathVal; Chain="$($Suspect.Proc) -> $Proc"; Syntax="N/A"; Context="Security" })
                }
            }

            # --- C. CORE STABILITY & RECOVERY (ARCHIVIST LOGIC) ---
            if ($Op -match "Process Exit" -and $AT_Processes.Contains($Proc)) {
                if ($Det -match "-1073740940") { $Findings.Add([PSCustomObject]@{ Cat="HEAP CORRUPTION"; Sev="Critical"; Proc=$Proc; UserX="Instant Crash"; Tech="Security DLL Memory Violation"; Dev="0xC0000374"; Guidance="Check Hook Injections"; Path="Kernel"; Chain="Memory"; Syntax="N/A"; Context="Crash" }) }
            }
            if ($AT_Processes.Contains($Proc) -and ($Res -match "OPLOCK_NOT_GRANTED" -or $Res -match "FAST_IO_DISALLOWED") -and $Dur -gt $SlowThresholdSeconds) {
                 $Findings.Add([PSCustomObject]@{ Cat="OPLOCK BREAK"; Sev="High"; Proc=$Proc; Path=$PathVal; UserX="Stutter"; Tech="OpLock Broken"; Dev="Filter Driver forced slow I/O"; DurVal=$Dur; Guidance="Exclude file type"; Chain="Driver"; Syntax="N/A"; Context="Performance" })
            }

            # --- D. FILTER & STORE ---
            if ($AT_Processes.Contains($Proc) -or $Sec_Processes.Contains($Proc) -or $Dur -gt $SlowThresholdSeconds) {
                if (-not [string]::IsNullOrWhiteSpace($PathVal)) {
                    if ($PathHotspots.ContainsKey($PathVal)) { $PathHotspots[$PathVal]++ } else { $PathHotspots[$PathVal] = 1 }
                }
                $CurrentBatchClean.Add([PSCustomObject]@{ Time=$ParsedTime; Proc=$Proc; Path=$PathVal; Res=$Res; Det=$Det; Dur=$Dur; Op=$Op })
            }
        }
        $TotalLinesScanned += $Batch.Count
    }
}

# --- 5. REPORT GENERATION ---
Write-Host "[!] Finalizing Overseer Report..." -ForegroundColor Green

$GroupedFindings = $Findings | Group-Object Cat, Proc, Path | Select-Object @{N="Category";E={$_.Group[0].Cat}}, @{N="Severity";E={$_.Group[0].Sev}}, @{N="Process";E={$_.Group[0].Proc}}, @{N="UserX";E={$_.Group[0].UserX}}, @{N="Tech";E={$_.Group[0].Tech}}, @{N="Dev";E={$_.Group[0].Dev}}, @{N="Count";E={$_.Count}}, @{N="Guidance";E={$_.Group[0].Guidance}}, @{N="Path";E={$_.Group[0].Path}}, @{N="Chain";E={$_.Group[0].Chain}}

$HtmlHeader = @"
<!DOCTYPE html>
<html>
<head>
<style>
    :root { --bg: #0b0c10; --card: #1f2833; --text: #c5c6c7; --blue: #66fcf1; --crit: #ff0055; --high: #ff9900; }
    body { font-family: 'Segoe UI', monospace; background: var(--bg); color: var(--text); padding: 20px; }
    h1 { color: var(--blue); border-bottom: 2px solid var(--dim); }
    .card { background: var(--card); padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 10px rgba(0,0,0,0.5); }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { background: #000; color: var(--blue); padding: 10px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #333; }
    .sev-critical { color: var(--crit); font-weight: bold; }
    .sev-high { color: var(--high); }
</style>
</head>
<body>
    <h1>// V1300 OVERSEER FORENSIC REPORT //</h1>
    <div class="card"><p><b>Events Scanned:</b> $TotalLinesScanned | <b>Path:</b> $Path</p></div>
    <div class="card">
    <table>
        <tr><th>SEV</th><th>CAT</th><th>PROC</th><th>USER EXPERIENCE</th><th>TECH EXPLAINER</th><th>DEV DETAIL</th><th>COUNT</th><th>PATH</th><th>REMEDIATION</th></tr>
"@

$HtmlBody = ""
foreach ($Item in ($GroupedFindings | Sort-Object Severity)) {
    $SevClass = "sev-" + $Item.Severity.ToLower()
    $HtmlBody += "<tr>
        <td class='$SevClass'>$($Item.Severity)</td>
        <td>$($Item.Category)</td>
        <td>$($Item.Process)</td>
        <td>$($Item.UserX)</td>
        <td>$($Item.Tech)</td>
        <td>$($Item.Dev)</td>
        <td>$($Item.Count)</td>
        <td>$($Item.Path)</td>
        <td>$($Item.Guidance)</td>
    </tr>"
}

$FinalHtml = $HtmlHeader + $HtmlBody + "</table></div></body></html>"
$FinalHtml | Out-File $ReportPath -Encoding UTF8
Invoke-Item $ReportPath