<#
.SYNOPSIS
    Generates test fixtures for chaos testing the ProcMon Analyzer.
#>

$FixtureDir = Join-Path $PSScriptRoot "fixtures"
if (-not (Test-Path $FixtureDir)) { New-Item -ItemType Directory -Path $FixtureDir -Force | Out-Null }

Write-Host "[*] Generating fixtures in $FixtureDir..."

# 1. Valid Small CSV
$ValidCsv = @"
"Time of Day","Process Name","PID","Operation","Path","Result","Detail","Duration","Thread ID"
"9:00:00.0000000","explorer.exe","1234","CreateFile","C:\Windows\System32\notepad.exe","SUCCESS","Desired Access: Read",0.000123,"100"
"9:00:00.5000000","jfw.exe","5555","RegOpenKey","HKLM\Software\Freedom Scientific","ACCESS DENIED","Access: Read",0.000456,"200"
"@
$ValidCsv | Out-File (Join-Path $FixtureDir "Valid_Small.csv") -Encoding UTF8

# 2. Malformed Rows (RFC 4180 violation - varying columns)
$MalformedCsv = @"
"Time of Day","Process Name","PID","Operation","Path","Result","Detail","Duration"
"9:00:00.0000000","explorer.exe","1234","CreateFile","C:\Test","SUCCESS"
"9:00:01.0000000","broken.exe"
"9:00:02.0000000","extra.exe","999","Op","Path","Res","Det","0.1","ExtraCol1","ExtraCol2"
"@
$MalformedCsv | Out-File (Join-Path $FixtureDir "Chaos_MalformedRows.csv") -Encoding UTF8

# 3. Empty CSV
"" | Out-File (Join-Path $FixtureDir "Chaos_Empty.csv") -Encoding UTF8

# 4. Bad Encoding / Binary Garbage
$Bytes = [byte[]](0..255)
[System.IO.File]::WriteAllBytes((Join-Path $FixtureDir "Chaos_BadEncoding.csv"), $Bytes)

# 5. Corrupt Oracle JSON
$CorruptJson = @"
{
    "schema": "v1",
    "entries": [
        { "app": "broken", "title": "missing closing brace"
"@
$CorruptJson | Out-File (Join-Path $FixtureDir "Chaos_CorruptOracle.json") -Encoding UTF8

Write-Host "[+] Fixtures generated."
