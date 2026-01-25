<#
.SYNOPSIS
    Runs the main ProcMon-Enterprise-Unified.ps1 script against chaos fixtures.
    Asserts that the script does not crash (exit code 0) and handles errors gracefully.
#>

$ScriptPath = Join-Path $PSScriptRoot "../ProcMon-Enterprise-Unified.ps1"
$FixtureDir = Join-Path $PSScriptRoot "fixtures"

if (-not (Test-Path $ScriptPath)) { Write-Error "Main script not found at $ScriptPath"; exit 1 }

$Failures = 0

function Run-Test {
    param([string]$Name, [string]$ArgsStr)
    Write-Host "----------------------------------------------------------------"
    Write-Host "Running Test: $Name" -ForegroundColor Cyan
    Write-Host "Command: $ArgsStr" -ForegroundColor Gray

    # We use Invoke-Expression or Start-Process to run it in this session scope or subscope
    # But since the script is standalone, we can just dot source it or invoke it.
    # To capture Exit Code cleanly, we run it in a child process

    $proc = Start-Process -FilePath "pwsh" -ArgumentList "-NoProfile -Command `& '$ScriptPath' $ArgsStr`" -PassThru -Wait -NoNewWindow

    if ($proc.ExitCode -ne 0) {
        Write-Host "[-] FAILED: Script exited with code $($proc.ExitCode)" -ForegroundColor Red
        return $false
    } else {
        Write-Host "[+] PASSED: Script completed gracefully." -ForegroundColor Green
        return $true
    }
}

# 1. Valid Run
if (-not (Run-Test "Valid Small CSV" "-Path '$FixtureDir/Valid_Small.csv'")) { $Failures++ }

# 2. Malformed Rows
if (-not (Run-Test "Malformed Rows CSV" "-Path '$FixtureDir/Chaos_MalformedRows.csv'")) { $Failures++ }

# 3. Empty CSV
# Expectation: Script should detect invalid headers or empty file and exit safely (return) without throwing raw exception.
if (-not (Run-Test "Empty CSV" "-Path '$FixtureDir/Chaos_Empty.csv'")) { $Failures++ }

# 4. Corrupt Oracle JSON
# We pass -OracleDbPath pointing to garbage
if (-not (Run-Test "Corrupt Oracle DB" "-Path '$FixtureDir/Valid_Small.csv' -OracleDbPath '$FixtureDir/Chaos_CorruptOracle.json'")) { $Failures++ }

# 5. Missing File
# Expectation: Script checks Test-Path and returns error, but shouldn't crash stack trace.
if (-not (Run-Test "Missing File" "-Path '$FixtureDir/NonExistent.csv'")) { $Failures++ }

Write-Host "----------------------------------------------------------------"
if ($Failures -eq 0) {
    Write-Host "ALL TESTS PASSED. Script is resilient." -ForegroundColor Green
} else {
    Write-Host "$Failures TESTS FAILED." -ForegroundColor Red
    exit 1
}
