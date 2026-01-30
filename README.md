# ProcMon-Enterprise: Overseer Edition (V1300)

## Overview
**ProcMon-Enterprise-Unified.ps1** is a forensic engine designed for analyzing Assistive Technology (AT) interoperability issues in enterprise environments. It processes Process Monitor (ProcMon) logs alongside system artifacts (TSS output, Event Logs, Dumps) to detect performance bottlenecks, security contention, and configuration errors.

This "Overseer" edition consolidates previous logic into a single, robust script capable of **recursive scanning**, **stateful analysis**, and **offline knowledge base** integration.

## Documentation
For deep technical details, please refer to the following documentation:

*   [Architecture Guide](docs/ARCHITECTURE.md): Technical deep dive into the engine's design.
*   [Scenario Library](docs/SCENARIO_LIBRARY.MD): Complete catalog of detection scenarios.
*   [Scenario Evidence](docs/SCENARIO_EVIDENCE.md): Proof of implementation and reference material.
*   [Data Dictionary](docs/DATA_DICTIONARY.md): Definitions of data fields and structures.

## Prerequisites

### 1. PowerShell
*   Windows PowerShell 5.1 (standard on Windows 10/11).
*   **Note**: You may need to change the execution policy to run the script:
    ```powershell
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    ```

### 2. Process Monitor Configuration (CRITICAL)
For the script to parse the CSV correctly, you must configure ProcMon to export the following columns in this specific order (or ensure they are present).

**Required Columns:**
1.  **Time of Day**
2.  **Process Name**
3.  **PID**
4.  **Operation**
5.  **Path**
6.  **Result**
7.  **Detail**
8.  **Duration**
9.  **Thread ID**
10. **Image Path**
11. **Command Line**
12. **User**
13. **Integrity**
14. **Session**

*Tip: In ProcMon, go to **Options > Select Columns...** to configure this.*

## Step-by-Step Usage Guide

### Phase 1: Preparation (Online Machine)
Since the analysis environment is often air-gapped or restricted, you first build the knowledge base on an internet-connected machine.

1.  Open PowerShell.
2.  Run the builder script:
    ```powershell
    .\ProcMon-OracleCache-Builder.ps1
    ```
    This downloads the latest known issues from Microsoft and Freedom Scientific into a local `OracleCache` folder.
3.  Copy the `OracleCache` folder to your offline analysis machine, placing it in the same directory as `ProcMon-Enterprise-Unified.ps1`.

### Phase 2: Analysis (Offline Machine)

#### Scenario A: Analyze a Support Folder (TSS)
This is the most common workflow. The script will recursively search the folder for the largest ProcMon CSV and inventory all other artifacts (Event Logs, Dumps, Text Logs).

1.  Open PowerShell as Administrator (recommended).
2.  Run the script pointing to the folder:
    ```powershell
    .\ProcMon-Enterprise-Unified.ps1 -Path "C:\Users\Admin\Desktop\TSS_Output_Folder"
    ```

#### Scenario B: Analyze a Single CSV
If you only have a CSV file:

1.  Run the script pointing to the file:
    ```powershell
    .\ProcMon-Enterprise-Unified.ps1 -Path "C:\Logs\repro.csv"
    ```

#### Scenario C: Update the Offline Oracle DB
If you have brought in a new `OracleCache` folder, update the local JSON database before scanning to ensure you have the latest known issues.

```powershell
.\ProcMon-Enterprise-Unified.ps1 -UpdateOracleDb
```

## Command Line Reference

| Switch | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `-Path` | String | `""` | **Required.** The path to a folder (TSS output) or a single ProcMon `.csv` file. |
| `-TargetProcess` | String | `""` | Optional. Specify an additional process name (e.g., `myapp.exe`) to treat as a high-priority target for latency/contention analysis. |
| `-ReportPath` | String | `.\ProcMon_V1300_Report.html` | Path where the HTML report will be generated. |
| `-CsvExportPath` | String | `.\ProcMon_V1300_Findings.csv` | Path where the raw findings CSV will be exported. |
| `-UpdateOracleDb` | Switch | `False` | Triggers the Offline Oracle DB update mode. Merges data from `-OracleCachePath` into `-OracleDbPath`. |
| `-OracleOnly` | Switch | `False` | If set, the script only loads/updates the Oracle DB and prints stats, then exits without scanning logs. |
| `-AnalyzeAllCsv` | Switch | `False` | If multiple CSVs are found in a folder, analyze *all* of them (default is only the largest). |
| `-SlowThresholdSeconds` | Double | `0.5` | Threshold (in seconds) to flag an operation as "High Latency". |
| `-CollisionWindowSeconds` | Double | `0.5` | Time window (in seconds) to correlate security scanner activity with access denials (Security Fratricide detection). |
| `-HotspotThreshold` | Int | `2000` | Number of registry operations required to trigger a "Registry Thrash" finding. |
| `-ValidationPasses` | Int | `7` | Number of internal self-validation checks to run after processing. |
| `-OracleDbPath` | String | `.\ProcMonOracle.db.json` | Path to the JSON database file storing known issues. |
| `-OracleCachePath` | String | `.\OracleCache` | Path to the folder containing raw HTML/JSON cache files (from the Builder script). |
| `-NoWeb` | Switch | `False` | Helper switch passed during Oracle updates to ensure no network calls are attempted (default behavior in this edition). |
| `-MaxFindingsPerCategory` | Int | `250` | Cap on the number of findings per category to prevent report bloating. |
| `-MaxEvidenceSamplesPerFinding` | Int | `6` | Number of evidence rows (ProcMon events) to attach to each finding in the HTML report details. |

## Output
The script generates:
1.  **HTML Report** (`ProcMon_V1300_Report.html`): The primary deliverable.
    *   **Prioritized Next Steps**: The top issues requiring attention.
    *   **Findings Explorer**: Filterable table of all detected anomalies.
    *   **Artifact Inventory**: Full list of files found in the scan path.
    *   **Aux Signals**: regex matches from text logs and registry exports.
2.  **CSV Findings** (`ProcMon_V1300_Findings.csv`): Raw data for Excel filtering.
3.  **Oracle DB** (`ProcMonOracle.db.json`): The compiled knowledge base.

## Troubleshooting
*   **"Header normalization: could not reliably locate..."**: Your ProcMon CSV is missing required columns. Check the **Prerequisites** section carefully.
*   **"Path not found"**: Ensure you are providing a valid path to a file or directory. If the path contains spaces, wrap it in quotes.
*   **Execution Policy Error**: If PowerShell refuses to run the script, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and try again.
