# ProcMon-Enterprise: Overseer Edition (V1300)

## Overview
**ProcMon-Enterprise-Unified.ps1** is a forensic engine designed for analyzing Assistive Technology (AT) interoperability issues in enterprise environments. It processes Process Monitor (ProcMon) logs alongside system artifacts (TSS output, Event Logs, Dumps) to detect performance bottlenecks, security contention, and configuration errors.

This "Overseer" edition consolidates previous logic into a single, robust script capable of **recursive scanning**, **stateful analysis**, and **offline knowledge base** integration.

## Key Features
*   **Recursive Ingestion**: Point it at a support folder (TSS output), and it automatically inventories and processes all relevant artifacts (CSVs, EVTX, Dumps, JAWS logs, etc.).
*   **Offline Oracle Knowledge Base**: Matches findings against a database of known issues (Microsoft Release Health, JAWS Release Notes, Office Known Issues) without requiring internet access on the analysis machine.
*   **Stateful Detection Engine**:
    *   **Global Suspect Buffer (GSB)**: Detects "Security Fratricide" where security tools scan/lock files immediately before an AT process is denied access.
    *   **Throttling Detection**: Identifies IPv6 failover latency, registry thrashing, and browser restart loops.
*   **Expanded Security Awareness**: Built-in recognition for modern enterprise agents including CrowdStrike, SentinelOne, Carbon Black, Trellix, Netskope, Zscaler, Cortex XDR, and more.
*   **"Do The Work" Reporting**: Generates a self-contained HTML report with prioritized next steps, glossary, and evidence correlation.

## Prerequisites

### 1. PowerShell
*   Windows PowerShell 5.1 (standard on Windows 10/11).

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

## Installation & Setup

### Step 1: Prepare the Oracle Cache (Online Machine)
Since the analysis environment is often air-gapped or restricted, you first build the knowledge base on an internet-connected machine.

1.  Run `ProcMon-OracleCache-Builder.ps1`.
    ```powershell
    .\ProcMon-OracleCache-Builder.ps1
    ```
    This downloads the latest known issues from Microsoft and Freedom Scientific into a local `OracleCache` folder.

2.  Copy the `OracleCache` folder to your offline analysis machine, placing it next to `ProcMon-Enterprise-Unified.ps1`.

### Step 2: Deploy to Analysis Machine
Ensure you have:
*   `ProcMon-Enterprise-Unified.ps1`
*   `OracleCache` folder (from Step 1)

## Usage

### Scenario A: Analyze a Support Folder (TSS)
The most common workflow. The script will recursively find the largest ProcMon CSV and inventory all other artifacts (Event Logs, Dumps, Text Logs).

```powershell
.\ProcMon-Enterprise-Unified.ps1 -Path "C:\Users\Admin\Desktop\TSS_Output_Folder"
```

### Scenario B: Analyze a Single CSV
```powershell
.\ProcMon-Enterprise-Unified.ps1 -Path "C:\Logs\repro.csv"
```

### Scenario C: Update the Offline Oracle DB
If you have brought in a new `OracleCache` folder, update the local JSON database before scanning.

```powershell
.\ProcMon-Enterprise-Unified.ps1 -Path "C:\Logs" -UpdateOracleDb
```

### Advanced Switches
*   `-AnalyzeAllCsv`: If multiple CSVs are found in the folder, analyze *all* of them (default is only the largest).
*   `-TargetProcess "myapp.exe"`: Explicitly treat `myapp.exe` as a target for latency/contention analysis.
*   `-SlowThresholdSeconds 0.5`: Adjust the threshold for "High Latency" flagging (default: 0.5s).
*   `-InteractiveInput`: Opens a dialog box (GUI) allowing you to paste a list of custom security processes or DLLs to watch for.
*   `-CustomListPath "C:\list.txt"`: Loads a list of custom security processes/DLLs from a text file (one per line).

## Output
The script generates:
1.  **HTML Report** (`ProcMon_V1300_Report.html`): The primary deliverable.
    *   **Prioritized Next Steps**: The top issues requiring attention.
    *   **Findings Explorer**: Filterable table of all detected anomalies.
    *   **Artifact Inventory**: Full list of files found in the scan path.
    *   **Aux Signals**: regex matches from text logs and registry exports.
2.  **CSV Findings** (`ProcMon_V1300_Findings.csv`): Raw data for Excel filtering.
3.  **Oracle DB** (`ProcMonOracle.db.json`): The compiled knowledge base.

## Architecture Notes
The engine uses a streaming pipeline (`TextFieldParser`) to handle gigabyte-scale CSVs with minimal RAM usage. It employs a "Global Suspect Buffer" to correlate security scanner activity with subsequent access denials in AT processes, effectively identifying "touch-then-block" race conditions.

## Troubleshooting
*   **"Header normalization: could not reliably locate..."**: Your ProcMon CSV is missing required columns. Check the **Prerequisites** section.
*   **Execution Policy**: You may need to run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` to allow the script to run.
*   **"GUI unavailable..."**: If running in a headless environment (Core/Remote), `-InteractiveInput` will fail gracefully. Use `-CustomListPath` instead.

