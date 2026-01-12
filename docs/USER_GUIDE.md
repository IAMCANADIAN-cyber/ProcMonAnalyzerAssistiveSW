# 📘 ProcMon-Reporter V1300: Operational User Guide

**"The Overseer Manual"**

This guide provides operational instructions for deploying and utilizing the **ProcMon-Reporter V1300 ("Overseer")** forensic engine in enterprise environments.

---

## 🛑 Part 1: The Air-Gapped Workflow (Offline Oracle)

In high-security environments, the analysis machine often has no internet access. V1300 uses a split "Harvester/Engine" architecture to solve this.

### Step 1: The "Harvester" (Online Machine)
*   **Role:** Fetch the latest "Known Issues" from Microsoft and Freedom Scientific.
*   **Tool:** `ProcMon-OracleCache-Builder.ps1`
*   **Action:**
    1.  Open PowerShell on an internet-connected laptop.
    2.  Run: `.\ProcMon-OracleCache-Builder.ps1`
    3.  **Result:** A folder named `.\OracleCache` is created, populated with HTML snapshots of release notes and known issue KBs.

### Step 2: The Transport
*   **Action:** Copy the `.\OracleCache` folder to a secure USB drive or transfer it via secure gateway to the isolated analysis machine.

### Step 3: The "Engine" (Offline Machine)
*   **Role:** Analyze logs using the cached intelligence.
*   **Tool:** `ProcMon-Enterprise-Unified.ps1`
*   **Action:**
    1.  Place `OracleCache` in the same directory as the main script.
    2.  Run the analysis with the update switch to ingest the new knowledge:
        ```powershell
        .\ProcMon-Enterprise-Unified.ps1 -Path "C:\Logs\Crash_01" -UpdateOracleDb
        ```
    3.  **Result:** The script parses the HTML files, updates its internal JSON database (`ProcMonOracle.db.json`), and then scans your logs against this fresh intelligence.

---

## 🏃 Part 2: Execution Scenarios

### Scenario A: The "TSS" Dump (Recursive Scan)
You have a zip file from a support technician containing ProcMon logs, Event Logs, and MSInfo.
```powershell
.\ProcMon-Enterprise-Unified.ps1 -Path "C:\Users\Admin\Downloads\TSS_Output_2026"
```
*   **Behavior:** The script recursively finds the largest `.csv` (ProcMon), parses all `.evtx` (Application/System), and reads `.nfo` files for OS version context.

### Scenario B: The "Specific App" Watch
You want to focus specifically on **Dragon NaturallySpeaking** issues.
```powershell
.\ProcMon-Enterprise-Unified.ps1 -Path "C:\Logs\Dragon_Freeze.csv" -TargetProcess "natspeak.exe"
```
*   **Behavior:** The script adds `natspeak.exe` to the high-priority watchlist and enables specific detectors for Named Pipe blocking (Dragon's primary IPC mechanism).

### Scenario C: The "Thread Starvation" Hunt
The application isn't crashing, but it "freezes" for 5 seconds at a time.
```powershell
.\ProcMon-Enterprise-Unified.ps1 -Path "C:\Logs\Freeze.csv" -SlowThresholdSeconds 0.2
```
*   **Behavior:** Lowers the latency threshold to 200ms. The report will highlight "OpLock Breaks" and "Thread Profiling" hotspots where the UI thread is waiting on security scanners.

---

## 🔎 Part 3: Interpreting the Report

The V1300 HTML report structure is designed for three distinct audiences.

### Layer 1: User Experience (The Symptom)
*   *Audience:* Helpdesk / Incident Manager.
*   *Example:* "User sees: System Freeze / Lag."
*   *Meaning:* This confirms the user's reported pain point. Use this to validate the ticket.

### Layer 2: Technical Context (The Mechanism)
*   *Audience:* Engineer / Sysadmin.
*   *Example:* "Technical: Interference from CsFalconService.exe. Race Condition on C:\Users\...\dictation.wav."
*   *Meaning:* This explains *why* it happened. In this case, CrowdStrike touched the file < 0.5s before Dragon tried to write to it, causing a lock.

### Layer 3: Remediation (The Fix)
*   *Audience:* Security Ops / Engineering.
*   *Example:* "Action: Exclude path from scan."
*   *Meaning:* The prescriptive fix. It directs you to the specific policy (AV Exclusion, Firewall Rule, App Update) required to resolve the conflict.

---

## 🧩 Part 4: Common "False Positives" & Noise

*   **NAME NOT FOUND (System32):** Windows apps check multiple paths for DLLs. V1300 filters out standard `System32` lookups unless they are critical dependencies (like `vcruntime140.dll`).
*   **BUFFER OVERFLOW:** In ProcMon, this is often normal (an app checking buffer size). The script ignores these unless they correlate with a crash.
*   **REPARSE (Singular):** Accessing OneDrive files triggers Reparse events. The script only flags "REPARSE LOOP" if it sees > 500 reparse events for the same file in a short burst.
