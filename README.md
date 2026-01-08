# ProcMon-Enterprise: V1300 "Overseer" Edition

> **"The Definitive Forensic Engine for Assistive Technology Interoperability."**

## 📜 Executive Summary
**ProcMon-Enterprise** (formerly ProcMon-Reporter) is a high-performance, memory-safe forensic engine written in PowerShell 5.1. It is engineered to perform **Stateful Heuristic Analysis** on Process Monitor (`.CSV`) logs, correlating them with Windows Event Logs (`.EVTX`), Crash Dumps (`.DMP`), and TSS artifacts to detect specific failure modes in Enterprise Assistive Technology (JAWS, ZoomText, Fusion).

While detecting **Security Interference** (EDR/DLP hooks) is a core pillar, this engine is equally specialized in identifying **Application Compatibility**, **OS Configuration**, and **Network Performance** bottlenecks that cause "Silent Failures" in screen readers.

## 🧠 Core Intelligence Engines
1.  **The "Overseer" Engine (Security Contention - V1300):**
    *   *Focus:* Real-time resource contention.
    *   *Logic:* Uses a `GlobalSuspectBuffer` to track security processes touching files. If an AT process is denied access to the same file within 0.5s, it flags a "Security Lock" race condition.
2.  **The "Archivist" Engine (Stability & I/O):**
    *   *Focus:* Low-level I/O & Driver conflicts.
    *   *Logic:* Detects OpLock Breaks, Fast I/O Disallowance, and Reparse Point Loops (OneDrive recursion).
3.  **The "Chronos" Engine (Time-Travel):**
    *   *Focus:* Asynchronous Correlation.
    *   *Logic:* Ingests historical Crash Dumps and scans the current live log for matching module loads (`LoadImage`) to predict recurring crashes.
4.  **The "Omnipotent" Engine (Context & OS):**
    *   *Focus:* OS Subsystems and Interoperability.
    *   *Logic:* Identifies Secure Desktop isolation, Legacy Bridge (UIA-to-MSAA) collapse, and Clipboard Chain contention.
5.  **The "Oracle" Knowledge Base (Vendor Intelligence - Offline):**
    *   *Focus:* Deterministic mapping of generic errors to vendor-specific KBs.
    *   *Logic:* `Process + Error Context -> Cause/Fix/Vendor Link`. Works entirely offline using a seeded database and cached sources.

## ⚙️ Technical Constraints (NON-NEGOTIABLE)
*   **Runtime:** PowerShell 5.1 (No .NET Core dependencies).
*   **Memory Model:** Streaming Pipeline (ReadCount: 10,000). **Never** load the full CSV into RAM.
*   **Dependency:** Zero-dependency (Self-contained script).
*   **Output:** Standalone HTML with embedded CSS/JS.
*   **Policy:** No Sentinel LDK or TeamViewer specific checks.

## Capabilities
-   **Recursive Ingestion:** Automatically scans subfolders for all supported artifact types (CSV, EVTX, DMP, LOG, REG, NFO, ETL, CAB, ZIP).
-   **Offline Oracle:** Built-in seed database for critical known issues (Edge Chromium bugs, Office deadlocks, JAWS patches).
-   **Security Contention Detection:** Identifies when EDR/AV scans lock files immediately before AT needs them.
-   **Forensic Thread Profiling:** Detects silent starvation and kernel wait-state issues.

## Usage
```powershell
.\ProcMon-Enterprise-Unified.ps1 -Path "C:\Logs\TSS_Output"
```
