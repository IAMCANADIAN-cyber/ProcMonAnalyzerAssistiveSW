# ProcMonAnalyzerAssistiveSW
Basically a "Mark Russinovich" in a script -- meant to basically do the work for you of analyzing Process Monitor logs and generate a report for you with multiple levels of details, technical understanding and clarity. The focus is on common enterprise AV/EDR/DLP/MDE/XDR tools and how they conflict with Assistive Software for People with Disabilities. 

# 🛡️ ProcMon-Reporter: The "Oracle" Edition (V1200)

> **"The Definitive Forensic Engine for Assistive Technology Interoperability."**

## 📜 Executive Summary
**ProcMon-Reporter** is a high-performance, memory-safe forensic engine written in PowerShell 5.1. It is engineered to perform **Stateful Heuristic Analysis** on Process Monitor (`.CSV`) logs, correlating them with Windows Event Logs (`.EVTX`) and Crash Dumps (`.DMP`) to detect specific failure modes in Enterprise Assistive Technology (JAWS, ZoomText, Fusion).

While detecting **Security Interference** (EDR/DLP hooks) is a core pillar, this engine is equally specialized in identifying **Application Compatibility**, **OS Configuration**, and **Network Performance** bottlenecks that cause "Silent Failures" in screen readers.

## 🧠 Core Intelligence Engines
1.  **The "Archivist" Engine (Stability & I/O):**
    * *Focus:* Low-level I/O & Driver conflicts.
    * *Logic:* Detects OpLock Breaks, Fast I/O Disallowance, and Reparse Point Loops (OneDrive recursion).
2.  **The "Chronos" Engine (Time-Travel):**
    * *Focus:* Asynchronous Correlation.
    * *Logic:* Ingests historical Crash Dumps and scans the current live log for matching module loads (`LoadImage`) to predict recurring crashes.
3.  **The "Omnipotent" Engine (Context & OS):**
    * *Focus:* OS Subsystems and Interoperability.
    * *Logic:* Identifies Secure Desktop isolation, Legacy Bridge (UIA-to-MSAA) collapse, and Clipboard Chain contention.
4.  **The "Oracle" Knowledge Base (Vendor Intelligence):**
    * *Focus:* Deterministic mapping of generic errors to vendor-specific KBs.
    * *Logic:* `Process + Error Context -> Cause/Fix/Vendor Link`.

## ⚙️ Technical Constraints (NON-NEGOTIABLE)
* **Runtime:** PowerShell 5.1 (No .NET Core dependencies).
* **Memory Model:** Streaming Pipeline (ReadCount: 10,000). **Never** load the full CSV into RAM.
* **Dependency:** Zero-dependency (Self-contained script).
* **Output:** Standalone HTML with embedded CSS/JS.
