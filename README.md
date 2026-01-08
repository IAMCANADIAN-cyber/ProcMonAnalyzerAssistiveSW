# ProcMonAnalyzerAssistiveSW
Basically a "Mark Russinovich" in a script -- meant to basically do the work for you of analyzing Process Monitor logs and generate a report for you with multiple levels of details, technical understanding and clarity. The focus is on common enterprise AV/EDR/DLP/MDE/XDR tools and how they conflict with Assistive Software for People with Disabilities. 

# 🛡️ ProcMon-Reporter: The "Oracle" Edition (V1200)

> **"The Definitive Forensic Engine for Assistive Technology Interoperability."**

## 📜 Executive Summary
**ProcMon-Reporter** is a high-performance, memory-safe forensic engine written in PowerShell 5.1. It is engineered to perform **Stateful Heuristic Analysis** on Process Monitor (`.CSV`) logs, correlating them with Windows Event Logs (`.EVTX`) and Crash Dumps (`.DMP`) to detect specific failure modes in Enterprise Assistive Technology (JAWS, ZoomText, Fusion).

Unlike standard log parsers which rely on static signature matching, this engine implements a **Sliding Window State Machine** to detect asynchronous race conditions, cross-process resource contention (OpLock breaks), and kernel-level interference (Filter Altitude collisions).

## 🧠 Core Intelligence Engines
1.  **The "Archivist" Engine:**
    * *Function:* Detects low-level I/O & Driver conflicts (OpLock Breaks, Fast I/O Disallowance, Reparse Loops).
    * *Logic:* Correlates `Result` codes with `Duration` thresholds to identify "Soft Hangs."
2.  **The "Chronos" Engine:**
    * *Function:* Performs Time-Travel Analysis.
    * *Logic:* Ingests historical Crash Dumps and scans the current live log for matching module loads (`LoadImage`) to predict recurring crashes.
3.  **The "Omnipotent" Engine:**
    * *Function:* Contextual awareness of OS subsystems.
    * *Logic:* Identifies Secure Desktop isolation, Legacy Bridge (UIA-to-MSAA) collapse, and Clipboard Chain contention.
4.  **The "Oracle" Knowledge Base:**
    * *Function:* Deterministic mapping of generic errors to vendor-specific KBs.
    * *Logic:* `Process + Error Context -> Cause/Fix/Vendor Link`.

## ⚙️ Technical Constraints (NON-NEGOTIABLE)
* **Runtime:** PowerShell 5.1 (No .NET Core dependencies).
* **Memory Model:** Streaming Pipeline (ReadCount: 10,000). **Never** load the full CSV into RAM.
* **Dependency:** Zero-dependency (Self-contained script).
* **Output:** Standalone HTML with embedded CSS/JS.
