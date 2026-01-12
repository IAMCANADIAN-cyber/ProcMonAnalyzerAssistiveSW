# ProcMon-Reporter: Overseer Edition (V1300)

## Mission
Automated forensic architect for enterprise accessibility performance.

## Core Features
- **Recursion:** Deep scans TSS/support packages.
- **Oracle DB:** 7-year history of JAWS, Microsoft 365, and Chromium regressions.
- **Stateful Engine:** Identifies cross-process locks and kernel violations (0xC0000374).

## 📖 Documentation
*   **[Operational User Guide (docs/USER_GUIDE.md)](docs/USER_GUIDE.md):** Step-by-step instructions for Air-Gapped deployment and interpreting reports.
*   **[Technical Architecture (docs/ARCHITECTURE.md)](docs/ARCHITECTURE.md):** Deep dive into the Sliding Window and Global Suspect Buffer logic.
*   **[Scenario Library (docs/SCENARIO_LIBRARY.MD)](docs/SCENARIO_LIBRARY.MD):** Definitions of all detected failure modes (Deadlocks, Hooking, Starvation).

## 🌐 The "Offline Oracle" Ecosystem
This tool is designed for **air-gapped** or highly restricted corporate environments. It uses a split architecture:

1.  **The Harvester (`ProcMon-OracleCache-Builder.ps1`):**
    *   Run this on an *internet-connected* machine.
    *   It scrapes Microsoft Release Health, Office Release Notes, and Freedom Scientific "What's New" pages.
    *   It saves these as raw snapshots in the `OracleCache` folder.

2.  **The Engine (`ProcMon-Enterprise-Unified.ps1`):**
    *   Run this on the *isolated/offline* machine.
    *   It ingests the `OracleCache` folder (via `-UpdateOracleDb`).
    *   It parses the snapshots locally to build its internal knowledge base of known bugs.

## Capabilities
- **TSS Recursive Processing:** Point to a TSS output folder; the engine does the rest.
- **Oracle Knowledge Engine:** Deterministic bug detection for Microsoft 365, Edge, and JAWS.
- **Forensic Thread Profiling:** Detects silent starvation and kernel wait-state issues.
