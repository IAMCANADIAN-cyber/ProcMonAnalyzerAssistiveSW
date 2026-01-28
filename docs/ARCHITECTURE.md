# 🏗️ System Architecture & Logic Flow

## 1. The Streaming Pipeline Strategy
To analyze gigabyte-scale logs without RAM exhaustion, the engine uses a specific pipeline architecture based on `Microsoft.VisualBasic.FileIO.TextFieldParser`. This allows processing CSVs line-by-line with minimal memory footprint.

`StreamReader -> TextFieldParser -> [Stateful Analysis] -> [Findings Accumulator]`

### State Management
Instead of batching, the engine processes events continuously.
* **Global Suspect Buffer (GSB):** Tracks the last time a Security Process touched a file to detect contention race conditions.
* **Reparse Count Buffer:** Tracks recursion depth to identify symlink loops.
* **Network Rate Buffer:** Aggregates TCP/UDP ops per process per second to detect floods (Packet Storms).

## 2. The Global Suspect Buffer (GSB)
The GSB is a `Dictionary<FilePath, EventObject>` representing the "Security State" of the system.
* **Write Operation:** Every time a defined Security Process (EDR/AV/DLP) touches a file, it is recorded in the GSB with a timestamp.
* **Read Operation:** When an AT Process (JAWS) fails to access a file (`ACCESS_DENIED` / `SHARING_VIOLATION`), the engine queries the GSB.
* **Heuristic Logic:**
    ```powershell
    IF (AT_Event.Result == FAILURE) AND (GSB[AT_Event.Path].Time - AT_Event.Time < 0.5s) 
    THEN 
        FLAG "Security Lock (Cross-Process Race Condition)"
    ```

## 3. The "Oracle" Data Structure (V1300 Overseer)
The Oracle is a multi-dimensional Hashtable enabling O(1) lookups for known issues, merged from offline cache files.
* **Schema:**
    ```text
    ProcessName (Key)
    └── IssueSignature (Key: Substring Match on Detail/Path)
        ├── Cause (String)
        ├── Fix (String)
        └── Link (String: URL)
    ```
* **Offline Operation:** The V1300 engine relies on `ProcMon-OracleCache-Builder.ps1` to pre-fetch knowledge base data (Microsoft Release Health, JAWS Release Notes) into a local JSON database, ensuring air-gapped analysis capability.

## 4. Detection Logic
The detection engine employs a hybrid model:
* **Deterministic Matching:** Using the `SCENARIO_LIBRARY` (IDs 1-1500) to match exact `Operation` + `Result` + `Path` patterns.
* **Heuristic Analysis:** Code modules (e.g., `Detect-HookInjection`, `Detect-ThreadProfiling`) that analyze behavior over time or check for patterns (e.g., "Any CrowdStrike DLL loaded into an AT process").
* **Strict Fratricide:** A specific subset of heuristics that flags when one Security/AT agent attacks another.

## 5. Report Generation & Evidence
* **Three-Layer Explanation:** Findings are mapped to `User Experience`, `Technical Context`, and `Remediation` layers.
* **Chain of Custody:** Every finding records the Source File, Line Number, and SHA256 Hash of the artifact.
* **Hash Cache:** An internal cache prevents re-hashing the same file multiple times during report generation.
