# 🏗️ System Architecture & Logic Flow

## 1. The Streaming Pipeline Strategy
To analyze gigabyte-scale logs without RAM exhaustion, the engine uses a specific pipeline architecture:

`Import-Csv (Stream) -> [Sliding Window Buffer] -> [Heuristic Analysis] -> [Findings Accumulator] -> Flush`

### The "Edge Case" Problem
A race condition might begin at the end of Batch N and conclude at the start of Batch N+1.
* **Solution:** The script maintains an `$EdgeBuffer` containing the last **2.0 seconds** of events from the previous batch.
* **Constraint:** Any modification to the looping logic must preserve this buffer, or detection of split-events will regress.

## 2. The Global Suspect Buffer (GSB) - *New in V1300*
The GSB is a `Dictionary<FilePath, EventObject>` representing the "Security State" of the system.
* **Write Operation:** Every time a defined Security Process (EDR/AV/DLP) touches a file, it is recorded in the GSB with a timestamp.
* **Read Operation:** When an AT Process (JAWS) fails to access a file (`ACCESS_DENIED` / `SHARING_VIOLATION`), the engine queries the GSB.
* **Heuristic Logic:**
    ```powershell
    IF (AT_Event.Result == FAILURE) AND (ABS(GSB[AT_Event.Path].Time - AT_Event.Time) < 0.5s)
    THEN 
        FLAG "Cross-Process Race Condition" (Security Lock)
    ```

## 3. The "Oracle" Data Structure (Offline)
The Oracle is a multi-dimensional Hashtable enabling O(1) lookups for known issues.
* **Schema:**
    ```text
    ProcessName (Key)
    └── IssueSignature (Key: Substring Match on Detail/Path)
        ├── Cause (String)
        ├── Fix (String)
        └── Link (String: URL)
    ```
* **Usage:** This bypasses heuristic scoring. If a match is found, it is treated as a **Confirmed Vendor Bug**. The DB is seeded with known issues (e.g., Edge v134, Office Modern Comments) and operates without external network calls.

## 4. Detection Logic: The "Strict Fratricide" Model
To prevent false positives, we define "AT Fratricide" strictly:
* **Condition A:** Multiple AT processes (e.g., `jfw.exe` AND `nvda.exe`) are present in the log.
* **Condition B:** One AT process attempts `OpenProcess` on the other.
* **Condition C:** The result is `ACCESS_DENIED`.
* *Note:* Mere presence of multiple ATs is **not** sufficient for a flag.
