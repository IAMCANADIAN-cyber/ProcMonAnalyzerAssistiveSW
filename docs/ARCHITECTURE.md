# 🏗️ System Architecture & Logic Flow

## 1. The Streaming Pipeline Strategy
To analyze gigabyte-scale logs without RAM exhaustion, the engine uses a specific pipeline architecture based on `Microsoft.VisualBasic.FileIO.TextFieldParser`. This allows processing CSVs line-by-line with minimal memory footprint.

`StreamReader -> TextFieldParser -> [Stateful Analysis] -> [Findings Accumulator]`

### State Management
Instead of batching, the engine processes events continuously.
* **Global Suspect Buffer:** Tracks the last time a Security Process touched a file. This state is preserved across the stream to detect "Touch-then-Deny" race conditions (contention) regardless of where they occur in the file.

## 2. The Global Suspect Buffer (GSB)
The GSB is a `Dictionary<FilePath, EventObject>` representing the "Security State" of the system.
* **Write Operation:** Every time a defined Security Process (EDR/AV/DLP) touches a file, it is recorded in the GSB with a timestamp.
* **Read Operation:** When an AT Process (JAWS) fails to access a file (`ACCESS_DENIED` / `SHARING_VIOLATION`), the engine queries the GSB.
* **Heuristic Logic:**
    ```powershell
    IF (AT_Event.Result == FAILURE) AND (GSB[AT_Event.Path].Time - AT_Event.Time < 0.5s) 
    THEN 
        FLAG "Cross-Process Race Condition"
    ```

## 3. The "Oracle" Data Structure
The Oracle is a multi-dimensional Hashtable enabling O(1) lookups for known issues.
* **Schema:**
    ```text
    ProcessName (Key)
    └── IssueSignature (Key: Substring Match on Detail/Path)
        ├── Cause (String)
        ├── Fix (String)
        └── Link (String: URL)
    ```
* **Usage:** This bypasses heuristic scoring. If a match is found, it is treated as a **Confirmed Vendor Bug**.

## 4. Detection Logic: The "Strict Fratricide" Model
To prevent false positives, we define "AT Fratricide" strictly:
* **Condition A:** Multiple AT processes (e.g., `jfw.exe` AND `nvda.exe`) are present in the log.
* **Condition B:** One AT process attempts `OpenProcess` on the other.
* **Condition C:** The result is `ACCESS_DENIED`.
* *Note:* Mere presence of multiple ATs is **not** sufficient for a flag.
