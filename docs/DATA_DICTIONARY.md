# 📚 Internal Data Dictionary (V1300)

## 1. Behavioral Tally Variables
These variables track the "velocity" of events to detect loops (Thrashing).
* `$FocusBounceCount`: `Dictionary<ProcID, Int>` - Increments on every `EVENT_SYSTEM_FOREGROUND` change.
* `$RegThrashCount`: `Dictionary<Path, Int>` - Tracks `RegQueryValue` frequency per path.
* `$UIAFloodCount`: `Dictionary<ProcName, Int>` - Counts UIA event generation volume per process.
* `$ReparseCounts`: `Dictionary<Path, Int>` - Tracks recursion depth for OneDrive/Reparse points.
* `$BrowserLoopCount`: `Dictionary<ProcPath, Int>` - Tracks renderer process restarts.
* `$EventRateByProcSec`: `Dictionary<String, Int>` - Tracks events per second per process for Flood detection.

## 2. Stateful Buffers
These buffers allow the script to have "Contextual Memory."
* `$WitnessBuffer`: `List<Object>` - Stores the last 200 raw events for "Post-Mortem" context in the report.
* `$EdgeBuffer`: `List<Object>` - **Critical.** Stores the last 2.0s of the previous batch to ensure no split-event loss.
* `$GlobalSuspectBuffer (GSB)`: `Dictionary<Path, Object>` - Stores `Time, Proc, Path` for all Security Agents. Used for V1300 Security Lock detection.
* `$HistoricalPatterns`: `HashSet<String>` - Loaded from `.dmp` and `.evtx`. Stores faulting module names for pattern matching.

## 3. Oracle Logic Triggers
Keys used in the `$OracleDB` to map generic logs to vendor knowledge.
* `AppInit_DLLs`: Triggers "Hook Integrity" check.
* `vcruntime140.dll`: Triggers "Missing Dependency" check.
* `oleacc.dll`: Triggers "Legacy Bridge" check.
* `FSLogon`: Triggers "Secure Desktop" check.
* `dgnword.dll`: Triggers "Dragon/Office Add-in" check.
* `134.0.0`: Triggers "Chromium Copy/Paste" check.

## 4. System Telemetry Map
Variables extracted from `SystemInfo.nfo` or `TSS` text logs.
* `$OS_Build`: Extracted version (e.g., 22631). Used to check against Windows Known Issue Rollbacks (KIR).
* `$CPU_Load`: Extracted average load. Used to weight "Latency" findings.
* `$Installed_KB`: List of KBs to correlate with "Known Bad" Windows updates.
