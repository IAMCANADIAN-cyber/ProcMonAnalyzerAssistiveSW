# 📚 Internal Data Dictionary

## State Variables
* `$WitnessBuffer` (List): Circular buffer of the last 200 events. Used for "Step-Back" debugging context.
* `$EdgeBuffer` (List): Stores the tail-end of the previous batch. Vital for sliding window analysis.
* `$GlobalSuspectBuffer` (Dictionary): Stores the last known activity of Security Agents.
    * *Key:* File Path (String)
    * *Value:* Custom Object `{ Time, Proc, Path }`
* `$OracleDB` (Hashtable): Static knowledge base of vendor bugs.

## Configuration Lists
* `$AT_Processes` (HashSet): "Allowlist" of Assistive Tech executables.
* `$Sec_Processes` (HashSet): "Blocklist" of known Security/EDR executables.

## Counters
* `$FocusBounceCount`: Tracks rapid foreground window changes.
* `$ReparseCounts`: Tracks infinite recursion in OneDrive/SharePoint folders.
* `$PacketStormCounter`: Tracks high-frequency small network packets.
