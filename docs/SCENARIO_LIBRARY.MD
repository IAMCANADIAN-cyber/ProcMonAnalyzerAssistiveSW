# 📚 Scenario Library (Automated Catalog)

This document defines the detection logic for `ProcMon-Enterprise-Unified.ps1`.
It correlates technical signatures (Operations/Results) with User Experiences and Root Causes.

## 🔎 How to Read
- **ID:** Unique identifier in the script engine.
- **Title:** The name of the detection scenario.
- **Technical Signature:** The specific ProcMon Operation, Result, and Path pattern that triggers the detection.
- **Context & Remediation:** Explanation of the root cause, symptoms, and potential fixes.

---

## Module 2: The "Cluster & High Availability" Suite

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `CreateFile\|WriteFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `C:\\Users\\.*\\.*` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **4** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `SetDispositionInformationFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **6** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `CreateFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `\\\\\.\\Pipe\\.*` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **7** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `CreateFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `\\System32\\spool` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **8** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `CreateFile`<br>**Res:** `STATUS\ DELETE\ PENDING`<br>**Path:** `*` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **16** | Quorum Drive Reservation Loss | **Op:** `CreateFile`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `X:\\` | **Cause:** SAN latency causing the node to lose its reservation on the disk. |
| **51** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `RegSetValue`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **52** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `RegSetValue`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **53** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `RegSetValue`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `Software\\Policies` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **64** | Cluster Database Registry Lock | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **72** | Cluster Database Registry Lock | **Proc:** `ctfmon\.exe` <br>**Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **77** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Query\ `HKCU\\.*\\Capabilities`` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **78** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Failure\ to\ enumerate\ installed\ SAPI\ voices\.` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **85** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `App\ forcing\ a\ specific\ sound\ scheme,\ overriding\ accessibility\ sounds\.` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **89** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `User\ lacks\ permission\ to\ save\ custom\ scripts\ for\ the\ specific\ application\.` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **90** | Heartbeat Network Saturation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `NetworkList\\Profiles` | **Cause:** Management traffic flooding the private heartbeat NIC. |
| **147** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VirtualStore` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **203** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `history\.ini` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **221** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `frxsvc` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **230** | Heartbeat Network Saturation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FVE` | **Cause:** Management traffic flooding the private heartbeat NIC. |
| **240** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wuauserv` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **273** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vaultcmd` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **278** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WaveIn` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **279** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Video` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **296** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.pst` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **310** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WindowsAccessBridge` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **317** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `applicationHost\.config`` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **342** | Cluster Database Registry Lock | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **347** | Quorum Drive Reservation Loss | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Tape0` | **Cause:** SAN latency causing the node to lose its reservation on the disk. |
| **359** | Cluster Database Registry Lock | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **404** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``parent\.lock`` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **419** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `index\.lock`` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **483** | Heartbeat Network Saturation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Management traffic flooding the private heartbeat NIC. |
| **519** | Quorum Drive Reservation Loss | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCU\\Network`` | **Cause:** SAN latency causing the node to lose its reservation on the disk. |
| **523** | Heartbeat Network Saturation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\NetworkList`` | **Cause:** Management traffic flooding the private heartbeat NIC. |
| **581** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000022` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **621** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.ldb` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **622** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `odbc32\.dll` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **641** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Cookies` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **642** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `History` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **772** | Heartbeat Network Saturation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `30\ second\ delay\ on\ connect\.` | **Cause:** Management traffic flooding the private heartbeat NIC. |
| **845** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `host_mnt` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **853** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FileCoAuth` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **865** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `sqlmin\.dll` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **870** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `database\.sqlite\-journal` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **877** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `package\-lock\.json`` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **1051** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AudioEndpoint` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **1070** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **1076** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\\\\Server\\Share` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **1105** | Quorum Drive Reservation Loss | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\\\tsclient\\c`\ latency` | **Cause:** SAN latency causing the node to lose its reservation on the disk. |
| **1119** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **1137** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Volume` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **1141** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `Shell\\Bags` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **1144** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `Recent\\AutomaticDestinations` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **1145** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **1155** | Heartbeat Network Saturation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Management traffic flooding the private heartbeat NIC. |
| **1165** | Quorum Drive Reservation Loss | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** SAN latency causing the node to lose its reservation on the disk. |
| **1171** | Cluster Database Registry Lock | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `System\\CurrentControlSet\\Enum\\DISPLAY` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **1211** | Quorum Drive Reservation Loss | **Proc:** `clussvc\.exe` <br>**Op:** `*`<br>**Res:** `STATUS_IO_TIMEOUT\|STATUS_DEVICE_BUSY`<br>**Path:** `Quorum\|Witness` | **Cause:** SAN latency causing the node to lose its reservation on the disk. |
| **1212** | Cluster Database Registry Lock | **Proc:** `System` <br>**Op:** `ReadFile`<br>**Res:** `*`<br>**Path:** `C:\\ClusterStorage` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **1213** | Cluster Database Registry Lock | **Proc:** `clussvc\.exe` <br>**Op:** `*`<br>**Res:** `SHARING_VIOLATION`<br>**Path:** `HKLM\\Cluster` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **1214** | Heartbeat Network Saturation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Management traffic flooding the private heartbeat NIC. |
| **1216** | CSV (Cluster Shared Volume) Redirected Access | **Proc:** `clussvc\.exe` <br>**Op:** `CreateFile`<br>**Res:** `ACCESS_DENIED`<br>**Path:** `\\\\.*\\.*` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **1218** | Cluster Database Registry Lock | **Proc:** `vmms\.exe` <br>**Op:** `*`<br>**Res:** `ACCESS_DENIED`<br>**Path:** `.*\.avhdx` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **1237** | Cluster Database Registry Lock | **Proc:** `w3wp\.exe` <br>**Op:** `*`<br>**Res:** `ACCESS_DENIED`<br>**Path:** `IIS Temporary Compressed Files` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **1250** | Quorum Drive Reservation Loss | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** SAN latency causing the node to lose its reservation on the disk. |
| **1253** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **1259** | Cluster Database Registry Lock | **Proc:** `OneDrive\.exe` <br>**Op:** `*`<br>**Res:** `SHARING_VIOLATION`<br>**Path:** `*` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **1287** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **1296** | Cluster Database Registry Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state. |
| **1338** | Heartbeat Network Saturation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Management traffic flooding the private heartbeat NIC. |
| **1424** | Heartbeat Network Saturation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Management traffic flooding the private heartbeat NIC. |
| **1450** | Quorum Drive Reservation Loss | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** SAN latency causing the node to lose its reservation on the disk. |
| **1478** | CSV (Cluster Shared Volume) Redirected Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Explorer connecting to FTP site` | **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow). |
| **1498** | Heartbeat Network Saturation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CheckNetIsolation loopback exempt missing` | **Cause:** Management traffic flooding the private heartbeat NIC. |

## Module 10: Advanced Security & Evasion (Sysmon Correlation)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **2** | Normalize | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Align\ all\ timestamps\.` | **Context:** Align all timestamps. |
| **3** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Iterate\ through\ the\ ` | **Context:** Iterate through the "Modules" above. |
| **5** | Output | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Generate\ a\ report\ that\ sounds\ like\ Mark\ R:` | **Context:** Generate a report that sounds like Mark R: |
| **37** | ADS (Alternate Data Stream) Execution | **Op:** `ProcessCreate`<br>**Res:** `*`<br>**Path:** `.*:Stream` | **Cause:** Hiding code inside NTFS streams (e.g., `calc.exe:evil.vbs`). |
| **68** | Scan | **Op:** `*`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Registry cleaner behavior |
| **107** | Process Hollowing (Image Mismatch) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Code injection; replacing the memory of a legit process with malware. |
| **222** | ADS (Alternate Data Stream) Execution | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ from\ `Q:`` | **Cause:** Hiding code inside NTFS streams (e.g., `calc.exe:evil.vbs`). |
| **251** | WMI Event Consumer Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CurrentVersion\\Run` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **252** | WMI Event Consumer Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Startup` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **253** | WMI Event Consumer Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Services` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **254** | WMI Event Consumer Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Tasks` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **256** | Process Hollowing (Image Mismatch) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Image File Execution Options` | **Cause:** Code injection; replacing the memory of a legit process with malware. |
| **274** | ADS (Alternate Data Stream) Execution | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Login Data` | **Cause:** Hiding code inside NTFS streams (e.g., `calc.exe:evil.vbs`). |
| **284** | WMI Event Consumer Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wevtutil cl` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **294** | DNS Tunneling / Beaconing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Data exfiltration over DNS (C2 traffic). |
| **344** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `twain_32\.dll` | **Cause:** Imaging |
| **349** | WMI Event Consumer Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ACPI` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **421** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mcshield\.exe`` | **Cause:** AV |
| **422** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``ccSvcHst\.exe`` | **Cause:** AV |
| **428** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Vuln Scan |
| **467** | WMI Event Consumer Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mmc\.exe`` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **560** | WMI Event Consumer Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WmiPrvSE`\ loading\ `wbemess\.dll`` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **644** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Download` | **Cause:** Delay |
| **694** | ADS (Alternate Data Stream) Execution | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hiding code inside NTFS streams (e.g., `calc.exe:evil.vbs`). |
| **715** | ADS (Alternate Data Stream) Execution | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ExecutionPolicy` | **Cause:** Hiding code inside NTFS streams (e.g., `calc.exe:evil.vbs`). |
| **746** | WMI Event Consumer Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Security\.evtx` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **787** | ADS (Alternate Data Stream) Execution | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Hiding\ data\ in\ ADS\.` | **Cause:** Hiding code inside NTFS streams (e.g., `calc.exe:evil.vbs`). |
| **889** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VST` | **Cause:** Audio |
| **998** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Input |
| **1043** | WMI Event Consumer Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `StructureChanged` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **1065** | WMI Event Consumer Persistence | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **1142** | Scan | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `ContextMenuHandlers` | **Cause:** Explorer loading shell extensions. High latency here means a hung extension. |
| **1143** | Scan | **Op:** `RegEnumKey`<br>**Res:** `*`<br>**Path:** `ShellIconOverlayIdentifiers` | **Cause:** Checking overlay icons. Limit is 15; excess apps fight for slots. |
| **1174** | Scan | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `MMDevices\\Audio\\Render` | **Cause:**  enumerating audio devices. Corruption here breaks sound. |
| **1199** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Context:** Iterate through the "Modules" above. |
| **1254** | WMI Event Consumer Persistence | **Proc:** `scrcons\.exe` <br>**Op:** `Process Create`<br>**Res:** `*`<br>**Path:** `cmd\.exe\|powershell\.exe` | **Cause:** Malware creating a permanent WMI subscription to run code on boot/event. |
| **1322** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Context:** Iterate through the "Modules" above. |
| **1409** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Context:** Iterate through the "Modules" above. |
| **1428** | DNS Tunneling / Beaconing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Data exfiltration over DNS (C2 traffic). |

## Module 7: VDI Specifics (Citrix / AVD / VMware)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **9** | UPM (Universal Profile Management) Sync Fail | **Op:** `CreateFile`<br>**Res:** `SHARING\ VIOLATION`<br>**Path:** `NTUSER\.DAT` | **Cause:** Network drop during logoff; profile changes are lost. |
| **210** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `NTUSER\.DAT` | **Cause:** Network drop during logoff; profile changes are lost. |
| **218** | Citrix API Hooking Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``CtxHk\.dll`\ load` | **Cause:** The application (e.g., Chrome) detects the Citrix hook as an intrusion and kills itself. Fix: Exclude via registry. |
| **220** | FSLogix RW/RO Contention | **Op:** `*`<br>**Res:** `*`<br>**Path:** `frxsvc` | **Cause:** The VHDX is mounted Read-Write on another session host (zombie session). |
| **223** | ThinPrint LPC Wait | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TPAutoConnect` | **Cause:** ThinPrint client component is stuck trying to map client-side printers. |
| **395** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `OneDrive` | **Cause:** Network drop during logoff; profile changes are lost. |
| **401** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SingletonLock` | **Cause:** Network drop during logoff; profile changes are lost. |
| **435** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Box` | **Cause:** Network drop during logoff; profile changes are lost. |
| **445** | ThinPrint LPC Wait | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** ThinPrint client component is stuck trying to map client-side printers. |
| **678** | Citrix API Hooking Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ctxtcp\.sys` | **Cause:** The application (e.g., Chrome) detects the Citrix hook as an intrusion and kills itself. Fix: Exclude via registry. |
| **679** | Citrix API Hooking Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ctxusbm\.sys` | **Cause:** The application (e.g., Chrome) detects the Citrix hook as an intrusion and kills itself. Fix: Exclude via registry. |
| **680** | FSLogix RW/RO Contention | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``frxdrv\.sys`` | **Cause:** The VHDX is mounted Read-Write on another session host (zombie session). |
| **682** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Network drop during logoff; profile changes are lost. |
| **698** | Citrix API Hooking Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The application (e.g., Chrome) detects the Citrix hook as an intrusion and kills itself. Fix: Exclude via registry. |
| **699** | Citrix API Hooking Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The application (e.g., Chrome) detects the Citrix hook as an intrusion and kills itself. Fix: Exclude via registry. |
| **713** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Microsoft\.PowerShell_profile\.ps1` | **Cause:** Network drop during logoff; profile changes are lost. |
| **859** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Conflicted Copy` | **Cause:** Network drop during logoff; profile changes are lost. |
| **904** | ThinPrint LPC Wait | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AitAgent` | **Cause:** ThinPrint client component is stuck trying to map client-side printers. |
| **966** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Network drop during logoff; profile changes are lost. |
| **1124** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `mscms\.dll` | **Cause:** Network drop during logoff; profile changes are lost. |
| **1227** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Network drop during logoff; profile changes are lost. |
| **1233** | FSLogix RW/RO Contention | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The VHDX is mounted Read-Write on another session host (zombie session). |
| **1289** | ThinPrint LPC Wait | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** ThinPrint client component is stuck trying to map client-side printers. |
| **1295** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Network drop during logoff; profile changes are lost. |
| **1357** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Network drop during logoff; profile changes are lost. |
| **1379** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Network drop during logoff; profile changes are lost. |
| **1419** | UPM (Universal Profile Management) Sync Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Network drop during logoff; profile changes are lost. |
| **1471** | UPM (Universal Profile Management) Sync Fail | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `ProfileList.*RefCount` | **Cause:** Network drop during logoff; profile changes are lost. |

## Module 3: Hyper-V & Virtualization Platform

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **10** | VHDX Snapshot Merge Lock | **Op:** `CreateFile`<br>**Res:** `SHARING\ VIOLATION`<br>**Path:** `.*\.vhdx` | **Cause:** Backup software (Veeam/Commvault) still holding a lock on the snapshot file after backup completion. |
| **23** | Pass-Through Disk Offline | **Op:** `WriteFile`<br>**Res:** `DISK\ FULL`<br>**Path:** `*` | **Cause:** The host OS unexpectedly claimed the LUN intended for the guest. |
| **28** | Pass-Through Disk Offline | **Op:** `CreateFile`<br>**Res:** `STATUS\ DEVICE\ OFF\ LINE`<br>**Path:** `*` | **Cause:** The host OS unexpectedly claimed the LUN intended for the guest. |
| **38** | Hyper-V Switch Extension Block | **Op:** `CreateFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `Zone\.Identifier` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **86** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Routing\ issues\ when\ using\ Virtual\ Audio\ Cables\ with\ Screen\ Readers\.` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **101** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **102** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **103** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **104** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000005` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **105** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000409` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **106** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000374` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **136** | Virtual Machine Worker Process Crash | **Op:** `Process\ Exit`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **137** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **140** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **145** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **146** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **208** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `STATUS\ TRUST\ FAILURE`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **211** | Pass-Through Disk Offline | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The host OS unexpectedly claimed the LUN intended for the guest. |
| **212** | Pass-Through Disk Offline | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CscService` | **Cause:** The host OS unexpectedly claimed the LUN intended for the guest. |
| **214** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``spoolsv\.exe`\ exit` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **219** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **229** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SrpUxNative` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **259** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `txtfile\\shell\\open`` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **315** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``w3wp\.exe`\ start` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **387** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FIPSAlgorithmPolicy` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **531** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``spoolsv\.exe`\ Exit\ Code\ !=\ 0` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **532** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``audiodg\.exe`\ Exit\ Code\ !=\ 0` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **533** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``dwm\.exe`\ Exit\ Code\ !=\ 0` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **534** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SearchIndexer\.exe` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **535** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WmiPrvSE\.exe`\ Exit\ Code\ !=\ 0` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **536** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TiWorker\.exe` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **537** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``MsMpEng\.exe`\ Exit\ Code\ !=\ 0` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **538** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mpssvc` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **539** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wevtsvc` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **540** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``taskeng\.exe`\ Exit` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **541** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Explorer\.exe`\ Exit` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **542** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``LogonUI\.exe`\ Exit` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **543** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `lsass\.exe` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **544** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``csrss\.exe`\ Exit` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **545** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `smss\.exe` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **586** | Pass-Through Disk Offline | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000007F` | **Cause:** The host OS unexpectedly claimed the LUN intended for the guest. |
| **778** | Pass-Through Disk Offline | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Queue\ length\ >\ 5\.` | **Cause:** The host OS unexpectedly claimed the LUN intended for the guest. |
| **781** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Writes\ to\ `VirtualStore`\.` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **841** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `hcsshim\.dll` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **850** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **925** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ctp\.sys` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **1020** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Shim Engine` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **1056** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **1177** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **1190** | Pass-Through Disk Offline | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The host OS unexpectedly claimed the LUN intended for the guest. |
| **1193** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **1219** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **1221** | Pass-Through Disk Offline | **Proc:** `vmms\.exe` <br>**Op:** `*`<br>**Res:** `STATUS_DEVICE_OFF_LINE`<br>**Path:** `\\\\.\\PhysicalDrive.*` | **Cause:** The host OS unexpectedly claimed the LUN intended for the guest. |
| **1222** | Virtual Machine Worker Process Crash | **Proc:** `vmwp\.exe` <br>**Op:** `Process Exit`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **1246** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **1247** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **1263** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **1286** | Pass-Through Disk Offline | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The host OS unexpectedly claimed the LUN intended for the guest. |
| **1389** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |
| **1415** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **1434** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **1461** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **1466** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **1469** | Virtual Machine Worker Process Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corrupt memory in the guest causing the worker process on the host to die. |
| **1497** | Hyper-V Switch Extension Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MitigationPolicy event` | **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch. |

## SECTION 1: FILE SYSTEM FORENSICS (NTFS & I/O)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **11** | Sharing Violation (Profile) | **Op:** `CreateFile`<br>**Res:** `SHARING\ VIOLATION`<br>**Path:** `.*\.log` | **Cause:** Profile locked by AV/Backup |
| **12** | Sharing Violation (Profile) | **Op:** `CreateFile`<br>**Res:** `SHARING\ VIOLATION`<br>**Path:** `.*\.dll` | **Cause:** Profile locked by AV/Backup |
| **24** | Quota Exceeded | **Op:** `WriteFile`<br>**Res:** `QUOTA\ EXCEEDED`<br>**Path:** `*` | **Cause:** User disk quota hit |
| **29** | Device Offline | **Op:** `DeviceIoControl`<br>**Res:** `STATUS\ DEVICE\ BUSY`<br>**Path:** `*` | **Cause:** USB/Storage disconnect |
| **30** | Oplock Break | **Op:** `FsRtlCheckOplock`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Network locking contention |
| **35** | Dir Not Empty | **Op:** `*`<br>**Res:** `STATUS\ DIRECTORY\ NOT\ EMPTY`<br>**Path:** `*` | **Cause:** Failed folder delete |
| **39** | Cloud Tiering | **Op:** `ReadFile`<br>**Res:** `STATUS\ FILE\ IS\ OFFLINE\|FILE\ IS\ OFFLINE`<br>**Path:** `*` | **Cause:** OneDrive/Azure Files recall needed |
| **41** | BitLocker Locked | **Op:** `CreateFile`<br>**Res:** `STATUS\ FVE\ LOCKED\ VOLUME`<br>**Path:** `*` | **Cause:** Drive mounted but locked |
| **46** | 1-Byte I/O | **Op:** `ReadFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Inefficient coding |
| **47** | Directory Enumeration Storm | **Op:** `FlushBuffersFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Inefficient loop |
| **50** | Access Denied (Write - User) | **Op:** `WriteFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** User permissions broken on own profile |
| **54** | Path Not Found (DLL) | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKCR\\CLSID` | **Cause:** Missing dependency |
| **55** | Path Not Found (DLL) | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKCR\\AppID` | **Cause:** Missing dependency |
| **57** | Path Not Found (DLL) | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKCR\\TypeLib` | **Cause:** Missing dependency |
| **59** | Path Not Found (DLL) | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKLM\\.*\\Uninstall` | **Cause:** Missing dependency |
| **60** | Path Not Found (DLL) | **Op:** `RegQueryValue`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Missing dependency |
| **61** | Path Not Found (DLL) | **Op:** `RegQueryValue`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Missing dependency |
| **166** | Directory Enumeration Storm | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Inefficient loop |
| **187** | Access Denied (Pipe) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\\\\Server\\pipe` | **Cause:** Service security hardening |
| **216** | Reparse Point Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Dopp` | **Cause:** Infinite symlink loop |
| **231** | Alternate Data Stream Exec | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``msiexec\.exe`` | **Cause:** Potential malware/hiding |
| **285** | Access Denied (Delete) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vssadmin delete` | **Cause:** Read-only attribute or ACL |
| **292** | Access Denied (Write - User) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** User permissions broken on own profile |
| **321** | Access Denied (Write - System) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\ODBC` | **Cause:** UAC/Permission issue |
| **337** | Access Denied (Pipe) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SCardPipe` | **Cause:** Service security hardening |
| **371** | Access Denied (Write - User) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VirtualStore` | **Cause:** User permissions broken on own profile |
| **417** | Access Denied (Pipe) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `docker_engine` | **Cause:** Service security hardening |
| **433** | Alternate Data Stream Exec | **Op:** `*`<br>**Res:** `*`<br>**Path:** `beremote` | **Cause:** Potential malware/hiding |
| **481** | Alternate Data Stream Exec | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``bash\.exe`` | **Cause:** Potential malware/hiding |
| **551** | Device Busy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `svchost\.exe\ \-k\ sysmain` | **Cause:** Hardware stuck |
| **552** | Device Busy | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``svchost\.exe\ \-k\ utisvc`\ Disk\ I` | **Cause:** Hardware stuck |
| **553** | Device Busy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `svchost\.exe\ \-k\ netsvcs` | **Cause:** Hardware stuck |
| **554** | Device Busy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MsMpEng\.exe` | **Cause:** Hardware stuck |
| **582** | Path Not Found (DLL) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000000` | **Cause:** Missing dependency |
| **583** | Path Not Found (DLL) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000034` | **Cause:** Missing dependency |
| **584** | Sharing Violation (Profile) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000043` | **Cause:** Profile locked by AV/Backup |
| **589** | Access Denied (Pipe) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC00000AE` | **Cause:** Service security hardening |
| **590** | Access Denied (Pipe) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000014B` | **Cause:** Service security hardening |
| **596** | Quota Exceeded | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000044` | **Cause:** User disk quota hit |
| **603** | Reparse Point Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000139` | **Cause:** Infinite symlink loop |
| **607** | Access Denied (Delete) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000056` | **Cause:** Read-only attribute or ACL |
| **609** | Reparse Point Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000275` | **Cause:** Infinite symlink loop |
| **742** | MFT Fragmentation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `$MFT` | **Cause:** Severe filesystem fragmentation |
| **743** | Log File Bloat | **Op:** `*`<br>**Res:** `*`<br>**Path:** `$LogFile` | **Cause:** Disk usage spike |
| **844** | BitLocker Locked | **Op:** `*`<br>**Res:** `*`<br>**Path:** `layer\.tar` | **Cause:** Drive mounted but locked |
| **846** | Access Denied (Pipe) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\\\\.\\pipe\\docker_engine`\ fail` | **Cause:** Service security hardening |
| **851** | Access Denied (Pipe) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\\\\.\\pipe\\OneDriveIPC`\ fail` | **Cause:** Service security hardening |
| **854** | Access Denied (Pipe) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\\\\.\\pipe\\DropboxPipe`\ fail` | **Cause:** Service security hardening |
| **856** | Access Denied (Pipe) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GoogleDriveFS` | **Cause:** Service security hardening |
| **863** | Access Denied (Pipe) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\\\\.\\pipe\\sql\\query`\ busy` | **Cause:** Service security hardening |
| **906** | Device Offline | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DeviceCensus\.exe` | **Cause:** USB/Storage disconnect |
| **1054** | Access Denied (Write - User) | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `user\.dic` | **Cause:** User permissions broken on own profile |
| **1063** | Access Denied (Write - User) | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** User permissions broken on own profile |
| **1064** | Access Denied (Write - User) | **Op:** `RegSetValue`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** User permissions broken on own profile |
| **1130** | File Corrupt | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DevMode` | **Cause:** Physical disk/filesystem rot |
| **1158** | Sharing Violation (Profile) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Profile locked by AV/Backup |
| **1195** | Directory Enumeration Storm | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Inefficient loop |
| **1204** | Quota Exceeded | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** User disk quota hit |
| **1230** | 1-Byte I/O | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Inefficient coding |
| **1242** | Directory Enumeration Storm | **Op:** `UDP Send`<br>**Res:** `*`<br>**Path:** `224\.0\.0\.252\|.*:5355` | **Cause:** Inefficient loop |
| **1375** | BitLocker Locked | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Drive mounted but locked |
| **1484** | Access Denied (Write - System) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Dates copy-pasted from Mac` | **Cause:** UAC/Permission issue |
| **1496** | BitLocker Locked | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Undelete tools fail on Empty space` | **Cause:** Drive mounted but locked |

## Module 11: COM, DCOM & RPC Subsystems

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **13** | COM Server Path Mismatch (The "Moved EXE") | **Op:** `LoadImage`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** The application was moved or updated, but the COM registration still points to the old location. |
| **14** | COM Server Path Mismatch (The "Moved EXE") | **Op:** `ProcessCreate`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** The application was moved or updated, but the COM registration still points to the old location. |
| **17** | COM Server Path Mismatch (The "Moved EXE") | **Op:** `CreateFile`<br>**Res:** `BAD\ NETWORK\ PATH`<br>**Path:** `\\\\Server\\Share` | **Cause:** The application was moved or updated, but the COM registration still points to the old location. |
| **18** | COM Server Path Mismatch (The "Moved EXE") | **Op:** `CreateFile`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `PROGRA\~1` | **Cause:** The application was moved or updated, but the COM registration still points to the old location. |
| **19** | COM Server Path Mismatch (The "Moved EXE") | **Op:** `CreateFile`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `C:\\Users\\DevName` | **Cause:** The application was moved or updated, but the COM registration still points to the old location. |
| **20** | COM Server Path Mismatch (The "Moved EXE") | **Op:** `CreateFile`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `\\WinSxS\\.*` | **Cause:** The application was moved or updated, but the COM registration still points to the old location. |
| **56** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKCR\\Interface` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **65** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``DrawFocusRect`\ not\ called\ or\ invisible\.` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **73** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **80** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``SpeechPlatform`\ failing\ to\ load\ required\ language\ model\.` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **87** | DCOM Launch Permission (Access Denied) | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** The user account does not have "Local Launch" or "Local Activation" permissions in `dcomcnfg`. |
| **169** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **170** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **171** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **172** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **173** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **174** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **175** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **176** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **179** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **189** | Global Interface Table (GIT) Revocation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The COM object in the server process crashed or was explicitly revoked, but the client still holds a pointer to it. |
| **311** | COM Server Path Mismatch (The "Moved EXE") | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PYTHONPATH` | **Cause:** The application was moved or updated, but the COM registration still points to the old location. |
| **345** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `COM1` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **346** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `LPT1` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **368** | COM Server Path Mismatch (The "Moved EXE") | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DOCUME\~1` | **Cause:** The application was moved or updated, but the COM registration still points to the old location. |
| **547** | DCOM Launch Permission (Access Denied) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``svchost\.exe\ \-k\ DcomLaunch`\ High\ CPU` | **Cause:** The user account does not have "Local Launch" or "Local Activation" permissions in `dcomcnfg`. |
| **646** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `*`<br>**Res:** `TIMEOUT`<br>**Path:** `\.pac` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **659** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `usbport\.sys` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **686** | Global Interface Table (GIT) Revocation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The COM object in the server process crashed or was explicitly revoked, but the client still holds a pointer to it. |
| **779** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``SeDebugPrivilege`\ check\ fail\.` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **1023** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``IAccessible::get_accName`\ returns\ empty` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **1027** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\JavaSoft\\Accessibility` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **1044** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``UIAutomationCore\.dll`\ loading\ wrong\ version` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **1061** | Global Interface Table (GIT) Revocation | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** The COM object in the server process crashed or was explicitly revoked, but the client still holds a pointer to it. |
| **1071** | COM Server Path Mismatch (The "Moved EXE") | **Op:** `LoadImage`<br>**Res:** `*`<br>**Path:** `%PATH%` | **Cause:** The application was moved or updated, but the COM registration still points to the old location. |
| **1072** | COM Server Path Mismatch (The "Moved EXE") | **Op:** `*`<br>**Res:** `*`<br>**Path:** `C:\\Users\\.*\\bin` | **Cause:** The application was moved or updated, but the COM registration still points to the old location. |
| **1129** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `monitordll` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **1251** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **1264** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **1292** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |
| **1371** | RPC Dynamic Port Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection. |
| **1448** | COM Server Path Mismatch (The "Moved EXE") | **Op:** `RegQueryValue`<br>**Res:** `BUFFER OVERFLOW`<br>**Path:** `Environment\\Path` | **Cause:** The application was moved or updated, but the COM registration still points to the old location. |
| **1486** | Interface Proxy/Stub Missing (Marshaling Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Meetings are 1 hour off` | **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered. |

## Module 4: IIS, Web & ASP.NET Deep Dive

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **15** | AppPool Identity Config Access | **Op:** `CreateFile`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `.*\.ini` | **Cause:** NTFS permissions on the website root don't include the virtual AppPool account. |
| **32** | Rapid Fail Protection (Crash Loop) | **Op:** `WriteFile`<br>**Res:** `DISK\ FULL`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **33** | Rapid Fail Protection (Crash Loop) | **Op:** `CreateFile`<br>**Res:** `STATUS\ REPARSE\ POINT\ NOT\ RESOLVED`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **43** | HTTP.sys Queue Full | **Op:** `*`<br>**Res:** `LOG\ FILE\ FULL`<br>**Path:** `Ntfs\.sys` | **Cause:** Application pool is hung; kernel queue filled up. |
| **75** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Failure\ to\ write\ to\ the\ user's\ custom\ dictionary\ file\.` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **93** | AppPool Identity Config Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Console\\Configuration` | **Cause:** NTFS permissions on the website root don't include the virtual AppPool account. |
| **108** | Rapid Fail Protection (Crash Loop) | **Op:** `LoadImage`<br>**Res:** `STATUS\ IMAGE\ NOT\ AT\ BASE`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **109** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `STATUS\ IMAGE\ MACHINE\ TYPE\ MISMATCH`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **110** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `STATUS\ INVALID\ IMAGE\ HASH`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **114** | HTTP.sys Queue Full | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PROCESS_ALL_ACCESS` | **Cause:** Application pool is hung; kernel queue filled up. |
| **138** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **159** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `HOST\ UNREACHABLE`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **163** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **185** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **186** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RPC_E_DISCONNECTED` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **190** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **201** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `gpt\.ini` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **202** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** ``gpscript\.exe`\ error`<br>**Path:** `gpscript\.exe` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **204** | Shared Configuration Latency | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\\\\Domain\\Sysvol` | **Cause:** Network latency to the file server hosting Shared Configuration is slowing down TTFB (Time to First Byte). |
| **205** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `_ldap` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **232** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **237** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Extract\ fail\ `%TEMP%`` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **242** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `cryptsvc` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **303** | ASP.NET Temp Folder Compilation Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `Temporary\ ASP\.NET\ Files`` | **Cause:** Anti-Virus scanning the dynamic compilation folder. |
| **304** | AppPool Identity Config Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `machine\.config`` | **Cause:** NTFS permissions on the website root don't include the virtual AppPool account. |
| **316** | AppPool Identity Config Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `web\.config` | **Cause:** NTFS permissions on the website root don't include the virtual AppPool account. |
| **318** | AppPool Identity Config Access | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** NTFS permissions on the website root don't include the virtual AppPool account. |
| **319** | ASP.NET Temp Folder Compilation Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TEMP` | **Cause:** Anti-Virus scanning the dynamic compilation folder. |
| **351** | Rapid Fail Protection (Crash Loop) | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **358** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WindowsAccessBridge` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **380** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CERT_E_CHAINING` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **388** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `STATUS\ INVALID\ IMAGE\ HASH`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **478** | AppPool Identity Config Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `\.wslconfig`` | **Cause:** NTFS permissions on the website root don't include the virtual AppPool account. |
| **556** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WmiPrvSE\.exe`\ High\ CPU` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **561** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{0D43FE01-F093-11CF-8940-00A0C9054228}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **562** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{13709620-C279-11CE-A49E-444553540000}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **563** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{72C24DD5-D70A-438B-8A42-98424B88AFB8}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **564** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{00000514-0000-0010-8000-00AA006D2EA4}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **565** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{2933BF90-7B36-11D2-B20E-00C04F983E60}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **566** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{88D96A0A-F192-11D4-A65F-0040963251E5}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **567** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{4991D34B-80A1-4291-83B6-3328366B9097}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **568** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **569** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{F7898AF5-CAC4-4632-A2EC-DA06E5111AF2}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **570** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{4CB43D7F-7EEE-4906-8698-60DA1C38F2FE}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **571** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{000C1090-0000-0000-C000-000000000046}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **572** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{4590F811-1D3A-11D0-891F-00AA004B2E24}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **573** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{96749377-3391-11D2-9EE3-00C04F797396}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **574** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{9E175B8D-F52A-11D8-B9A5-505054503030}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **575** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{557CF406-1A04-11D3-9A73-0000F81EF32E}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **576** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{06290BD5-48AA-11D2-8432-006008C3FBFC}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **577** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{3050F4D8-98B5-11CF-BB82-00AA00BDCE0B}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **578** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **579** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{F3364BA0-65B9-11CE-A9BA-00AA004AE837}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **580** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{00021401-0000-0000-C000-000000000046}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **587** | HTTP.sys Queue Full | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000017` | **Cause:** Application pool is hung; kernel queue filled up. |
| **690** | HTTP.sys Queue Full | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Application pool is hung; kernel queue filled up. |
| **766** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `Resource\ load\ fail\ \->\ Blank\ Error\.`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **785** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Symlink\ cycle\.` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **847** | AppPool Identity Config Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `config` | **Cause:** NTFS permissions on the website root don't include the virtual AppPool account. |
| **848** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **849** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **860** | Rapid Fail Protection (Crash Loop) | **Op:** `SetFileAttributes`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **871** | AppPool Identity Config Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.gitconfig` | **Cause:** NTFS permissions on the website root don't include the virtual AppPool account. |
| **939** | HTTP.sys Queue Full | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `\.spl`` | **Cause:** Application pool is hung; kernel queue filled up. |
| **960** | ASP.NET Temp Folder Compilation Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mpi\.dll` | **Cause:** Anti-Virus scanning the dynamic compilation folder. |
| **1031** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `IAudioSessionControl` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1033** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1036** | Rapid Fail Protection (Crash Loop) | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `HKCR\\CLSID\\\{ProxyStub\}` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1040** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1042** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1047** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SetWindowsHookEx` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1114** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1157** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1169** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1173** | HTTP.sys Queue Full | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Application pool is hung; kernel queue filled up. |
| **1184** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1189** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1201** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1223** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1225** | Rapid Fail Protection (Crash Loop) | **Proc:** `Omadmclient\.exe` <br>**Op:** `Process Exit`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1226** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1234** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1235** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1236** | HTTP.sys Queue Full | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Application pool is hung; kernel queue filled up. |
| **1238** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1244** | Rapid Fail Protection (Crash Loop) | **Op:** `LoadImage`<br>**Res:** `NAME_NOT_FOUND\|PATH_NOT_FOUND`<br>**Path:** `api-ms-win-crt-runtime.*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1274** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1285** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1298** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1365** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1381** | ASP.NET Temp Folder Compilation Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Anti-Virus scanning the dynamic compilation folder. |
| **1412** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1445** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1452** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1472** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |
| **1482** | Rapid Fail Protection (Crash Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `tzautoupdate service` | **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init. |

## Module 1: The "Kernel & Memory" Deep Dive

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **21** | DLL Base Address Collision (Relocation Thrashing) | **Op:** `CreateFile`<br>**Res:** `NAME\ COLLISION`<br>**Path:** `%TEMP%` | **Cause:** ASLR issues or fixed-base DLLs fighting for the same memory address space. |
| **22** | DLL Base Address Collision (Relocation Thrashing) | **Op:** `CreateFile`<br>**Res:** `NAME\ COLLISION`<br>**Path:** `*` | **Cause:** ASLR issues or fixed-base DLLs fighting for the same memory address space. |
| **25** | Page File Fragmentation/Resize Storms | **Op:** `ReadFile`<br>**Res:** `FILE\ CORRUPT\ ERROR`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **31** | Filter Manager Altitude Collision | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **40** | Page File Fragmentation/Resize Storms | **Op:** `CreateFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **44** | Page File Fragmentation/Resize Storms | **Op:** `ReadFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **48** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `>1000\ creates\ in\ `%TEMP%`\ in\ 1\ min` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **49** | Page File Fragmentation/Resize Storms | **Op:** `WriteFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **126** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AllocateLocallyUniqueId` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **127** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `CreateFile\|CloseHandle`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **128** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **129** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **130** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `STATUS\ INSUFFICIENT\ RESOURCES`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **133** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **181** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.pac` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **215** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PrintIsolationHost` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **244** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `drvstore` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **277** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `BitBlt` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **288** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `hosts` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **323** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `sqlncli\.dll` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **436** | Desktop Heap Depletion (Session 0) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RtlFreeHeap` | **Cause:** Too many services running interactively or leaking window handles in the non-interactive session. |
| **442** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `CloseHandle`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **446** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **450** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **465** | Filter Manager Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Taskmgr` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **477** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Access\ `\\\\wsl\$`` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **479** | Filter Manager Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `LxssManager` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **601** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000008` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **651** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``ntfs\.sys`\ activity` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **652** | Filter Manager Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `fltmgr\.sys` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **655** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `afd\.sys` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **656** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``fwpkclnt\.sys`\ activity` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **657** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``ndis\.sys`\ activity` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **669** | Filter Manager Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``symefasi\.sys`` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **670** | Filter Manager Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mfehidk\.sys`` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **723** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Exec\ `\.wsf`` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **725** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.bat` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **726** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Exec\ `\.cmd`` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **730** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.jar` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **748** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `memory\.dmp` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **775** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Black\ screen\ due\ to\ 10k\ objects\.` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **776** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Slowdown\ due\ to\ 100k\ handles\.` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **784** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `DISK\ FULL`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **786** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Hierarchical\ Storage\ fail\.` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **788** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Redirect\ verification\.` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **791** | Desktop Heap Depletion (Session 0) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Service\ interacting\ with\ desktop\.` | **Cause:** Too many services running interactively or leaking window handles in the non-interactive session. |
| **792** | Desktop Heap Depletion (Session 0) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Service\ GUI\ fail\.` | **Cause:** Too many services running interactively or leaking window handles in the non-interactive session. |
| **907** | DLL Base Address Collision (Relocation Thrashing) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Geofence` | **Cause:** ASLR issues or fixed-base DLLs fighting for the same memory address space. |
| **918** | Desktop Heap Depletion (Session 0) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``tssdis\.exe`\ fail` | **Cause:** Too many services running interactively or leaking window handles in the non-interactive session. |
| **938** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DriverStore` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1014** | Desktop Heap Depletion (Session 0) | **Op:** `Process\ Exit`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Too many services running interactively or leaking window handles in the non-interactive session. |
| **1030** | Desktop Heap Depletion (Session 0) | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Too many services running interactively or leaking window handles in the non-interactive session. |
| **1032** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `jfwvid\.dll`\ \(JAWS\)\ or\ `nvda_mirror`\ fail` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1034** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `-32000` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1049** | Filter Manager Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DwmSetColorizationParameters` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **1068** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1081** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TCP Retransmit` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1082** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WSAEADDRINUSE`\ \(10048\)\ on\ .*Outbound.*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1111** | Filter Manager Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `fltmgr` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **1112** | DLL Base Address Collision (Relocation Thrashing) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `User32!BeginPaint` | **Cause:** ASLR issues or fixed-base DLLs fighting for the same memory address space. |
| **1115** | Filter Manager Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **1117** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1121** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PrintIsolationHost` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1123** | Filter Manager Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mxdwdrv\.dll` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **1139** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Explorer` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1147** | Page File Fragmentation/Resize Storms | **Op:** `RegSetValue`<br>**Res:** `*`<br>**Path:** `UserChoice\\Hash` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1154** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1159** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1161** | Filter Manager Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **1167** | Desktop Heap Depletion (Session 0) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Too many services running interactively or leaking window handles in the non-interactive session. |
| **1172** | DLL Base Address Collision (Relocation Thrashing) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** ASLR issues or fixed-base DLLs fighting for the same memory address space. |
| **1175** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1176** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1186** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1188** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1207** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1208** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1209** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1210** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1231** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1239** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1240** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1243** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1261** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1265** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1279** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1280** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1281** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1282** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1283** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1300** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1301** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1302** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1303** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1304** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1305** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1306** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1307** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1308** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1309** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1310** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1311** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1312** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1313** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1314** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1315** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1317** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1318** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1323** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1329** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1330** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1331** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1332** | Desktop Heap Depletion (Session 0) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Too many services running interactively or leaking window handles in the non-interactive session. |
| **1335** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1341** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1342** | Filter Manager Altitude Collision | **Op:** `RegSetValue`<br>**Res:** `*`<br>**Path:** `Accessibility\\Keyboard Response` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **1343** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1345** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1347** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1349** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1351** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1354** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1359** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1362** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1366** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1382** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1384** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1388** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1395** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1397** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1398** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1399** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1400** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1401** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1403** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1406** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1407** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1413** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1421** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1425** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1431** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1432** | Desktop Heap Depletion (Session 0) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Too many services running interactively or leaking window handles in the non-interactive session. |
| **1435** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1436** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1439** | Page File Fragmentation/Resize Storms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion. |
| **1440** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1443** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1444** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1457** | GDI Handle Leak (The "Black Screen" Cause) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing. |
| **1463** | Filter Manager Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow. |
| **1464** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1465** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1474** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1491** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `User32 resource fail` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1492** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GlobalAddAtom fail` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |
| **1494** | Non-Paged Pool Exhaustion (Driver Leak) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Paged Pool high` | **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening. |

## Module 9: The "Mark Russinovich" Forensics (Sysinternals Style)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **26** | The "Case of the Unexplained Error Message" | **Op:** `ReadFile`<br>**Res:** `DATA\ ERROR`<br>**Path:** `*` | **Cause:** The app tried to load the *text* of the error message, failed, and showed a default/blank error. |
| **27** | The "Case of the Unexplained Error Message" | **Op:** `ReadFile`<br>**Res:** `STATUS\ IN\ PAGE\ ERROR`<br>**Path:** `*` | **Cause:** The app tried to load the *text* of the error message, failed, and showed a default/blank error. |
| **36** | The "Case of the Unexplained Error Message" | **Op:** `CreateFile`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** The app tried to load the *text* of the error message, failed, and showed a default/blank error. |
| **74** | The "Ghost Window" Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App sent a message to all windows, and an invisible hidden window isn't replying. |
| **135** | The "Ghost Window" Hang | **Op:** `LoadImage`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App sent a message to all windows, and an invisible hidden window isn't replying. |
| **769** | The "HKCU vs HKCR" Masking | **Op:** `*`<br>**Res:** `*`<br>**Path:** `User\ key\ hiding\ System\ key\.` | **Cause:** `HKCU\Software\Classes` (User setting) is overriding `HKLM\Software\Classes` (System setting). |
| **770** | The "Environment Variable Expansion" Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``%SystemRoot%`\ literal\ lookup\.` | **Cause:** The registry value type is `REG_SZ` (String) instead of `REG_EXPAND_SZ`. |
| **783** | The "Case of the Unexplained Error Message" | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``File`\ !=\ `file`\.` | **Cause:** The app tried to load the *text* of the error message, failed, and showed a default/blank error. |
| **1009** | The "Case of the Unexplained Error Message" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The app tried to load the *text* of the error message, failed, and showed a default/blank error. |
| **1018** | The "Environment Variable Expansion" Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The registry value type is `REG_SZ` (String) instead of `REG_EXPAND_SZ`. |
| **1086** | The "Ghost Window" Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App sent a message to all windows, and an invisible hidden window isn't replying. |
| **1148** | The "Ghost Window" Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App sent a message to all windows, and an invisible hidden window isn't replying. |
| **1183** | The "Ghost Window" Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App sent a message to all windows, and an invisible hidden window isn't replying. |
| **1228** | The "Case of the Unexplained Error Message" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The app tried to load the *text* of the error message, failed, and showed a default/blank error. |
| **1248** | The "Ghost Window" Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App sent a message to all windows, and an invisible hidden window isn't replying. |
| **1262** | The "Case of the Unexplained Error Message" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The app tried to load the *text* of the error message, failed, and showed a default/blank error. |
| **1297** | The "Ghost Window" Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App sent a message to all windows, and an invisible hidden window isn't replying. |
| **1316** | The "Ghost Window" Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App sent a message to all windows, and an invisible hidden window isn't replying. |
| **1391** | The "Environment Variable Expansion" Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The registry value type is `REG_SZ` (String) instead of `REG_EXPAND_SZ`. |
| **1396** | The "Case of the Unexplained Error Message" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The app tried to load the *text* of the error message, failed, and showed a default/blank error. |
| **1427** | The "Ghost Window" Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App sent a message to all windows, and an invisible hidden window isn't replying. |
| **1500** | The "Ghost Window" Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CreateWindow with NULL class` | **Cause:** App sent a message to all windows, and an invisible hidden window isn't replying. |

## Module 19: File System Edge Cases

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **34** | Directory Change Notification Overflow | **Op:** `CreateFile`<br>**Res:** `STATUS\ NOT\ A\ DIRECTORY`<br>**Path:** `*` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **45** | Directory Change Notification Overflow | **Op:** `QueryDirectory`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **63** | Directory Change Notification Overflow | **Op:** `RegQueryValue`<br>**Res:** `BUFFER\ OVERFLOW`<br>**Path:** `*` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **98** | Directory Change Notification Overflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **134** | Directory Change Notification Overflow | **Op:** `*`<br>**Res:** `STATUS\ STACK\ OVERFLOW`<br>**Path:** `*` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **353** | Short Name (8.3) Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `accName` | **Cause:** The 8.3 generated name (e.g., `PROJEC~1.DOC`) conflicts with an existing entry, even if the long name is unique. |
| **608** | Directory Change Notification Overflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000103` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **693** | Short Name (8.3) Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The 8.3 generated name (e.g., `PROJEC~1.DOC`) conflicts with an existing entry, even if the long name is unique. |
| **767** | Directory Change Notification Overflow | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **771** | Directory Change Notification Overflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Registry\ value\ too\ small\.` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **774** | Zone.Identifier Stream Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ADS\ causing\ security\ block\.` | **Cause:** Anti-virus preventing the "Mark of the Web" from being written or read, potentially blocking execution. |
| **782** | Short Name (8.3) Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\~1` | **Cause:** The 8.3 generated name (e.g., `PROJEC~1.DOC`) conflicts with an existing entry, even if the long name is unique. |
| **1013** | Directory Change Notification Overflow | **Op:** `Process\ Exit`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **1135** | Directory Change Notification Overflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DisplaySettings` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **1136** | Directory Change Notification Overflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Theme` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **1138** | Directory Change Notification Overflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SetSystemTime` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **1187** | Directory Change Notification Overflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |
| **1490** | Directory Change Notification Overflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetTickCount 32-bit rollover` | **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer. |

## Module 8: Advanced Storage & File System

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **42** | USN Journal Wrap | **Op:** `*`<br>**Res:** `USN\ JOURNAL\ WRAP`<br>**Path:** `*` | **Cause:** High churn on volume overwrote the Change Journal before backup could read it. |
| **744** | USN Journal Wrap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `\$Extend\\\$UsnJrnl`` | **Cause:** High churn on volume overwrote the Change Journal before backup could read it. |

## Module 15: Cryptography & PKI

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **58** | Smart Card Service Block | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKLM\\System\\.*\\Services` | **Cause:** Smart Card service is stopped or the card reader driver is unresponsive. |
| **246** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SoftwareDistribution` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **377** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Download\ `authroot\.stl`` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **383** | MachineKey Access Denied (IIS/ASP.NET) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MachineKeys` | **Cause:** The Application Pool Identity cannot read the private key required for encryption/decryption. |
| **389** | Catalog Database Corruption (CatRoot2) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `catdb` | **Cause:** The cryptographic catalog database is corrupt, preventing Windows Updates or driver installs. |
| **403** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MicrosoftEdgeUpdate` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **414** | Smart Card Service Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WebExService` | **Cause:** Smart Card service is stopped or the card reader driver is unresponsive. |
| **625** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `OfficeClickToRun\.exe` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **638** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MicrosoftEdgeUpdate\.exe` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **930** | Catalog Database Corruption (CatRoot2) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GlobalCatalog` | **Cause:** The cryptographic catalog database is corrupt, preventing Windows Updates or driver installs. |
| **1052** | Smart Card Service Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``ctfmon\.exe`\ deadlock` | **Cause:** Smart Card service is stopped or the card reader driver is unresponsive. |
| **1058** | Smart Card Service Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TabTip\.exe` | **Cause:** Smart Card service is stopped or the card reader driver is unresponsive. |
| **1062** | Smart Card Service Block | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Smart Card service is stopped or the card reader driver is unresponsive. |
| **1118** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **1196** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **1200** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **1217** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **1252** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **1339** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **1386** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |
| **1387** | Root Certificate Update Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification. |

## Module 6: Windows Update & Component Store (CBS)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **62** | Catroot2 Timestamp Mismatch | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Cryptographic database corruption; prevents update installation. |
| **71** | Pending.xml Exclusive Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Windows\ Dictation\ failing\ to\ access\ Mic\.` | **Cause:** A previous update failed to clear its pending actions, blocking all future updates. |
| **239** | Pending.xml Exclusive Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PendingFileRename` | **Cause:** A previous update failed to clear its pending actions, blocking all future updates. |
| **241** | CBS Manifest Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TrustedInstaller` | **Cause:** Disk corruption or failed update causing unserviceable OS. |
| **243** | CBS Manifest Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `winsxs` | **Cause:** Disk corruption or failed update causing unserviceable OS. |
| **248** | CBS Manifest Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AppxManifest\.xml` | **Cause:** Disk corruption or failed update causing unserviceable OS. |
| **382** | Catroot2 Timestamp Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CERT_E_CN_NO_MATCH` | **Cause:** Cryptographic database corruption; prevents update installation. |
| **752** | CBS Manifest Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `CBS\.log`` | **Cause:** Disk corruption or failed update causing unserviceable OS. |
| **768** | Pending.xml Exclusive Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `File\ locked\ by\ previous\ delete\ \->\ Install\ Fail\.` | **Cause:** A previous update failed to clear its pending actions, blocking all future updates. |
| **1024** | Catroot2 Timestamp Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ROLE_SYSTEM_GRAPHIC` | **Cause:** Cryptographic database corruption; prevents update installation. |
| **1079** | Catroot2 Timestamp Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MultiByteToWideChar` | **Cause:** Cryptographic database corruption; prevents update installation. |
| **1125** | Catroot2 Timestamp Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Cryptographic database corruption; prevents update installation. |
| **1166** | CBS Manifest Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disk corruption or failed update causing unserviceable OS. |
| **1245** | CBS Manifest Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disk corruption or failed update causing unserviceable OS. |
| **1288** | Catroot2 Timestamp Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Cryptographic database corruption; prevents update installation. |
| **1290** | Catroot2 Timestamp Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Cryptographic database corruption; prevents update installation. |
| **1291** | CBS Manifest Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disk corruption or failed update causing unserviceable OS. |
| **1368** | CBS Manifest Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disk corruption or failed update causing unserviceable OS. |
| **1383** | Pending.xml Exclusive Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A previous update failed to clear its pending actions, blocking all future updates. |
| **1411** | Catroot2 Timestamp Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Cryptographic database corruption; prevents update installation. |
| **1460** | CBS Manifest Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disk corruption or failed update causing unserviceable OS. |
| **1473** | CBS Manifest Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disk corruption or failed update causing unserviceable OS. |
| **1475** | Catroot2 Timestamp Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Cryptographic database corruption; prevents update installation. |

## SECTION 33: CLOUD STORAGE & SYNC (Advanced)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **66** | Sync Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ClearType\ rendering\ artifacts\ when\ magnification\ is\ active\.` | **Cause:** Race |
| **1059** | Sync Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Race |
| **1095** | Sync Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Alt+F` | **Cause:** Race |

## SECTION 52: ASSISTIVE TECH - INPUT & MAGNIFICATION

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **67** | High DPI Blur | **Op:** `*`<br>**Res:** `*`<br>**Path:** `App\ not\ DPI\ aware,\ resulting\ in\ blurry\ text\ at\ 200%\ scaling\.` | **Cause:** Fuzzy UI |
| **1053** | Correction UI | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Invisible menu |
| **1055** | Eye Tracker HID | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hardware connect |

## Module 25: Legacy & "Very Old" Windows

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **69** | INI File Mapping (Legacy Redirect) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `win\.ini` | **Cause:** The app is ancient. Windows automatically maps these calls to the Registry (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\IniFileMapping`), which creates confusion if the mapping is wrong. |
| **361** | INI File Mapping (Legacy Redirect) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `win\.ini`` | **Cause:** The app is ancient. Windows automatically maps these calls to the Registry (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\IniFileMapping`), which creates confusion if the mapping is wrong. |
| **373** | INI File Mapping (Legacy Redirect) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `winhlp32\.exe` | **Cause:** The app is ancient. Windows automatically maps these calls to the Registry (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\IniFileMapping`), which creates confusion if the mapping is wrong. |
| **1104** | INI File Mapping (Legacy Redirect) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `C:\\Windows\\System32\\spool\\servers` | **Cause:** The app is ancient. Windows automatically maps these calls to the Registry (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\IniFileMapping`), which creates confusion if the mapping is wrong. |
| **1268** | 16-bit Subsystem (NTVDM) Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** 64-bit Windows does not support 16-bit apps. NTVDM is missing. |

## SECTION 7: SECURITY & MALWARE INDICATORS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **70** | Disable Def | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SPI_GETCLIENTAREAANIMATION` | **Cause:** AV Kill |
| **258** | Image Hijack | **Op:** `*`<br>**Res:** `*`<br>**Path:** `InprocServer32` | **Cause:** Debug hijack |
| **261** | Phantom DLL | **Op:** `*`<br>**Res:** `*`<br>**Path:** `version\.dll` | **Cause:** Sideloading |
| **262** | Winlogon Persist | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `Objects\.data`` | **Cause:** Hijack |
| **265** | LoLBin CertUtil | **Op:** `*`<br>**Res:** `*`<br>**Path:** `certutil -urlcache` | **Cause:** Download |
| **266** | LoLBin CertUtil | **Op:** `*`<br>**Res:** `*`<br>**Path:** `bitsadmin /transfer` | **Cause:** Download |
| **267** | LoLBin CertUtil | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mshta vbscript` | **Cause:** Download |
| **268** | LoLBin CertUtil | **Op:** `*`<br>**Res:** `*`<br>**Path:** `rundll32 entrypoint` | **Cause:** Download |
| **269** | LoLBin CertUtil | **Op:** `*`<br>**Res:** `*`<br>**Path:** `regsvr32 /s /u` | **Cause:** Download |
| **270** | Credential Dump | **Op:** `*`<br>**Res:** `*`<br>**Path:** `lsass` | **Cause:** Mimikatz |
| **271** | Credential Dump | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SAM` | **Cause:** Mimikatz |
| **272** | LSA Secret | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Policy\\Secrets` | **Cause:** Password dump |
| **275** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetAsyncKeyState` | **Cause:** Spyware |
| **276** | Clipboard Monitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Spyware |
| **280** | Recon Whoami | **Op:** `*`<br>**Res:** `*`<br>**Path:** `whoami /all` | **Cause:** Discovery |
| **281** | Recon Whoami | **Op:** `*`<br>**Res:** `*`<br>**Path:** `net group` | **Cause:** Discovery |
| **283** | Task Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `tasklist /svc` | **Cause:** Scheduled Task |
| **286** | Backup Stop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wbadmin delete` | **Cause:** Ransomware |
| **287** | Disable Def | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DisableRealtimeMonitoring` | **Cause:** AV Kill |
| **289** | Timestomp | **Op:** `SetBasicInformationFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hiding |
| **290** | Masquerade | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``svchost`\ in\ `%TEMP%`` | **Cause:** Hiding |
| **298** | RDP Saved | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Default\.rdp` | **Cause:** Lateral move |
| **299** | SSH Keys | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Wlansvc` | **Cause:** Lateral move |
| **305** | Recon Net | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mscorjit\.dll` | **Cause:** Discovery |
| **306** | Recon Net | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ngen\.exe` | **Cause:** Discovery |
| **348** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `batmeter` | **Cause:** Spyware |
| **511** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCU\\Control\ Panel\\Desktop\\Wallpaper`` | **Cause:** Spyware |
| **512** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Control\ Panel\\Desktop\\ScreenSaveActive` | **Cause:** Spyware |
| **514** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ThemeManager`` | **Cause:** Spyware |
| **515** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Control\ Panel\\Colors` | **Cause:** Spyware |
| **516** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Control\ Panel\\Cursors` | **Cause:** Spyware |
| **517** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\AppEvents\\Schemes` | **Cause:** Spyware |
| **521** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\MUI\\Settings`` | **Cause:** Spyware |
| **525** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\SECURITY\\Policy\\PolAdtEv` | **Cause:** Spyware |
| **526** | LSA Secret | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa`` | **Cause:** Password dump |
| **527** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL`` | **Cause:** Spyware |
| **528** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy` | **Cause:** Spyware |
| **530** | AppInit Injection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Windows\\AppInit_DLLs` | **Cause:** Dll inject |
| **558** | WMI Persist | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WmiPrvSE`\ loading\ `storagewmi\.dll`` | **Cause:** Fileless persist |
| **559** | WMI Persist | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wmidex\.dll` | **Cause:** Fileless persist |
| **591** | Recon Net | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000023C` | **Cause:** Discovery |
| **602** | Phantom DLL | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000142` | **Cause:** Sideloading |
| **666** | SAM Dump | **Op:** `*`<br>**Res:** `*`<br>**Path:** `atikmdag\.sys` | **Cause:** Hash dump |
| **688** | Browser Helper | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Adware |
| **689** | RDP Saved | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Lateral move |
| **749** | Credential Dump | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Minidump` | **Cause:** Mimikatz |
| **862** | Credential Dump | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SQLDump.*\.mdmp` | **Cause:** Mimikatz |
| **912** | RDP Saved | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``rdpclip\.exe`\ fail` | **Cause:** Lateral move |
| **913** | RDP Saved | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``rdpdr\.sys`\ fail` | **Cause:** Lateral move |
| **914** | RDP Saved | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``rdpsnd\.sys`\ fail` | **Cause:** Lateral move |
| **916** | RDP Saved | **Op:** `*`<br>**Res:** `*`<br>**Path:** `rdpinput\.sys` | **Cause:** Lateral move |
| **917** | RDP Saved | **Op:** `*`<br>**Res:** `*`<br>**Path:** `rdpgfx\.sys` | **Cause:** Lateral move |
| **977** | Mic Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Nuance` | **Cause:** Eavesdrop |
| **1093** | Shadow Delete | **Op:** `*`<br>**Res:** `*`<br>**Path:** `#shadow-root` | **Cause:** Ransomware |
| **1107** | Clipboard Monitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `rdpclip` | **Cause:** Spyware |
| **1181** | Clipboard Monitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Spyware |
| **1255** | SSH Keys | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Lateral move |
| **1256** | Image Hijack | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Debug hijack |
| **1258** | Image Hijack | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Debug hijack |
| **1336** | Browser Helper | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Adware |
| **1337** | Startup Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Autostart |
| **1361** | Startup Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Autostart |
| **1416** | Webcam Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Spyware |
| **1418** | Clipboard Monitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Spyware |
| **1430** | Wifi Keys | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Lateral move |
| **1446** | LoLBin Bits | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Download |
| **1449** | Image Hijack | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `Image File Execution Options.*Debugger` | **Cause:** Debug hijack |
| **1476** | Credential Dump | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Mimikatz |

## SECTION 2: REGISTRY INTERNALS (HKLM/HKCU/HKCR)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **76** | Pending Rename Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ZoneMap\\Domains` | **Cause:** Reboot check |
| **82** | Winlogon Helper | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Winlogon\\Shell` | **Cause:** Persistence/Kiosk mode |
| **83** | LSA Provider Mod | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ to\ `Security\\Providers`` | **Cause:** Credential theft/Inject |
| **88** | USB Enum | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `Enum\\USB`` | **Cause:** Hardware enumeration |
| **92** | WPA Key | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `Wlansvc\\Parameters`` | **Cause:** WiFi config |
| **99** | Crypto Seed | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RNG\\Seed` | **Cause:** Entropy generation |
| **111** | Driver Service Create | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Driver load |
| **112** | Silent Process Exit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** WER monitoring |
| **165** | Product ID Lookup | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** License check |
| **180** | Product ID Lookup | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wpad` | **Cause:** License check |
| **193** | Pending Rename Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `msftncsi` | **Cause:** Reboot check |
| **255** | Winlogon Helper | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Userinit` | **Cause:** Persistence/Kiosk mode |
| **260** | Winlogon Helper | **Op:** `*`<br>**Res:** `*`<br>**Path:** `BHO` | **Cause:** Persistence/Kiosk mode |
| **291** | Pending Rename Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Reboot check |
| **331** | USB Enum | **Op:** `DeviceIoControl`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hardware enumeration |
| **332** | USB Enum | **Op:** `DeviceIoControl`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hardware enumeration |
| **335** | USB Enum | **Op:** `*`<br>**Res:** `*`<br>**Path:** `BthEnum` | **Cause:** Hardware enumeration |
| **370** | Pending Rename Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CdRom0` | **Cause:** Reboot check |
| **379** | Pending Rename Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Reboot check |
| **386** | WPA Key | **Op:** `*`<br>**Res:** `*`<br>**Path:** `KeyStorage` | **Cause:** WiFi config |
| **390** | Crypto Seed | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RNG` | **Cause:** Entropy generation |
| **393** | WPA Key | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Ngc` | **Cause:** WiFi config |
| **440** | Buffer Overflow (Reg) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Data larger than buffer |
| **462** | Services Start Mode | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ShellExperienceHost` | **Cause:** Service disabling |
| **464** | Internet Settings Mod | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SystemSettings` | **Cause:** Proxy hijack/config |
| **469** | Shell Extension Lookup | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``cmd\.exe`` | **Cause:** Explorer add-in load |
| **522** | Time Zone | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation`` | **Cause:** Time sync |
| **529** | Winlogon Helper | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Winlogon`` | **Cause:** Persistence/Kiosk mode |
| **557** | LSA Provider Mod | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WmiPrvSE`\ loading\ `cimwin32\.dll`` | **Cause:** Credential theft/Inject |
| **598** | Buffer Overflow (Reg) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000023` | **Cause:** Data larger than buffer |
| **645** | Pending Rename Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Root` | **Cause:** Reboot check |
| **660** | USB Enum | **Op:** `*`<br>**Res:** `*`<br>**Path:** `usbhub\.sys` | **Cause:** Hardware enumeration |
| **714** | Group Policy History | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ConsoleHost_history\.txt` | **Cause:** GPO processing |
| **731** | Driver Service Create | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `.*\.pf`` | **Cause:** Driver load |
| **888** | Pending Rename Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Reboot check |
| **895** | USB Enum | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HMD` | **Cause:** Hardware enumeration |
| **921** | Driver Service Create | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vssvc\.exe` | **Cause:** Driver load |
| **923** | LSA Provider Mod | **Op:** `*`<br>**Res:** `*`<br>**Path:** `swprv` | **Cause:** Credential theft/Inject |
| **970** | KnownDLLs Bypass | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Dll hijacking |
| **1016** | Pending Rename Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Reboot check |
| **1019** | Console Config | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** CMD settings |
| **1041** | Orphaned Key Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Registry cleaner behavior |
| **1066** | Driver Service Create | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Driver load |
| **1134** | USB Enum | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DeviceRemoval` | **Cause:** Hardware enumeration |
| **1153** | LSA Provider Mod | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Credential theft/Inject |
| **1164** | Silent Process Exit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** WER monitoring |
| **1320** | KnownDLLs Bypass | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Dll hijacking |
| **1328** | Silent Process Exit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** WER monitoring |
| **1417** | USB Enum | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hardware enumeration |
| **1462** | Performance Counter | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** PerfMon data |

## Module 23: Audio & Media

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **79** | Audio Endpoint Builder Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Audiosrv`\ failing\ to\ build\ graph\ for\ Dictation\.` | **Cause:** Third-party audio enhancement (Nahimic, Waves) deadlocked the audio graph. |
| **340** | Audio Endpoint Builder Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AUDCLNT_E_DEVICE_IN_USE` | **Cause:** Third-party audio enhancement (Nahimic, Waves) deadlocked the audio graph. |
| **341** | Audio Endpoint Builder Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `audiodg` | **Cause:** Third-party audio enhancement (Nahimic, Waves) deadlocked the audio graph. |
| **486** | Exclusive Mode Theft | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GameBar\.exe` | **Cause:** Another app has exclusive control of the sound card. |
| **639** | Exclusive Mode Theft | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ieexplore\.exe` | **Cause:** Another app has exclusive control of the sound card. |
| **668** | Audio Endpoint Builder Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``rtkvhd64\.sys`\ activity` | **Cause:** Third-party audio enhancement (Nahimic, Waves) deadlocked the audio graph. |
| **1000** | Exclusive Mode Theft | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Another app has exclusive control of the sound card. |
| **1021** | Exclusive Mode Theft | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SetForegroundWindow` | **Cause:** Another app has exclusive control of the sound card. |
| **1103** | Audio Endpoint Builder Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `audiodg` | **Cause:** Third-party audio enhancement (Nahimic, Waves) deadlocked the audio graph. |
| **1202** | Audio Endpoint Builder Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Third-party audio enhancement (Nahimic, Waves) deadlocked the audio graph. |
| **1203** | Exclusive Mode Theft | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Another app has exclusive control of the sound card. |
| **1319** | Audio Endpoint Builder Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Third-party audio enhancement (Nahimic, Waves) deadlocked the audio graph. |
| **1355** | Audio Endpoint Builder Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Third-party audio enhancement (Nahimic, Waves) deadlocked the audio graph. |
| **1356** | Audio Endpoint Builder Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Third-party audio enhancement (Nahimic, Waves) deadlocked the audio graph. |

## Module 5: Active Directory & Kerberos (Client Side)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **81** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GroupPolicy\\History` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **206** | Kerberos Ticket Bloat (MaxTokenSize) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `KRB_AP_ERR_SKEW` | **Cause:** User is in too many groups; Token size > 48k (or 12k legacy). |
| **207** | Kerberos Ticket Bloat (MaxTokenSize) | **Op:** `*`<br>**Res:** `BUFFER\ OVERFLOW\|STATUS\ BUFFER\ OVERFLOW`<br>**Path:** `*` | **Cause:** User is in too many groups; Token size > 48k (or 12k legacy). |
| **217** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `gpprinter` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **397** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PolicyManager` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **501** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **502** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System`` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **503** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **504** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\Policies\\Microsoft\\Internet\ Explorer` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **505** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\Policies\\Microsoft\\Edge` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **506** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\Policies\\Google\\Chrome` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **507** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCU\\Software\\Policies\\Microsoft\\Office`` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **508** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\Policies\\Microsoft\\Windows\ Defender` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **509** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **510** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\Software\\Policies\\Microsoft\\Power\\PowerSettings`` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **610** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC00002D0` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **633** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CloudManagement` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **709** | DC Discovery Fail (NetLogon) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** DNS misconfiguration; client cannot find a domain controller. |
| **1106** | Time Skew Auth Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Client clock is > 5 minutes off from DC. |
| **1122** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PackagePointAndPrint` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **1163** | Kerberos Ticket Bloat (MaxTokenSize) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** User is in too many groups; Token size > 48k (or 12k legacy). |
| **1192** | Time Skew Auth Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Client clock is > 5 minutes off from DC. |
| **1197** | Group Policy Ini Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs. |
| **1294** | Time Skew Auth Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Client clock is > 5 minutes off from DC. |
| **1324** | Kerberos Ticket Bloat (MaxTokenSize) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** User is in too many groups; Token size > 48k (or 12k legacy). |
| **1380** | Kerberos Ticket Bloat (MaxTokenSize) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** User is in too many groups; Token size > 48k (or 12k legacy). |
| **1480** | Machine Account Password Desync | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ACLs full of S-1-5-21-` | **Cause:** Computer account password mismatch; requires re-joining domain. |
| **1483** | Kerberos Ticket Bloat (MaxTokenSize) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Client time > 5 mins difference` | **Cause:** User is in too many groups; Token size > 48k (or 12k legacy). |

## Module 17: User Profile & Registry Bloat

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **84** | Stuck "Logon Script" (The Invisible Wait) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``utilman`\ failing\ to\ launch\ the\ configured\ AT\ on\ the\ logon\ screen\.` | **Cause:** A logon script is waiting for user input (e.g., `pause` or a mapped drive prompt) but is running hidden. |
| **524** | Firewall Rule Bloat | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy` | **Cause:** 50,000+ firewall rules created (often by containerization software or bad GPOs), slowing down every network connection. |
| **1128** | Stuck "Logon Script" (The Invisible Wait) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\.spl`\ file\ locked\ by\ AV` | **Cause:** A logon script is waiting for user input (e.g., `pause` or a mapped drive prompt) but is running hidden. |
| **1162** | Stuck "Logon Script" (The Invisible Wait) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A logon script is waiting for user input (e.g., `pause` or a mapped drive prompt) but is running hidden. |
| **1447** | Firewall Rule Bloat | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** 50,000+ firewall rules created (often by containerization software or bad GPOs), slowing down every network connection. |

## Module 13: Windows Installer (MSI) & Deployment

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **91** | Custom Action Script Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DirectX\ but\ implements\ 0\ accessibility\.` | **Cause:** A poorly written logic script inside the MSI installer failed. |
| **139** | MSI Self-Repair Loop (The "Resiliency" Trap) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `cmd /c del` | **Cause:** The "KeyPath" for a component is missing. MSI repairs it, but the app deletes it or fails to write it, triggering an infinite repair loop. |
| **233** | MSI Self-Repair Loop (The "Resiliency" Trap) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `msiexec` | **Cause:** The "KeyPath" for a component is missing. MSI repairs it, but the app deletes it or fails to write it, triggering an infinite repair loop. |
| **235** | Installer Mutex Contention (`_MSIExecute`) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `_MSIExecute` | **Cause:** Another installation is running in the background (often Windows Update or SMS Agent), blocking this one. |
| **236** | Custom Action Script Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `cmd` | **Cause:** A poorly written logic script inside the MSI installer failed. |
| **463** | Custom Action Script Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ActionCenter` | **Cause:** A poorly written logic script inside the MSI installer failed. |
| **727** | Custom Action Script Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.py` | **Cause:** A poorly written logic script inside the MSI installer failed. |
| **728** | Custom Action Script Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.pl` | **Cause:** A poorly written logic script inside the MSI installer failed. |
| **729** | Custom Action Script Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Exec\ `\.rb`` | **Cause:** A poorly written logic script inside the MSI installer failed. |
| **1094** | MSI Self-Repair Loop (The "Resiliency" Trap) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The "KeyPath" for a component is missing. MSI repairs it, but the app deletes it or fails to write it, triggering an infinite repair loop. |
| **1140** | Installer Mutex Contention (`_MSIExecute`) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `msiexec` | **Cause:** Another installation is running in the background (often Windows Update or SMS Agent), blocking this one. |
| **1198** | Pending Reboot Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A previous update moved a file but needs a reboot to delete the old one. |
| **1275** | Source List Exhaustion (Prompt for CD) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A patch/repair is required, but the cached MSI in `C:\Windows\Installer` is missing, and the original source is unreachable. |
| **1333** | Installer Mutex Contention (`_MSIExecute`) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Another installation is running in the background (often Windows Update or SMS Agent), blocking this one. |

## SECTION 140: THE "TRULY UNEXPLAINABLE" LOGIC BUGS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **94** | Timed Tooltip | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Tooltip\ disappears\ too\ fast\ for\ the\ screen\ reader\ to\ catch\ it\.` | **Context:** Tooltip disappears too fast for the screen reader to catch it. |
| **95** | Non-Standard Combobox | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** no role, no expand/collapse state |

## SECTION 55: COMPLEX NETWORKING (The "It's the Firewall" Red Herrings)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **96** | PAWS Drop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Operation\ requires\ dragging,\ no\ keyboard\ alternative\.` | **Cause:** Sequence number wrap |
| **1084** | Nagle Algorithm | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** NoDelay not set |
| **1085** | Delayed ACK | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** ACK timer |
| **1087** | PAWS Drop | **Op:** `*`<br>**Res:** `Timestamp\ error`<br>**Path:** `*` | **Cause:** Sequence number wrap |
| **1088** | PAWS Drop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Sequence number wrap |
| **1089** | RSS Imbalance | **Op:** `*`<br>**Res:** `*`<br>**Path:** `One\ CPU\ core\ 100%\ on\ network\ interrupt` | **Cause:** Card setting |
| **1090** | Chimney Offload | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** NIC Driver bug |
| **1149** | PAWS Drop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Sequence number wrap |
| **1327** | Chimney Offload | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** NIC Driver bug |
| **1334** | PAWS Drop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Sequence number wrap |

## SECTION 19: GROUP POLICY & REGISTRY POLLING (The "Noise")

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **97** | Color Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** High Contrast |
| **626** | Policy Poll (Office) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `OSPP\.VBS` | **Cause:** Macro settings |
| **740** | Icon Cache Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `IconCache\.db`` | **Cause:** Overlays |
| **793** | Policy Poll (Power) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Sleep\ prevention\.` | **Cause:** Sleep/Wake |
| **1004** | Policy Poll (Power) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Sleep/Wake |
| **1360** | Policy Poll (Power) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Sleep/Wake |
| **1458** | Policy Poll (Power) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Sleep/Wake |

## SECTION 49: THE "SILENT FAILURES" (Hardest to Diagnose)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **100** | Console Hidden | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** UI logic |
| **1011** | Swallowed Exception (CLR) | **Op:** `*`<br>**Res:** ``\.NET\ Runtime`\ logs\ `<br>**Path:** `\.NET\ Runtime` | **Cause:** Dev caught exception but didn't log it |
| **1091** | Console Hidden | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AriaProperties` | **Cause:** UI logic |

## SECTION 3: PROCESS, MEMORY & THREADS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **113** | CreateRemoteThread | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Thread\ in\ .*other.*\ process` | **Cause:** Injection/Debug |
| **115** | OpenProcess (Full) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VM_READ/WRITE` | **Cause:** Admin/AV |
| **116** | OpenProcess (Full) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TERMINATE` | **Cause:** Admin/AV |
| **117** | TerminateProcess | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Watchdog/User kill |
| **118** | Debug Active | **Op:** `*`<br>**Res:** `*`<br>**Path:** `IsDebuggerPresent` | **Cause:** Anti-debug |
| **119** | WerFault Trigger | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WerFault\.exe` | **Cause:** Crash reporting |
| **120** | Dr Watson | **Op:** `*`<br>**Res:** `*`<br>**Path:** `dwwin\.exe` | **Cause:** Legacy crash |
| **121** | Conhost Spawn | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Spawning\ `conhost\.exe`` | **Cause:** Console window |
| **122** | Wow64 Transition | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Compatibility |
| **123** | Job Object Assign | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Resource limit |
| **131** | Commit Limit | **Op:** `*`<br>**Res:** `STATUS\ COMMITMENT\ LIMIT`<br>**Path:** `*` | **Cause:** RAM/Pagefile full |
| **132** | Working Set Trim | **Op:** `*`<br>**Res:** `*`<br>**Path:** `EmptyWorkingSet` | **Cause:** Memory reclaiming |
| **142** | SvcHost Split | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Stability |
| **143** | AppContainer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Store App |
| **148** | Shim Engine | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AcLayers\.dll` | **Cause:** AppCompat |
| **149** | Detours | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``detoured\.dll`\ load` | **Cause:** Hooking |
| **150** | Inject Library | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AppInit_DLLs` | **Cause:** Global injection |
| **151** | Process Exit (Success) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Clean shutdown |
| **199** | Debug Active | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Anti-debug |
| **200** | Debug Active | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Anti-debug |
| **364** | Shim Engine | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `sysmain\.sdb`` | **Cause:** AppCompat |
| **441** | Stack Overflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Recursion` | **Cause:** Recursion loop |
| **447** | GDI Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Graphics leak |
| **449** | Thread Create | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Parallelism |
| **546** | SvcHost Split | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``svchost\.exe\ \-k\ netsvcs`\ High\ CPU` | **Cause:** Stability |
| **548** | SvcHost Split | **Op:** `*`<br>**Res:** `*`<br>**Path:** `svchost\.exe\ \-k\ RpcSs` | **Cause:** Stability |
| **549** | SvcHost Split | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``svchost\.exe\ \-k\ LocalService`\ High\ CPU` | **Cause:** Stability |
| **550** | SvcHost Split | **Op:** `*`<br>**Res:** `*`<br>**Path:** `svchost\.exe\ \-k\ NetworkService` | **Cause:** Stability |
| **595** | Commit Limit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000012D` | **Cause:** RAM/Pagefile full |
| **721** | Shim Engine | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vbscript\.dll` | **Cause:** AppCompat |
| **722** | Shim Engine | **Op:** `*`<br>**Res:** `*`<br>**Path:** `jscript\.dll` | **Cause:** AppCompat |
| **777** | Thread Create | **Op:** `*`<br>**Res:** `*`<br>**Path:** `High\ context\ switch\ rate\.` | **Cause:** Parallelism |
| **799** | Process Exit (Hard) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Paging\ from\ disk\.` | **Cause:** Stack Buffer Overrun |
| **800** | Working Set Trim | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RAM\ trimming\.` | **Cause:** Memory reclaiming |
| **815** | TerminateProcess | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Kill\.` | **Cause:** Watchdog/User kill |
| **861** | OpenProcess (Mem) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``sqlservr\.exe`\ Mem\ limit` | **Cause:** Debug/Hack |
| **903** | Dr Watson | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Watson` | **Cause:** Legacy crash |
| **1012** | WerFault Trigger | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WerFault\.exe` | **Cause:** Crash reporting |
| **1067** | Debug Active | **Op:** `OpenProcess`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Anti-debug |
| **1110** | Image Load Fail (Sign) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``ssonsvr\.exe`\ fail` | **Cause:** Unsigned binary |
| **1113** | Inject Library | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Global injection |
| **1156** | Debug Active | **Op:** `CreateFile`<br>**Res:** `SUCCESS`<br>**Path:** `lmhosts` | **Cause:** Anti-debug |
| **1266** | Self-Deletion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Installer/Malware |
| **1433** | Commit Limit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** RAM/Pagefile full |
| **1453** | WerFault Trigger | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Crash reporting |
| **1479** | Inject Library | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Folder type = Pictures` | **Cause:** Global injection |
| **1493** | Job Object Assign | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GDI Objects = 10,000` | **Cause:** Resource limit |

## Module 20: Security Boundaries & Integrity

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **124** | Token Primary Group Modification | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ImpersonateLoggedOnUser` | **Cause:** App trying to change its primary group to something not in its token (Exploit or bad code). |
| **125** | Token Primary Group Modification | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AdjustTokenPrivileges` | **Cause:** App trying to change its primary group to something not in its token (Exploit or bad code). |
| **144** | Integrity Level (UIPI) Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** User Interface Privilege Isolation (UIPI) prevents lower-privileged apps from driving higher-privileged ones. |
| **391** | Token Primary Group Modification | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TokenBroker` | **Cause:** App trying to change its primary group to something not in its token (Exploit or bad code). |
| **780** | Integrity Level (UIPI) Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Low\ IL\ write\ to\ Medium\ IL\ fail\.` | **Cause:** User Interface Privilege Isolation (UIPI) prevents lower-privileged apps from driving higher-privileged ones. |
| **1257** | Token Primary Group Modification | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** App trying to change its primary group to something not in its token (Exploit or bad code). |

## Module 18: DLL Hell & Loading Issues (Advanced)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **141** | Delay-Load Import Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The DLL is "Delay Loaded" (only loaded when needed). It was missing all along, but the app didn't check at startup. |
| **191** | Delay-Load Import Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ws2_32\.dll` | **Cause:** The DLL is "Delay Loaded" (only loaded when needed). It was missing all along, but the app didn't check at startup. |
| **301** | Delay-Load Import Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mscoree\.dll`\ load` | **Cause:** The DLL is "Delay Loaded" (only loaded when needed). It was missing all along, but the app didn't check at startup. |
| **302** | Delay-Load Import Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `C:\\Windows\\Assembly` | **Cause:** The DLL is "Delay Loaded" (only loaded when needed). It was missing all along, but the app didn't check at startup. |
| **312** | Delay-Load Import Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `__init__\.py`` | **Cause:** The DLL is "Delay Loaded" (only loaded when needed). It was missing all along, but the app didn't check at startup. |
| **444** | Loader Lock Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A DLL attempted to spawn a thread or call a dangerous API inside its entry point (`DllMain`), triggering the OS Loader Lock. |
| **650** | Delay-Load Import Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `pepflashplayer` | **Cause:** The DLL is "Delay Loaded" (only loaded when needed). It was missing all along, but the app didn't check at startup. |
| **890** | Delay-Load Import Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ffmpeg\.dll` | **Cause:** The DLL is "Delay Loaded" (only loaded when needed). It was missing all along, but the app didn't check at startup. |
| **1015** | Loader Lock Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `App\ exits\ before\ `Main\(\)`\.\ `LdrInitializeThunk`\ fail` | **Cause:** A DLL attempted to spawn a thread or call a dangerous API inside its entry point (`DllMain`), triggering the OS Loader Lock. |
| **1075** | KnownDLLs Exclusion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `KnownDLLs` | **Cause:** Malware or a hacked app trying to bypass the `KnownDLLs` registry list to load a hijacked system library. |
| **1215** | Loader Lock Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A DLL attempted to spawn a thread or call a dangerous API inside its entry point (`DllMain`), triggering the OS Loader Lock. |

## SECTION 4: NETWORK STACK (TCP/IP & RPC)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **152** | TCP Connect (Success) | **Op:** `*`<br>**Res:** `CONNECTION\ REFUSED`<br>**Path:** `*` | **Cause:** Connected |
| **154** | TCP Connect (Success) | **Op:** `*`<br>**Res:** `NETWORK\ UNREACHABLE`<br>**Path:** `*` | **Cause:** Connected |
| **155** | TCP Connect (Success) | **Op:** `*`<br>**Res:** `ADDRESS\ ALREADY\ ASSOCIATED`<br>**Path:** `*` | **Cause:** Connected |
| **156** | TCP Reconnect | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Flapping |
| **157** | TCP Disconnect (Reset) | **Op:** `*`<br>**Res:** `ECONNRESET`<br>**Path:** `*` | **Cause:** Force close |
| **158** | TCP Reconnect | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Flapping |
| **160** | UDP Receive | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Listener active |
| **161** | DNS Query (A) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** IPv4 |
| **162** | DNS Query (A) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** IPv4 |
| **167** | Multicast Join | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Streaming/Cluster |
| **168** | IPv6 Failover | **Op:** `*`<br>**Res:** `SUCCESS`<br>**Path:** `*` | **Cause:** Protocol lag |
| **178** | High Ports | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Client/RPC |
| **182** | SMBv1 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Security risk |
| **183** | SMBv3 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Modern/Encryption |
| **184** | RPC Bind | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** DCOM start |
| **188** | Mail Slot | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\mailslot\\browse`` | **Cause:** Browser election |
| **192** | LSP Injection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Interference |
| **194** | Teredo/Isatap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** IPv6 transition |
| **195** | TCP Connect (Success) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `127\.0\.0\.1` | **Cause:** Connected |
| **196** | Link Local | **Op:** `*`<br>**Res:** `*`<br>**Path:** `169\.254\.x\.x` | **Cause:** DHCP fail |
| **197** | Private IP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `192\.168\.x` | **Cause:** Internal |
| **198** | Private IP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Internal |
| **257** | LSP Injection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AppInit_DLLs` | **Cause:** Interference |
| **282** | Private IP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ipconfig /all` | **Cause:** Internal |
| **293** | DNS Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Typo/Missing record |
| **295** | Tor Ports | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Suspicious |
| **297** | SSH Active | **Op:** `*`<br>**Res:** `*`<br>**Path:** `id_rsa` | **Cause:** Admin/Tunnel |
| **300** | FTP Active | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ftp -s` | **Cause:** Data exfil/Legacy |
| **338** | TCP Disconnect (Reset) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `dxgkrnl` | **Cause:** Force close |
| **374** | Mail Slot | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `mapi32\.dll`` | **Cause:** Browser election |
| **376** | Cert Revocation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SystemCertificates` | **Cause:** SSL check |
| **392** | Multicast Join | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WorkplaceJoin` | **Cause:** Streaming/Cluster |
| **593** | TCP Connect (Refused) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000236` | **Cause:** Port closed/Blocked |
| **594** | TCP Connect (AddrInUse) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000020A` | **Cause:** Port exhaustion |
| **618** | RPC Bind | **Op:** `TCP\ Connect`<br>**Res:** `*`<br>**Path:** `outlook\.office365\.com` | **Cause:** DCOM start |
| **632** | Link Local | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Local State` | **Cause:** DHCP fail |
| **653** | TCP Reconnect | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``tcpip\.sys`\ activity` | **Cause:** Flapping |
| **683** | DNS Query (A) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** IPv4 |
| **684** | UDP Send (Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Delivery fail |
| **692** | RPC Bind | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** DCOM start |
| **706** | Teredo/Isatap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** IPv6 transition |
| **789** | LSP Injection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Network\ filter\ blocking\.` | **Cause:** Interference |
| **872** | SSH Active | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ssh-agent` | **Cause:** Admin/Tunnel |
| **965** | Multicast Join | **Op:** `*`<br>**Res:** `*`<br>**Path:** `UDP\ 224\.x\.x\.x` | **Cause:** Streaming/Cluster |
| **973** | UDP Send (Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Delivery fail |
| **1057** | LSP Injection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SendInput` | **Cause:** Interference |
| **1126** | RPC Bind | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RpcEpMap` | **Cause:** DCOM start |
| **1152** | LSP Injection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Interference |
| **1422** | IPv6 Failover | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Protocol lag |
| **1438** | Link Local | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** DHCP fail |

## Module 16: Graphics, Fonts & Desktop Window Manager

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **153** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **164** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **209** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **227** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ccmcache` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **314** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GPUCache` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **322** | Missing EUDC (End User Defined Character) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Software\\ODBC` | **Cause:** Missing custom font linking (common in Asian language locales). |
| **405** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Code Cache` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **415** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Cache` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **420** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `_cacache` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **443** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **448** | Missing EUDC (End User Defined Character) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Missing custom font linking (common in Asian language locales). |
| **499** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `D3DSCache` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **513** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `TIMEOUT`<br>**Path:** `*` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **518** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell\ Icons`` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **588** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC00000B5` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **624** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.bin` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **643** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Cache_Data` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **790** | Missing EUDC (End User Defined Character) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Context\ of\ operation\.` | **Cause:** Missing custom font linking (common in Asian language locales). |
| **857** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `content_cache` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **878** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `pip` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **882** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `AdobeFnt\.lst`` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **893** | DWM Redirection Surface Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``MixedRealityPortal\.exe`` | **Cause:** A graphics driver leak causing the Desktop Window Manager to run out of memory (black screen/flicker). |
| **941** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AddFontResource` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **942** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CreateFontIndirect` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **943** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FontLink` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **944** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FontSubstitutes` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **945** | Missing EUDC (End User Defined Character) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `EUDC\.TE`` | **Cause:** Missing custom font linking (common in Asian language locales). |
| **949** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FNTCACHE\.DAT` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **950** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.pfm` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **1017** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Exit 0` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **1022** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WM_GETOBJECT` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **1039** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetText` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **1080** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FontSubstitutes` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **1101** | DWM Redirection Surface Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `tsusbhub\.sys` | **Cause:** A graphics driver leak causing the Desktop Window Manager to run out of memory (black screen/flicker). |
| **1131** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **1151** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **1160** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `NAME NOT FOUND`<br>**Path:** `wpad` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **1170** | Missing EUDC (End User Defined Character) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Missing custom font linking (common in Asian language locales). |
| **1224** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **1241** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `NAME_NOT_FOUND`<br>**Path:** `*` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **1267** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **1276** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **1277** | Missing EUDC (End User Defined Character) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Missing custom font linking (common in Asian language locales). |
| **1352** | Font Cache Service Thrashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop. |
| **1392** | Missing EUDC (End User Defined Character) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Missing custom font linking (common in Asian language locales). |
| **1429** | TDR (Timeout Detection and Recovery) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze. |
| **1477** | DWM Redirection Surface Leak | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `User Shell Folders.*OneDrive` | **Cause:** A graphics driver leak causing the Desktop Window Manager to run out of memory (black screen/flicker). |

## Module 21: Hardware & Power

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **177** | High Performance Timer Drift | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** BIOS/HAL issue with High Precision Event Timer (HPET). Causes gaming stutters/audio desync. |
| **333** | USB Selective Suspend Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Windows puts USB device to sleep; device wakes up immediately. Driver incompatibility. |
| **339** | Thermal Throttling Events | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** CPU speed capped by firmware due to overheating. |
| **355** | High Performance Timer Drift | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetSysColor` | **Cause:** BIOS/HAL issue with High Precision Event Timer (HPET). Causes gaming stutters/audio desync. |
| **455** | Thermal Throttling Events | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.evtx` | **Cause:** CPU speed capped by firmware due to overheating. |
| **794** | High Performance Timer Drift | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Timer\ resolution\ change\.` | **Cause:** BIOS/HAL issue with High Precision Event Timer (HPET). Causes gaming stutters/audio desync. |
| **1006** | Thermal Throttling Events | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** CPU speed capped by firmware due to overheating. |
| **1060** | High Performance Timer Drift | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetScaleFactorForMonitor` | **Cause:** BIOS/HAL issue with High Precision Event Timer (HPET). Causes gaming stutters/audio desync. |
| **1220** | High Performance Timer Drift | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** BIOS/HAL issue with High Precision Event Timer (HPET). Causes gaming stutters/audio desync. |
| **1370** | USB Selective Suspend Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Windows puts USB device to sleep; device wakes up immediately. Driver incompatibility. |
| **1455** | Thermal Throttling Events | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** CPU speed capped by firmware due to overheating. |
| **1456** | High Performance Timer Drift | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** BIOS/HAL issue with High Precision Event Timer (HPET). Causes gaming stutters/audio desync. |
| **1487** | High Performance Timer Drift | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Clock loses 10 mins per day` | **Cause:** BIOS/HAL issue with High Precision Event Timer (HPET). Causes gaming stutters/audio desync. |

## SECTION 5: ENTERPRISE INFRA (AD, GPO, VDI)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **213** | DFS Referral | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\\\\Domain\\DFS` | **Cause:** Namespace |
| **224** | VMware Tools | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vmtoolsd` | **Cause:** Guest agent |
| **225** | WEM Agent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Norskale` | **Cause:** Environment mgmt |
| **226** | WEM Agent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CcmExec` | **Cause:** Environment mgmt |
| **228** | Intune Mgmt | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Omadmclient` | **Cause:** MDM sync |
| **325** | GPO Read Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.udl` | **Cause:** Policy fail |
| **357** | Citrix Hook | **Op:** `*`<br>**Res:** `*`<br>**Path:** `NarratorHook` | **Cause:** VDI hook |
| **427** | WEM Agent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `QualysAgent` | **Cause:** Environment mgmt |
| **431** | WEM Agent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VeeamAgent` | **Cause:** Environment mgmt |
| **492** | Citrix Hook | **Op:** `*`<br>**Res:** `*`<br>**Path:** `graphics-hook` | **Cause:** VDI hook |
| **520** | Group Policy Printer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCU\\Printers`` | **Cause:** Mapping fail |
| **676** | VMware Tools | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vmmouse\.sys` | **Cause:** Guest agent |
| **677** | VMware Tools | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vm3dmp\.sys` | **Cause:** Guest agent |
| **685** | LDAP Timeout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Slow AD |
| **700** | VMware Tools | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Guest agent |
| **761** | SCCM Agent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `ccmsetup\.log`` | **Cause:** Mgmt agent |
| **762** | Intune Mgmt | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `IntuneManagementExtension\.log`` | **Cause:** MDM sync |
| **915** | Print Spooler Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `EasyPrint` | **Cause:** Print kill |
| **927** | GPO Read Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `BackupRead` | **Cause:** Policy fail |
| **931** | Print Spooler Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `winprint\.dll`` | **Cause:** Print kill |
| **932** | Print Spooler Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `usbmon\.dll` | **Cause:** Print kill |
| **933** | Print Spooler Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `pjlmon\.dll`` | **Cause:** Print kill |
| **934** | Print Spooler Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `tcpmon\.dll` | **Cause:** Print kill |
| **935** | Print Spooler Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Forms` | **Cause:** Print kill |
| **936** | Print Spooler Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ColorProfiles` | **Cause:** Print kill |
| **937** | Print Spooler Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Separator` | **Cause:** Print kill |
| **940** | Print Spooler Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.shd` | **Cause:** Print kill |
| **1102** | Folder Redir Offline | **Op:** `*`<br>**Res:** `*`<br>**Path:** `scard\.dll` | **Cause:** Sync fail |

## SECTION 6: INSTALLERS & UPDATES (MSI, WU)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **234** | MSI Rollback | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SetRename` | **Cause:** Fatal error |
| **238** | MSI Rollback | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\.mst`\ missing` | **Cause:** Fatal error |
| **245** | TiWorker CPU | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TiWorker` | **Cause:** Post-install |
| **247** | Bled/Hydrate | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** AppX |
| **249** | AppX Manifest | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AppXDeploymentServer` | **Cause:** Store App |
| **453** | CBS Manifest | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `cbs\.log`` | **Cause:** Corrupt OS |
| **456** | State Repo | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `Index\.btr`` | **Cause:** Store DB lock |
| **487** | Driver Store | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.mp4` | **Cause:** Driver staging |
| **754** | Windows Update Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WindowsUpdate\.log` | **Cause:** DB lock |
| **755** | MSI Rollback | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `MSI.*\.log`` | **Cause:** Fatal error |
| **879** | State Repo | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `\.m2`` | **Cause:** Store DB lock |
| **1168** | Windows Update Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** DB lock |
| **1326** | MSI Rollback | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Fatal error |

## Module 14: Modern Apps (UWP/AppX) & Store

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **250** | StateRepository Database Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `StateRepository` | **Cause:** The SQLite database tracking AppX apps is corrupt or locked, breaking the Start Menu and all Store apps. |
| **1146** | Push Notification Registration Fail | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `TrayNotify` | **Cause:** App cannot register for Live Tiles/Toasts due to firewall or registry permissions. |

## Module 24: Scripting & Automation

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **263** | PowerShell Execution Policy Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `powershell -e` | **Cause:** Policy set to `Restricted` or `AllSigned`. |
| **264** | PowerShell Execution Policy Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Net\.WebClient`` | **Cause:** Policy set to `Restricted` or `AllSigned`. |
| **470** | PowerShell Execution Policy Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `powershell\.exe` | **Cause:** Policy set to `Restricted` or `AllSigned`. |

## SECTION 8: APPLICATION FRAMEWORKS (Java, .NET, Web)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **307** | Java Home | **Op:** `*`<br>**Res:** `*`<br>**Path:** `JAVA_HOME` | **Cause:** Config |
| **308** | Java Home | **Op:** `*`<br>**Res:** `*`<br>**Path:** `jvm\.dll` | **Cause:** Config |
| **309** | Java Home | **Op:** `*`<br>**Res:** `*`<br>**Path:** `lib/ext` | **Cause:** Config |
| **313** | Node Modules | **Op:** `*`<br>**Res:** `*`<br>**Path:** `node_modules` | **Cause:** JS dep |
| **320** | Oracle TNS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `tnsnames\.ora`` | **Cause:** DB Config |
| **324** | OLEDB Reg | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCR\\CLSID\\\{Provider\}`` | **Cause:** Driver |
| **326** | Report Viewer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Microsoft\.ReportViewer` | **Cause:** Reporting |
| **327** | Crystal Reports | **Op:** `*`<br>**Res:** `*`<br>**Path:** `crpe32\.dll` | **Cause:** Reporting |
| **328** | Flash OCX | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Flash\.ocx` | **Cause:** Legacy |
| **329** | Silverlight | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `npctrl\.dll`` | **Cause:** Legacy |
| **330** | ActiveX Killbit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Compatibility Flags` | **Cause:** Block |
| **366** | Java Runtime | **Op:** `*`<br>**Res:** `*`<br>**Path:** `msvbvm60\.dll` | **Cause:** Java start |
| **468** | OLEDB Reg | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``regedit\.exe`` | **Cause:** Driver |
| **747** | Report Viewer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Report\.wer` | **Cause:** Reporting |
| **759** | SQL Driver | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `Summary\.txt`` | **Cause:** Connectivity |
| **760** | IIS Worker | **Op:** `*`<br>**Res:** `*`<br>**Path:** `iis\.log` | **Cause:** Web server |
| **864** | SQL Driver | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `sqlvia\.dll`` | **Cause:** Connectivity |
| **866** | Oracle TNS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `oci\.dll` | **Cause:** DB Config |
| **867** | Java Home | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ojdbc\.jar` | **Cause:** Config |
| **899** | Java Runtime | **Op:** `*`<br>**Res:** `*`<br>**Path:** `LibOVRRT` | **Cause:** Java start |
| **1026** | Java Home | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WindowsAccessBridge\-32\.dll` | **Cause:** Config |
| **1097** | Flash OCX | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MacromediaFlash` | **Cause:** Legacy |

## SECTION 9: HARDWARE & DRIVERS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **334** | HID Input | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HidUsb` | **Cause:** Keyboard/Mouse |
| **336** | SmartCard Insert | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SCardSvr` | **Cause:** Auth |
| **350** | BIOS Info | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Hardwaredescription\\System` | **Cause:** Firmware |
| **396** | BIOS Info | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Tenants` | **Cause:** Firmware |
| **635** | GPU Reset | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GpuProcess` | **Cause:** Crash |
| **661** | HID Input | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``hidclass\.sys`\ activity` | **Cause:** Keyboard/Mouse |
| **976** | Scanner Twain | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Imaging |
| **1180** | GPU Reset | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Crash |
| **1481** | Battery Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Date is Jan 1, 1980 on boot` | **Cause:** Power |

## Module 12: The Print Spooler & Drivers

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **343** | Bidirectional (BiDi) Extension Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** The driver is waiting for status (Ink Level/Paper) from an offline printer. **Fix:** Disable "Enable Bidirectional Support". |
| **363** | Splwow64 Thunking Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `wow64\.dll`` | **Cause:** The translation layer between 32-bit apps and the 64-bit spooler is deadlocked. |
| **476** | Driver Isolation Host Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``wslhost\.exe`` | **Cause:** A buggy printer driver is crashing. Because it's "Isolated" (Shared or Sandbox mode), it kills the host process, not the spooler, but printing stops. |
| **592** | Driver Isolation Host Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000023D` | **Cause:** A buggy printer driver is crashing. Because it's "Isolated" (Shared or Sandbox mode), it kills the host process, not the spooler, but printing stops. |

## SECTION 10: ACCESSIBILITY & UI

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **352** | WM_GETOBJECT | **Op:** `*`<br>**Res:** `TIMEOUT`<br>**Path:** `*` | **Cause:** No response |
| **354** | Focus Fight | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SetFocus` | **Cause:** Loop |
| **356** | Cursor Track | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetGUIThreadInfo` | **Cause:** Visual |
| **360** | Speech Dict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Voice |
| **1099** | High Contrast | **Op:** `*`<br>**Res:** `*`<br>**Path:** `@media(forced-colors)` | **Cause:** Theme |
| **1340** | Focus Fight | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Loop |
| **1344** | Focus Fight | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `NOC_GLOBAL_SETTING_TOASTS_ENABLED` | **Cause:** Loop |
| **1470** | Focus Fight | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Loop |

## SECTION 11: LEGACY & COMPATIBILITY

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **362** | 16-bit App | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `ntvdm\.exe`` | **Cause:** DOS |
| **365** | DirectX 9 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `d3d9\.dll` | **Cause:** Old Gfx |
| **367** | MFC 42 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mfc42\.dll` | **Cause:** C++ |
| **369** | Hardcoded Drv | **Op:** `*`<br>**Res:** `*`<br>**Path:** `D:\\` | **Cause:** Missing drive |
| **372** | Deprecated API | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WinExec` | **Cause:** Old code |
| **375** | NetDDE | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Ancient IPC |
| **756** | DirectX 9 | **Op:** `*`<br>**Res:** `DXError\.log`<br>**Path:** `*` | **Cause:** Old Gfx |

## SECTION 12: CRYPTOGRAPHY & PKI

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **378** | CRL Fetch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HTTP\ fetch\ `\.crl`` | **Cause:** Revocation |
| **381** | Expired | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CERT_E_EXPIRED` | **Cause:** Date |
| **384** | UserKey | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Protect` | **Cause:** Private key |
| **385** | DPAPI | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CryptUnprotectData` | **Cause:** Decryption |
| **457** | Catalog DB | **Op:** `*`<br>**Res:** `*`<br>**Path:** `srudb\.dat` | **Cause:** Sig DB |
| **647** | CRL Fetch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Revocation |
| **745** | Catalog DB | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `Windows\.edb`` | **Cause:** Sig DB |

## SECTION 13: CLOUD & HYBRID (Azure/M365)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **394** | M365 Activate | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Connect\ `office\.com`` | **Cause:** Licensing |
| **398** | Entra ID | **Op:** `*`<br>**Res:** `*`<br>**Path:** `dsregcmd` | **Cause:** Join status |
| **399** | Compliance | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HealthAttestation` | **Cause:** Security |
| **400** | Telemetry | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CompatTelRunner` | **Cause:** Diag data |
| **627** | Telemetry | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mso\.dll` | **Cause:** Diag data |
| **852** | OneDrive Sync | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Status` | **Cause:** Cloud file |
| **1374** | Ngc Key | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hello for Bus |

## SECTION 14: SPECIFIC SOFTWARE PATTERNS (The "Top Hitters")

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **402** | Chrome Profile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Extensions` | **Cause:** Stuck |
| **406** | Teams Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `logs\.txt` | **Cause:** Performance |
| **407** | Outlook OST | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.ost` | **Cause:** Disk IO |
| **408** | Outlook OST | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Offline Address Books` | **Cause:** Disk IO |
| **409** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `\.xll`` | **Cause:** Extension |
| **410** | Word Template | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Normal\.dotm` | **Cause:** Config |
| **411** | Adobe Reader | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AcroRd32\.dll` | **Cause:** PDF |
| **412** | Adobe Reader | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``AdobeARM\.exe`` | **Cause:** PDF |
| **413** | Zoom Cpt | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``CptHost\.exe`` | **Cause:** Sharing |
| **416** | VSCode IPC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vscode-ipc` | **Cause:** Dev |
| **418** | Kubernetes | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.kube` | **Cause:** Config |
| **423** | CrowdStrike | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CSFalconService` | **Cause:** EDR |
| **424** | SentinelOne | **Op:** `*`<br>**Res:** `*`<br>**Path:** `LogProcessor` | **Cause:** EDR |
| **425** | Splunk Fwd | **Op:** `*`<br>**Res:** `*`<br>**Path:** `splunk-optimize` | **Cause:** Log |
| **426** | Tanium Client | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TaniumClient` | **Cause:** Mgmt |
| **429** | Datadog | **Op:** `*`<br>**Res:** `*`<br>**Path:** `datadog-agent` | **Cause:** Monitor |
| **430** | NewRelic | **Op:** `*`<br>**Res:** `*`<br>**Path:** `newrelic-infra` | **Cause:** Monitor |
| **432** | Commvault | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ClMgrS` | **Cause:** Backup |
| **434** | Dropbox Watch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Dropbox` | **Cause:** Sync |
| **451** | Teams Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `ntbtlog\.txt`` | **Cause:** Diag |
| **452** | Teams Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `setupapi\.dev\.log` | **Cause:** Diag |
| **454** | Teams Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `dism\.log`` | **Cause:** Diag |
| **611** | Word Template | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Normal\.dotm` | **Cause:** Config |
| **612** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.wll` | **Cause:** Extension |
| **613** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `High\ CPU\ `EXCEL\.EXE`` | **Cause:** Extension |
| **614** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Splwow64` | **Cause:** Extension |
| **615** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.xla` | **Cause:** Extension |
| **616** | Outlook OST | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.ost` | **Cause:** Disk IO |
| **617** | Outlook OST | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SearchProtocolHost` | **Cause:** Disk IO |
| **619** | Outlook OST | **Op:** `*`<br>**Res:** `*`<br>**Path:** `autodiscover\.xml` | **Cause:** Disk IO |
| **620** | Outlook OST | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `outlvba\.dll`` | **Cause:** Disk IO |
| **628** | Teams Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ub_` | **Cause:** Performance |
| **629** | Teams Cache | **Op:** `UDP\ Send`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Performance |
| **631** | Chrome Profile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Preferences` | **Cause:** Stuck |
| **634** | Chrome Profile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `manifest\.json`\ fail` | **Cause:** Stuck |
| **636** | Chrome Profile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Renderer` | **Cause:** Stuck |
| **637** | Chrome Profile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Broker` | **Cause:** Stuck |
| **640** | Edge Update | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``msedgewebview2\.exe`\ crash` | **Cause:** Patch |
| **671** | CrowdStrike | **Op:** `*`<br>**Res:** `*`<br>**Path:** `csagent\.sys` | **Cause:** EDR |
| **672** | SentinelOne | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``SentinelMonitor\.sys`` | **Cause:** EDR |
| **842** | Docker Pipe | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``dockerd\.exe`\ fail` | **Cause:** Container |
| **855** | Dropbox Watch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `\.dropboxignore`` | **Cause:** Sync |
| **858** | Box Sync | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Box Drive` | **Cause:** Sync |
| **873** | Chrome Ext | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `extensions\.json`` | **Cause:** Add-on |
| **881** | Adobe Reader | **Op:** `*`<br>**Res:** `DISK\ FULL`<br>**Path:** `*` | **Cause:** PDF |
| **883** | Adobe Reader | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AdobeIPCBroker` | **Cause:** PDF |
| **926** | Veeam Agent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VeeamTransport` | **Cause:** Backup |
| **963** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Extension |
| **964** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Extension |
| **1028** | Adobe Reader | **Op:** `*`<br>**Res:** `*`<br>**Path:** `structTreeRoot` | **Cause:** PDF |
| **1100** | Zoom Cpt | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Text\ overlaps\ at\ 200%` | **Cause:** Sharing |
| **1127** | Tanium Client | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``winspool\.drv`\ heavy\ CPU` | **Cause:** Mgmt |
| **1185** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Extension |
| **1191** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Extension |
| **1260** | Dropbox Watch | **Proc:** `Dropbox\.exe` <br>**Op:** `*`<br>**Res:** `ACCESS_DENIED`<br>**Path:** `\.dropbox\.cache` | **Cause:** Sync |
| **1299** | Outlook OST | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disk IO |
| **1376** | Chrome Profile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Stuck |
| **1377** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Extension |
| **1378** | Zoom Cpt | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Sharing |

## SECTION 15: ADVANCED MEMORY & DEBUGGING

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **437** | Double Free | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Crash |
| **438** | Double Free | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Crash |
| **439** | Null Pointer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bug |
| **600** | Handle Invalid | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000000D` | **Cause:** Logic |
| **885** | Use After Free | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AfterFX\.exe` | **Cause:** Exploit |
| **1037** | Null Pointer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AutomationId` | **Cause:** Bug |
| **1116** | Memory Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `NtReadVirtualMemory` | **Cause:** Leak |
| **1232** | Memory Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Leak |
| **1293** | Thread Count | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Spam |

## SECTION 16: SYSTEM CONFIGURATION & BOOT

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **458** | Prefetch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `\.pf`` | **Cause:** Optimize |
| **459** | Superfetch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SysMain` | **Cause:** Cache |
| **460** | Search Index | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SearchIndexer` | **Cause:** Index |
| **461** | Cortana | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SearchUI` | **Cause:** Shell |
| **466** | Resource Mon | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Perfmon` | **Cause:** Admin |
| **471** | Run Dialog | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``explorer\.exe`\ Run` | **Cause:** Shell |
| **472** | LogonUI | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``LogonUI\.exe`` | **Cause:** Auth |
| **473** | WinInit | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``wininit\.exe`` | **Cause:** Boot |
| **474** | LSM | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``lsm\.exe`` | **Cause:** Session |
| **475** | Smss | **Op:** `*`<br>**Res:** `*`<br>**Path:** `smss\.exe` | **Cause:** Session |
| **724** | Settings App | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Exec\ `\.hta`` | **Cause:** Config |
| **753** | DISM Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `dism\.log`` | **Cause:** Image |
| **773** | Search Index | **Op:** `*`<br>**Res:** `*`<br>**Path:** `evil\.dll` | **Cause:** Index |
| **898** | Setup Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `chaperone` | **Cause:** Driver |
| **1367** | Start Menu | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** UI |
| **1369** | Search Index | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Index |

## SECTION 17: WINDOWS SUBSYSTEM FOR LINUX (WSL)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **480** | Plan 9 FS | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``p9rdr\.sys`` | **Cause:** Filesystem |
| **482** | Linux Binary | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Compat |
| **484** | WSL Host | **Op:** `*`<br>**Res:** `*`<br>**Path:** `drvfs` | **Cause:** Kernel |
| **485** | WSL2 VHD | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ext4\.vhdx` | **Cause:** Disk |

## SECTION 18: GAMING & MEDIA (DirectX/Audio)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **488** | Steam Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SteamService` | **Cause:** Platform |
| **489** | Steam Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `EpicGamesLauncher` | **Cause:** Platform |
| **490** | Steam Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Origin` | **Cause:** Platform |
| **491** | Discord Overlay | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Discord` | **Cause:** Hook |
| **493** | XInput | **Op:** `*`<br>**Res:** `*`<br>**Path:** `xinput` | **Cause:** Controller |
| **494** | DirectInput | **Op:** `*`<br>**Res:** `*`<br>**Path:** `dinput` | **Cause:** Controller |
| **495** | Vulkan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vulkan\-1\.dll` | **Cause:** Graphics |
| **496** | OpenGL | **Op:** `*`<br>**Res:** `*`<br>**Path:** `opengl32\.dll` | **Cause:** Graphics |
| **497** | OpenCL | **Op:** `*`<br>**Res:** `*`<br>**Path:** `OpenCL\.dll` | **Cause:** Compute |
| **498** | PhysX | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PhysX` | **Cause:** Physics |
| **500** | Refresh Rate | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ChangeDisplaySettings` | **Cause:** Hz |
| **704** | Steam Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Platform |
| **910** | Steam Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ClientLicense` | **Cause:** Platform |
| **919** | Steam Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `lserver\.exe` | **Cause:** Platform |
| **971** | Epic Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Hyperspace\.exe`` | **Cause:** Platform |
| **1046** | Discord Overlay | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Magnification\.dll`\ init\ fail` | **Cause:** Hook |
| **1098** | Refresh Rate | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hz |
| **1120** | Discord Overlay | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hook |
| **1410** | Game Mode | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Overlay |
| **1420** | Refresh Rate | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hz |

## SECTION 20: WINDOWS SERVICES (Specific Detection)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **555** | TrustedInstall | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TrustedInstaller\.exe` | **Cause:** Update |
| **901** | DiagTrack Busy | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``CompatTelRunner\.exe`` | **Cause:** Telemetry |

## SECTION 22: ERROR CODES (NTSTATUS / WIN32)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **585** | Privilege | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000061` | **Cause:** Elevation req |
| **597** | Cancel | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000120` | **Cause:** User abort |
| **599** | Not Found | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000002` | **Cause:** Missing |
| **604** | Ordinal | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000138` | **Cause:** Export fail |
| **605** | SideBySide | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000365` | **Cause:** Manifest |
| **606** | Hashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000428` | **Cause:** Signature |
| **819** | Privilege | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Elevate\.` | **Cause:** Elevation req |
| **838** | Directory | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Watcher\.` | **Cause:** Is not dir |
| **1045** | Privilege | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Elevation req |

## SECTION 23: OFFICE & PRODUCTIVITY (Specifics)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **623** | PowerPoint Media | **Op:** `*`<br>**Res:** `*`<br>**Path:** `pflash\.dll` | **Cause:** Flash |
| **630** | Teams Mtg | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``lync\.exe`\ activity` | **Cause:** Media |
| **956** | Office License | **Op:** `*`<br>**Res:** `*`<br>**Path:** `lmgrd\.exe` | **Cause:** Activation |

## SECTION 24: BROWSER INTERNALS (Chrome/Edge)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **648** | QUIC Proto | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Google Net |
| **649** | WebRTC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Media |

## SECTION 25: DRIVERS & KERNEL MODULES (.SYS)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **654** | NetBIOS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `netbt\.sys` | **Cause:** Legacy |
| **658** | Storport | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``storport\.sys`\ activity` | **Cause:** SAN |
| **662** | HID Class | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mouclass\.sys`\ activity` | **Cause:** Input |
| **663** | HID Class | **Op:** `*`<br>**Res:** `*`<br>**Path:** `kbdclass\.sys` | **Cause:** Input |
| **664** | Graphics | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``dxgkrnl\.sys`\ activity` | **Cause:** GPU |
| **665** | Nvidia | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``nvlddmkm\.sys`\ activity` | **Cause:** GPU |
| **667** | Intel Gfx | **Op:** `*`<br>**Res:** `*`<br>**Path:** `igdkmd64\.sys` | **Cause:** GPU |
| **673** | CarbonBlack | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``cbk7\.sys`` | **Cause:** EDR |
| **674** | Sysmon | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``SysmonDrv\.sys`` | **Cause:** Log |
| **675** | ProcMon | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PROCMON24\.SYS` | **Cause:** Self |
| **695** | NetBIOS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Legacy |
| **1346** | Mouse Class | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Input |
| **1348** | Intel Gfx | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** GPU |
| **1408** | Mouse Class | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Input |

## SECTION 26: NETWORK PROTOCOLS (Expanded)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **681** | DHCP Renew | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** IP |
| **687** | LDAP SSL | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Auth |
| **691** | WinRM HTTP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Mgmt |
| **696** | SMB Direct | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** File |
| **697** | VNC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Remote |
| **701** | PCoIP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** VDI |
| **702** | BitTorrent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** P2P |
| **703** | Spotify | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Media |
| **705** | Xbox Live | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Game |
| **707** | LLMNR | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Local DNS |
| **708** | SSDP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** UPnP |
| **710** | mDNS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bonjour |
| **891** | Steam | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``vrserver\.exe`` | **Cause:** Game |
| **1025** | Xbox Live | **Op:** `*`<br>**Res:** `*`<br>**Path:** `EVENT_OBJECT_LIVEREGIONCHANGED` | **Cause:** Game |

## SECTION 27: POWERSHELL & SCRIPTING (Expanded)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **711** | PS Version | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PowerShellVersion` | **Cause:** Compat |
| **712** | PS Version | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PSModulePath` | **Cause:** Compat |
| **716** | PS Version | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `Transcript\.txt`` | **Cause:** Compat |
| **717** | PS Version | **Op:** `*`<br>**Res:** `*`<br>**Path:** `powershellgallery\.com` | **Cause:** Compat |
| **718** | PS Version | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wsman` | **Cause:** Compat |
| **719** | PS Version | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ConstrainedLanguage` | **Cause:** Compat |
| **720** | PS Version | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ScriptBlockLogging` | **Cause:** Compat |

## SECTION 28: FORENSICS & ARTIFACTS (Filesystem)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **732** | Recent Docs | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Recent` | **Cause:** Access |
| **733** | JumpList | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AutomaticDestinations` | **Cause:** Access |
| **734** | ShellBag | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Shell\\Bags` | **Cause:** Folder view |
| **735** | UserAssist | **Op:** `*`<br>**Res:** `*`<br>**Path:** `UserAssist` | **Cause:** Exec count |
| **736** | ShimCache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AppCompatCache` | **Cause:** Compat |
| **737** | Amcache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Amcache\.hve` | **Cause:** Inventory |
| **738** | SRUM | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SRUDB\.dat` | **Cause:** Usage |
| **739** | ThumbCache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `thumbcache_.*\.db` | **Cause:** Image |
| **741** | Recycle Bin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\$Recycle\.Bin` | **Cause:** Delete |
| **750** | Hibernation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `hiberfil\.sys` | **Cause:** Power |
| **1442** | UserAssist | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Exec count |

## SECTION 29: INSTALLATION & SETUP (Logs)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **751** | SetupAPI | **Op:** `*`<br>**Res:** `*`<br>**Path:** `setupapi\.dev\.log` | **Cause:** Driver |
| **757** | DotNet | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `dd_.*\.log`` | **Cause:** Runtime |
| **758** | VCRedist | **Op:** `*`<br>**Res:** `*`<br>**Path:** `dd_vcredist.*\.log` | **Cause:** Runtime |
| **763** | Sysprep | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `setupact\.log`` | **Cause:** Image |
| **764** | Unattend | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `unattend\.xml`` | **Cause:** Config |
| **765** | Panther | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `\\Panther`` | **Cause:** Setup |

## SECTION 30: "THE MARK RUSSINOVICH CLASSICS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **795** | MMIO | **Op:** `*`<br>**Res:** `O\ error\.`<br>**Path:** `*` | **Context:** Memory Mapped I/O error. |
| **796** | DMA | **Op:** `*`<br>**Res:** `Direct\ Memory\ Access\ error\.`<br>**Path:** `*` | **Context:** Direct Memory Access error. |
| **797** | Interrupts | **Op:** `*`<br>**Res:** `*`<br>**Path:** `High\ hardware\ interrupts\.` | **Context:** High hardware interrupts. |
| **798** | DPC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `High\ Deferred\ Procedure\ Calls\.` | **Context:** High Deferred Procedure Calls. |
| **969** | DMA | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Speed |
| **1035** | Dll Search Order | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Tab order jump |

## SECTION 31: ADVANCED API & INTERNALS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **801** | NtQuerySystemInfo | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Enum\ processes\.` | **Context:** Enum processes. |
| **802** | NtQueryObject | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Enum\ handles\.` | **Context:** Enum handles. |
| **803** | NtQueryInformationFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `File\ meta\.` | **Context:** File meta. |
| **804** | NtSetInformationFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Delete\.` | **Context:** Rename/Delete. |
| **805** | NtDeviceIoControlFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Driver\ talk\.` | **Context:** Driver talk. |
| **806** | NtCreateSection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Shared\ memory\.` | **Context:** Shared memory. |
| **807** | NtMapViewOfSection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Map\ memory\.` | **Context:** Map memory. |
| **808** | NtUnmapViewOfSection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Free\ memory\.` | **Context:** Free memory. |
| **809** | NtAllocateVirtualMemory | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Alloc\ RAM\.` | **Context:** Alloc RAM. |
| **810** | NtFreeVirtualMemory | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Free\ RAM\.` | **Context:** Free RAM. |
| **811** | NtProtectVirtualMemory | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Permissions\.` | **Context:** DEP/Permissions. |
| **812** | NtReadVirtualMemory | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\.` | **Context:** Debug/Read. |
| **813** | NtWriteVirtualMemory | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Inject\.` | **Context:** Debug/Inject. |
| **814** | NtCreateThreadEx | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Thread\ spawn\.` | **Context:** Thread spawn. |
| **816** | NtSuspendProcess | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Freeze\.` | **Context:** Freeze. |
| **817** | NtResumeProcess | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Thaw\.` | **Context:** Thaw. |
| **818** | NtOpenProcessToken | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Auth\ check\.` | **Context:** Auth check. |
| **820** | NtDuplicateToken | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Impersonate\.` | **Context:** Impersonate. |
| **821** | NtSetSecurityObject | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ACL\ change\.` | **Context:** ACL change. |
| **822** | NtQuerySecurityObject | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ACL\ read\.` | **Context:** ACL read. |
| **823** | NtCreateKey | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Reg\ create\.` | **Context:** Reg create. |
| **824** | NtOpenKey | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Reg\ open\.` | **Context:** Reg open. |
| **825** | NtSetValueKey | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Reg\ write\.` | **Context:** Reg write. |
| **826** | NtDeleteKey | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Reg\ delete\.` | **Context:** Reg delete. |
| **827** | NtEnumerateKey | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Reg\ scan\.` | **Context:** Reg scan. |
| **828** | NtLoadDriver | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Driver\ load\.` | **Context:** Driver load. |
| **829** | NtUnloadDriver | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Driver\ unload\.` | **Context:** Driver unload. |
| **830** | NtRaiseHardError | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Popup\.` | **Context:** BSOD/Popup. |
| **831** | NtShutdownSystem | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Reboot\.` | **Context:** Reboot. |
| **832** | NtSystemDebugControl | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Kernel\ debug\.` | **Context:** Kernel debug. |
| **833** | NtTraceControl | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ETW\ trace\.` | **Context:** ETW trace. |
| **834** | NtAlpcSendWait | **Op:** `*`<br>**Res:** `*`<br>**Path:** `LPC\.` | **Context:** RPC/LPC. |
| **835** | NtFsControlFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Filesystem\ op\.` | **Context:** Filesystem op. |
| **836** | NtLockFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `File\ lock\.` | **Context:** File lock. |
| **837** | NtUnlockFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `File\ unlock\.` | **Context:** File unlock. |
| **839** | NtQueryEaFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Ext\ attributes\.` | **Context:** Ext attributes. |
| **840** | NtSetEaFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Ext\ attributes\.` | **Context:** Ext attributes. |

## SECTION 32: CONTAINERIZATION (Docker/K8s on Windows)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **843** | Container NIC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vEthernet (HNS)` | **Cause:** Net |

## SECTION 34: DATABASE (Advanced SQL/Oracle)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **868** | Postgres | **Op:** `*`<br>**Res:** `*`<br>**Path:** `postgres\.exe` | **Cause:** OSS DB |
| **869** | MySQL | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mysqld\.exe`\ activity` | **Cause:** OSS DB |

## SECTION 35: DEVELOPMENT TOOLS (DevOps)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **874** | Visual Studio | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``devenv\.exe`\ crash` | **Cause:** IDE |
| **875** | MSBuild | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``MSBuild\.exe`\ fail` | **Cause:** Build |
| **876** | NuGet | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `nuget\.config`` | **Cause:** Pkg |
| **880** | Gradle | **Op:** `*`<br>**Res:** `*`<br>**Path:** `gradlew` | **Cause:** Build |

## SECTION 36: MEDIA PRODUCTION (Adobe/Davinci)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **884** | Premiere | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Adobe\ Premiere\ Pro\.exe`` | **Cause:** Video |
| **886** | Photoshop | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Photoshop\.exe`` | **Cause:** Image |
| **887** | Davinci Resolve | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Resolve\.exe`` | **Cause:** Video |
| **957** | Dongle Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `hasplms\.exe` | **Cause:** License |
| **958** | Dongle Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Sentinel` | **Cause:** License |

## SECTION 37: VIRTUAL REALITY (VR/AR)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **892** | Oculus | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``OVRServer_x64\.exe`` | **Cause:** VR |
| **894** | OpenVR | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `openvr_api\.dll`` | **Cause:** API |
| **896** | Tracking | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** USB |
| **897** | Compositor | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``vrcompositor\.exe`\ crash` | **Cause:** Display |
| **900** | Async Reprojection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Framerate |
| **1048** | Tracking | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetGUIThreadInfo` | **Cause:** USB |

## SECTION 38: TELEMETRY & PRIVACY

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **902** | SQM | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `sqm.*\.dat`` | **Cause:** Quality |
| **905** | Inventory | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Inventory\.exe`` | **Cause:** App scan |
| **908** | Feedback | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FeedbackHub` | **Cause:** User |
| **909** | Timeline | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `ActivitiesCache\.db`` | **Cause:** History |
| **1083** | AIT | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Install |

## SECTION 39: REMOTE DESKTOP (RDP/RDS)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **911** | TermSvc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TermService` | **Cause:** Svc |
| **920** | RemoteApp | **Op:** `*`<br>**Res:** `*`<br>**Path:** `rdpshell\.exe` | **Cause:** Seamless |

## SECTION 40: BACKUP & RECOVERY

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **922** | VSS Create | **Op:** `*`<br>**Res:** `TIMEOUT`<br>**Path:** `*` | **Cause:** Snapshot |
| **924** | VSS Create | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``vds\.exe`\ fail` | **Cause:** Snapshot |
| **928** | Archive Bit | **Op:** `SetFileAttributes`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Flag |
| **929** | Last Modified | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Inc |
| **1001** | Archive Bit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Flag |
| **1485** | Last Modified | **Op:** `*`<br>**Res:** `*`<br>**Path:** `File modified date is before creation date` | **Cause:** Inc |

## SECTION 42: FONTS & TEXT

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **946** | Freetype | **Op:** `*`<br>**Res:** `*`<br>**Path:** `freetype\.dll` | **Cause:** OSS |
| **947** | DirectWrite | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `dwrite\.dll`` | **Cause:** Modern |
| **948** | Uniscribe | **Op:** `*`<br>**Res:** `*`<br>**Path:** `usp10\.dll` | **Cause:** Complex |

## SECTION 43: SCIENTIFIC & ENGINEERING

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **951** | AutoCAD | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``acad\.exe`\ crash` | **Cause:** CAD |
| **952** | Revit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `revit\.exe` | **Cause:** BIM |
| **953** | SolidWorks | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``SLDWORKS\.exe`` | **Cause:** CAD |
| **954** | Matlab | **Op:** `*`<br>**Res:** `*`<br>**Path:** `matlab\.exe` | **Cause:** Math |
| **955** | LabView | **Op:** `*`<br>**Res:** `*`<br>**Path:** `labview\.exe` | **Cause:** Eng |
| **959** | CUDA | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `nvcuda\.dll`` | **Cause:** Compute |

## SECTION 44: FINANCIAL & TRADING

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **961** | Bloomberg | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``bbcomm\.exe`` | **Cause:** Terminal |
| **962** | Thomson | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Eikon\.exe`` | **Cause:** Terminal |
| **967** | Solarflare | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `sf.*dll`` | **Cause:** NIC |
| **968** | Mellanox | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mlx.*sys` | **Cause:** NIC |

## SECTION 45: HEALTHCARE & DICOM

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **972** | Cerner | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Citrix` | **Cause:** EMR |
| **974** | PACS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Image |
| **975** | HL7 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Msg |
| **978** | Foot Pedal | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Control |
| **979** | Badge Tap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Auth |
| **980** | Imprivata | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SSO` | **Cause:** Auth |

## SECTION 46: EDUCATION & LAB

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **981** | LanSchool | **Op:** `*`<br>**Res:** `*`<br>**Path:** `student\.exe` | **Cause:** Monitor |
| **982** | NetSupport | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``client32\.exe`` | **Cause:** Monitor |
| **983** | Faronics | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DeepFreeze` | **Cause:** Restore |
| **984** | Respondus | **Op:** `*`<br>**Res:** `*`<br>**Path:** `LockDownBrowser` | **Cause:** Test |
| **985** | SmartBoard | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SmartBoard` | **Cause:** Input |
| **986** | SafeExam | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SEB` | **Cause:** Test |
| **987** | PaperCut | **Op:** `*`<br>**Res:** `*`<br>**Path:** `pc-client` | **Cause:** Print |
| **988** | Pharos | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Pharos` | **Cause:** Print |
| **989** | LabStats | **Op:** `*`<br>**Res:** `*`<br>**Path:** `LabStats` | **Cause:** Usage |
| **990** | Veyon | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Veyon` | **Cause:** Monitor |

## SECTION 47: POINT OF SALE (POS)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **991** | OPOS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `OPOS\.dll`` | **Cause:** Device |
| **992** | JavaPOS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `jpos\.jar` | **Cause:** Device |
| **993** | Cash Drawer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** HW |
| **994** | Receipt Prn | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** HW |
| **995** | Pole Display | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** HW |
| **996** | Pin Pad | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Pay |
| **997** | Mag Stripe | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Card |
| **999** | Scale | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** HW |
| **1108** | Pole Display | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** HW |
| **1205** | Pole Display | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** HW |
| **1350** | Cash Drawer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** HW |

## SECTION 48: "THE FINAL STRAW" (Last Resort Checks)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1002** | Cosmic Ray | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physics |
| **1003** | Cable Rot | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physical |
| **1005** | Capacitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physical |
| **1007** | Dust | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physical |
| **1008** | Liquid | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physical |
| **1010** | Gremlins | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Undefined |
| **1133** | Cable Rot | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physical |
| **1206** | Bit Flip | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** RAM |

## SECTION 50: ASSISTIVE TECH - SCREEN READERS (JAWS/NVDA)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1029** | Chromium A11y Tree | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Chrome_RenderWidgetHostHWND` | **Cause:** Browser lag |
| **1050** | Off-Screen Text | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SystemParametersInfo` | **Cause:** Hidden text read aloud |
| **1423** | Adobe Reader Tagging | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Untagged PDF |
| **1489** | Live Region Spam | **Op:** `*`<br>**Res:** `*`<br>**Path:** `App parses 14:00 as error` | **Cause:** Floods speech buffer |

## SECTION 51: ASSISTIVE TECH - UI AUTOMATION (UIA)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1038** | Pattern Not Supported | **Op:** `*`<br>**Res:** `*`<br>**Path:** `IUIAutomation::GetPattern` | **Cause:** Control broken |
| **1092** | Privilege Boundary | **Op:** `*`<br>**Res:** `*`<br>**Path:** `<iframe>` | **Cause:** UIPI |
| **1096** | Element Orphaned | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Crash risk |

## SECTION 53: THE "WORKS AS ADMIN" MYSTERIES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1069** | Raw Socket | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Network tool |

## SECTION 54: ENVIRONMENT DRIFT & "DLL HELL"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1073** | Current Work Dir | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Shortcut "Start In" wrong |
| **1074** | GAC Priority | **Op:** `*`<br>**Res:** `*`<br>**Path:** `C:\\Windows\\Assembly` | **Cause:** GAC |
| **1077** | Regional Date | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** MM/DD vs DD/MM |
| **1078** | Decimal Separator | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Comma vs Dot |
| **1194** | Decimal Separator | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Comma vs Dot |

## SECTION 57: VIRTUALIZATION & VDI EDGE CASES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1109** | DPI Matching | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Tiny/Huge text |

## SECTION 60: THE "HUMAN FACTOR" (User Behavior Detections)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1132** | Force Shutdown | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hard reset |

## SECTION 61: THE "GHOST IN THE SHELL" (Explorer & UI Rot)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1150** | Taskbar Unclickable | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Start Menu works, but Taskbar icons are dead.<br><br>**Cause:** A "DeskBand" (Toolbar widget) crashed the taskbar thread specifically. |

## SECTION 64: THE "PHANTOM HARDWARE" (PnP & Peripherals)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1178** | Touchpad Palm Rejection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Cursor jumps randomly while typing.<br><br>**Cause:** Palm Rejection setting disabled or driver update reset sensitivity. |
| **1372** | Docking Station Ethernet Flap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Network drops for 1 second every time user bumps desk.<br><br>**Cause:** Physical loose connection in the USB-C dock connector (Mechanical failure disguised as software). |
| **1393** | Docking Station Ethernet Flap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Network drops for 1 second every time user bumps desk.<br><br>**Cause:** Physical loose connection in the USB-C dock connector (Mechanical failure disguised as software). |

## SECTION 62: THE "NETWORK POLTERGEISTS" (Stack & Caching)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1179** | Browser Proxy "Automatically Detect" Flap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Internet cuts out for 10 seconds every minute.<br><br>**Cause:** "Automatically Detect Settings" is checked, but no WPAD server exists, causing a timeout loop. |
| **1363** | VPN Split Tunnel DNS Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User can access Internal Site A but not Internal Site B.<br><br>**Cause:** Windows Interface Metric prioritizes the physical adapter over the VPN adapter for specific domains. |
| **1364** | ICS (Internet Connection Sharing) Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User plugs in a phone to charge; Corporate LAN drops.<br><br>**Cause:** PC starts acting as a Router/DHCP server because ICS was triggered, causing IP conflicts. |
| **1467** | VPN Split Tunnel DNS Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User can access Internal Site A but not Internal Site B.<br><br>**Cause:** Windows Interface Metric prioritizes the physical adapter over the VPN adapter for specific domains. |

## SECTION 65: THE "COPY/PASTE" ABYSS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1182** | Format Not Available | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Can copy text from Notepad, but not from Excel.<br><br>**Cause:** Security software filtering complex clipboard formats to prevent data exfiltration. |

## SECTION 74: SQL SERVER INTERNALS (OS Perspective)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1229** | SQL OS Scheduler Yielding | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** SQL CPU high, but queries slow.<br><br>**Cause:** "SOS_SCHEDULER_YIELD" - Internal SQL cooperative multitasking is fighting for CPU time. |

## SECTION 78: ADVANCED INPUT & UI

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1249** | DPI Awareness Lie | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** App is tiny or blurry.<br><br>**Cause:** Developer lied in manifest to avoid Windows scaling, but didn't implement scaling code. |

## SECTION 85: 16-BIT & DOS (The Ancients)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1269** | AUTOEXEC.NT Parsing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** 16-bit app fails to start.<br><br>**Cause:** File missing or corrupt (often flagged by AV). |

## SECTION 86: SPECIFIC ERROR CODES (RPC/Win32)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1270** | RPC_S_SERVER_UNAVAILABLE (0x6BA) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Context:** RPC endpoint mapper reachable (135), but dynamic port blocked. |
| **1271** | RPC_S_CALL_FAILED (0x6BE) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Context:** The remote procedure call started, but the server process crashed mid-execution. |
| **1272** | ERROR_MORE_DATA (0xEA) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Context:** Buffer too small. (App logic error). |
| **1273** | ERROR_NO_SYSTEM_RESOURCES (0x5AA) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Context:** Non-paged pool limit or Thread limit hit. |

## SECTION 89: BATTERY & POWER

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1278** | Modern Standby (S0) Drain | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Laptop hot in bag, battery dead.<br><br>**Cause:** "Connected Standby" allows apps to wake network. (Need `powercfg /sleepstudy`). |
| **1358** | Modern Standby (S0) Drain | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Laptop hot in bag, battery dead.<br><br>**Cause:** "Connected Standby" allows apps to wake network. (Need `powercfg /sleepstudy`). |

## SECTION 91: APP-V / THINAPP

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1284** | Bubble-to-Bubble Comms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** App A cannot see App B's DLLs.<br><br>**Cause:** Virtual environments are isolated. Requires "Connection Group" configuration. |

## SECTION 63: THE "IDENTITY CRISIS" (Credentials & Auth)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1321** | User Rights Assignment (Logon as Batch) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Scheduled Task as User fails to start.<br><br>**Cause:** GPO removed "Logon as a Batch Job" right for that user. |

## SECTION 106: ACTIVE DIRECTORY "TIME BOMBS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1325** | AdminSDHolder (The "Protected" User) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** You grant a user permissions on their phone object, 60 mins later it disappears.<br><br>**Cause:** SDProp process runs every hour and resets permissions on "Protected Groups" to match `AdminSDHolder` template. |

## SECTION 112: DISPLAY & GPU "POLTERGEISTS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1353** | Wallpaper "Transcoding" Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Desktop background is black. Cannot set new image.<br><br>**Cause:** Windows converts all wallpapers to a standard JPG. If that process crashes, the file gets locked/corrupted and the UI fails silently. |

## SECTION 118: CRYPTO & TPM "LOCKOUTS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1373** | TPM "Hysteresis" Lockout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Windows Hello "Something went wrong".<br><br>**Cause:** User entered wrong PIN too many times. TPM hardware enters "Dictation Attack" lockout mode (can last 2-24 hours). |

## SECTION 108: APPLICATION COMPATIBILITY "SHIMS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1385** | Installer Detection (UAC) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Renaming a tool `updater.exe` makes it ask for Admin.<br><br>**Cause:** Heuristic detection: filenames containing "setup", "patch", "update" automatically trigger UAC virtualization. |

## SECTION 125: THE "TIME TRAVEL" FILES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1390** | Future Timestamps (Build Fails) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "Make" or "Compile" fails. "File modification time is in the future".<br><br>**Cause:** File was touched by a server with a clock set 5 minutes ahead. Local build tool treats it as "impossible" and crashes. |

## SECTION 128: THE "OEM" BLOATWARE INTERFERENCE

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1394** | Dell/HP "Optimizer" Network Shaping | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Zoom is perfect, but Browser download is 10Kbps.<br><br>**Cause:** OEM bloatware traffic shaper prioritizing UDP (Video) and throttling TCP (Download) aggressively. |

## SECTION 131: THE "INPUT" POLTERGEISTS (HID/USB)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1402** | Touchscreen "Phantom" Moisture | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Windows Start Menu opens and closes rapidly.<br><br>**Cause:** The bezel of the screen is slightly pinched or dirty, and thermal expansion causes it to register a touch in the corner. |
| **1404** | Wireless Receiver Interference (USB 3.0) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Wireless mouse lags/stutters only when an external hard drive is transferring data.<br><br>**Cause:** USB 3.0 ports emit radio frequency interference at 2.4GHz, jamming the wireless dongle plugged into the adjacent port. |

## SECTION 111: THE "INVISIBLE" INPUT GLITCHES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1405** | The "Phantom" Digitizer Touch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Mouse cursor jumps to the top-right corner randomly.<br><br>**Cause:** Micro-fracture in the touchscreen glass or humidity buildup in the bezel causing ghost inputs. |

## SECTION 113: AUDIO & MEDIA "GREMLINS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1414** | HDMI Audio "Silent" Stream | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** TV shows "PCM Audio" but no sound comes out.<br><br>**Cause:** Windows thinks the TV is 5.1 surround. It sends vocals to the "Center" channel. The TV is stereo (2.0) and drops the Center channel. (User hears background music but no voices). |

## SECTION 133: NETWORK "BLACK HOLES"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1426** | WLAN "Background Scan" Lag | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Online games spike lag every 60 seconds.<br><br>**Cause:** Windows scans for better WiFi networks periodically. This scan requires tuning off the radio for 500ms. |

## SECTION 134: FILESYSTEM "ARCHAEOLOGY"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1437** | Metadata "Date Taken" Sorting | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Photos sort randomly.<br><br>**Cause:** "Date" column uses EXIF metadata (Date Taken) which might be missing or wrong in the camera. |

## SECTION 135: REGISTRY & CONFIG "ROT"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1441** | ShutdownWithoutLogon | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Shutdown button missing from login screen.<br><br>**Cause:** Security policy hidden setting. |

## SECTION 136: HARDWARE & PHYSICS "INTERFERENCE"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1451** | Static Discharge (The "Carpet" Reboot) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PC reboots when user sits down.<br><br>**Cause:** ESD (Electrostatic Discharge) from chair/carpet jumping to the USB port or metal chassis. |
| **1454** | Piezoelectric "Singing" Capacitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** High pitched whine from laptop.<br><br>**Cause:** Ceramic capacitors vibrating at audible frequencies (Coil Whine). |
| **1459** | Loose RAM Stick | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Random BSODs (various codes).<br><br>**Cause:** RAM stick unseated by thermal expansion/contraction. |

## SECTION 137: 3RD PARTY "OVERLAY" WARS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1468** | Antivirus "HTTPS Scanning" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Browser Certificate Errors (Unknown Issuer).<br><br>**Cause:** AV is performing Man-in-the-Middle TLS inspection, but its Root CA is not trusted by Firefox/Java. |

## Module 22: Time & Regional

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1488** | Leap Second / Time Jump | **Op:** `*`<br>**Res:** `*`<br>**Path:** `App crashes on Feb 29` | **Cause:** W32Time syncing with a bad NTP source, causing huge jumps that break Kerberos/SSL. |

## SECTION 114: POWER & SLEEP "INSOMNIA"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1495** | Modern Standby "Network" Wake | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Wake on LAN Pattern Match` | **Symptom:** Laptop hot in bag. Battery drained.<br><br>**Cause:** "Network connectivity in Standby" is Enabled. Laptop woke up to process a multicast packet or update check. |

## SECTION 123: BROWSER "CERTIFICATE" WEIRDNESS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1499** | Root CA "Disable" Flag | **Op:** `*`<br>**Res:** `*`<br>**Path:** `OOBEComplete registry mismatch` | **Symptom:** All HTTPS sites invalid.<br><br>**Cause:** User accidentally moved a Root CA (like DigiCert) into the "Untrusted Certificates" store. |

## 🧩 Dynamic Detectors (Heuristic Modules)

These advanced modules run code logic beyond simple signature matching.

| Module | Logic Pattern | User Experience |
| :--- | :--- | :--- |
| **Global Lock (GSB)** | `[Sec_Proc]` touches `[Path]` -> `< 0.5s` later `[AT_Proc]` fails `[Path]` with `SHARING_VIOLATION`. | System 'hiccups' or AT speech skips. Detects 'Security Fratricide'. |
| **Hook Injection** | `LoadImage` of suspicious DLLs (CrowdStrike, Citrix) into AT Process. | Application crash on startup or focus loss. |
| **Thread Profiling** | High frequency of `Thread Profiling` events (>100/s). | CPU-bound freezing (not I/O bound). |
| **Filter Conflict** | `INSTANCE_ALTITUDE_COLLISION` error in Minifilter driver. | File operations fail with strange errors; BSOD risk. |
| **Clipboard Lock** | `ACCESS_DENIED` on `\Device\NamedPipe\Clipboard` or `rdpclip`. | Copy/Paste stops working. Identifies the process holding the lock. |
| **Audio Ducking** | `ACCESS_DENIED` on `MMDevices` by `audiodg.exe`. | Volume drops and doesn't recover. |
| **MFA Block** | `TCP Connect` fail to `login.microsoftonline.com`. | Sign-in loop or prompt spam. |
| **OCR Fail** | `PATH NOT FOUND` for `Windows.Media.Ocr` / `tessdata`. | Screen reader cannot read images/PDFs. |
| **Packet Storm** | >500 Network Ops/sec by a single process. | Network sluggishness or DoS condition. |
| **Browser Loop** | Browser Parent spawning Child Renderer repeatedly (>20x). | Browser tabs crash 'Aw Snap'. |
