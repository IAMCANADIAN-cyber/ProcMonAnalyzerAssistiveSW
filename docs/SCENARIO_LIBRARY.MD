# 📚 Scenario Library (Automated Catalog)

This document defines the detection logic for `ProcMon-Enterprise-Unified.ps1`.
It correlates technical signatures (Operations/Results) with User Experiences and Root Causes.

## 🔎 How to Read
- **ID:** Unique identifier in the script engine.
- **Title:** The name of the detection scenario.
- **Technical Signature:** The specific ProcMon Operation, Result, and Path pattern that triggers the detection.
- **Context & Remediation:** Explanation of the root cause, symptoms, and potential fixes.

---

## Module 10: Advanced Security & Evasion (Sysmon Correlation)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **2** | Normalize | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Align\ all\ timestamps\.` | **Cause:** UAC/Permission issue |
| **3** | Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Iterate\ through\ the\ ` | **Cause:** AppLocker/SRP blocking binary |
| **5** | Output | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Generate\ a\ report\ that\ sounds\ like\ Mark\ R:` | **Cause:** The app is ancient. Windows automatically maps these calls to the Registry (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\IniFileMapping`), which creates confusion if the mapping is wrong. |

## SECTION 1: FILE SYSTEM FORENSICS (NTFS & I/O)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **6** | Access Denied (Pipe) | **Op:** `CreateFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `\\\\\.\\Pipe\\.*` | **Cause:** Service security hardening |
| **7** | Access Denied (Spool) | **Op:** `CreateFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `\\System32\\spool` | **Cause:** Print nightmare mitigation |
| **8** | Access Denied (WasDeletePending) | **Op:** `CreateFile`<br>**Res:** `STATUS\ DELETE\ PENDING`<br>**Path:** `*` | **Cause:** File deleted but handle open; zombie file |
| **9** | Sharing Violation (Profile) | **Op:** `CreateFile`<br>**Res:** `SHARING\ VIOLATION`<br>**Path:** `NTUSER\.DAT` | **Cause:** Profile locked by AV/Backup |
| **10** | Sharing Violation (VHDX) | **Op:** `CreateFile`<br>**Res:** `SHARING\ VIOLATION`<br>**Path:** `.*\.vhdx` | **Cause:** FSLogix/VDI double-mount |
| **11** | Sharing Violation (Log) | **Op:** `CreateFile`<br>**Res:** `SHARING\ VIOLATION`<br>**Path:** `.*\.log` | **Cause:** Log rotation race condition |
| **12** | Sharing Violation (Dll) | **Op:** `CreateFile`<br>**Res:** `SHARING\ VIOLATION`<br>**Path:** `.*\.dll` | **Cause:** Update trying to replace loaded library |
| **13** | Path Not Found (DLL) | **Op:** `LoadImage`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Missing dependency |
| **14** | Path Not Found (Exe) | **Op:** `ProcessCreate`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Broken shortcut/service path |
| **15** | Path Not Found (Config) | **Op:** `CreateFile`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `.*\.ini` | **Cause:** Missing configuration |
| **16** | Path Not Found (Drive) | **Op:** `CreateFile`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `X:\\` | **Cause:** Mapped drive disconnected |
| **17** | Path Not Found (UNC) | **Op:** `CreateFile`<br>**Res:** `BAD\ NETWORK\ PATH`<br>**Path:** `\\\\Server\\Share` | **Cause:** Server offline/DNS fail |
| **18** | Path Not Found (8.3) | **Op:** `CreateFile`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `PROGRA\~1` | **Cause:** Short names disabled |
| **19** | Path Not Found (Dev) | **Op:** `CreateFile`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `C:\\Users\\DevName` | **Cause:** Hardcoded developer path |
| **20** | Path Not Found (SXS) | **Op:** `CreateFile`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `\\WinSxS\\.*` | **Cause:** Component Store corruption |
| **21** | Name Collision (Temp) | **Op:** `CreateFile`<br>**Res:** `NAME\ COLLISION`<br>**Path:** `%TEMP%` | **Cause:** Temp folder flooding |
| **22** | Name Collision (ShortName) | **Op:** `CreateFile`<br>**Res:** `NAME\ COLLISION`<br>**Path:** `*` | **Cause:** Hash collision on volume |
| **23** | Disk Full | **Op:** `WriteFile`<br>**Res:** `DISK\ FULL`<br>**Path:** `*` | **Cause:** Volume out of space |
| **24** | Quota Exceeded | **Op:** `WriteFile`<br>**Res:** `QUOTA\ EXCEEDED`<br>**Path:** `*` | **Cause:** User disk quota hit |
| **25** | File Corrupt | **Op:** `ReadFile`<br>**Res:** `FILE\ CORRUPT\ ERROR`<br>**Path:** `*` | **Cause:** Physical disk/filesystem rot |
| **26** | CRC Error | **Op:** `ReadFile`<br>**Res:** `DATA\ ERROR`<br>**Path:** `*` | **Cause:** Bad sectors/Dedup corruption |
| **27** | InPage Error | **Op:** `ReadFile`<br>**Res:** `STATUS\ IN\ PAGE\ ERROR`<br>**Path:** `*` | **Cause:** Swap file/Memory/Network paging failure |
| **28** | Device Offline | **Op:** `CreateFile`<br>**Res:** `STATUS\ DEVICE\ OFF\ LINE`<br>**Path:** `*` | **Cause:** USB/Storage disconnect |
| **29** | Device Busy | **Op:** `DeviceIoControl`<br>**Res:** `STATUS\ DEVICE\ BUSY`<br>**Path:** `*` | **Cause:** Hardware stuck |
| **30** | Oplock Break | **Op:** `FsRtlCheckOplock`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Network locking contention |
| **31** | Filter Latency | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** AV/EDR filter driver overhead |
| **32** | Sparse Write Fail | **Op:** `WriteFile`<br>**Res:** `DISK\ FULL`<br>**Path:** `*` | **Cause:** Over-provisioning failure |
| **33** | Reparse Point Loop | **Op:** `CreateFile`<br>**Res:** `STATUS\ REPARSE\ POINT\ NOT\ RESOLVED`<br>**Path:** `*` | **Cause:** Infinite symlink loop |
| **34** | Not A Directory | **Op:** `CreateFile`<br>**Res:** `STATUS\ NOT\ A\ DIRECTORY`<br>**Path:** `*` | **Cause:** File exists with name of requested folder |
| **35** | Dir Not Empty | **Op:** `*`<br>**Res:** `STATUS\ DIRECTORY\ NOT\ EMPTY`<br>**Path:** `*` | **Cause:** Failed folder delete |
| **36** | Case Sensitivity | **Op:** `CreateFile`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Per-directory case sensitivity enabled |
| **37** | Alternate Data Stream Exec | **Op:** `ProcessCreate`<br>**Res:** `*`<br>**Path:** `.*:Stream` | **Cause:** Potential malware/hiding |
| **38** | ZoneID Block | **Op:** `CreateFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `Zone\.Identifier` | **Cause:** Security tool blocking unblock |
| **39** | Cloud Tiering | **Op:** `ReadFile`<br>**Res:** `STATUS\ FILE\ IS\ OFFLINE\|FILE\ IS\ OFFLINE`<br>**Path:** `*` | **Cause:** OneDrive/Azure Files recall needed |
| **40** | Encrypted File (EFS) | **Op:** `CreateFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** User mismatch on EFS |
| **41** | BitLocker Locked | **Op:** `CreateFile`<br>**Res:** `STATUS\ FVE\ LOCKED\ VOLUME`<br>**Path:** `*` | **Cause:** Drive mounted but locked |
| **42** | USN Journal Wrap | **Op:** `*`<br>**Res:** `USN\ JOURNAL\ WRAP`<br>**Path:** `*` | **Cause:** Backup failure warning |
| **43** | Transaction Log Full | **Op:** `*`<br>**Res:** `LOG\ FILE\ FULL`<br>**Path:** `Ntfs\.sys` | **Cause:** Metadata explosion |
| **44** | MFT Fragmentation | **Op:** `ReadFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Severe filesystem fragmentation |
| **45** | Directory Enumeration Storm | **Op:** `QueryDirectory`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Inefficient loop |
| **46** | 1-Byte I/O | **Op:** `ReadFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Inefficient coding |
| **47** | Flush Storm | **Op:** `FlushBuffersFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Performance killer |
| **48** | Temp File Churn | **Op:** `*`<br>**Res:** `*`<br>**Path:** `>1000\ creates\ in\ `%TEMP%`\ in\ 1\ min` | **Cause:** MFT exhaustion risk |
| **49** | Log File Bloat | **Op:** `WriteFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disk usage spike |
| **50** | Zero Byte Write | **Op:** `WriteFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Truncation/Logic error |

## SECTION 2: REGISTRY INTERNALS (HKLM/HKCU/HKCR)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **51** | Reg Access Denied (HKLM) | **Op:** `RegSetValue`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Standard user trying to change system |
| **52** | Reg Access Denied (HKCU) | **Op:** `RegSetValue`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Permission corruption on user hive |
| **53** | Reg Access Denied (GroupPolicy) | **Op:** `RegSetValue`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `Software\\Policies` | **Cause:** App trying to override GPO |
| **54** | Reg Key Not Found (CLSID) | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKCR\\CLSID` | **Cause:** Unregistered COM object |
| **55** | Reg Key Not Found (AppID) | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKCR\\AppID` | **Cause:** DCOM config missing |
| **56** | Reg Key Not Found (Interface) | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKCR\\Interface` | **Cause:** Proxy/Stub missing |
| **57** | Reg Key Not Found (TypeLib) | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKCR\\TypeLib` | **Cause:** Automation failure |
| **58** | Reg Key Not Found (Service) | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKLM\\System\\.*\\Services` | **Cause:** Service missing |
| **59** | Reg Key Not Found (Uninstall) | **Op:** `RegOpenKey`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `HKLM\\.*\\Uninstall` | **Cause:** Installer corruption |
| **60** | Reg Value Not Found (Run) | **Op:** `RegQueryValue`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Startup item missing |
| **61** | Reg Value Not Found (Env) | **Op:** `RegQueryValue`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Missing env var |
| **62** | Reg Type Mismatch | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Crash risk |
| **63** | Buffer Overflow (Reg) | **Op:** `RegQueryValue`<br>**Res:** `BUFFER\ OVERFLOW`<br>**Path:** `*` | **Cause:** Data larger than buffer |
| **64** | Registry Hive Bloat | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hive fragmentation |
| **68** | Orphaned Key Scan | **Op:** `*`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Registry cleaner behavior |
| **69** | IniFileMapping | **Op:** `*`<br>**Res:** `*`<br>**Path:** `win\.ini` | **Cause:** Ancient app compatibility |
| **72** | Services Start Mode | **Proc:** `ctfmon\.exe` <br>**Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Service disabling |
| **76** | ZoneMap Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ZoneMap\\Domains` | **Cause:** IE Security Zone check |
| **77** | Capability Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Query\ `HKCU\\.*\\Capabilities`` | **Cause:** Privacy permission check |
| **81** | Group Policy History | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GroupPolicy\\History` | **Cause:** GPO processing |
| **82** | Winlogon Helper | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Winlogon\\Shell` | **Cause:** Persistence/Kiosk mode |
| **83** | LSA Provider Mod | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ to\ `Security\\Providers`` | **Cause:** Credential theft/Inject |
| **88** | USB Enum | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `Enum\\USB`` | **Cause:** Hardware enumeration |
| **90** | Network Profile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `NetworkList\\Profiles` | **Cause:** Network location awareness |
| **92** | WPA Key | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `Wlansvc\\Parameters`` | **Cause:** WiFi config |
| **93** | Console Config | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Console\\Configuration` | **Cause:** CMD settings |
| **99** | Crypto Seed | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RNG\\Seed` | **Cause:** Entropy generation |

## SECTION 3: PROCESS, MEMORY & THREADS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **101** | Process Create | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Activity tracking |
| **102** | Process Exit (Success) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Clean shutdown |
| **103** | Process Exit (Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Error/Crash |
| **104** | Process Exit (Crash) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000005` | **Cause:** Access Violation |
| **105** | Process Exit (Hard) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000409` | **Cause:** Stack Buffer Overrun |
| **106** | Process Exit (Abort) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000374` | **Cause:** Heap Corruption |
| **107** | Image Load (DLL) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Dependency tracking |
| **108** | Image Load Fail | **Op:** `LoadImage`<br>**Res:** `STATUS\ IMAGE\ NOT\ AT\ BASE`<br>**Path:** `*` | **Cause:** Relocation |
| **109** | Image Load Fail (Arch) | **Op:** `*`<br>**Res:** `STATUS\ IMAGE\ MACHINE\ TYPE\ MISMATCH`<br>**Path:** `*` | **Cause:** 32/64 bit mix |
| **110** | Image Load Fail (Sign) | **Op:** `*`<br>**Res:** `STATUS\ INVALID\ IMAGE\ HASH`<br>**Path:** `*` | **Cause:** Unsigned binary |
| **111** | Thread Create | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Parallelism |
| **112** | Thread Exit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Worker completion |
| **113** | CreateRemoteThread | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Thread\ in\ .*other.*\ process` | **Cause:** Injection/Debug |
| **114** | OpenProcess (Full) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PROCESS_ALL_ACCESS` | **Cause:** Admin/AV |
| **115** | OpenProcess (Mem) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VM_READ/WRITE` | **Cause:** Debug/Hack |
| **116** | OpenProcess (Term) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TERMINATE` | **Cause:** Kill attempt |
| **117** | TerminateProcess | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Watchdog/User kill |
| **118** | Debug Active | **Op:** `*`<br>**Res:** `*`<br>**Path:** `IsDebuggerPresent` | **Cause:** Anti-debug |
| **119** | WerFault Trigger | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WerFault\.exe` | **Cause:** Crash reporting |
| **120** | Dr Watson | **Op:** `*`<br>**Res:** `*`<br>**Path:** `dwwin\.exe` | **Cause:** Legacy crash |
| **121** | Conhost Spawn | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Spawning\ `conhost\.exe`` | **Cause:** Console window |
| **122** | Wow64 Transition | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Compatibility |
| **123** | Job Object Assign | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Resource limit |
| **124** | Token Impersonation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ImpersonateLoggedOnUser` | **Cause:** Context switch |
| **125** | Token Priv Adjust | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AdjustTokenPrivileges` | **Cause:** Elevating |
| **126** | LUID Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AllocateLocallyUniqueId` | **Cause:** Auth resource limit |
| **127** | Handle Leak | **Op:** `CreateFile\|CloseHandle`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Resource leak |
| **128** | GDI Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Graphics leak |
| **129** | User Handle Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Window leak |
| **130** | Non-Paged Pool | **Op:** `*`<br>**Res:** `STATUS\ INSUFFICIENT\ RESOURCES`<br>**Path:** `*` | **Cause:** Kernel memory full |
| **131** | Commit Limit | **Op:** `*`<br>**Res:** `STATUS\ COMMITMENT\ LIMIT`<br>**Path:** `*` | **Cause:** RAM/Pagefile full |
| **132** | Working Set Trim | **Op:** `*`<br>**Res:** `*`<br>**Path:** `EmptyWorkingSet` | **Cause:** Memory reclaiming |
| **133** | Page Fault | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Thrashing |
| **134** | Stack Overflow | **Op:** `*`<br>**Res:** `STATUS\ STACK\ OVERFLOW`<br>**Path:** `*` | **Cause:** Recursion loop |
| **135** | DllMain Hang | **Op:** `LoadImage`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Loader lock |
| **136** | Zombie Process | **Op:** `Process\ Exit`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Deletion block |
| **137** | Orphaned Process | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Backgrounding |
| **138** | Rapid Spawn | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Fork bomb/Crash loop |
| **139** | Self-Deletion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `cmd /c del` | **Cause:** Installer/Malware |
| **140** | Process Hollowing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Malware |
| **141** | Reflective Load | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Fileless malware |
| **142** | SvcHost Split | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Stability |
| **143** | AppContainer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Store App |
| **144** | Low Integrity | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Browser sandbox |
| **145** | Protected Process | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** AV/System |
| **146** | System Process | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Kernel |
| **147** | Registry Virtualization | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VirtualStore` | **Cause:** Legacy compat |
| **148** | Shim Engine | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AcLayers\.dll` | **Cause:** AppCompat |
| **149** | Detours | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``detoured\.dll`\ load` | **Cause:** Hooking |
| **150** | Inject Library | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AppInit_DLLs` | **Cause:** Global injection |

## SECTION 4: NETWORK STACK (TCP/IP & RPC)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **151** | TCP Connect (Success) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Connected |
| **152** | TCP Connect (Refused) | **Op:** `*`<br>**Res:** `CONNECTION\ REFUSED`<br>**Path:** `*` | **Cause:** Port closed/Blocked |
| **153** | TCP Connect (Timeout) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Drop/No Route |
| **154** | TCP Connect (Unreachable) | **Op:** `*`<br>**Res:** `NETWORK\ UNREACHABLE`<br>**Path:** `*` | **Cause:** Routing fail |
| **155** | TCP Connect (AddrInUse) | **Op:** `*`<br>**Res:** `ADDRESS\ ALREADY\ ASSOCIATED`<br>**Path:** `*` | **Cause:** Port exhaustion |
| **156** | TCP Reconnect | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Flapping |
| **157** | TCP Disconnect (Reset) | **Op:** `*`<br>**Res:** `ECONNRESET`<br>**Path:** `*` | **Cause:** Force close |
| **158** | TCP KeepAlive | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Idle maintenance |
| **159** | UDP Send (Fail) | **Op:** `*`<br>**Res:** `HOST\ UNREACHABLE`<br>**Path:** `*` | **Cause:** Delivery fail |
| **160** | UDP Receive | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Listener active |
| **161** | DNS Query (A) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** IPv4 |
| **162** | DNS Query (AAAA) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** IPv6 |
| **163** | DNS Fail | **Op:** `*`<br>**Res:** `NAME\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Typo/Missing record |
| **164** | DNS Timeout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** DNS Server down |
| **165** | Reverse Lookup | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Logging/Security |
| **166** | Broadcast Storm | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** NetBIOS/Disco |
| **167** | Multicast Join | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Streaming/Cluster |
| **168** | IPv6 Failover | **Op:** `*`<br>**Res:** `SUCCESS`<br>**Path:** `*` | **Cause:** Protocol lag |
| **169** | Port 80/443 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Web traffic |
| **170** | Port 445 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** File share |
| **171** | Port 135/139 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Legacy/Mgmt |
| **172** | Port 389/636 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** AD Auth |
| **173** | Port 88 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Auth |
| **174** | Port 53 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Resolution |
| **175** | Port 3389 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Remote Access |
| **176** | Port 1433 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Database |
| **177** | High Ports | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Client/RPC |
| **178** | Tor Ports | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Suspicious |
| **179** | Proxy Connect | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Web filter |
| **180** | WPAD Lookup | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wpad` | **Cause:** Proxy auto-config |
| **181** | PAC File Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.pac` | **Cause:** Slow browsing |
| **182** | SMBv1 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Security risk |
| **183** | SMBv3 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Modern/Encryption |
| **184** | RPC Bind | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** DCOM start |
| **185** | RPC Auth Fail | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Permission |
| **186** | RPC Stub Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RPC_E_DISCONNECTED` | **Cause:** Crash on server |
| **187** | Named Pipe Connect | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\\\\Server\\pipe` | **Cause:** IPC |
| **188** | Mail Slot | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\mailslot\\browse`` | **Cause:** Browser election |
| **189** | Cert Revocation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** SSL check |
| **190** | OCSP Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Cert hang |
| **191** | Winsock Load | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ws2_32\.dll` | **Cause:** Net stack init |
| **192** | LSP Injection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Interference |
| **193** | NLA Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `msftncsi` | **Cause:** Internet check |
| **194** | Teredo/Isatap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** IPv6 transition |
| **195** | Loopback Connect | **Op:** `*`<br>**Res:** `*`<br>**Path:** `127\.0\.0\.1` | **Cause:** Local service |
| **196** | Link Local | **Op:** `*`<br>**Res:** `*`<br>**Path:** `169\.254\.x\.x` | **Cause:** DHCP fail |
| **197** | Private IP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `192\.168\.x` | **Cause:** Internal |
| **198** | Public IP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** External |
| **199** | FTP Active | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Data exfil/Legacy |
| **200** | SSH Active | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Admin/Tunnel |

## SECTION 5: ENTERPRISE INFRA (AD, GPO, VDI)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **201** | GPO Read Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `gpt\.ini` | **Cause:** Policy fail |
| **202** | GPO Script Fail | **Op:** `*`<br>**Res:** ``gpscript\.exe`\ error`<br>**Path:** `gpscript\.exe` | **Cause:** Startup script |
| **203** | GPO History Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `history\.ini` | **Cause:** Processing hang |
| **204** | Sysvol Latency | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\\\\Domain\\Sysvol` | **Cause:** DC overload |
| **205** | Netlogon Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `_ldap` | **Cause:** DC discovery |
| **206** | Kerberos Skew | **Op:** `*`<br>**Res:** `*`<br>**Path:** `KRB_AP_ERR_SKEW` | **Cause:** Time sync |
| **207** | Ticket Bloat | **Op:** `*`<br>**Res:** `BUFFER\ OVERFLOW\|STATUS\ BUFFER\ OVERFLOW`<br>**Path:** `*` | **Cause:** MaxTokenSize |
| **208** | Machine Trust | **Op:** `*`<br>**Res:** `STATUS\ TRUST\ FAILURE`<br>**Path:** `*` | **Cause:** Broken trust |
| **209** | LDAP Timeout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Slow AD |
| **210** | Roaming Profile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `NTUSER\.DAT` | **Cause:** Logon error |
| **211** | Folder Redir Offline | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Sync fail |
| **212** | Offline Files Sync | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CscService` | **Cause:** Caching |
| **213** | DFS Referral | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\\\\Domain\\DFS` | **Cause:** Namespace |
| **214** | Print Spooler Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``spoolsv\.exe`\ exit` | **Cause:** Print kill |
| **215** | Driver Isolation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PrintIsolationHost` | **Cause:** Bad driver |
| **216** | Point and Print | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Dopp` | **Cause:** Driver install |
| **217** | Group Policy Printer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `gpprinter` | **Cause:** Mapping fail |
| **218** | Citrix Hook | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``CtxHk\.dll`\ load` | **Cause:** VDI hook |
| **219** | Citrix API Block | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** AV conflict |
| **220** | FSLogix Service | **Op:** `*`<br>**Res:** `*`<br>**Path:** `frxsvc` | **Cause:** Profile container |
| **221** | VHDX Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `frxsvc` | **Cause:** Session lock |
| **222** | App-V Stream | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ from\ `Q:`` | **Cause:** Streaming |
| **223** | ThinPrint | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TPAutoConnect` | **Cause:** VDI Print |
| **224** | VMware Tools | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vmtoolsd` | **Cause:** Guest agent |
| **225** | WEM Agent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Norskale` | **Cause:** Environment mgmt |
| **226** | SCCM Agent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CcmExec` | **Cause:** Mgmt agent |
| **227** | SCCM Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ccmcache` | **Cause:** Download |
| **228** | Intune Mgmt | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Omadmclient` | **Cause:** MDM sync |
| **229** | AppLocker Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SrpUxNative` | **Cause:** Whitelisting |
| **230** | BitLocker Network | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FVE` | **Cause:** Boot unlock |

## SECTION 6: INSTALLERS & UPDATES (MSI, WU)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **231** | MSI Exec Start | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``msiexec\.exe`` | **Cause:** Install start |
| **232** | MSI Source Fail | **Op:** `*`<br>**Res:** `PATH\ NOT\ FOUND`<br>**Path:** `*` | **Cause:** Media missing |
| **233** | MSI Self Repair | **Op:** `*`<br>**Res:** `*`<br>**Path:** `msiexec` | **Cause:** Resiliency |
| **234** | MSI Rollback | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SetRename` | **Cause:** Fatal error |
| **235** | MSI Mutex | **Op:** `*`<br>**Res:** `*`<br>**Path:** `_MSIExecute` | **Cause:** Concurrent install |
| **236** | MSI Custom Action | **Op:** `*`<br>**Res:** `*`<br>**Path:** `cmd` | **Cause:** Script logic |
| **237** | MSI Cab Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Extract\ fail\ `%TEMP%`` | **Cause:** Disk/Perms |
| **238** | MSI Transform | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\.mst`\ missing` | **Cause:** Customization lost |
| **239** | Pending Reboot | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PendingFileRename` | **Cause:** Blocker |
| **240** | Windows Update Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wuauserv` | **Cause:** DB lock |
| **241** | CBS Manifest | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TrustedInstaller` | **Cause:** Corrupt OS |
| **242** | CatRoot2 Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `cryptsvc` | **Cause:** Catalog corrupt |
| **243** | SXS Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `winsxs` | **Cause:** Component store |
| **244** | Driver Store | **Op:** `*`<br>**Res:** `*`<br>**Path:** `drvstore` | **Cause:** Driver staging |
| **245** | TiWorker CPU | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TiWorker` | **Cause:** Post-install |
| **246** | Update Download | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SoftwareDistribution` | **Cause:** Patching |
| **247** | Bled/Hydrate | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** AppX |
| **248** | AppX Manifest | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AppxManifest\.xml` | **Cause:** Store App |
| **249** | AppX Deploy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AppXDeploymentServer` | **Cause:** Install fail |
| **250** | State Repo | **Op:** `*`<br>**Res:** `*`<br>**Path:** `StateRepository` | **Cause:** Store DB lock |

## SECTION 7: SECURITY & MALWARE INDICATORS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **251** | Run Key Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CurrentVersion\\Run` | **Cause:** Autostart |
| **252** | Startup Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Startup` | **Cause:** Autostart |
| **253** | Service Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Services` | **Cause:** Rootkit |
| **254** | Task Persistence | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Tasks` | **Cause:** Scheduled Task |
| **255** | Winlogon Persist | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Userinit` | **Cause:** Hijack |
| **256** | Image Hijack | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Image File Execution Options` | **Cause:** Debug hijack |
| **257** | AppInit Injection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AppInit_DLLs` | **Cause:** Dll inject |
| **258** | COM Hijack | **Op:** `*`<br>**Res:** `*`<br>**Path:** `InprocServer32` | **Cause:** Object hijack |
| **259** | Extension Hijack | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `txtfile\\shell\\open`` | **Cause:** Assoc hijack |
| **260** | Browser Helper | **Op:** `*`<br>**Res:** `*`<br>**Path:** `BHO` | **Cause:** Adware |
| **261** | Phantom DLL | **Op:** `*`<br>**Res:** `*`<br>**Path:** `version\.dll` | **Cause:** Sideloading |
| **262** | WMI Persist | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `Objects\.data`` | **Cause:** Fileless persist |
| **263** | Powershell Enc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `powershell -e` | **Cause:** Obfuscation |
| **264** | Powershell Download | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Net\.WebClient`` | **Cause:** Downloader |
| **265** | LoLBin CertUtil | **Op:** `*`<br>**Res:** `*`<br>**Path:** `certutil -urlcache` | **Cause:** Download |
| **266** | LoLBin Bits | **Op:** `*`<br>**Res:** `*`<br>**Path:** `bitsadmin /transfer` | **Cause:** Download |
| **267** | LoLBin Mshta | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mshta vbscript` | **Cause:** Execution |
| **268** | LoLBin Rundll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `rundll32 entrypoint` | **Cause:** Execution |
| **269** | LoLBin Regsvr | **Op:** `*`<br>**Res:** `*`<br>**Path:** `regsvr32 /s /u` | **Cause:** Squiblydoo |
| **270** | Credential Dump | **Op:** `*`<br>**Res:** `*`<br>**Path:** `lsass` | **Cause:** Mimikatz |
| **271** | SAM Dump | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SAM` | **Cause:** Hash dump |
| **272** | LSA Secret | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Policy\\Secrets` | **Cause:** Password dump |
| **273** | Vault Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vaultcmd` | **Cause:** Cred dump |
| **274** | Browser Data | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Login Data` | **Cause:** Cookie theft |
| **275** | Keylog Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetAsyncKeyState` | **Cause:** Spyware |
| **276** | Clipboard Monitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Spyware |
| **277** | Screen Capture | **Op:** `*`<br>**Res:** `*`<br>**Path:** `BitBlt` | **Cause:** Spyware |
| **278** | Mic Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WaveIn` | **Cause:** Eavesdrop |
| **279** | Webcam Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Video` | **Cause:** Spyware |
| **280** | Recon Whoami | **Op:** `*`<br>**Res:** `*`<br>**Path:** `whoami /all` | **Cause:** Discovery |
| **281** | Recon Net | **Op:** `*`<br>**Res:** `*`<br>**Path:** `net group` | **Cause:** Discovery |
| **282** | Recon IP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ipconfig /all` | **Cause:** Discovery |
| **283** | Recon Task | **Op:** `*`<br>**Res:** `*`<br>**Path:** `tasklist /svc` | **Cause:** AV check |
| **284** | Event Clear | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wevtutil cl` | **Cause:** Anti-forensics |
| **285** | Shadow Delete | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vssadmin delete` | **Cause:** Ransomware |
| **286** | Backup Stop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wbadmin delete` | **Cause:** Ransomware |
| **287** | Disable Def | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DisableRealtimeMonitoring` | **Cause:** AV Kill |
| **288** | Host File Mod | **Op:** `*`<br>**Res:** `*`<br>**Path:** `hosts` | **Cause:** Redirect |
| **289** | Timestomp | **Op:** `SetBasicInformationFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hiding |
| **290** | Masquerade | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``svchost`\ in\ `%TEMP%`` | **Cause:** Hiding |
| **291** | Ransom Rename | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Encryption |
| **292** | Ransom Write | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Encryption |
| **293** | DGA DNS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** C2 |
| **294** | Beaconing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** C2 |
| **295** | Tor Traffic | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Anon |
| **296** | PST Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.pst` | **Cause:** Email theft |
| **297** | SSH Keys | **Op:** `*`<br>**Res:** `*`<br>**Path:** `id_rsa` | **Cause:** Lateral move |
| **298** | RDP Saved | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Default\.rdp` | **Cause:** Lateral move |
| **299** | Wifi Keys | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Wlansvc` | **Cause:** Lateral move |
| **300** | Exfil FTP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ftp -s` | **Cause:** Data theft |

## SECTION 8: APPLICATION FRAMEWORKS (Java, .NET, Web)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **301** | .NET CLR Load | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mscoree\.dll`\ load` | **Cause:** .NET start |
| **302** | .NET GAC Load | **Op:** `*`<br>**Res:** `*`<br>**Path:** `C:\\Windows\\Assembly` | **Cause:** Global lib |
| **303** | .NET Temp | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `Temporary\ ASP\.NET\ Files`` | **Cause:** Compile |
| **304** | .NET Config | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `machine\.config`` | **Cause:** Settings |
| **305** | .NET JIT | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mscorjit\.dll` | **Cause:** Compilation |
| **306** | .NET NGEN | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ngen\.exe` | **Cause:** Optimization |
| **307** | Java Home | **Op:** `*`<br>**Res:** `*`<br>**Path:** `JAVA_HOME` | **Cause:** Config |
| **308** | Java Runtime | **Op:** `*`<br>**Res:** `*`<br>**Path:** `jvm\.dll` | **Cause:** Java start |
| **309** | Java Classpath | **Op:** `*`<br>**Res:** `*`<br>**Path:** `lib/ext` | **Cause:** Dependency |
| **310** | Java Access | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WindowsAccessBridge` | **Cause:** A11y |
| **311** | Python Path | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PYTHONPATH` | **Cause:** Config |
| **312** | Python Import | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `__init__\.py`` | **Cause:** Module load |
| **313** | Node Modules | **Op:** `*`<br>**Res:** `*`<br>**Path:** `node_modules` | **Cause:** JS dep |
| **314** | Electron Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GPUCache` | **Cause:** Chromium |
| **315** | IIS Worker | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``w3wp\.exe`\ start` | **Cause:** Web server |
| **316** | IIS Config | **Op:** `*`<br>**Res:** `*`<br>**Path:** `web\.config` | **Cause:** App settings |
| **317** | IIS Shared | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `applicationHost\.config`` | **Cause:** Server set |
| **318** | AppPool Identity | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Perms |
| **319** | Temp Path | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TEMP` | **Cause:** Scratch space |
| **320** | Oracle TNS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `tnsnames\.ora`` | **Cause:** DB Config |
| **321** | ODBC System | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\ODBC` | **Cause:** DSN |
| **322** | ODBC User | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Software\\ODBC` | **Cause:** DSN |
| **323** | SQL Driver | **Op:** `*`<br>**Res:** `*`<br>**Path:** `sqlncli\.dll` | **Cause:** Connectivity |
| **324** | OLEDB Reg | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCR\\CLSID\\\{Provider\}`` | **Cause:** Driver |
| **325** | UDL Read | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.udl` | **Cause:** Conn string |
| **326** | Report Viewer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Microsoft\.ReportViewer` | **Cause:** Reporting |
| **327** | Crystal Reports | **Op:** `*`<br>**Res:** `*`<br>**Path:** `crpe32\.dll` | **Cause:** Reporting |
| **328** | Flash OCX | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Flash\.ocx` | **Cause:** Legacy |
| **329** | Silverlight | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `npctrl\.dll`` | **Cause:** Legacy |
| **330** | ActiveX Killbit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Compatibility Flags` | **Cause:** Block |

## SECTION 9: HARDWARE & DRIVERS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **331** | USB Arrival | **Op:** `DeviceIoControl`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Connect |
| **332** | USB Removal | **Op:** `DeviceIoControl`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disconnect |
| **333** | USB Suspend | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Power |
| **334** | HID Input | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HidUsb` | **Cause:** Keyboard/Mouse |
| **335** | Bluetooth Enum | **Op:** `*`<br>**Res:** `*`<br>**Path:** `BthEnum` | **Cause:** Wireless |
| **336** | SmartCard Insert | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SCardSvr` | **Cause:** Auth |
| **337** | SmartCard Pipe | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SCardPipe` | **Cause:** Driver |
| **338** | GPU Reset | **Op:** `*`<br>**Res:** `*`<br>**Path:** `dxgkrnl` | **Cause:** Crash |
| **339** | GPU Throttling | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Thermal |
| **340** | Audio Excl | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AUDCLNT_E_DEVICE_IN_USE` | **Cause:** Lock |
| **341** | Audio Graph | **Op:** `*`<br>**Res:** `*`<br>**Path:** `audiodg` | **Cause:** Sound |
| **342** | Webcam Lock | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Privacy |
| **343** | Printer Bidirectional | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Status |
| **344** | Scanner Twain | **Op:** `*`<br>**Res:** `*`<br>**Path:** `twain_32\.dll` | **Cause:** Imaging |
| **345** | Serial Port | **Op:** `*`<br>**Res:** `*`<br>**Path:** `COM1` | **Cause:** Legacy IO |
| **346** | Parallel Port | **Op:** `*`<br>**Res:** `*`<br>**Path:** `LPT1` | **Cause:** Legacy IO |
| **347** | Tape Drive | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Tape0` | **Cause:** Backup |
| **348** | Battery Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `batmeter` | **Cause:** Power |
| **349** | ACPI Event | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ACPI` | **Cause:** Heat |
| **350** | BIOS Info | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Hardwaredescription\\System` | **Cause:** Firmware |

## SECTION 10: ACCESSIBILITY & UI

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **351** | UIA Prov Fail | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Automation |
| **352** | WM_GETOBJECT | **Op:** `*`<br>**Res:** `TIMEOUT`<br>**Path:** `*` | **Cause:** No response |
| **353** | Acc Name | **Op:** `*`<br>**Res:** `*`<br>**Path:** `accName` | **Cause:** Unlabeled |
| **354** | Focus Fight | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SetFocus` | **Cause:** Loop |
| **355** | High Contrast | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetSysColor` | **Cause:** Theme |
| **356** | Cursor Track | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetGUIThreadInfo` | **Cause:** Visual |
| **357** | Narrator Hook | **Op:** `*`<br>**Res:** `*`<br>**Path:** `NarratorHook` | **Cause:** Reader |
| **358** | JAB Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WindowsAccessBridge` | **Cause:** Java |
| **359** | Braille Lock | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Display |
| **360** | Speech Dict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Voice |

## SECTION 11: LEGACY & COMPATIBILITY

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **361** | INI Redirect | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `win\.ini`` | **Cause:** 16-bit |
| **362** | 16-bit App | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `ntvdm\.exe`` | **Cause:** DOS |
| **363** | Thunking | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `wow64\.dll`` | **Cause:** 32-on-64 |
| **364** | Shim Apply | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `sysmain\.sdb`` | **Cause:** Patches |
| **365** | DirectX 9 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `d3d9\.dll` | **Cause:** Old Gfx |
| **366** | VB6 Runtime | **Op:** `*`<br>**Res:** `*`<br>**Path:** `msvbvm60\.dll` | **Cause:** Basic |
| **367** | MFC 42 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mfc42\.dll` | **Cause:** C++ |
| **368** | 8.3 Path | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DOCUME\~1` | **Cause:** Shortname |
| **369** | Hardcoded Drv | **Op:** `*`<br>**Res:** `*`<br>**Path:** `D:\\` | **Cause:** Missing drive |
| **370** | CD Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CdRom0` | **Cause:** DRM |
| **371** | Admin Write | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VirtualStore` | **Cause:** UAC |
| **372** | Deprecated API | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WinExec` | **Cause:** Old code |
| **373** | Legacy Help | **Op:** `*`<br>**Res:** `*`<br>**Path:** `winhlp32\.exe` | **Cause:** .hlp |
| **374** | MAPI Mail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `mapi32\.dll`` | **Cause:** Email |
| **375** | NetDDE | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Ancient IPC |

## SECTION 12: CRYPTOGRAPHY & PKI

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **376** | Cert Store | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SystemCertificates` | **Cause:** Trust |
| **377** | Root Update | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Download\ `authroot\.stl`` | **Cause:** Update |
| **378** | CRL Fetch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HTTP\ fetch\ `\.crl`` | **Cause:** Revocation |
| **379** | OCSP Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Revocation |
| **380** | Chain Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CERT_E_CHAINING` | **Cause:** Trust path |
| **381** | Expired | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CERT_E_EXPIRED` | **Cause:** Date |
| **382** | Name Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CERT_E_CN_NO_MATCH` | **Cause:** SSL |
| **383** | MachineKey | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MachineKeys` | **Cause:** Private key |
| **384** | UserKey | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Protect` | **Cause:** Private key |
| **385** | DPAPI | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CryptUnprotectData` | **Cause:** Decryption |
| **386** | CNG Key | **Op:** `*`<br>**Res:** `*`<br>**Path:** `KeyStorage` | **Cause:** Modern key |
| **387** | FIPS Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FIPSAlgorithmPolicy` | **Cause:** Compliance |
| **388** | Hash Fail | **Op:** `*`<br>**Res:** `STATUS\ INVALID\ IMAGE\ HASH`<br>**Path:** `*` | **Cause:** Sign |
| **389** | Catalog DB | **Op:** `*`<br>**Res:** `*`<br>**Path:** `catdb` | **Cause:** Sig DB |
| **390** | RNG Seed | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RNG` | **Cause:** Random |

## SECTION 13: CLOUD & HYBRID (Azure/M365)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **391** | AAD Token | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TokenBroker` | **Cause:** SSO |
| **392** | Workplace Join | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WorkplaceJoin` | **Cause:** Registration |
| **393** | Ngc Key | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Ngc` | **Cause:** Hello for Bus |
| **394** | M365 Activate | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Connect\ `office\.com`` | **Cause:** Licensing |
| **395** | OneDrive Sync | **Op:** `*`<br>**Res:** `*`<br>**Path:** `OneDrive` | **Cause:** Cloud file |
| **396** | Azure Info | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Tenants` | **Cause:** Identity |
| **397** | MDM Policy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PolicyManager` | **Cause:** Intune |
| **398** | Entra ID | **Op:** `*`<br>**Res:** `*`<br>**Path:** `dsregcmd` | **Cause:** Join status |
| **399** | Compliance | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HealthAttestation` | **Cause:** Security |
| **400** | Telemetry | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CompatTelRunner` | **Cause:** Diag data |

## SECTION 14: SPECIFIC SOFTWARE PATTERNS (The "Top Hitters")

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **401** | Chrome Profile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SingletonLock` | **Cause:** Stuck |
| **402** | Chrome Ext | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Extensions` | **Cause:** Add-on |
| **403** | Edge Update | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MicrosoftEdgeUpdate` | **Cause:** Patch |
| **404** | Firefox Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``parent\.lock`` | **Cause:** Stuck |
| **405** | Teams Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Code Cache` | **Cause:** Performance |
| **406** | Teams Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `logs\.txt` | **Cause:** Diag |
| **407** | Outlook OST | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.ost` | **Cause:** Disk IO |
| **408** | Outlook OAB | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Offline Address Books` | **Cause:** Sync |
| **409** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `\.xll`` | **Cause:** Extension |
| **410** | Word Template | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Normal\.dotm` | **Cause:** Config |
| **411** | Adobe Reader | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AcroRd32\.dll` | **Cause:** PDF |
| **412** | Adobe Arm | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``AdobeARM\.exe`` | **Cause:** Update |
| **413** | Zoom Cpt | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``CptHost\.exe`` | **Cause:** Sharing |
| **414** | WebEx Service | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WebExService` | **Cause:** Meeting |
| **415** | Slack Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Cache` | **Cause:** Electron |
| **416** | VSCode IPC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vscode-ipc` | **Cause:** Dev |
| **417** | Docker Pipe | **Op:** `*`<br>**Res:** `*`<br>**Path:** `docker_engine` | **Cause:** Container |
| **418** | Kubernetes | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.kube` | **Cause:** Config |
| **419** | Git Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `index\.lock`` | **Cause:** Repo |
| **420** | Npm Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `_cacache` | **Cause:** Dev |
| **421** | McAfee Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mcshield\.exe`` | **Cause:** AV |
| **422** | Symantec Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``ccSvcHst\.exe`` | **Cause:** AV |
| **423** | CrowdStrike | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CSFalconService` | **Cause:** EDR |
| **424** | SentinelOne | **Op:** `*`<br>**Res:** `*`<br>**Path:** `LogProcessor` | **Cause:** EDR |
| **425** | Splunk Fwd | **Op:** `*`<br>**Res:** `*`<br>**Path:** `splunk-optimize` | **Cause:** Log |
| **426** | Tanium Client | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TaniumClient` | **Cause:** Mgmt |
| **427** | Qualys Agent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `QualysAgent` | **Cause:** Scan |
| **428** | Nessus Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Vuln Scan |
| **429** | Datadog | **Op:** `*`<br>**Res:** `*`<br>**Path:** `datadog-agent` | **Cause:** Monitor |
| **430** | NewRelic | **Op:** `*`<br>**Res:** `*`<br>**Path:** `newrelic-infra` | **Cause:** Monitor |
| **431** | Veeam Agent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VeeamAgent` | **Cause:** Backup |
| **432** | Commvault | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ClMgrS` | **Cause:** Backup |
| **433** | Backup Exec | **Op:** `*`<br>**Res:** `*`<br>**Path:** `beremote` | **Cause:** Backup |
| **434** | Dropbox Watch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Dropbox` | **Cause:** Sync |
| **435** | Box Sync | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Box` | **Cause:** Sync |

## SECTION 15: ADVANCED MEMORY & DEBUGGING

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **436** | Heap Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RtlFreeHeap` | **Cause:** Memory |
| **437** | Double Free | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Crash |
| **438** | Use After Free | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Exploit |
| **439** | Null Pointer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bug |
| **440** | Buffer Overrun | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Security |
| **441** | Stack Exhaust | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Recursion` | **Cause:** Overflow |
| **442** | Handle Invalid | **Op:** `CloseHandle`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Logic |
| **443** | CritSec Timeout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hang |
| **444** | Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hang |
| **445** | LPC Wait | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** IPC Hang |
| **446** | Memory Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Leak |
| **447** | GDI Objects | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Limit |
| **448** | User Objects | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Limit |
| **449** | Thread Count | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Spam |
| **450** | Handle Count | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Leak |

## SECTION 16: SYSTEM CONFIGURATION & BOOT

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **451** | Boot Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `ntbtlog\.txt`` | **Cause:** Diag |
| **452** | Setup Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `setupapi\.dev\.log` | **Cause:** Driver |
| **453** | CBS Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `cbs\.log`` | **Cause:** Update |
| **454** | DISM Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `dism\.log`` | **Cause:** Image |
| **455** | Events Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.evtx` | **Cause:** Audit |
| **456** | WMI Repo | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `Index\.btr`` | **Cause:** Mgmt |
| **457** | SRU DB | **Op:** `*`<br>**Res:** `*`<br>**Path:** `srudb\.dat` | **Cause:** Usage |
| **458** | Prefetch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `\.pf`` | **Cause:** Optimize |
| **459** | Superfetch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SysMain` | **Cause:** Cache |
| **460** | Search Index | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SearchIndexer` | **Cause:** Index |
| **461** | Cortana | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SearchUI` | **Cause:** Shell |
| **462** | Start Menu | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ShellExperienceHost` | **Cause:** UI |
| **463** | Action Center | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ActionCenter` | **Cause:** Notify |
| **464** | Settings App | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SystemSettings` | **Cause:** Config |
| **465** | Task Manager | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Taskmgr` | **Cause:** Admin |
| **466** | Resource Mon | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Perfmon` | **Cause:** Admin |
| **467** | Event Viewer | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mmc\.exe`` | **Cause:** Admin |
| **468** | Reg Editor | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``regedit\.exe`` | **Cause:** Admin |
| **469** | CMD Shell | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``cmd\.exe`` | **Cause:** Shell |
| **470** | PowerShell | **Op:** `*`<br>**Res:** `*`<br>**Path:** `powershell\.exe` | **Cause:** Shell |
| **471** | Run Dialog | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``explorer\.exe`\ Run` | **Cause:** Shell |
| **472** | LogonUI | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``LogonUI\.exe`` | **Cause:** Auth |
| **473** | WinInit | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``wininit\.exe`` | **Cause:** Boot |
| **474** | LSM | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``lsm\.exe`` | **Cause:** Session |
| **475** | Smss | **Op:** `*`<br>**Res:** `*`<br>**Path:** `smss\.exe` | **Cause:** Session |

## SECTION 17: WINDOWS SUBSYSTEM FOR LINUX (WSL)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **476** | WSL Host | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``wslhost\.exe`` | **Cause:** Kernel |
| **477** | WSL File | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Access\ `\\\\wsl\$`` | **Cause:** Network |
| **478** | WSL Config | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `\.wslconfig`` | **Cause:** Settings |
| **479** | Lxss Manager | **Op:** `*`<br>**Res:** `*`<br>**Path:** `LxssManager` | **Cause:** Svc |
| **480** | Plan 9 FS | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``p9rdr\.sys`` | **Cause:** Filesystem |
| **481** | Bash Exec | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``bash\.exe`` | **Cause:** Shell |
| **482** | Linux Binary | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Compat |
| **483** | WSL Network | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Connect |
| **484** | WSL Mount | **Op:** `*`<br>**Res:** `*`<br>**Path:** `drvfs` | **Cause:** Storage |
| **485** | WSL2 VHD | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ext4\.vhdx` | **Cause:** Disk |

## SECTION 18: GAMING & MEDIA (DirectX/Audio)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **486** | Game Mode | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GameBar\.exe` | **Cause:** Overlay |
| **487** | DVR Store | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.mp4` | **Cause:** Record |
| **488** | Steam Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SteamService` | **Cause:** Platform |
| **489** | Epic Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `EpicGamesLauncher` | **Cause:** Platform |
| **490** | Origin Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Origin` | **Cause:** Platform |
| **491** | Discord Overlay | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Discord` | **Cause:** Hook |
| **492** | OBS Hook | **Op:** `*`<br>**Res:** `*`<br>**Path:** `graphics-hook` | **Cause:** Capture |
| **493** | XInput | **Op:** `*`<br>**Res:** `*`<br>**Path:** `xinput` | **Cause:** Controller |
| **494** | DirectInput | **Op:** `*`<br>**Res:** `*`<br>**Path:** `dinput` | **Cause:** Controller |
| **495** | Vulkan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vulkan\-1\.dll` | **Cause:** Graphics |
| **496** | OpenGL | **Op:** `*`<br>**Res:** `*`<br>**Path:** `opengl32\.dll` | **Cause:** Graphics |
| **497** | OpenCL | **Op:** `*`<br>**Res:** `*`<br>**Path:** `OpenCL\.dll` | **Cause:** Compute |
| **498** | PhysX | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PhysX` | **Cause:** Physics |
| **499** | Shader Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `D3DSCache` | **Cause:** Perf |
| **500** | Refresh Rate | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ChangeDisplaySettings` | **Cause:** Hz |

## SECTION 19: GROUP POLICY & REGISTRY POLLING (The "Noise")

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **501** | Policy Poll (Explorer) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer` | **Cause:** UI restrictions |
| **502** | Policy Poll (System) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System`` | **Cause:** UAC/Logon |
| **503** | Policy Poll (Assoc) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts` | **Cause:** Assoc hijacking |
| **504** | Policy Poll (IE) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\Policies\\Microsoft\\Internet\ Explorer` | **Cause:** Browser lock |
| **505** | Policy Poll (Edge) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\Policies\\Microsoft\\Edge` | **Cause:** Browser lock |
| **506** | Policy Poll (Chrome) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\Policies\\Google\\Chrome` | **Cause:** Browser lock |
| **507** | Policy Poll (Office) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCU\\Software\\Policies\\Microsoft\\Office`` | **Cause:** Macro settings |
| **508** | Policy Poll (Defender) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\Policies\\Microsoft\\Windows\ Defender` | **Cause:** AV settings |
| **509** | Policy Poll (Update) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate` | **Cause:** Patching |
| **510** | Policy Poll (Power) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\Software\\Policies\\Microsoft\\Power\\PowerSettings`` | **Cause:** Sleep/Wake |
| **511** | Background Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCU\\Control\ Panel\\Desktop\\Wallpaper`` | **Cause:** GPO Refresh |
| **512** | ScreenSaver Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Control\ Panel\\Desktop\\ScreenSaveActive` | **Cause:** Lockout |
| **513** | TimeOut Poll | **Op:** `*`<br>**Res:** `TIMEOUT`<br>**Path:** `*` | **Cause:** Lockout |
| **514** | Theme Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\ThemeManager`` | **Cause:** Visuals |
| **515** | Color Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Control\ Panel\\Colors` | **Cause:** High Contrast |
| **516** | Cursor Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\Control\ Panel\\Cursors` | **Cause:** Accessibility |
| **517** | Sound Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKCU\\AppEvents\\Schemes` | **Cause:** Audio feedback |
| **518** | Icon Cache Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell\ Icons`` | **Cause:** Overlays |
| **519** | Drive Map Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCU\\Network`` | **Cause:** Mapped Drives |
| **520** | Printer Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKCU\\Printers`` | **Cause:** Default printer |
| **521** | MUI Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\MUI\\Settings`` | **Cause:** Language |
| **522** | TimeZone Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation`` | **Cause:** Clock |
| **523** | Network List Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\NetworkList`` | **Cause:** NLA |
| **524** | Firewall Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy` | **Cause:** Rules |
| **525** | Audit Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\SECURITY\\Policy\\PolAdtEv` | **Cause:** Event generation |
| **526** | LSA Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa`` | **Cause:** Auth |
| **527** | Schannel Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL`` | **Cause:** TLS/SSL |
| **528** | FIPS Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy` | **Cause:** Crypto |
| **529** | Winlogon Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `HKLM\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Winlogon`` | **Cause:** Shell |
| **530** | AppInit Poll | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HKLM\\SOFTWARE\\Microsoft\\Windows\ NT\\CurrentVersion\\Windows\\AppInit_DLLs` | **Cause:** Injection |

## SECTION 20: WINDOWS SERVICES (Specific Detection)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **531** | Spooler Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``spoolsv\.exe`\ Exit\ Code\ !=\ 0` | **Cause:** Print |
| **532** | Audio Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``audiodg\.exe`\ Exit\ Code\ !=\ 0` | **Cause:** Sound |
| **533** | DWM Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``dwm\.exe`\ Exit\ Code\ !=\ 0` | **Cause:** Graphics |
| **534** | Search Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SearchIndexer\.exe` | **Cause:** Index |
| **535** | WMI Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WmiPrvSE\.exe`\ Exit\ Code\ !=\ 0` | **Cause:** Mgmt |
| **536** | Update Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TiWorker\.exe` | **Cause:** Install |
| **537** | Defender Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``MsMpEng\.exe`\ Exit\ Code\ !=\ 0` | **Cause:** AV |
| **538** | Firewall Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mpssvc` | **Cause:** Security |
| **539** | EventLog Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wevtsvc` | **Cause:** Audit |
| **540** | TaskSched Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``taskeng\.exe`\ Exit` | **Cause:** Tasks |
| **541** | Explorer Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Explorer\.exe`\ Exit` | **Cause:** Shell |
| **542** | LogonUI Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``LogonUI\.exe`\ Exit` | **Cause:** Login |
| **543** | Lsass Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `lsass\.exe` | **Cause:** Reboot |
| **544** | Csrss Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``csrss\.exe`\ Exit` | **Cause:** BSOD |
| **545** | Smss Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `smss\.exe` | **Cause:** BSOD |
| **546** | Svchost Split | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``svchost\.exe\ \-k\ netsvcs`\ High\ CPU` | **Cause:** Shared |
| **547** | Svchost Dcom | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``svchost\.exe\ \-k\ DcomLaunch`\ High\ CPU` | **Cause:** RPC |
| **548** | Svchost RPC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `svchost\.exe\ \-k\ RpcSs` | **Cause:** RPC |
| **549** | Svchost Local | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``svchost\.exe\ \-k\ LocalService`\ High\ CPU` | **Cause:** Background |
| **550** | Svchost Net | **Op:** `*`<br>**Res:** `*`<br>**Path:** `svchost\.exe\ \-k\ NetworkService` | **Cause:** Network |
| **551** | SysMain Busy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `svchost\.exe\ \-k\ sysmain` | **Cause:** Superfetch |
| **552** | DiagTrack Busy | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``svchost\.exe\ \-k\ utisvc`\ Disk\ I` | **Cause:** Telemetry |
| **553** | Bits Busy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `svchost\.exe\ \-k\ netsvcs` | **Cause:** Download |
| **554** | WinDefend Busy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MsMpEng\.exe` | **Cause:** Scan |
| **555** | TrustedInstall | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TrustedInstaller\.exe` | **Cause:** Update |
| **556** | WMI Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WmiPrvSE\.exe`\ High\ CPU` | **Cause:** Query storm |
| **557** | WMI Provider | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WmiPrvSE`\ loading\ `cimwin32\.dll`` | **Cause:** Inventory |
| **558** | WMI Storage | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WmiPrvSE`\ loading\ `storagewmi\.dll`` | **Cause:** Disk check |
| **559** | WMI Net | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wmidex\.dll` | **Cause:** Net check |
| **560** | WMI Event | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WmiPrvSE`\ loading\ `wbemess\.dll`` | **Cause:** Event sub |

## SECTION 21: COM/DCOM CLSIDs (Common Failures)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **561** | FSO Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{0D43FE01-F093-11CF-8940-00A0C9054228}` | **Cause:** FileSystemObject |
| **562** | Shell Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{13709620-C279-11CE-A49E-444553540000}` | **Cause:** Shell.Application |
| **563** | WScript Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{72C24DD5-D70A-438B-8A42-98424B88AFB8}` | **Cause:** WScript.Shell |
| **564** | ADODB Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{00000514-0000-0010-8000-00AA006D2EA4}` | **Cause:** Database |
| **565** | XMLDOM Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{2933BF90-7B36-11D2-B20E-00C04F983E60}` | **Cause:** XML Parser |
| **566** | HTTPReq Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{88D96A0A-F192-11D4-A65F-0040963251E5}` | **Cause:** WinHTTP |
| **567** | BITS Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{4991D34B-80A1-4291-83B6-3328366B9097}` | **Cause:** Background Transfer |
| **568** | TaskSched Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}` | **Cause:** Scheduler |
| **569** | Firewall Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{F7898AF5-CAC4-4632-A2EC-DA06E5111AF2}` | **Cause:** NetFwPolicy |
| **570** | Update Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{4CB43D7F-7EEE-4906-8698-60DA1C38F2FE}` | **Cause:** WindowsUpdate |
| **571** | Installer Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{000C1090-0000-0000-C000-000000000046}` | **Cause:** MSI |
| **572** | WMI Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{4590F811-1D3A-11D0-891F-00AA004B2E24}` | **Cause:** WbemLocator |
| **573** | Speech Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{96749377-3391-11D2-9EE3-00C04F797396}` | **Cause:** SAPI |
| **574** | Search Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{9E175B8D-F52A-11D8-B9A5-505054503030}` | **Cause:** WindowsSearch |
| **575** | ImgUtil Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{557CF406-1A04-11D3-9A73-0000F81EF32E}` | **Cause:** ImageUtil |
| **576** | Scriptlet Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{06290BD5-48AA-11D2-8432-006008C3FBFC}` | **Cause:** Scriptlet |
| **577** | HTA Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{3050F4D8-98B5-11CF-BB82-00AA00BDCE0B}` | **Cause:** HTML App |
| **578** | ShellWin Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}` | **Cause:** ShellWindows |
| **579** | Folder Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{F3364BA0-65B9-11CE-A9BA-00AA004AE837}` | **Cause:** ShellFolder |
| **580** | Link Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `{00021401-0000-0000-C000-000000000046}` | **Cause:** ShellLink |

## SECTION 22: ERROR CODES (NTSTATUS / WIN32)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **581** | Access Denied | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000022` | **Cause:** Permission |
| **582** | Object Found | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000000` | **Cause:** Success |
| **583** | Not Found | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000034` | **Cause:** Missing |
| **584** | Sharing Vio | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000043` | **Cause:** Locked |
| **585** | Privilege | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000061` | **Cause:** Elevation req |
| **586** | Disk Full | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000007F` | **Cause:** Space |
| **587** | Mem Full | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000017` | **Cause:** RAM/Commit |
| **588** | Timeout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC00000B5` | **Cause:** Wait |
| **589** | Pipe Busy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC00000AE` | **Cause:** Load |
| **590** | Pipe Broken | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000014B` | **Cause:** Disconnect |
| **591** | Net Unreach | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000023C` | **Cause:** Route |
| **592** | Host Unreach | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000023D` | **Cause:** Target |
| **593** | Conn Refused | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000236` | **Cause:** Port |
| **594** | Addr In Use | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000020A` | **Cause:** Conflict |
| **595** | Proc Limit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000012D` | **Cause:** Job limit |
| **596** | Quota | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000044` | **Cause:** Disk quota |
| **597** | Cancel | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000120` | **Cause:** User abort |
| **598** | Buffer Over | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000023` | **Cause:** Data size |
| **599** | Not Impl | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000002` | **Cause:** API missing |
| **600** | Invalid Param | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC000000D` | **Cause:** Bad call |
| **601** | Invalid Handle | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000008` | **Cause:** Logic bug |
| **602** | DLL Init | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000142` | **Cause:** Loader fail |
| **603** | Entry Point | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000139` | **Cause:** Version fail |
| **604** | Ordinal | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000138` | **Cause:** Export fail |
| **605** | SideBySide | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000365` | **Cause:** Manifest |
| **606** | Hashing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000428` | **Cause:** Signature |
| **607** | Delete Pend | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000056` | **Cause:** Zombie file |
| **608** | Directory | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000103` | **Cause:** Is not dir |
| **609** | Reparse | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC0000275` | **Cause:** Symlink |
| **610** | EAS Policy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `0xC00002D0` | **Cause:** Password complexity |

## SECTION 23: OFFICE & PRODUCTIVITY (Specifics)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **611** | Word Template | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Normal\.dotm` | **Cause:** Corruption |
| **612** | Word Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.wll` | **Cause:** Plugin |
| **613** | Excel Calc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `High\ CPU\ `EXCEL\.EXE`` | **Cause:** Calculation |
| **614** | Excel OLE | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Splwow64` | **Cause:** Print/PDF |
| **615** | Excel Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.xla` | **Cause:** Plugin |
| **616** | Outlook OST | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.ost` | **Cause:** Lock |
| **617** | Outlook Index | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SearchProtocolHost` | **Cause:** Index |
| **618** | Outlook RPC | **Op:** `TCP\ Connect`<br>**Res:** `*`<br>**Path:** `outlook\.office365\.com` | **Cause:** Net |
| **619** | Outlook Autodiscover | **Op:** `*`<br>**Res:** `*`<br>**Path:** `autodiscover\.xml` | **Cause:** Config |
| **620** | Outlook Addin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `outlvba\.dll`` | **Cause:** Macro |
| **621** | Access Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.ldb` | **Cause:** Record lock |
| **622** | Access ODBC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `odbc32\.dll` | **Cause:** Driver |
| **623** | PowerPoint Media | **Op:** `*`<br>**Res:** `*`<br>**Path:** `pflash\.dll` | **Cause:** Flash |
| **624** | OneNote Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.bin` | **Cause:** Sync |
| **625** | Office Update | **Op:** `*`<br>**Res:** `*`<br>**Path:** `OfficeClickToRun\.exe` | **Cause:** Update |
| **626** | Office License | **Op:** `*`<br>**Res:** `*`<br>**Path:** `OSPP\.VBS` | **Cause:** Activation |
| **627** | Office Telemetry | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mso\.dll` | **Cause:** Diag |
| **628** | Teams Status | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ub_` | **Cause:** Presence |
| **629** | Teams Mtg | **Op:** `UDP\ Send`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Media |
| **630** | Skype Mtg | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``lync\.exe`\ activity` | **Cause:** Legacy |

## SECTION 24: BROWSER INTERNALS (Chrome/Edge)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **631** | Chrome Prefs | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Preferences` | **Cause:** Corruption |
| **632** | Chrome Local | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Local State` | **Cause:** Config |
| **633** | Chrome Policy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CloudManagement` | **Cause:** Mgmt |
| **634** | Chrome Ext | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `manifest\.json`\ fail` | **Cause:** Addon |
| **635** | Chrome GPU | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GpuProcess` | **Cause:** Driver |
| **636** | Chrome Render | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Renderer` | **Cause:** Page |
| **637** | Chrome Sandbox | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Broker` | **Cause:** Security |
| **638** | Edge Update | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MicrosoftEdgeUpdate\.exe` | **Cause:** Patch |
| **639** | Edge IE Mode | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ieexplore\.exe` | **Cause:** Compat |
| **640** | Edge WebView | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``msedgewebview2\.exe`\ crash` | **Cause:** App |
| **641** | Cookie Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Cookies` | **Cause:** Sync |
| **642** | History Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `History` | **Cause:** Sync |
| **643** | Cache Size | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Cache_Data` | **Cause:** Space |
| **644** | Download Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Download` | **Cause:** Delay |
| **645** | Cert Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Root` | **Cause:** SSL |
| **646** | Proxy Script | **Op:** `*`<br>**Res:** `TIMEOUT`<br>**Path:** `\.pac` | **Cause:** Net |
| **647** | DNS Pre-fetch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Speed |
| **648** | QUIC Proto | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Google Net |
| **649** | WebRTC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Media |
| **650** | Flash Load | **Op:** `*`<br>**Res:** `*`<br>**Path:** `pepflashplayer` | **Cause:** Legacy |

## SECTION 25: DRIVERS & KERNEL MODULES (.SYS)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **651** | NTFS Driver | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``ntfs\.sys`\ activity` | **Cause:** Disk |
| **652** | Filter Mgr | **Op:** `*`<br>**Res:** `*`<br>**Path:** `fltmgr\.sys` | **Cause:** Filters |
| **653** | TCP/IP | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``tcpip\.sys`\ activity` | **Cause:** Net |
| **654** | NetBIOS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `netbt\.sys` | **Cause:** Legacy |
| **655** | AFD Driver | **Op:** `*`<br>**Res:** `*`<br>**Path:** `afd\.sys` | **Cause:** Sock |
| **656** | WFP Driver | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``fwpkclnt\.sys`\ activity` | **Cause:** Firewall |
| **657** | NDIS Driver | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``ndis\.sys`\ activity` | **Cause:** NIC |
| **658** | Storport | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``storport\.sys`\ activity` | **Cause:** SAN |
| **659** | USB Port | **Op:** `*`<br>**Res:** `*`<br>**Path:** `usbport\.sys` | **Cause:** Bus |
| **660** | USB Hub | **Op:** `*`<br>**Res:** `*`<br>**Path:** `usbhub\.sys` | **Cause:** Bus |
| **661** | HID Class | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``hidclass\.sys`\ activity` | **Cause:** Input |
| **662** | Mouse Class | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mouclass\.sys`\ activity` | **Cause:** Input |
| **663** | Kbd Class | **Op:** `*`<br>**Res:** `*`<br>**Path:** `kbdclass\.sys` | **Cause:** Input |
| **664** | Graphics | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``dxgkrnl\.sys`\ activity` | **Cause:** GPU |
| **665** | Nvidia | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``nvlddmkm\.sys`\ activity` | **Cause:** GPU |
| **666** | AMD | **Op:** `*`<br>**Res:** `*`<br>**Path:** `atikmdag\.sys` | **Cause:** GPU |
| **667** | Intel Gfx | **Op:** `*`<br>**Res:** `*`<br>**Path:** `igdkmd64\.sys` | **Cause:** GPU |
| **668** | Realtek Audio | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``rtkvhd64\.sys`\ activity` | **Cause:** Sound |
| **669** | Symantec Filter | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``symefasi\.sys`` | **Cause:** AV |
| **670** | McAfee Filter | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mfehidk\.sys`` | **Cause:** AV |
| **671** | CrowdStrike | **Op:** `*`<br>**Res:** `*`<br>**Path:** `csagent\.sys` | **Cause:** EDR |
| **672** | SentinelOne | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``SentinelMonitor\.sys`` | **Cause:** EDR |
| **673** | CarbonBlack | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``cbk7\.sys`` | **Cause:** EDR |
| **674** | Sysmon | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``SysmonDrv\.sys`` | **Cause:** Log |
| **675** | ProcMon | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PROCMON24\.SYS` | **Cause:** Self |
| **676** | VMware Mouse | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vmmouse\.sys` | **Cause:** Guest |
| **677** | VMware Video | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vm3dmp\.sys` | **Cause:** Guest |
| **678** | Citrix Net | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ctxtcp\.sys` | **Cause:** VDI |
| **679** | Citrix Usb | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ctxusbm\.sys` | **Cause:** VDI |
| **680** | FSLogix | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``frxdrv\.sys`` | **Cause:** Profile |

## SECTION 26: NETWORK PROTOCOLS (Expanded)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **681** | DHCP Renew | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** IP |
| **682** | NTP Sync | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Time |
| **683** | SNMP Query | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Mgmt |
| **684** | Syslog Send | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Log |
| **685** | LDAP SSL | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Auth |
| **686** | Global Cat | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** AD |
| **687** | GC SSL | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** AD |
| **688** | SQL Browser | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** DB |
| **689** | RDP Gateway | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Tunnel |
| **690** | WinRM HTTP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Mgmt |
| **691** | WinRM HTTPS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Mgmt |
| **692** | RPC Mapper | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** DCOM |
| **693** | NetBIOS Name | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Name |
| **694** | NetBIOS Data | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Data |
| **695** | NetBIOS Sess | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Sess |
| **696** | SMB Direct | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** File |
| **697** | VNC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Remote |
| **698** | ICA (Citrix) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** VDI |
| **699** | CGP (Citrix) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** VDI |
| **700** | Blast (VMware) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** VDI |
| **701** | PCoIP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** VDI |
| **702** | BitTorrent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** P2P |
| **703** | Spotify | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Media |
| **704** | Steam | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Game |
| **705** | Xbox Live | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Game |
| **706** | Teredo | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Tunnel |
| **707** | LLMNR | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Local DNS |
| **708** | SSDP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** UPnP |
| **709** | WS-Discovery | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disco |
| **710** | mDNS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bonjour |

## SECTION 27: POWERSHELL & SCRIPTING (Expanded)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **711** | PS Version | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PowerShellVersion` | **Cause:** Compat |
| **712** | PS Module | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PSModulePath` | **Cause:** Load |
| **713** | PS Profile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Microsoft\.PowerShell_profile\.ps1` | **Cause:** Config |
| **714** | PS History | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ConsoleHost_history\.txt` | **Cause:** Log |
| **715** | PS Execution | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ExecutionPolicy` | **Cause:** Security |
| **716** | PS Transcript | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `Transcript\.txt`` | **Cause:** Log |
| **717** | PS Gallery | **Op:** `*`<br>**Res:** `*`<br>**Path:** `powershellgallery\.com` | **Cause:** Download |
| **718** | PS Remoting | **Op:** `*`<br>**Res:** `*`<br>**Path:** `wsman` | **Cause:** Remote |
| **719** | PS Constrained | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ConstrainedLanguage` | **Cause:** Security |
| **720** | PS Logging | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ScriptBlockLogging` | **Cause:** Audit |
| **721** | VBS Engine | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vbscript\.dll` | **Cause:** Legacy |
| **722** | JS Engine | **Op:** `*`<br>**Res:** `*`<br>**Path:** `jscript\.dll` | **Cause:** Legacy |
| **723** | WSF File | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Exec\ `\.wsf`` | **Cause:** Mixed |
| **724** | HTA App | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Exec\ `\.hta`` | **Cause:** UI |
| **725** | Batch File | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.bat` | **Cause:** Shell |
| **726** | Cmd File | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Exec\ `\.cmd`` | **Cause:** Shell |
| **727** | Python Script | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.py` | **Cause:** Dev |
| **728** | Perl Script | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.pl` | **Cause:** Dev |
| **729** | Ruby Script | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Exec\ `\.rb`` | **Cause:** Dev |
| **730** | Jar File | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.jar` | **Cause:** Java |

## SECTION 28: FORENSICS & ARTIFACTS (Filesystem)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **731** | Prefetch Create | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `.*\.pf`` | **Cause:** Exec |
| **732** | Recent Docs | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Recent` | **Cause:** Access |
| **733** | JumpList | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AutomaticDestinations` | **Cause:** Access |
| **734** | ShellBag | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Shell\\Bags` | **Cause:** Folder view |
| **735** | UserAssist | **Op:** `*`<br>**Res:** `*`<br>**Path:** `UserAssist` | **Cause:** Exec count |
| **736** | ShimCache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AppCompatCache` | **Cause:** Compat |
| **737** | Amcache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Amcache\.hve` | **Cause:** Inventory |
| **738** | SRUM | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SRUDB\.dat` | **Cause:** Usage |
| **739** | ThumbCache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `thumbcache_.*\.db` | **Cause:** Image |
| **740** | IconCache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `IconCache\.db`` | **Cause:** Icon |
| **741** | Recycle Bin | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\$Recycle\.Bin` | **Cause:** Delete |
| **742** | MFT Record | **Op:** `*`<br>**Res:** `*`<br>**Path:** `$MFT` | **Cause:** Meta |
| **743** | LogFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `$LogFile` | **Cause:** Journal |
| **744** | USN | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `\$Extend\\\$UsnJrnl`` | **Cause:** Change |
| **745** | Index DB | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `Windows\.edb`` | **Cause:** Search |
| **746** | Event Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Security\.evtx` | **Cause:** Audit |
| **747** | WER Report | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Report\.wer` | **Cause:** Crash |
| **748** | Dump File | **Op:** `*`<br>**Res:** `*`<br>**Path:** `memory\.dmp` | **Cause:** Crash |
| **749** | Mini Dump | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Minidump` | **Cause:** Crash |
| **750** | Hibernation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `hiberfil\.sys` | **Cause:** Power |

## SECTION 29: INSTALLATION & SETUP (Logs)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **751** | SetupAPI | **Op:** `*`<br>**Res:** `*`<br>**Path:** `setupapi\.dev\.log` | **Cause:** Driver |
| **752** | CBS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `CBS\.log`` | **Cause:** OS |
| **753** | DISM | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `dism\.log`` | **Cause:** Image |
| **754** | WindowsUpdate | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WindowsUpdate\.log` | **Cause:** Patch |
| **755** | MSI Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `MSI.*\.log`` | **Cause:** App |
| **756** | DirectX | **Op:** `*`<br>**Res:** `DXError\.log`<br>**Path:** `*` | **Cause:** Graphics |
| **757** | DotNet | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `dd_.*\.log`` | **Cause:** Runtime |
| **758** | VCRedist | **Op:** `*`<br>**Res:** `*`<br>**Path:** `dd_vcredist.*\.log` | **Cause:** Runtime |
| **759** | SQL Setup | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `Summary\.txt`` | **Cause:** DB |
| **760** | IIS Setup | **Op:** `*`<br>**Res:** `*`<br>**Path:** `iis\.log` | **Cause:** Web |
| **761** | SCCM Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `ccmsetup\.log`` | **Cause:** Mgmt |
| **762** | Intune Log | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `IntuneManagementExtension\.log`` | **Cause:** Mgmt |
| **763** | Sysprep | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `setupact\.log`` | **Cause:** Image |
| **764** | Unattend | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `unattend\.xml`` | **Cause:** Config |
| **765** | Panther | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `\\Panther`` | **Cause:** Setup |

## SECTION 30: "THE MARK RUSSINOVICH CLASSICS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **766** | LoadString Fail | **Op:** `*`<br>**Res:** `Resource\ load\ fail\ \->\ Blank\ Error\.`<br>**Path:** `*` | **Context:** Resource load fail -> Blank Error. |
| **767** | CreateFile Directory | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Context:** Opening Dir as File -> Access Denied. |
| **768** | Delete Pending | **Op:** `*`<br>**Res:** `*`<br>**Path:** `File\ locked\ by\ previous\ delete\ \->\ Install\ Fail\.` | **Context:** File locked by previous delete -> Install Fail. |
| **769** | HKCU Override | **Op:** `*`<br>**Res:** `*`<br>**Path:** `User\ key\ hiding\ System\ key\.` | **Context:** User key hiding System key. |
| **770** | Environment Var | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``%SystemRoot%`\ literal\ lookup\.` | **Context:** `%SystemRoot%` literal lookup. |
| **771** | Buffer Overflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Registry\ value\ too\ small\.` | **Context:** Registry value too small. |
| **772** | Network Timeout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `30\ second\ delay\ on\ connect\.` | **Context:** 30 second delay on connect. |
| **773** | Dll Search Order | **Op:** `*`<br>**Res:** `*`<br>**Path:** `evil\.dll` | **Context:** Loading `evil.dll` from CWD. |
| **774** | Zone Identifier | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ADS\ causing\ security\ block\.` | **Context:** ADS causing security block. |
| **775** | GDI Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Black\ screen\ due\ to\ 10k\ objects\.` | **Context:** Black screen due to 10k objects. |
| **776** | Handle Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Slowdown\ due\ to\ 100k\ handles\.` | **Context:** Slowdown due to 100k handles. |
| **777** | Thread Spike | **Op:** `*`<br>**Res:** `*`<br>**Path:** `High\ context\ switch\ rate\.` | **Context:** High context switch rate. |
| **778** | Disk Queue | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Queue\ length\ >\ 5\.` | **Context:** Queue length > 5. |
| **779** | Privilege Missing | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``SeDebugPrivilege`\ check\ fail\.` | **Context:** `SeDebugPrivilege` check fail. |
| **780** | Integrity Level | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Low\ IL\ write\ to\ Medium\ IL\ fail\.` | **Context:** Low IL write to Medium IL fail. |
| **781** | Virtual Store | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Writes\ to\ `VirtualStore`\.` | **Context:** Writes to `VirtualStore`. |
| **782** | Short Name | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\~1` | **Context:** `~1` collision. |
| **783** | Case Sensitivity | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``File`\ !=\ `file`\.` | **Context:** `File` != `file`. |
| **784** | Sparse File | **Op:** `*`<br>**Res:** `DISK\ FULL`<br>**Path:** `*` | **Context:** Disk Full on sparse write. |
| **785** | Reparse Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Symlink\ cycle\.` | **Context:** Symlink cycle. |
| **786** | Offline File | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Hierarchical\ Storage\ fail\.` | **Context:** Hierarchical Storage fail. |
| **787** | Alternate Stream | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Hiding\ data\ in\ ADS\.` | **Context:** Hiding data in ADS. |
| **788** | Host File | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Redirect\ verification\.` | **Context:** Redirect verification. |
| **789** | LSP/WFP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Network\ filter\ blocking\.` | **Context:** Network filter blocking. |
| **790** | User/Kernel Mode | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Context\ of\ operation\.` | **Context:** Context of operation. |
| **791** | Session 0 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Service\ interacting\ with\ desktop\.` | **Context:** Service interacting with desktop. |
| **792** | Desktop Heap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Service\ GUI\ fail\.` | **Context:** Service GUI fail. |
| **793** | Power Request | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Sleep\ prevention\.` | **Context:** Sleep prevention. |
| **794** | Timer Res | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Timer\ resolution\ change\.` | **Context:** Timer resolution change. |
| **795** | MMIO | **Op:** `*`<br>**Res:** `O\ error\.`<br>**Path:** `*` | **Context:** Memory Mapped I/O error. |
| **796** | DMA | **Op:** `*`<br>**Res:** `Direct\ Memory\ Access\ error\.`<br>**Path:** `*` | **Context:** Direct Memory Access error. |
| **797** | Interrupts | **Op:** `*`<br>**Res:** `*`<br>**Path:** `High\ hardware\ interrupts\.` | **Context:** High hardware interrupts. |
| **798** | DPC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `High\ Deferred\ Procedure\ Calls\.` | **Context:** High Deferred Procedure Calls. |
| **799** | Hard Fault | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Paging\ from\ disk\.` | **Context:** Paging from disk. |
| **800** | Working Set | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RAM\ trimming\.` | **Context:** RAM trimming. |

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
| **815** | NtTerminateProcess | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Kill\.` | **Context:** Kill. |
| **816** | NtSuspendProcess | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Freeze\.` | **Context:** Freeze. |
| **817** | NtResumeProcess | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Thaw\.` | **Context:** Thaw. |
| **818** | NtOpenProcessToken | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Auth\ check\.` | **Context:** Auth check. |
| **819** | NtAdjustPrivilegesToken | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Elevate\.` | **Context:** Elevate. |
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
| **838** | NtNotifyChangeDirectoryFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Watcher\.` | **Context:** Watcher. |
| **839** | NtQueryEaFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Ext\ attributes\.` | **Context:** Ext attributes. |
| **840** | NtSetEaFile | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Ext\ attributes\.` | **Context:** Ext attributes. |

## SECTION 32: CONTAINERIZATION (Docker/K8s on Windows)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **841** | HCS Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `hcsshim\.dll` | **Cause:** Container |
| **842** | Docker Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``dockerd\.exe`\ fail` | **Cause:** Engine |
| **843** | Container NIC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vEthernet (HNS)` | **Cause:** Net |
| **844** | Layer Locked | **Op:** `*`<br>**Res:** `*`<br>**Path:** `layer\.tar` | **Cause:** Image |
| **845** | Volume Mount | **Op:** `*`<br>**Res:** `*`<br>**Path:** `host_mnt` | **Cause:** Storage |
| **846** | Pipe Docker | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\\\\.\\pipe\\docker_engine`\ fail` | **Cause:** API |
| **847** | Kube Config | **Op:** `*`<br>**Res:** `*`<br>**Path:** `config` | **Cause:** Cluster |
| **848** | CRI Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Orch |
| **849** | GMSA Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Auth |
| **850** | Process Isolation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Kernel |

## SECTION 33: CLOUD STORAGE & SYNC (Advanced)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **851** | OneDrive Pipe | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\\\\.\\pipe\\OneDriveIPC`\ fail` | **Cause:** IPC |
| **852** | OneDrive Status | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Status` | **Cause:** Overlay |
| **853** | OneDrive Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FileCoAuth` | **Cause:** Office |
| **854** | Dropbox Pipe | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\\\\.\\pipe\\DropboxPipe`\ fail` | **Cause:** IPC |
| **855** | Dropbox Ignore | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `\.dropboxignore`` | **Cause:** Config |
| **856** | GDrive Pipe | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GoogleDriveFS` | **Cause:** IPC |
| **857** | GDrive Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `content_cache` | **Cause:** Space |
| **858** | Box Mount | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Box Drive` | **Cause:** Mount |
| **859** | Sync Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Conflicted Copy` | **Cause:** Race |
| **860** | Attr Fail | **Op:** `SetFileAttributes`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Tiering |

## SECTION 34: DATABASE (Advanced SQL/Oracle)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **861** | SQL Mem | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``sqlservr\.exe`\ Mem\ limit` | **Cause:** RAM |
| **862** | SQL Dump | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SQLDump.*\.mdmp` | **Cause:** Crash |
| **863** | SQL Pipe | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\\\\.\\pipe\\sql\\query`\ busy` | **Cause:** Load |
| **864** | SQL VIA | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `sqlvia\.dll`` | **Cause:** Legacy Proto |
| **865** | SQL Shared | **Op:** `*`<br>**Res:** `*`<br>**Path:** `sqlmin\.dll` | **Cause:** Engine |
| **866** | Oracle OCI | **Op:** `*`<br>**Res:** `*`<br>**Path:** `oci\.dll` | **Cause:** Client |
| **867** | Oracle Java | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ojdbc\.jar` | **Cause:** Java |
| **868** | Postgres | **Op:** `*`<br>**Res:** `*`<br>**Path:** `postgres\.exe` | **Cause:** OSS DB |
| **869** | MySQL | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``mysqld\.exe`\ activity` | **Cause:** OSS DB |
| **870** | SQLite Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `database\.sqlite\-journal` | **Cause:** Local |

## SECTION 35: DEVELOPMENT TOOLS (DevOps)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **871** | Git Config | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.gitconfig` | **Cause:** Settings |
| **872** | SSH Agent | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ssh-agent` | **Cause:** Auth |
| **873** | VSCode Ext | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `extensions\.json`` | **Cause:** IDE |
| **874** | Visual Studio | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``devenv\.exe`\ crash` | **Cause:** IDE |
| **875** | MSBuild | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``MSBuild\.exe`\ fail` | **Cause:** Build |
| **876** | NuGet | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `nuget\.config`` | **Cause:** Pkg |
| **877** | Npm Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `package\-lock\.json`` | **Cause:** Dep |
| **878** | Pip Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `pip` | **Cause:** Python |
| **879** | Maven Repo | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `\.m2`` | **Cause:** Java |
| **880** | Gradle | **Op:** `*`<br>**Res:** `*`<br>**Path:** `gradlew` | **Cause:** Build |

## SECTION 36: MEDIA PRODUCTION (Adobe/Davinci)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **881** | Adobe Scratch | **Op:** `*`<br>**Res:** `DISK\ FULL`<br>**Path:** `*` | **Cause:** Space |
| **882** | Adobe Font | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `AdobeFnt\.lst`` | **Cause:** Cache |
| **883** | Adobe License | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AdobeIPCBroker` | **Cause:** Auth |
| **884** | Premiere | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Adobe\ Premiere\ Pro\.exe`` | **Cause:** Video |
| **885** | After Effects | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AfterFX\.exe` | **Cause:** VFX |
| **886** | Photoshop | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Photoshop\.exe`` | **Cause:** Image |
| **887** | Davinci Resolve | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Resolve\.exe`` | **Cause:** Video |
| **888** | Dongle Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** License |
| **889** | Plugin Scan | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VST` | **Cause:** Audio |
| **890** | Codec Load | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ffmpeg\.dll` | **Cause:** Media |

## SECTION 37: VIRTUAL REALITY (VR/AR)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **891** | SteamVR | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``vrserver\.exe`` | **Cause:** VR |
| **892** | Oculus | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``OVRServer_x64\.exe`` | **Cause:** VR |
| **893** | WMR | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``MixedRealityPortal\.exe`` | **Cause:** VR |
| **894** | OpenVR | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `openvr_api\.dll`` | **Cause:** API |
| **895** | HMD USB | **Op:** `*`<br>**Res:** `*`<br>**Path:** `HMD` | **Cause:** Headset |
| **896** | Tracking | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** USB |
| **897** | Compositor | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``vrcompositor\.exe`\ crash` | **Cause:** Display |
| **898** | Room Setup | **Op:** `*`<br>**Res:** `*`<br>**Path:** `chaperone` | **Cause:** Config |
| **899** | Runtime | **Op:** `*`<br>**Res:** `*`<br>**Path:** `LibOVRRT` | **Cause:** Driver |
| **900** | Async Reprojection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Framerate |

## SECTION 38: TELEMETRY & PRIVACY

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **901** | DiagTrack | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``CompatTelRunner\.exe`` | **Cause:** Usage |
| **902** | SQM | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `sqm.*\.dat`` | **Cause:** Quality |
| **903** | Watson | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Watson` | **Cause:** Crash |
| **904** | AIT | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AitAgent` | **Cause:** Install |
| **905** | Inventory | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Inventory\.exe`` | **Cause:** App scan |
| **906** | Device Census | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DeviceCensus\.exe` | **Cause:** Hw scan |
| **907** | Location | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Geofence` | **Cause:** GPS |
| **908** | Feedback | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FeedbackHub` | **Cause:** User |
| **909** | Timeline | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `ActivitiesCache\.db`` | **Cause:** History |
| **910** | Clip SVC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ClientLicense` | **Cause:** Store |

## SECTION 39: REMOTE DESKTOP (RDP/RDS)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **911** | TermSvc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TermService` | **Cause:** Svc |
| **912** | RDP Clip | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``rdpclip\.exe`\ fail` | **Cause:** Copy/Paste |
| **913** | RDP Drv | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``rdpdr\.sys`\ fail` | **Cause:** Redirection |
| **914** | RDP Sound | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``rdpsnd\.sys`\ fail` | **Cause:** Audio |
| **915** | RDP Print | **Op:** `*`<br>**Res:** `*`<br>**Path:** `EasyPrint` | **Cause:** Print |
| **916** | RDP Input | **Op:** `*`<br>**Res:** `*`<br>**Path:** `rdpinput\.sys` | **Cause:** Mouse |
| **917** | RDP Gfx | **Op:** `*`<br>**Res:** `*`<br>**Path:** `rdpgfx\.sys` | **Cause:** Video |
| **918** | Session Dir | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``tssdis\.exe`\ fail` | **Cause:** Broker |
| **919** | License Svc | **Op:** `*`<br>**Res:** `*`<br>**Path:** `lserver\.exe` | **Cause:** CALs |
| **920** | RemoteApp | **Op:** `*`<br>**Res:** `*`<br>**Path:** `rdpshell\.exe` | **Cause:** Seamless |

## SECTION 40: BACKUP & RECOVERY

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **921** | VSS Create | **Op:** `*`<br>**Res:** `*`<br>**Path:** `vssvc\.exe` | **Cause:** Snapshot |
| **922** | VSS Writer | **Op:** `*`<br>**Res:** `TIMEOUT`<br>**Path:** `*` | **Cause:** SQL |
| **923** | VSS Provider | **Op:** `*`<br>**Res:** `*`<br>**Path:** `swprv` | **Cause:** Software |
| **924** | VSS Hardware | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``vds\.exe`\ fail` | **Cause:** SAN |
| **925** | Change Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ctp\.sys` | **Cause:** CBT |
| **926** | Veeam Transport | **Op:** `*`<br>**Res:** `*`<br>**Path:** `VeeamTransport` | **Cause:** Net |
| **927** | Backup Read | **Op:** `*`<br>**Res:** `*`<br>**Path:** `BackupRead` | **Cause:** Stream |
| **928** | Archive Bit | **Op:** `SetFileAttributes`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Flag |
| **929** | Last Modified | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Inc |
| **930** | Catalog | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GlobalCatalog` | **Cause:** Tape |

## SECTION 41: PRINTING (Expanded)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **931** | Print Processor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `winprint\.dll`` | **Cause:** Spool |
| **932** | Print Monitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `usbmon\.dll` | **Cause:** Port |
| **933** | Print Lang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `pjlmon\.dll`` | **Cause:** PJL |
| **934** | Print Net | **Op:** `*`<br>**Res:** `*`<br>**Path:** `tcpmon\.dll` | **Cause:** IP |
| **935** | Print Form | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Forms` | **Cause:** Paper |
| **936** | Print Color | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ColorProfiles` | **Cause:** ICC |
| **937** | Print Sep | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Separator` | **Cause:** Page |
| **938** | Print Driver | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DriverStore` | **Cause:** File |
| **939** | Print Queue | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Write\ `\.spl`` | **Cause:** Spool |
| **940** | Print Job | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.shd` | **Cause:** Shadow |

## SECTION 42: FONTS & TEXT

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **941** | Font Load | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AddFontResource` | **Cause:** Install |
| **942** | Font Mem | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CreateFontIndirect` | **Cause:** GDI |
| **943** | Font Link | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FontLink` | **Cause:** Fallbacks |
| **944** | Font Sub | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FontSubstitutes` | **Cause:** Alias |
| **945** | EUDC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Read\ `EUDC\.TE`` | **Cause:** Custom |
| **946** | Freetype | **Op:** `*`<br>**Res:** `*`<br>**Path:** `freetype\.dll` | **Cause:** OSS |
| **947** | DirectWrite | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `dwrite\.dll`` | **Cause:** Modern |
| **948** | Uniscribe | **Op:** `*`<br>**Res:** `*`<br>**Path:** `usp10\.dll` | **Cause:** Complex |
| **949** | Font Cache | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FNTCACHE\.DAT` | **Cause:** Boot |
| **950** | Type1 Font | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\.pfm` | **Cause:** Legacy |

## SECTION 43: SCIENTIFIC & ENGINEERING

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **951** | AutoCAD | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``acad\.exe`\ crash` | **Cause:** CAD |
| **952** | Revit | **Op:** `*`<br>**Res:** `*`<br>**Path:** `revit\.exe` | **Cause:** BIM |
| **953** | SolidWorks | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``SLDWORKS\.exe`` | **Cause:** CAD |
| **954** | Matlab | **Op:** `*`<br>**Res:** `*`<br>**Path:** `matlab\.exe` | **Cause:** Math |
| **955** | LabView | **Op:** `*`<br>**Res:** `*`<br>**Path:** `labview\.exe` | **Cause:** Eng |
| **956** | License Flex | **Op:** `*`<br>**Res:** `*`<br>**Path:** `lmgrd\.exe` | **Cause:** Licensing |
| **957** | Dongle HASP | **Op:** `*`<br>**Res:** `*`<br>**Path:** `hasplms\.exe` | **Cause:** Key |
| **958** | Dongle Sentinel | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Sentinel` | **Cause:** Key |
| **959** | CUDA | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `nvcuda\.dll`` | **Cause:** Compute |
| **960** | MPI | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mpi\.dll` | **Cause:** Cluster |

## SECTION 44: FINANCIAL & TRADING

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **961** | Bloomberg | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``bbcomm\.exe`` | **Cause:** Terminal |
| **962** | Thomson | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Eikon\.exe`` | **Cause:** Terminal |
| **963** | Excel RTD | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Feed |
| **964** | Excel DDE | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Legacy |
| **965** | Multicast | **Op:** `*`<br>**Res:** `*`<br>**Path:** `UDP\ 224\.x\.x\.x` | **Cause:** Ticker |
| **966** | PTP Sync | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Time |
| **967** | Solarflare | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `sf.*dll`` | **Cause:** NIC |
| **968** | Mellanox | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mlx.*sys` | **Cause:** NIC |
| **969** | RDMA | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Speed |
| **970** | Kernel Bypass | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Speed |

## SECTION 45: HEALTHCARE & DICOM

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **971** | Epic | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Hyperspace\.exe`` | **Cause:** EMR |
| **972** | Cerner | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Citrix` | **Cause:** EMR |
| **973** | DICOM Send | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Image |
| **974** | PACS | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Image |
| **975** | HL7 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Msg |
| **976** | Twain | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Scan |
| **977** | Speech Mic | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Nuance` | **Cause:** Dictation |
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
| **998** | Scanner | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Input |
| **999** | Scale | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** HW |
| **1000** | EFT | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Net |

## SECTION 48: "THE FINAL STRAW" (Last Resort Checks)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1001** | Bit Flip | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** RAM |
| **1002** | Cosmic Ray | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physics |
| **1003** | Cable Rot | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physical |
| **1004** | Power Sag | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physical |
| **1005** | Capacitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physical |
| **1006** | Thermal | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physical |
| **1007** | Dust | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physical |
| **1008** | Liquid | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Physical |
| **1009** | User Error | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Layer 8 |
| **1010** | Gremlins | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Undefined |

## SECTION 49: THE "SILENT FAILURES" (Hardest to Diagnose)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1011** | Swallowed Exception (CLR) | **Op:** `*`<br>**Res:** ``\.NET\ Runtime`\ logs\ `<br>**Path:** `\.NET\ Runtime` | **Cause:** Dev caught exception but didn't log it |
| **1012** | WerFault Suppression | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WerFault\.exe` | **Cause:** Headless mode crash |
| **1013** | Stack Overflow (Silent) | **Op:** `Process\ Exit`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Recursion limit hit, often no dump |
| **1014** | Heap Corruption (Immediate) | **Op:** `Process\ Exit`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Kernel kills app instantly to save OS |
| **1015** | Dependency Loader Snap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `App\ exits\ before\ `Main\(\)`\.\ `LdrInitializeThunk`\ fail` | **Cause:** Static import missing |
| **1016** | Sentinel/Dongle Check | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hardware key missing |
| **1017** | Licensing Timeout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Exit 0` | **Cause:** License server unreachable |
| **1018** | Environment Variable Null | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Logic error |
| **1019** | Console Hidden | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** UI logic |
| **1020** | Shim Engine Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Shim Engine` | **Cause:** Windows compatibility |

## SECTION 50: ASSISTIVE TECH - SCREEN READERS (JAWS/NVDA)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1021** | Focus Theft | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SetForegroundWindow` | **Cause:** Interrupts speech |
| **1022** | UIA Timeout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WM_GETOBJECT` | **Cause:** App hanging the screen reader |
| **1023** | AccName Missing | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``IAccessible::get_accName`\ returns\ empty` | **Cause:** Unlabeled button |
| **1024** | AccRole Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ROLE_SYSTEM_GRAPHIC` | **Cause:** Not clickable |
| **1025** | Live Region Spam | **Op:** `*`<br>**Res:** `*`<br>**Path:** `EVENT_OBJECT_LIVEREGIONCHANGED` | **Cause:** Floods speech buffer |
| **1026** | Java Bridge 32/64 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `WindowsAccessBridge\-32\.dll` | **Cause:** Silent Java |
| **1027** | Java Bridge Missing | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `HKLM\\Software\\JavaSoft\\Accessibility` | **Cause:** Not installed |
| **1028** | Adobe Reader Tagging | **Op:** `*`<br>**Res:** `*`<br>**Path:** `structTreeRoot` | **Cause:** Untagged PDF |
| **1029** | Chromium A11y Tree | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Chrome_RenderWidgetHostHWND` | **Cause:** Browser lag |
| **1030** | Secure Desktop Block | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Security boundary |
| **1031** | Audio Ducking Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `IAudioSessionControl` | **Cause:** Background noise loud |
| **1032** | Mirror Driver Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Load\ `jfwvid\.dll`\ \(JAWS\)\ or\ `nvda_mirror`\ fail` | **Cause:** Video hook broken |
| **1033** | Touch API Fail | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Touchscreen reader fail |
| **1034** | Off-Screen Text | **Op:** `*`<br>**Res:** `*`<br>**Path:** `-32000` | **Cause:** Hidden text read aloud |
| **1035** | Z-Order Confusion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Tab order jump |

## SECTION 51: ASSISTIVE TECH - UI AUTOMATION (UIA)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1036** | Provider Reg Fail | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `HKCR\\CLSID\\\{ProxyStub\}` | **Cause:** UIA broken |
| **1037** | AutomationID Null | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AutomationId` | **Cause:** Bot cannot find control |
| **1038** | Pattern Not Supported | **Op:** `*`<br>**Res:** `*`<br>**Path:** `IUIAutomation::GetPattern` | **Cause:** Control broken |
| **1039** | TextPattern Timeout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetText` | **Cause:** Word processor lag |
| **1040** | TreeWalker Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Freeze |
| **1041** | Element Orphaned | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Crash risk |
| **1042** | Virtualization Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Memory spike |
| **1043** | Event Storm | **Op:** `*`<br>**Res:** `*`<br>**Path:** `StructureChanged` | **Cause:** Performance kill |
| **1044** | Proxy Loading | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``UIAutomationCore\.dll`\ loading\ wrong\ version` | **Cause:** Compat |
| **1045** | Privilege Boundary | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** UIPI |

## SECTION 52: ASSISTIVE TECH - INPUT & MAGNIFICATION

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1046** | Magnifier Overlay | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Magnification\.dll`\ init\ fail` | **Cause:** Driver conflict |
| **1047** | Cursor Hook Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SetWindowsHookEx` | **Cause:** Tracking broken |
| **1048** | Caret Tracking | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetGUIThreadInfo` | **Cause:** Zoom doesn't follow type |
| **1049** | Color Filter Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DwmSetColorizationParameters` | **Cause:** High contrast break |
| **1050** | Smoothed Text | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SystemParametersInfo` | **Cause:** Blurry zoom |
| **1051** | Dictation Mic Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AudioEndpoint` | **Cause:** Dragon can't hear |
| **1052** | Text Service (TSF) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``ctfmon\.exe`\ deadlock` | **Cause:** Dictation freeze |
| **1053** | Correction UI | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Invisible menu |
| **1054** | Vocabulary Write | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `user\.dic` | **Cause:** Learning fail |
| **1055** | Eye Tracker HID | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hardware connect |
| **1056** | Switch Input Lag | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Motor aid delay |
| **1057** | OSK Injection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SendInput` | **Cause:** Keyboard security |
| **1058** | Tablet Service | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TabTip\.exe` | **Cause:** Touch keyboard |
| **1059** | Gesture Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** OS nav broken |
| **1060** | High DPI Blur | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetScaleFactorForMonitor` | **Cause:** Fuzzy UI |

## SECTION 53: THE "WORKS AS ADMIN" MYSTERIES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1061** | Global Object Creation | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Needs SeCreateGlobalPrivilege |
| **1062** | Service Control | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Trying to start service |
| **1063** | Program Files Write | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad coding |
| **1064** | HKLM Write | **Op:** `RegSetValue`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Bad coding |
| **1065** | Event Log Write | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Audit write |
| **1066** | Symlink Create | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Needs privilege |
| **1067** | Debug Privilege | **Op:** `OpenProcess`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Debug |
| **1068** | Driver Load | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Kernel |
| **1069** | Raw Socket | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Network tool |
| **1070** | Volume Access | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disk tool |

## SECTION 54: ENVIRONMENT DRIFT & "DLL HELL"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1071** | Modified PATH | **Op:** `LoadImage`<br>**Res:** `*`<br>**Path:** `%PATH%` | **Context:** `LoadImage` fails because `%PATH%` truncated > 2048 chars. |
| **1072** | User vs System Path | **Op:** `*`<br>**Res:** `*`<br>**Path:** `C:\\Users\\.*\\bin` | **Cause:** Wrong version |
| **1073** | Current Work Dir | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Shortcut "Start In" wrong |
| **1074** | GAC Priority | **Op:** `*`<br>**Res:** `*`<br>**Path:** `C:\\Windows\\Assembly` | **Cause:** GAC |
| **1075** | KnownDLLs | **Op:** `*`<br>**Res:** `*`<br>**Path:** `KnownDLLs` | **Cause:** Ignores local copy |
| **1076** | Redirected Folders | **Op:** `*`<br>**Res:** `*`<br>**Path:** `\\\\Server\\Share` | **Context:** App hardcodes `C:\Users`, fails on `\\Server\Share`. |
| **1077** | Regional Date | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** MM/DD vs DD/MM |
| **1078** | Decimal Separator | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Comma vs Dot |
| **1079** | Codepage Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MultiByteToWideChar` | **Cause:** Locale |
| **1080** | Font Substitution | **Op:** `*`<br>**Res:** `*`<br>**Path:** `FontSubstitutes` | **Cause:** UI garbage |

## SECTION 55: COMPLEX NETWORKING (The "It's the Firewall" Red Herrings)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1081** | MTU Black Hole | **Op:** `*`<br>**Res:** `*`<br>**Path:** `TCP Retransmit` | **Cause:** Packet too big, DF set |
| **1082** | Ephemeral Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``WSAEADDRINUSE`\ \(10048\)\ on\ .*Outbound.*` | **Cause:** Ran out of ports |
| **1083** | Time_Wait Accumulation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** High churn |
| **1084** | Nagle Algorithm | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** NoDelay not set |
| **1085** | Delayed ACK | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** ACK timer |
| **1086** | Window Scaling | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Scale factor 0 |
| **1087** | PAWS Drop | **Op:** `*`<br>**Res:** `Timestamp\ error`<br>**Path:** `*` | **Cause:** Sequence number wrap |
| **1088** | ECN Drop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Router compat |
| **1089** | RSS Imbalance | **Op:** `*`<br>**Res:** `*`<br>**Path:** `One\ CPU\ core\ 100%\ on\ network\ interrupt` | **Cause:** Card setting |
| **1090** | Chimney Offload | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** NIC Driver bug |

## SECTION 56: BROWSER & WEB CONTENT ACCESSIBILITY

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1091** | Aria-Hidden True | **Op:** `*`<br>**Res:** `*`<br>**Path:** `AriaProperties` | **Cause:** Invisible to Reader |
| **1092** | IFrame Boundary | **Op:** `*`<br>**Res:** `*`<br>**Path:** `<iframe>` | **Cause:** Cross-origin security |
| **1093** | Shadow DOM | **Op:** `*`<br>**Res:** `*`<br>**Path:** `#shadow-root` | **Cause:** Encapsulation |
| **1094** | Focus Trap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** JS Logic |
| **1095** | AccessKey Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Alt+F` | **Cause:** Keyboard |
| **1096** | Canvas Element | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** No semantic info |
| **1097** | Flash/ActiveX | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MacromediaFlash` | **Cause:** Inaccessible black box |
| **1098** | Auto-Refresh | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** UX |
| **1099** | Contrast Media | **Op:** `*`<br>**Res:** `*`<br>**Path:** `@media(forced-colors)` | **Cause:** Visual |
| **1100** | Zoom Reflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Text\ overlaps\ at\ 200%` | **Cause:** Layout break |

## SECTION 57: VIRTUALIZATION & VDI EDGE CASES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1101** | USB Redirection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `tsusbhub\.sys` | **Cause:** Scanner doesn't map |
| **1102** | SmartCard Redir | **Op:** `*`<br>**Res:** `*`<br>**Path:** `scard\.dll` | **Cause:** Middleware |
| **1103** | Audio Redir | **Op:** `*`<br>**Res:** `*`<br>**Path:** `audiodg` | **Cause:** Lag/Quality |
| **1104** | Printer Mapping | **Op:** `*`<br>**Res:** `*`<br>**Path:** `C:\\Windows\\System32\\spool\\servers` | **Cause:** Driver pull |
| **1105** | Drive Map Slow | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\\\\tsclient\\c`\ latency` | **Cause:** Client drive access |
| **1106** | Time Zone Redir | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Meeting time wrong |
| **1107** | Clipboard Chain | **Op:** `*`<br>**Res:** `*`<br>**Path:** `rdpclip` | **Cause:** Copy/Paste break |
| **1108** | Display Topology | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Coordinates |
| **1109** | DPI Matching | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Tiny/Huge text |
| **1110** | Single Sign On | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``ssonsvr\.exe`\ fail` | **Cause:** Cred prompt |

## SECTION 58: SECURITY PRODUCTS FIGHTING EACH OTHER

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1111** | Filter Stack | **Op:** `*`<br>**Res:** `*`<br>**Path:** `fltmgr` | **Cause:** Latency |
| **1112** | Hook Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `User32!BeginPaint` | **Cause:** Crash |
| **1113** | Inject War | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Code integrity |
| **1114** | Scan Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Disk IO |
| **1115** | Net Filter | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Network |
| **1116** | EDR Memory | **Op:** `*`<br>**Res:** `*`<br>**Path:** `NtReadVirtualMemory` | **Cause:** Heuristic flag |
| **1117** | File Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Corruption |
| **1118** | Certificate Intercept | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Trust |
| **1119** | Registry Monitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Loop |
| **1120** | Overlay War | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Flicker |

## SECTION 59: PRINTING NIGHTMARES (Advanced)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1121** | V4 Driver Isolation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PrintIsolationHost` | **Cause:** Perms |
| **1122** | Point & Print Policy | **Op:** `*`<br>**Res:** `*`<br>**Path:** `PackagePointAndPrint` | **Cause:** GPO |
| **1123** | Render Filter | **Op:** `*`<br>**Res:** `*`<br>**Path:** `mxdwdrv\.dll` | **Cause:** XPS convert |
| **1124** | Color Profile | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `mscms\.dll` | **Cause:** Bad colors |
| **1125** | Form Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Tray selection |
| **1126** | Spooler RPC | **Op:** `*`<br>**Res:** `*`<br>**Path:** `RpcEpMap` | **Cause:** Service dead |
| **1127** | CSR (Client Side Render) | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``winspool\.drv`\ heavy\ CPU` | **Cause:** Rendering |
| **1128** | Job Stuck | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``\.spl`\ file\ locked\ by\ AV` | **Cause:** Queue jam |
| **1129** | Port Monitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `monitordll` | **Cause:** Comm error |
| **1130** | DevMode Corrupt | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DevMode` | **Cause:** Settings reset |

## SECTION 60: THE "HUMAN FACTOR" (User Behavior Detections)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1131** | Idle Timeout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** User away |
| **1132** | Force Shutdown | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Hard reset |
| **1133** | Cable Pull | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Unplugged |
| **1134** | USB Eject | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DeviceRemoval` | **Cause:** Thumb drive pull |
| **1135** | Resolution Change | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DisplaySettings` | **Cause:** User mess with screen |
| **1136** | Theme Change | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Theme` | **Cause:** User High Contrast toggle |
| **1137** | Volume Mute | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Volume` | **Cause:** User muted app |
| **1138** | Date Change | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SetSystemTime` | **Cause:** User changed clock |
| **1139** | File Move | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Explorer` | **Cause:** User moved folder |
| **1140** | Install | **Op:** `*`<br>**Res:** `*`<br>**Path:** `msiexec` | **Cause:** User installed software |

## SECTION 61: THE "GHOST IN THE SHELL" (Explorer & UI Rot)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1141** | Shellbag Corruption | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `Shell\\Bags` | **Symptom:** Explorer crashes only when opening a specific folder (e.g., "Downloads").<br><br>**Cause:** The saved "View State" (Icon position/size) for that specific folder GUID is malformed. |
| **1142** | Context Menu Handler Hang | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `ContextMenuHandlers` | **Symptom:** Right-clicking a file takes 30 seconds to show the menu.<br><br>**Cause:** A shell extension is trying to reach a network resource or is buggy, blocking the UI thread. |
| **1143** | Icon Overlay Exhaustion | **Op:** `RegEnumKey`<br>**Res:** `*`<br>**Path:** `ShellIconOverlayIdentifiers` | **Symptom:** Dropbox/OneDrive green checkmarks disappear, or icons turn black.<br><br>**Cause:** Windows has a hard limit of 15 overlay handlers. Apps fight for the top spots by adding spaces to their names (`   OneDrive`). |
| **1144** | Quick Access Dead Link | **Op:** `CreateFile`<br>**Res:** `*`<br>**Path:** `Recent\\AutomaticDestinations` | **Symptom:** Explorer freezes for 20s immediately upon opening.<br><br>**Cause:** The "Quick Access" (Recent Files) pinned a file from a decommissioned server. Explorer tries to resolve the icon/metadata on launch. |
| **1145** | Thumbnail Cache Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User cannot delete a folder; "File in use".<br><br>**Cause:** Windows is stuck trying to generate a thumbnail for a corrupt video/image file in that folder. |
| **1146** | Notification Area (Tray) Corruption | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `TrayNotify` | **Symptom:** System Tray icons are missing or blank spaces appear.<br><br>**Cause:** The `IconStreams` binary blob registry value is corrupt. |
| **1147** | Open With... Reset | **Op:** `RegSetValue`<br>**Res:** `*`<br>**Path:** `UserChoice\\Hash` | **Symptom:** Windows keeps asking "How do you want to open this?" for PDFs.<br><br>**Cause:** Windows 10/11 detects "tampering" with file associations (hash mismatch) and resets them to Edge. |
| **1148** | Invisible Window Focus | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User types, but nothing happens. Clicking the app works.<br><br>**Cause:** A background app stole focus but didn't bring a window to the front. |
| **1149** | Drag and Drop Freeze | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Dragging a file causes the mouse to stick to the file icon; Esc doesn't work.<br><br>**Cause:** The Drop Target (the app you are dragging *over*) is hung/busy and hasn't replied to the OLE Drag loop. |
| **1150** | Taskbar Unclickable | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Start Menu works, but Taskbar icons are dead.<br><br>**Cause:** A "DeskBand" (Toolbar widget) crashed the taskbar thread specifically. |

## SECTION 62: THE "NETWORK POLTERGEISTS" (Stack & Caching)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1151** | ARP Cache Poisoning (Local) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User cannot reach the Gateway, but neighbors can.<br><br>**Cause:** Another device (or malware) has claimed the Gateway IP (IP Conflict/Spoofing). |
| **1152** | Persistent Route Injection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User cannot reach Corporate Intranet, traffic goes to Internet.<br><br>**Cause:** A "Persistent Route" (`route print -p`) was added years ago and persists across reboots/VPN installs. |
| **1153** | Winsock Namespace Provider (NSP) Rot | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Browsers work, but `ping` and `nslookup` fail (or vice versa).<br><br>**Cause:** An old VPN client or Malware left a broken Namespace Provider in the Winsock catalog. |
| **1154** | Source Port Exhaustion (The "1 user" version) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Apps work for 5 minutes, then all network fails until reboot.<br><br>**Cause:** Malware or a buggy script is opening 60,000 connections to `localhost` and leaving them in `TIME_WAIT`. |
| **1155** | Ghost Network Adapter | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "IP Address Configured" error when setting static IP, but the IP isn't visible.<br><br>**Cause:** Old NIC still holds the IP config in registry. |
| **1156** | LMHOSTS Lookup Enabled | **Op:** `CreateFile`<br>**Res:** `SUCCESS`<br>**Path:** `lmhosts` | **Symptom:** User resolves "Server1" to an IP address that hasn't existed for 5 years.<br><br>**Cause:** The user has an ancient `lmhosts` file enabled that overrides DNS. |
| **1157** | Teredo Tunneling Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** High CPU in `svchost (iphlpsvc)`. Network sluggish.<br><br>**Cause:** Teredo trying to establish a tunnel through a firewall that blocks it, retrying infinitely. |
| **1158** | ICS (Internet Connection Sharing) Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User plugs in a phone to charge; Corporate LAN drops.<br><br>**Cause:** PC starts acting as a Router/DHCP server because ICS was triggered, causing IP conflicts. |
| **1159** | VPN Split Tunnel DNS Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User can access Internal Site A but not Internal Site B.<br><br>**Cause:** Windows Interface Metric prioritizes the physical adapter over the VPN adapter for specific domains. |

## SECTION 63: THE "IDENTITY CRISIS" (Credentials & Auth)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1161** | Credential Manager "Zombie" Cred | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Outlook prompts for password daily, even after saving.<br><br>**Cause:** The Credential Vault file on disk is corrupt or has hit a size limit (thousands of old entries). |
| **1162** | Cached Logon Count Exceeded | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Laptop user cannot login when away from office.<br><br>**Cause:** Machine has not talked to DC in X days, and the cached credential has expired or rolled over. |
| **1163** | Kerberos Encryption Type Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User access denied to File Share, but can access Web Apps.<br><br>**Cause:** User account in AD is flagged "Use DES encryption types" or legacy GPO disabling AES on client. |
| **1164** | Workstation Trust Broken (Silent) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "The trust relationship between this workstation and the primary domain failed."<br><br>**Cause:** Computer password changed on DC, but machine didn't get the memo (Restore from snapshot / Time jump). |
| **1165** | Phantom Drive Mapping Auth | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Account locks out every morning at 9:00 AM.<br><br>**Cause:** A persistent drive map (or Service, or Scheduled Task) running as the user has stored old credentials. |
| **1166** | DPAPI Master Key Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Chrome forgets all passwords; Wi-Fi forgets keys.<br><br>**Cause:** The user changed their password, but the DPAPI Master Key (protected by the old password) wasn't re-wrapped. |
| **1167** | Session 0 Isolation Auth | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Service fails to access network share.<br><br>**Cause:** `LocalSystem` uses the *Computer Account* (`Domain\PC$`) for auth, not the User. Share ACL needs to include the Computer Object. |
| **1168** | NGC (Windows Hello) Container Rot | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User cannot use PIN or Fingerprint. "Something went wrong".<br><br>**Cause:** The Windows Hello database is corrupt. Requires folder deletion to reset. |
| **1169** | AAD Broker Token Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Office 365 "Need Password" -> Click -> Disappears -> "Need Password".<br><br>**Cause:** TPM (Trusted Platform Module) failure or WAM (Web Account Manager) plugin broken. |
| **1170** | User Rights Assignment (Logon as Batch) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Scheduled Task as User fails to start.<br><br>**Cause:** GPO removed "Logon as a Batch Job" right for that user. |

## SECTION 64: THE "PHANTOM HARDWARE" (PnP & Peripherals)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1171** | Ghost Monitor (EDID Cache) | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `System\\CurrentControlSet\\Enum\\DISPLAY` | **Symptom:** Application opens off-screen; Windows thinks a 2nd monitor is attached.<br><br>**Cause:** Windows cached the EDID of a projector/monitor and refuses to forget it. |
| **1172** | USB Serial Number Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User plugs in two identical USB drives; only one works.<br><br>**Cause:** Cheap USB drives often share the exact same Serial Number. Windows cannot distinguish them. |
| **1173** | Print Queue "Deleting" State | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Printer refuses to print. Queue shows job as "Deleting" forever.<br><br>**Cause:** The Driver's rendering filter crashed while processing the job, locking the file handle. |
| **1174** | Audio Endpoint Builder Zombie | **Op:** `RegOpenKey`<br>**Res:** `*`<br>**Path:** `MMDevices\\Audio\\Render` | **Symptom:** "No Audio Output Device is installed" (red X).<br><br>**Cause:** Registry corruption in the audio device enumeration tree. |
| **1175** | TWAIN Driver Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Scanner app freezes on launch.<br><br>**Cause:** A TWAIN source selection dialog is hidden behind the main window, waiting for input. |
| **1176** | Bluetooth Handle Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Bluetooth mouse stops working after 2 days uptime.<br><br>**Cause:** Driver bug leaking handles every time the device enters sleep mode. |
| **1177** | Laptop Lid Switch Sensor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Laptop goes to sleep randomly while typing.<br><br>**Cause:** User is wearing a magnetic bracelet/watch band that triggers the "Lid Closed" Hall Effect sensor in the palm rest. (Classic "Defies Logic"). |
| **1178** | Touchpad Palm Rejection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Cursor jumps randomly while typing.<br><br>**Cause:** Palm Rejection setting disabled or driver update reset sensitivity. |
| **1179** | Docking Station Ethernet Flap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Network drops for 1 second every time user bumps desk.<br><br>**Cause:** Physical loose connection in the USB-C dock connector (Mechanical failure disguised as software). |
| **1180** | GPU "Fake" Monitor (Headless Dongle) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Remote Desktop is fast, local screen is black.<br><br>**Cause:** User forgot a dummy plug in the HDMI port. |

## SECTION 65: THE "COPY/PASTE" ABYSS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1181** | Clipboard Chain Broken | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Copy works, but Paste is greyed out.<br><br>**Cause:** A poorly coded RDP tool or Clipboard Manager opened the clipboard but crashed/forgot to close it, locking it globally. |
| **1182** | Format Not Available | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Can copy text from Notepad, but not from Excel.<br><br>**Cause:** Security software filtering complex clipboard formats to prevent data exfiltration. |
| **1183** | Drag-Drop Handler Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Dragging a file to Outlook freezes Outlook.<br><br>**Cause:** Incompatible shell extension loaded into Outlook's process space. |
| **1184** | RDP Clipboard Sync Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** `rdpclip.exe` High CPU.<br><br>**Cause:** Copying a large file (1GB) via RDP clipboard (Copy/Paste file) on a slow link. |
| **1185** | Excel "The picture is too large" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Error copying cells.<br><br>**Cause:** The cells contain thousands of invisible, tiny vector objects (metadata from a web copy-paste). |

## SECTION 66: THE "FILE SYSTEM TWILIGHT ZONE"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1186** | Sparse File "Disk Full" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** File is 1GB size, 0 bytes on disk. Copying it to FAT32 fails "Disk Full".<br><br>**Cause:** The file is a "Sparse File". Copying it explodes it to its full real size, which exceeds destination capacity. |
| **1187** | Directory Junction Recursion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Backup software runs forever / Anti-Virus hangs.<br><br>**Cause:** Legacy Junction Point permissions are wrong, allowing recursive entry (Infinite Loop). |
| **1188** | File ID Reuse (The "Wrong File" Bug) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Opening "Report.pdf" opens "Photo.jpg".<br><br>**Cause:** Rare logic bug in indexing/caching software (e.g., old Outlook search). |
| **1189** | USN Journal Wrap (Backup Fail) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "Incremental Backup" triggers "Full Backup".<br><br>**Cause:** Too many file changes happened between backups (e.g., a script creating/deleting 1 million files), overflowing the journal history. |
| **1190** | Offline Attribute (Sticky) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** File shows with a grey "X". Cannot open.<br><br>**Cause:** File was tiered to cloud (HSM), but the agent software was uninstalled. Windows still thinks the file is on tape/cloud. |

## SECTION 67: THE "TIME AND SPACE" GREMLINS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1191** | Excel "Date is text" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Formulas break on one PC.<br><br>**Cause:** User customized Region settings in Control Panel, breaking assumptions in shared macros. |
| **1192** | Time Skew (Small) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** weird auth errors, MFA codes "Invalid".<br><br>**Cause:** CMOS battery dying, or VM host time drift. |
| **1193** | Leap Second Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Linux servers crash, Windows apps calculating high-precision intervals hang.<br><br>**Cause:** Poorly handled leap second insertion in NTP upstream. |
| **1194** | Decimal vs Comma | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** CSV imports fail. 1.000 becomes 1000.<br><br>**Cause:** User set locale to German (Comma) but is processing US CSVs (Dot). |

## SECTION 68: "IT ONLY HAPPENS ON TUESDAYS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1195** | Defrag Storm | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PC slow every Wednesday at 2am.<br><br>**Cause:** Scheduled maintenance task. |
| **1196** | Certificate Auto-Enrollment | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Smart Card prompt pops up randomly.<br><br>**Cause:** GPO forcing user to renew cert, but card not inserted. |
| **1197** | Group Policy Refresh (Background) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Active window loses focus every 90 minutes.<br><br>**Cause:** A badly configured GPO (e.g., Drive Maps "Replace" mode) causes a UI refresh on every background interval. |
| **1198** | WSUS Reboot | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PC reboots overnight even with "No Auto Restart".<br><br>**Cause:** Deadline reached in WSUS policy. |
| **1199** | Inventory Scan (SCCM) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Fans spin up for 10 mins.<br><br>**Cause:** Software Inventory Cycle scanning every .exe on the C: drive. |
| **1200** | Browser Update Task | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Chrome closes and reopens.<br><br>**Cause:** Scheduled task set to force update restart. |

## SECTION 69: THE "MEDIA & PRESENTATION" NIGHTMARE

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1201** | HDCP Handshake Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Projector shows "No Signal" or snow, but laptop sees it.<br><br>**Cause:** Content (Netflix/Teams) requires encryption, projector is old/incompatible. |
| **1202** | Audio Switching Lag | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Teams call audio stays on laptop after plugging in headset.<br><br>**Cause:** Hardware ID change event took too long to propagate to Teams. |
| **1203** | PowerPoint Presentation Mode | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** External screen black.<br><br>**Cause:** "Presenter View" is enabled but misconfigured or blocked by overlay software. |
| **1204** | USB Bandwidth Exceeded | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** 4K Webcam freezes when using USB Mic.<br><br>**Cause:** Both devices on same USB Root Hub / Bus controller limit. |
| **1205** | Display Scaling (Blurry App) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** App looks fuzzy on Monitor 2.<br><br>**Cause:** Monitor 1 is 150%, Monitor 2 is 100%. App is not "Per-Monitor DPI Aware". |

## SECTION 70: THE "FINAL 1%" (Logic Defying)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1206** | Bit Flip (Cosmic Ray/Bad RAM) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Chrome crashes on the same website, hash verification fail.<br><br>**Cause:** Physical RAM stick bad bit. |
| **1207** | The "Magnet" User | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Laptop sleeps when user stacks it on top of another laptop.<br><br>**Cause:** Magnet in bottom laptop triggers lid sensor of top laptop. |
| **1208** | The "Spacebar" Heater | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PC wakes up immediately after sleep.<br><br>**Cause:** Keyboard is faulty/dirty, sending "Space" key signal intermittently. |
| **1209** | The "Printer" Voltage | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** USB connection drops when printer turns on.<br><br>**Cause:** Ground loop/Electrical noise from printer spikes the USB bus, resetting the controller. |

## SECTION 71: FAILOVER CLUSTERING (The "High Availability" paradox)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1211** | Quorum Arbitration Loss | **Proc:** `clussvc\.exe` <br>**Op:** `*`<br>**Res:** `STATUS_IO_TIMEOUT\|STATUS_DEVICE_BUSY`<br>**Path:** `Quorum\|Witness` | **Symptom:** Cluster node randomly reboots (Fencing).<br><br>**Cause:** SAN latency exceeded the cluster heartbeat threshold (default 5s/10s), causing the node to panic to prevent corruption. |
| **1212** | CSV (Cluster Shared Volume) Redirected Mode | **Proc:** `System` <br>**Op:** `ReadFile`<br>**Res:** `*`<br>**Path:** `C:\\ClusterStorage` | **Symptom:** Disk I/O performance drops by 90%.<br><br>**Cause:** Metadata node connectivity is lost or a backup snapshot locked the volume, forcing traffic through the network coordinator (Redirected Access). |
| **1213** | Cluster Database (CLUSDB) Hive Lock | **Proc:** `clussvc\.exe` <br>**Op:** `*`<br>**Res:** `SHARING_VIOLATION`<br>**Path:** `HKLM\\Cluster` | **Symptom:** Cluster Service fails to start.<br><br>**Cause:** Anti-Virus or Backup software is scanning the registry hive file `C:\Windows\Cluster\CLUSDB`. |
| **1214** | NetFT Adapter Saturation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Heartbeats missed, node removed.<br><br>**Cause:** "Private" cluster network is being flooded by Live Migration traffic (misconfigured network priority). |
| **1215** | Resource DLL Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** A specific role (e.g., File Server) stays "Pending" forever.<br><br>**Cause:** The custom resource DLL for that role is buggy and hung on a lock. |
| **1216** | Witness Share Access Denied | **Proc:** `clussvc\.exe` <br>**Op:** `CreateFile`<br>**Res:** `ACCESS_DENIED`<br>**Path:** `\\\\.*\\.*` | **Symptom:** File Share Witness goes offline.<br><br>**Cause:** The *Computer Account* (`ClusterName$`) permissions were removed from the share (User accounts don't matter here). |

## SECTION 72: HYPER-V & VIRTUALIZATION HOSTING

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1217** | VMMS Certificate Expiry | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Live Migration fails; VM Connect fails.<br><br>**Cause:** The self-signed certificate used for VM Service communication expired. |
| **1218** | VHDX Merge Lock (The "Backlog") | **Proc:** `vmms\.exe` <br>**Op:** `*`<br>**Res:** `ACCESS_DENIED`<br>**Path:** `.*\.avhdx` | **Symptom:** VM disk space fills up; "Checkpoints" show empty, but `.avhdx` files exist.<br><br>**Cause:** Backup software (Veeam/Commvault) still holds a lock on the delta disk. |
| **1219** | Virtual Switch Extension Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** VMs lose network connectivity intermittently.<br><br>**Cause:** Incompatible network filter driver inserted into the Virtual Switch stack. |
| **1220** | NUMA Spanning Performance Kill | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** VM CPU usage high, Host CPU low.<br><br>**Cause:** VM is allocated RAM/CPU larger than a single physical NUMA node, forcing expensive remote memory access. |
| **1221** | Pass-Through Disk Offline | **Proc:** `vmms\.exe` <br>**Op:** `*`<br>**Res:** `STATUS_DEVICE_OFF_LINE`<br>**Path:** `\\\\.\\PhysicalDrive.*` | **Symptom:** VM fails to start "General Access Denied error".<br><br>**Cause:** The Host OS marked the LUN as "Online" (automount), stealing it from the VM. |
| **1222** | Worker Process (VMWP) Crash | **Proc:** `vmwp\.exe` <br>**Op:** `Process Exit`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** VM turns off instantly.<br><br>**Cause:** Host-side crash of the worker process (often due to video driver or state corruption). |

## SECTION 73: MODERN MANAGEMENT (INTUNE / MDM)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1223** | IME (Intune Mgmt Ext) Hash Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** App shows "Fail" in Company Portal.<br><br>**Cause:** The content downloaded does not match the hash generated during package upload (Proxy corruption or upload error). |
| **1224** | Sidecar / PowerShell Timeout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Script fails.<br><br>**Cause:** Hardcoded 10-minute timeout for Intune PowerShell scripts. |
| **1225** | OMA-DM Sync Failure | **Proc:** `Omadmclient\.exe` <br>**Op:** `Process Exit`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Policies not applying.<br><br>**Cause:** Firewall blocking HTTPS to specific Microsoft MDM endpoints. |
| **1226** | Win32 App Detection Logic Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** App installs, then says "Failed" immediately.<br><br>**Cause:** The detection rule (Registry/File) does not match what the installer actually created (e.g., Version number mismatch). |
| **1227** | Autopilot Profile Not Found | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** OOBE shows standard consumer setup, not Corporate.<br><br>**Cause:** Hardware Hash not uploaded, or device record assigned to wrong group. |
| **1228** | BitLocker Compliance Error (65000) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Device "Non-Compliant".<br><br>**Cause:** DMA DMA Protection settings in BIOS conflict with BitLocker policy, preventing "Secure Boot" validation. |

## SECTION 74: SQL SERVER INTERNALS (OS Perspective)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1229** | SQL OS Scheduler Yielding | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** SQL CPU high, but queries slow.<br><br>**Cause:** "SOS_SCHEDULER_YIELD" - Internal SQL cooperative multitasking is fighting for CPU time. |
| **1230** | Backup I/O Freeze | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** App times out every night at 11pm.<br><br>**Cause:** VSS Snapshot initiation pauses I/O (briefly), but storage latency makes it > 10s. |
| **1231** | Instant File Initialization Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Creating a database takes 20 minutes.<br><br>**Cause:** Service Account lacks "Perform Volume Maintenance Tasks" privilege (cannot skip zeroing). |
| **1232** | SQL Memory Paging | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Performance tanks.<br><br>**Cause:** OS is under pressure and trimming SQL RAM (which shouldn't happen if "Lock Pages in Memory" is set). |
| **1233** | TempDB Contention | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** General slowness.<br><br>**Cause:** Application using heavy temp tables; insufficient TempDB data files (should allow 1 per core). |

## SECTION 75: IIS & WEB INTERNALS (Advanced)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1234** | Application Initialization Warmup Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** First user after deploy gets 503/Error.<br><br>**Cause:** The "Warmup" module is configured to hit a URL that requires Auth, but the warmer is anonymous. |
| **1235** | Rapid Fail Protection (Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** AppPool stops.<br><br>**Cause:** Crash on startup (e.g., Bad `web.config` section, missing DLL). |
| **1236** | HTTP.sys Cert Binding Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Service won't start (Port 443).<br><br>**Cause:** Ghost certificate binding left over from a previous install blocking the port. |
| **1237** | Compression Directory Lock | **Proc:** `w3wp\.exe` <br>**Op:** `*`<br>**Res:** `ACCESS_DENIED`<br>**Path:** `IIS Temporary Compressed Files` | **Symptom:** Static content fails to load.<br><br>**Cause:** Permissions broken on the compression cache folder. |
| **1238** | WebSocket Upgrade Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Real-time chat fails.<br><br>**Cause:** "WebSocket Protocol" feature not installed in Windows Features. |

## SECTION 76: "IT'S DNS" (Advanced Edition)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1239** | DNS Suffix Search List Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Slow app startup (20s).<br><br>**Cause:** Application uses a short name (`server`) and the client has 50 suffixes to check before hitting the right one. |
| **1240** | EDNS0 Fragmentation Drop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Some sites resolve, others don't (Large TXT/DNSSEC).<br><br>**Cause:** Firewall blocks UDP packets > 512 bytes (Legacy DNS limit), dropping EDNS0 extensions. |
| **1241** | Negative Cache "Sticky" Fail | **Op:** `*`<br>**Res:** `NAME_NOT_FOUND`<br>**Path:** `*` | **Symptom:** DNS record fixed on server, client still fails.<br><br>**Cause:** Windows "Negative Cache" (Cache of failures) holding the bad result. `ipconfig /flushdns` required. |
| **1242** | LLMNR/NetBIOS Broadcast Storm | **Op:** `UDP Send`<br>**Res:** `*`<br>**Path:** `224\.0\.0\.252\|.*:5355` | **Symptom:** Network sluggish.<br><br>**Cause:** DNS server unreachable, clients failing over to noisy multicast protocols. |
| **1243** | Hosts File BOM (Byte Order Mark) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Hosts file ignored.<br><br>**Cause:** User saved `hosts` file with UTF-8 BOM or Unicode encoding. Windows networking stack expects ANSI/ASCII. |

## SECTION 77: THE "DLL HELL" 2.0 (Modern Dependencies)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1244** | ApiSetSchema Mapping Fail | **Op:** `LoadImage`<br>**Res:** `NAME_NOT_FOUND\|PATH_NOT_FOUND`<br>**Path:** `api-ms-win-crt-runtime.*` | **Symptom:** App fails to load `api-ms-win-crt-runtime-l1-1-0.dll`.<br><br>**Cause:** Missing "Universal C Runtime" (KB2999226) on older Windows 7/8/Server machines. |
| **1245** | Manifest Activation (SxS) Parse Error | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "The application has failed to start because its side-by-side configuration is incorrect."<br><br>**Cause:** Typo in the application's embedded XML manifest or `application.exe.config`. |
| **1246** | Extension DLL Block (Office) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Excel crash on open.<br><br>**Cause:** Add-in compiled for .NET 2.0 trying to run in .NET 4.0 process (Mixed mode assembly issues). |
| **1247** | Untrusted Font Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Fonts missing in Edge/IE.<br><br>**Cause:** "Untrusted Font Blocking" GPO is enabled. |

## SECTION 78: ADVANCED INPUT & UI

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1248** | Raw Input Thread Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Mouse moves, but clicks ignore. Keyboard dead.<br><br>**Cause:** A low-level keyboard hook (Keylogger/Anti-Cheat) crashed but didn't unhook, blocking the input chain. |
| **1249** | DPI Awareness Lie | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** App is tiny or blurry.<br><br>**Cause:** Developer lied in manifest to avoid Windows scaling, but didn't implement scaling code. |
| **1250** | Composition Surface Loss | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Window content goes black.<br><br>**Cause:** Graphics driver crash/recover invalidated the window texture. |

## SECTION 79: AZURE AD / HYBRID SYNC

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1251** | PRT (Primary Refresh Token) Missing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** SSO fails on M365 apps.<br><br>**Cause:** Device not Hybrid Joined or TPM failure preventing token acquisition. |
| **1252** | Workplace Join Certificate Rot | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Login loops.<br><br>**Cause:** The certificate identifying the device to Azure AD has expired or is corrupt. |
| **1253** | Conditional Access (Device State) Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "You cannot access this resource".<br><br>**Cause:** Device is "Compliant" in Intune, but Azure AD hasn't received the sync signal yet (Latency). |

## SECTION 80: ADVANCED FORENSICS (Persistence)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1254** | WMI Event Consumer (Command Line) | **Proc:** `scrcons\.exe` <br>**Op:** `Process Create`<br>**Res:** `*`<br>**Path:** `cmd\.exe\|powershell\.exe` | **Symptom:** Random `powershell` window pops up.<br><br>**Cause:** Malware using WMI ActiveScriptEventConsumer (Fileless persistence). |
| **1255** | Sticky Keys Backdoor (Classic) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Press Shift 5 times -> CMD prompt opens (instead of Sticky Keys).<br><br>**Cause:** Attacker replaced `sethc.exe` with `cmd.exe`. |
| **1256** | Utilman Hijack | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Click Accessibility on Lock Screen -> CMD opens.<br><br>**Cause:** Attacker replaced `utilman.exe`. |
| **1257** | UserInit Modification | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User logs in, malware runs.<br><br>**Cause:** Comma-separated execution list in UserInit. |
| **1258** | Screensaver Hijack | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Machine idle -> Malware runs.<br><br>**Cause:** Screensavers are just standard executables; attacker changed the path. |

## SECTION 81: CLOUD STORAGE EDGE CASES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1259** | OneDrive "File Locked" (Office Upload) | **Proc:** `OneDrive\.exe` <br>**Op:** `*`<br>**Res:** `SHARING_VIOLATION`<br>**Path:** `*` | **Symptom:** Sync stuck.<br><br>**Cause:** "Use Office applications to sync Office files" setting conflict. |
| **1260** | Dropbox Permissions Rot | **Proc:** `Dropbox\.exe` <br>**Op:** `*`<br>**Res:** `ACCESS_DENIED`<br>**Path:** `\.dropbox\.cache` | **Symptom:** Sync fails "Permission Denied".<br><br>**Cause:** User copied files from another PC with explicit ACLs that don't match current user. |
| **1261** | File Name Character sync fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** File won't sync to SharePoint.<br><br>**Cause:** SharePoint/OneDrive restricted characters/names. |

## SECTION 82: HARDWARE ERRORS (WHEA)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1262** | WHEA Corrected Error (PCIe) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** System micro-stutters.<br><br>**Cause:** PCIe card (NIC/GPU) signaling errors, OS keeps retrying. Hardware failing. |
| **1263** | Machine Check Exception (MCE) - Soft | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Random app crashes.<br><br>**Cause:** CPU L2/L3 cache bit flip (Corrected, but indicates dying CPU). |

## SECTION 83: PRINTER "GHOSTS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1264** | WSD (Web Services for Devices) Port Flap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Printer shows "Offline" then "Online".<br><br>**Cause:** WSD multicast discovery is unreliable on enterprise Wi-Fi; printer drops off. |
| **1265** | Driver Version Mismatch (Point & Print) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User cannot connect to shared printer.<br><br>**Cause:** Mismatched driver generations preventing connection. |

## SECTION 84: SYSTEM RESTORE & RECOVERY

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1266** | VSS Shadow Copy Deletion (Defender) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Restore points vanish.<br><br>**Cause:** Low disk space triggers automatic VSS cleanup (High Churn). |
| **1267** | Recovery Partition Disabled | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Cannot "Reset this PC".<br><br>**Cause:** Windows Update moved the partition map, breaking the link to `WinRE.wim`. |

## SECTION 85: 16-BIT & DOS (The Ancients)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1268** | NTVDM CPU Spike | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** 100% CPU on `ntvdm.exe`.<br><br>**Cause:** Old DOS apps rely on CPU cycles for timing; modern CPUs run them too fast. (Requires `TAME.COM` or similar). |
| **1269** | AUTOEXEC.NT Parsing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** 16-bit app fails to start.<br><br>**Cause:** File missing or corrupt (often flagged by AV). |

## SECTION 86: SPECIFIC ERROR CODES (RPC/Win32)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1270** | RPC_S_SERVER_UNAVAILABLE (0x6BA) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Context:** RPC endpoint mapper reachable (135), but dynamic port blocked. |
| **1271** | RPC_S_CALL_FAILED (0x6BE) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Context:** The remote procedure call started, but the server process crashed mid-execution. |
| **1272** | ERROR_MORE_DATA (0xEA) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Context:** Buffer too small. (App logic error). |
| **1273** | ERROR_NO_SYSTEM_RESOURCES (0x5AA) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Context:** Non-paged pool limit or Thread limit hit. |

## SECTION 87: ADVANCED EVENT LOGGING

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1274** | Event Log Service Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** High CPU `wevtsvc`.<br><br>**Cause:** Audit log full, system trying to handle the "CrashOnAuditFail" condition. |
| **1275** | Subscription Failure (Source Initiated) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Logs not forwarding.<br><br>**Cause:** Network Service account lacks permission to read the Event Log. |

## SECTION 88: FONT CACHE & RENDERING

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1276** | Presentation Cache Corrupt | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** WPF Apps (Visual Studio, etc.) crash on launch.<br><br>**Cause:** WPF Font Cache service data corruption. |
| **1277** | EUDC (End User Defined Character) Link | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Squares appear instead of characters.<br><br>**Cause:** Missing link to custom character map (Asian markets). |

## SECTION 89: BATTERY & POWER

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1278** | Modern Standby (S0) Drain | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Laptop hot in bag, battery dead.<br><br>**Cause:** "Connected Standby" allows apps to wake network. (Need `powercfg /sleepstudy`). |
| **1279** | Hibernation File Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Cannot hibernate.<br><br>**Cause:** Anti-Virus locking the hibernation file. |

## SECTION 90: THE "IMPOSSIBLE" (Logic Defying)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1281** | The "Invisible" File | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** File exists in CMD, invisible in Explorer.<br><br>**Cause:** File has `System` + `Hidden` attributes set. |
| **1282** | The "Null" User | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** ACL shows "Account Unknown (S-1-5-...)".<br><br>**Cause:** The user was deleted from AD, but the file permissions remain (Orphaned SID). |

## SECTION 91: APP-V / THINAPP

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1284** | Bubble-to-Bubble Comms | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** App A cannot see App B's DLLs.<br><br>**Cause:** Virtual environments are isolated. Requires "Connection Group" configuration. |

## SECTION 92: DFS (DISTRIBUTED FILE SYSTEM)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1285** | DFS Referral Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Accessing `\\Domain\DFS\Share` hangs.<br><br>**Cause:** Site cost configuration missing in AD Sites & Services; client treating remote server as local. |
| **1286** | Offline Files sync trap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User sees old files.<br><br>**Cause:** DFS target moved, client stuck in Offline mode pointing to old target logic. |

## SECTION 93: CERTIFICATES (Advanced)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1287** | AIA (Authority Info Access) Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Certificate Valid, but "Extra download" lag.<br><br>**Cause:** Intermediate CA certificate missing locally; Windows trying to fetch it from web on every use. |
| **1288** | Key Spec Mismatch (Exchange/IIS) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** SSL/TLS handshake fail.<br><br>**Cause:** Cert imported with wrong `KeySpec`, unusable for SSL. |

## SECTION 94: TASK SCHEDULER

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1289** | Task Queued (Wait) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Task doesn't run.<br><br>**Cause:** "Run only if idle" condition not met (Mouse moved). |
| **1290** | Run Level Mismatch | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Scripts fails silently.<br><br>**Cause:** "Run with highest privileges" not checked, script needs Admin. |

## SECTION 95: PERFMON & COUNTERS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1291** | Counter Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PerfMon empty.<br><br>**Cause:** Registry counter strings mismatched. Needs `lodctr /r`. |
| **1292** | WMI Class Missing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Monitoring tool fails.<br><br>**Cause:** WMI ADAP (AutoDiscovery) failed to parse driver perf counters. |

## SECTION 96: LICENSING (KMS/MAK)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1293** | KMS Count Too Low | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Windows not activating.<br><br>**Cause:** KMS Host hasn't reached the threshold count (25 for Clients, 5 for Servers). |
| **1294** | Time Drift Activation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Activation fails.<br><br>**Cause:** Client time differs from KMS host time > 4 hours. |

## SECTION 97: ROAMING PROFILES (The Horror)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1295** | Profile Tombstoning | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Temp profile login.<br><br>**Cause:** Admin deleted `C:\Users\Bob` manually but didn't remove Registry key. |
| **1296** | Ntuser.dat.LOG Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Hive corruption.<br><br>**Cause:** Profile failed to unload cleanly on last logoff. |

## SECTION 98: DYNAMIC DATA EXCHANGE (DDE)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1297** | DDE Broadcast Hang | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Excel hangs opening file.<br><br>**Cause:** DDE "Ignore other applications" setting, or another app (Word) not replying to DDE broadcast. |

## SECTION 99: WINDOWS SEARCH

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1298** | Index Rebuild Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** High CPU `SearchIndexer`.<br><br>**Cause:** Corrupt file (PDF/TIFF) crashing the `IFilter` extraction process repeatedly. |
| **1299** | Outlook Search Scope | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "No results".<br><br>**Cause:** Outlook excluded from Indexing Options by GPO. |

## SECTION 100: THE "END OF THE LINE"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1300** | The "Solar Flare" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** ECC Memory Error.<br><br>**Cause:** Literal cosmic radiation flipping a bit in RAM. (The ultimate "Mark Russinovich" excuse). |

## SECTION 101: THE "PHYSICAL WORLD" INTERFERENCE

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1302** | The "Tidal" WiFi | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Point-to-Point wireless link drops at high tide.<br><br>**Cause:** The water level rising reflects/refracts the signal (Multipath Fading) differently, killing the link. |
| **1305** | The "Spacebar" Heater | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PC wakes from sleep instantly, every time.<br><br>**Cause:** A space heater under the desk is blowing hot air on a cheap membrane keyboard, causing the plastic to expand and trigger a "Space" key press. |
| **1306** | The "Vampire" Tap | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** 10Mbps link speed negotiation on a Gigabit port.<br><br>**Cause:** Physical cable damage. One of the 4 pairs is broken, forcing the NIC to fall back to 100Mbps or 10Mbps (which uses fewer pairs). |

## SECTION 102: LEGACY & RESERVED NAMES (The "CON" Bugs)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1308** | The "CON" Folder | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User cannot save file "Con.txt" or "Aux.doc". "The handle is invalid".<br><br>**Cause:** These are reserved device names from 1981 DOS. Windows still blocks them at the kernel object manager level. |
| **1309** | The "Initial" Bug | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User "P.R.N. Smith" cannot have a profile.<br><br>**Cause:** "PRN" is a reserved device name (Printer). |
| **1311** | The "Deep" Path | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Backup fails on one specific folder.<br><br>**Cause:** User mapped a drive `Z:` to `\\Server\Share\Deep\Folder`, then created deep folders inside Z:. The absolute path is now > 260 chars, invisible to the user but visible to the Backup Agent running as System. |

## SECTION 103: THE "HEISENBERG" BUGS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1313** | The "Focus" Stealer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Fullscreen game minimizes randomly.<br><br>**Cause:** An app checks "Is User Idle?". If you are debugging, you aren't idle, so the bug doesn't trigger. |
| **1314** | The "ProcMon" Denial | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Malware runs. You open ProcMon. Malware terminates.<br><br>**Cause:** Anti-analysis evasion. |

## SECTION 104: DRIVER & KERNEL "ZOMBIES"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1316** | Ghost NIC (Hidden Device) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "IP Address already assigned to another adapter".<br><br>**Cause:** You moved the VM network card to a new slot. Windows sees it as a "New" card, but the "Old" card (Hidden) still holds the Static IP. |
| **1317** | Filter Driver Altitude Collision | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Blue Screen `0x7F` or `0x3B` on file access.<br><br>**Cause:** They are fighting for the same stack frame in the kernel. |
| **1319** | Audio "Enhancement" Deadlock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Sound works in Chrome, but Spotify hangs.<br><br>**Cause:** "Audio Enhancements" (Bloatware) inject into the audio stream and deadlock on specific sample rates. |

## SECTION 105: SECURITY & PERMISSION "LAYERS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1320** | Bypass Traverse Checking (The "Deep" Access) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User can access `\\Server\Share\Folder\File.txt` by direct path, but cannot browse to it.<br><br>**Cause:** "Bypass Traverse Checking" privilege allows passing through denied folders if you know the destination path. |
| **1321** | Owner Rights (The "Creator" Trap) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User creates a file, closes it, and cannot open it again.<br><br>**Cause:** When the file is created, "Creator Owner" logic applies. If that ACE is missing or broken, the user loses control of their own file immediately after creation. |
| **1322** | ICACLS Canonical Order | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Permissions behave erratically (Deny doesn't deny).<br><br>**Cause:** A script or non-Windows tool modified the ACLs and put "Allow" before "Deny". |
| **1323** | The "Null" SID | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** File has no owner. Impossible to delete.<br><br>**Cause:** Corruption or a bug in a file migration tool. Requires `takeown` to fix. |

## SECTION 106: ACTIVE DIRECTORY "TIME BOMBS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1324** | Token Bloat (The "1000 Groups") | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User logs in, but cannot access File Shares or IIS apps. "400 Bad Request".<br><br>**Cause:** User is in > 100 groups. The Kerberos token exceeds the default HTTP header size limit (MaxTokenSize). |
| **1325** | AdminSDHolder (The "Protected" User) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** You grant a user permissions on their phone object, 60 mins later it disappears.<br><br>**Cause:** SDProp process runs every hour and resets permissions on "Protected Groups" to match `AdminSDHolder` template. |
| **1326** | USN Rollback (The "Zombie" DC) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Deleted users reappear. Passwords revert.<br><br>**Cause:** A VM Snapshot of a Domain Controller was restored. It is now out of sync and replicating "old" truth back to the network. |

## SECTION 107: NETWORK "INVISIBLE" DROPS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1327** | TCP Chimney Offload Bug | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** SQL Connection drops during heavy load.<br><br>**Cause:** Buggy NIC firmware corrupting packets when Offload is enabled. |
| **1328** | Windows Filtering Platform (WFP) Silent Drop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Packet arrives at NIC (Wireshark sees it), but App doesn't get it. Windows Firewall is OFF.<br><br>**Cause:** A hidden WFP filter (from an uninstalled Antivirus or VPN) is still active and silently dropping traffic. |
| **1329** | Ephemeral Port Exhaustion (Outbound) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Server cannot make *outbound* connections (e.g., to a backend DB).<br><br>**Cause:** App is opening/closing TCP connections too fast, using up all 65k ports before they can timeout. |
| **1330** | Path MTU Discovery Black Hole | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Can ping server, but cannot load web page.<br><br>**Cause:** A router in the middle has a small MTU (e.g., VPN tunnel) but is blocking the ICMP "Fragmentation Needed" message. The handshake works (small packets), but data (large packets) is dropped silently. |

## SECTION 108: APPLICATION COMPATIBILITY "SHIMS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1331** | The "Lie" Shim | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** App thinks it's running on Windows XP.<br><br>**Cause:** Windows automatically detected the app name (e.g., `setup.exe`) and applied a compatibility fix. |
| **1332** | Heap Mitigation Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Old app crashes on Windows 10.<br><br>**Cause:** App has a heap buffer overrun. Windows tried to fix it with FTH, but the fix caused a logic error. |
| **1333** | Installer Detection (UAC) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Renaming a tool `updater.exe` makes it ask for Admin.<br><br>**Cause:** Heuristic detection: filenames containing "setup", "patch", "update" automatically trigger UAC virtualization. |

## SECTION 109: "THE USER DIDN'T DO IT" (But they did)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1334** | Drag and Drop Accidental Move | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "The Finance Folder is gone!"<br><br>**Cause:** User clicked and dragged the folder 2 pixels while moving the mouse. Windows interpreted it as a "Move" command. |
| **1336** | Browser Zoom Prank | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "The internet is tiny."<br><br>**Cause:** User hit `Ctrl + Scroll Wheel`. |

## SECTION 110: "IT'S NOT A BUG, IT'S A FEATURE"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1337** | Fast Startup (The "Fake" Shutdown) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "I rebooted!" (Uptime says 30 days).<br><br>**Cause:** "Shutdown" in Windows 10/11 is actually "Hibernate". Only "Restart" performs a full kernel reset. |
| **1338** | Modern Standby (Network Connected) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Laptop battery dead in bag. Hot to touch.<br><br>**Cause:** Laptop woke up to install an update or sync email while in the bag. |
| **1339** | Windows Update "Active Hours" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PC reboots while user is getting coffee.<br><br>**Cause:** Current time was outside the configured "Active Hours". |
| **1340** | Focus Assist (Do Not Disturb) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "I'm missing Outlook notifications!"<br><br>**Cause:** Turned on automatically because user is "Duplicating Display" (Presenting). |

## SECTION 111: THE "INVISIBLE" INPUT GLITCHES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1342** | Filter Keys "Slow Mode" Trap | **Op:** `RegSetValue`<br>**Res:** `*`<br>**Path:** `Accessibility\\Keyboard Response` | **Symptom:** User claims keyboard is broken; have to hold keys for 2 seconds to type.<br><br>**Cause:** User held the Right-Shift key for exactly 8 seconds (often while thinking), triggering the Accessibility Filter Keys shortcut without noticing the toast notification. |
| **1344** | Focus Assist "Game" Lock | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `NOC_GLOBAL_SETTING_TOASTS_ENABLED` | **Symptom:** Windows key doesn't work. Alt-Tab doesn't work.<br><br>**Cause:** Windows thinks Excel is a "Full Screen Game" because it is using GPU acceleration, so it disabled shell shortcuts (Game Mode). |
| **1346** | Mouse "Polling Rate" stutter | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** High-end PC stutters when moving mouse.<br><br>**Cause:** User bought a "1000Hz" gaming mouse. The CPU interrupt load (1000 ints/sec) is overwhelming a specific USB controller driver. |

## SECTION 112: DISPLAY & GPU "POLTERGEISTS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1347** | The "Sepia" Screen (Night Light Registry Rot) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Screen is yellow/orange. Night Light is "Off" in Settings.<br><br>**Cause:** The UI toggle desynced from the underlying registry state (often after a driver update or fast shutdown). |
| **1348** | Intel DPST "Flicker" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Screen brightness changes randomly when switching from Dark Mode app to Light Mode app.<br><br>**Cause:** Feature dimming the backlight to save power based on image content (Content Adaptive Brightness). |
| **1349** | The "Invisible" App (Off-Screen Coordinates) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User launches App, sees icon in taskbar, but no window.<br><br>**Cause:** App was last closed when laptop was docked to 3 monitors. Now undocked, it remembers coordinates that don't exist. |
| **1351** | The "Ghost" Overlay (Unclickable Spot) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** User cannot click a specific 50x50 pixel spot on the screen.<br><br>**Cause:** An in-game overlay got stuck on the desktop with 1% opacity. |
| **1352** | Icon Cache "Black Box" Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Desktop icons turn into black squares.<br><br>**Cause:** The database grew beyond 24MB (undocumented legacy limit in some versions) or header corruption. |
| **1353** | Wallpaper "Transcoding" Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Desktop background is black. Cannot set new image.<br><br>**Cause:** Windows converts all wallpapers to a standard JPG. If that process crashes, the file gets locked/corrupted and the UI fails silently. |

## SECTION 113: AUDIO & MEDIA "GREMLINS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1355** | Audio "Enhancement" Processing Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Audio sounds robotic or echoed.<br><br>**Cause:** Third-party driver effects ("Bass Boost", "Room Correction") malfunctioned. (Fix: "Disable all enhancements" checkbox). |
| **1356** | HDMI Audio "Silent" Stream | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** TV shows "PCM Audio" but no sound comes out.<br><br>**Cause:** Windows thinks the TV is 5.1 surround. It sends vocals to the "Center" channel. The TV is stereo (2.0) and drops the Center channel. (User hears background music but no voices). |
| **1357** | Bluetooth Hands-Free Profile (HFP) Quality | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Spotify sounds like a telephone call (Mono, Low Quality).<br><br>**Cause:** An app opened the Microphone. Bluetooth bandwidth cannot support High Def Audio + Mic simultaneously, so it drops to HFP. |

## SECTION 114: POWER & SLEEP "INSOMNIA"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1358** | Modern Standby "Network" Wake | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Laptop hot in bag. Battery drained.<br><br>**Cause:** "Network connectivity in Standby" is Enabled. Laptop woke up to process a multicast packet or update check. |
| **1360** | Power Request "System" Override | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PC never sleeps.<br><br>**Cause:** An app (like Chrome playing a video, or a stuck Print Job) has requested the power management system to stay awake. |
| **1361** | Shutdown vs Hibernate (Fast Startup) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "I shut it down every night!" (Uptime 45 days).<br><br>**Cause:** User clicks "Shut Down". Windows Kernel hibernates (S4) to allow Fast Startup. The kernel never reinitializes. |

## SECTION 115: WIFI & NETWORK "V00D00"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1362** | The "Roaming" Aggressiveness | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** WiFi drops every 2 minutes.<br><br>**Cause:** "Roaming Aggressiveness" driver setting is "Highest". Laptop bounces between the Living Room AP and Kitchen AP constantly. |
| **1364** | Metered Connection "Outlook Block" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Outlook says "Disconnected" but Chrome works.<br><br>**Cause:** User clicked "Set as Metered Connection" for their Home WiFi. Outlook respects this and stops syncing to save data. |
| **1365** | MAC Randomization (Captive Portal Loop) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Hotel WiFi asks to login every single day.<br><br>**Cause:** "Use random hardware addresses" is On. The Hotel tracks the device by MAC. |

## SECTION 116: SHELL & EXPLORER "ROT"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1367** | Context Menu "Cloud" Delay | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Right-click on Desktop takes 5 seconds.<br><br>**Cause:** Graphics driver context menu extension is initializing a slow API. |
| **1368** | Recycle Bin Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "The Recycle Bin on C:\ is corrupted. Do you want to empty it?"<br><br>**Cause:** Mismatched SID (Security ID) in the recycler folder meta-files after a user profile migration. |
| **1369** | Search Index "Outlook" Missing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Start Menu doesn't find emails.<br><br>**Cause:** Outlook was installed with "Run as Admin", creating registry keys the System Indexer couldn't read/merge. |

## SECTION 117: USB & PERIPHERAL "GHOSTS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1370** | USB Selective Suspend (The "Dying Mouse") | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** USB mouse disconnects, reconnects 2 seconds later.<br><br>**Cause:** Windows puts the USB Hub to sleep to save power. The Mouse takes too long to wake up, so Windows resets the port. |
| **1371** | Phantom COM Port (In Use) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Cannot use USB-to-Serial adapter on COM1. "Port in use".<br><br>**Cause:** A device that is physically unplugged "reserved" COM1 in the registry years ago. |
| **1372** | Docking Station "Billboard" Device | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** USB-C Dock doesn't work. "USB Device not recognized".<br><br>**Cause:** USB-C "Alternate Mode" negotiation failed. The dock fell back to USB 2.0 "Billboard" class to tell the OS it failed. |

## SECTION 118: CRYPTO & TPM "LOCKOUTS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1373** | TPM "Hysteresis" Lockout | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Windows Hello "Something went wrong".<br><br>**Cause:** User entered wrong PIN too many times. TPM hardware enters "Dictation Attack" lockout mode (can last 2-24 hours). |
| **1374** | NGC Container "Desync" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Fingerprint works, but asks for PIN, which fails.<br><br>**Cause:** The cryptographic key protected by the TPM is valid, but the user's password changed, and the "Protector" wasn't updated. |
| **1375** | BitLocker "DMA" Trigger | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** BitLocker asks for Recovery Key on every boot.<br><br>**Cause:** A Thunderbolt dock was plugged in at boot. BIOS DMA protection policies triggered a "Hardware Change" alert to the TPM. |

## SECTION 119: 3RD PARTY APP INTERACTIONS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1376** | Chrome "Renderer" Code Integrity | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Chrome tabs crash instantly "Aw Snap".<br><br>**Cause:** Old Symantec/McAfee DLP agent trying to inject a DLL into the Chrome Renderer process, which Chrome blocks (Microsoft mitigation policy). |
| **1377** | Excel "Clipboard" Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "We couldn't free up space on the Clipboard".<br><br>**Cause:** An RDP session or "Remote Desktop App" is syncing the clipboard and locked it. |
| **1378** | Zoom "Camera" Exclusive Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Camera black in Zoom. Works in Camera App.<br><br>**Cause:** The "Windows Camera Frame Server" service crashed, holding the handle to the hardware driver, preventing new apps from binding. |

## SECTION 120: THE "USER PROFILE" SINGULARITIES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1379** | Temporary Profile (Ref Count) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "We can't sign into your account".<br><br>**Cause:** The User Registry Hive (`NTUSER.DAT`) was locked by an Anti-Virus scanner during logoff, preventing unload. |
| **1380** | Roaming AppData Bloat | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Black screen at logon for 10 minutes.<br><br>**Cause:** AppData\Roaming is 20GB. Windows tries to sync it all from the server before showing the desktop. |
| **1381** | Known Folder Redirection "Loop" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Documents folder is empty.<br><br>**Cause:** Bad OneDrive or GPO logic created a recursive path mapping. |

## SECTION 121: INSTALLATION & MSI "GHOSTS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1383** | Pending Reboot "Sentinel" File | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Software fails to install "Restart Required", even after restart.<br><br>**Cause:** A specific Windows Update flag got stuck. |

## SECTION 123: BROWSER "CERTIFICATE" WEIRDNESS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1386** | Date "Validity" 2038 | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Website secure connection fails.<br><br>**Cause:** 32-bit timestamp overflow in older crypto libraries used by specific banking middleware. |
| **1387** | Root CA "Disable" Flag | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** All HTTPS sites invalid.<br><br>**Cause:** User accidentally moved a Root CA (like DigiCert) into the "Untrusted Certificates" store. |

## SECTION 124: HARDWARE "BUTTON" OVERRIDES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1389** | Physical WiFi Switch (BIOS) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** WiFi adapter missing from Device Manager.<br><br>**Cause:** Physical toggle switch on the side of the laptop (older models) turns off the PCIe bus for the card. |

## SECTION 125: THE "TIME TRAVEL" FILES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1390** | Future Timestamps (Build Fails) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "Make" or "Compile" fails. "File modification time is in the future".<br><br>**Cause:** File was touched by a server with a clock set 5 minutes ahead. Local build tool treats it as "impossible" and crashes. |

## SECTION 126: FONT & TEXT RENDERING

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1391** | Variable Font "Glitches" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Text appears as blocks or overlaps in one app.<br><br>**Cause:** App uses an old text rendering engine (GDI) that doesn't support "Variable Fonts" (single file, multiple weights). |
| **1392** | EUDC (End User Defined Character) Link | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Strange squares in text.<br><br>**Cause:** System is trying to link a custom character map (common in legacy enterprise apps) that is missing. |

## SECTION 127: "IT'S THE CABLE" (But Software)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1393** | Ethernet "Energy Efficient" Drop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Network drops when downloading large files.<br><br>**Cause:** "Energy Efficient Ethernet" (EEE) or "Green Ethernet" in driver settings. It tries to sleep the PHY during micro-gaps in data, but the switch port doesn't wake up fast enough. |

## SECTION 128: THE "OEM" BLOATWARE INTERFERENCE

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1394** | Dell/HP "Optimizer" Network Shaping | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Zoom is perfect, but Browser download is 10Kbps.<br><br>**Cause:** OEM bloatware traffic shaper prioritizing UDP (Video) and throttling TCP (Download) aggressively. |

## SECTION 129: FILE SYSTEM "CASE" SENSITIVITY

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1396** | WSL (Linux) Case Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "File not found" when the file is right there.<br><br>**Cause:** User enabled WSL, which turned on per-folder case sensitivity. Windows Apps (NotePad) usually fail this check. |

## SECTION 131: THE "INPUT" POLTERGEISTS (HID/USB)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1402** | Touchscreen "Phantom" Moisture | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Windows Start Menu opens and closes rapidly.<br><br>**Cause:** The bezel of the screen is slightly pinched or dirty, and thermal expansion causes it to register a touch in the corner. |
| **1404** | Wireless Receiver Interference (USB 3.0) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Wireless mouse lags/stutters only when an external hard drive is transferring data.<br><br>**Cause:** USB 3.0 ports emit radio frequency interference at 2.4GHz, jamming the wireless dongle plugged into the adjacent port. |
| **1405** | Digitizer Pen "Hover" Click | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Clicks register before the pen touches the screen.<br><br>**Cause:** The pressure sensor inside the stylus tip is physically stuck or calibrated wrong. |
| **1407** | Wacom Driver "Windows Ink" War | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Photoshop canvas pans instead of painting.<br><br>**Cause:** "Use Windows Ink" checkbox in tablet settings conflicts with app-specific API calls. |
| **1408** | Mouse "Lift-Off" Jitter | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Cursor jumps to ceiling when picking up the mouse.<br><br>**Cause:** Optical sensor Lift-Off Distance (LOD) is set too high for the mousepad surface. |
| **1409** | Barcode Scanner "Enter" Key | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Forms submit automatically before user finishes typing.<br><br>**Cause:** Handheld scanner is configured to send a "Carriage Return" suffix after every scan. |
| **1410** | Game Controller "Screensaver" Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PC never locks/sleeps.<br><br>**Cause:** A plugged-in joystick with a slight drift (0.1%) is sending constant "Input" events, resetting the idle timer. |

## SECTION 132: AUDIO & VIDEO "GREMLINS"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1411** | Sample Rate Mismatch (The "Chipmunk" Effect) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Microphone audio is sped up (high pitch) or slow (demon voice).<br><br>**Cause:** Clock drift or driver mismatch without resampling. |
| **1412** | Front Panel Jack Detection Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Headphones plugged in, sound still comes from speakers.<br><br>**Cause:** The physical sensing pin inside the 3.5mm jack is bent or the connector to the motherboard (HD Audio) is loose. |
| **1414** | HDMI "Sleep" Audio Loss | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Audio works on TV until PC sleeps. On wake, silence.<br><br>**Cause:** GPU driver failed to re-handshake HDCP audio encryption on wake. |
| **1415** | Spatial Sound Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Game crashes immediately on launch.<br><br>**Cause:** Game engine is incompatible with "Windows Sonic for Headphones" virtualization. |
| **1416** | Webcam "Privacy" Shutter (Hardware) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Camera is black. Driver is fine. LED is on.<br><br>**Cause:** The physical plastic slider is closed. (Surprisingly common "tech" issue). |
| **1417** | USB Bandwidth "Robotic" Mic | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Voice cuts out or sounds robotic during video calls.<br><br>**Cause:** 4K Webcam and USB Mic on the same root hub. Not enough reserved bandwidth for both streams. |
| **1418** | Monitor "Deep Sleep" disconnect | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Windows move to primary monitor every time user returns from lunch.<br><br>**Cause:** Monitor enters "Deep Sleep" and physically disconnects from the bus, triggering Windows to rearrange desktops. |
| **1419** | ICC Profile "Yellow" Photo Viewer | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Photos look yellow in Windows Photo Viewer, fine in Chrome.<br><br>**Cause:** Windows Update installed a broken OEM color profile for the monitor. |
| **1420** | Refresh Rate Mixing Stutter | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** 144Hz Main monitor lags when video plays on 60Hz Second monitor.<br><br>**Cause:** Desktop Window Manager (DWM) struggling to V-Sync two different refresh rates simultaneously on one GPU. |

## SECTION 133: NETWORK "BLACK HOLES"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1422** | IPv6 "Link-Local" Broadcast Storm | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** WiFi slow.<br><br>**Cause:** A device on the network is misconfigured and looping multicast traffic. |
| **1423** | QoS Packet Tagging Drop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** VoIP app connects but audio is one-way.<br><br>**Cause:** Cheap home router sees the QoS tag, doesn't understand it, and drops the packet. |
| **1424** | Network Location Awareness (NLA) Stuck | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Firewall profile stays "Public" on Domain Network.<br><br>**Cause:** Switch portfast is disabled; PC boots faster than switch port negotiates, NLA fails detection and defaults to Public. |
| **1426** | WLAN "Background Scan" Lag | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Online games spike lag every 60 seconds.<br><br>**Cause:** Windows scans for better WiFi networks periodically. This scan requires tuning off the radio for 500ms. |
| **1427** | TCP Window Scaling (Old Router) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Downloads cap at 2Mbps on a 100Mbps line.<br><br>**Cause:** Legacy router/firewall creates a "Window Scaling" incompatibility, stripping the scale factor option. |
| **1429** | Captive Portal Detection (NCSI) False Negative | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "No Internet Access" globe icon, but internet works.<br><br>**Cause:** Corporate firewall blocks the specific Microsoft test URL, confusing the Network Connectivity Status Indicator. |
| **1430** | SMB Direct (RDMA) over WiFi | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** File copies fail instantly.<br><br>**Cause:** Driver bug reporting RDMA capability on a wireless interface that doesn't support it. |

## SECTION 134: FILESYSTEM "ARCHAEOLOGY"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1432** | Desktop.ini "Hiding" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Folder looks empty but isn't.<br><br>**Cause:** Malware or prankster set the folder to behave like a "Recycle Bin" or "Control Panel" via `Desktop.ini`. |
| **1433** | FAT32 4GB Limit (The "Generic" Error) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Copying movie file to USB fails: "The file is too large for the destination file system".<br><br>**Cause:** Standard file system limitation often misread by users as "Not enough space". |
| **1434** | Long Path (>260) Legacy App Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** App crashes opening file.<br><br>**Cause:** Even if Windows 10 "Long Paths" is enabled, the specific application is built on an old .NET/Win32 version that doesn't support it. |
| **1435** | The "Dot" Folder (Naming) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Cannot delete folder named `Con.` or `Folder.`<br><br>**Cause:** Created via command line or Linux. Needs `\\?\C:\Path\Folder.` syntax to remove. |
| **1436** | WebDAV File Lock | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Word document "Locked for editing by 'Another User'".<br><br>**Cause:** A WebDAV (SharePoint) session crashed leaving a persistent lock file on the server. |
| **1437** | Metadata "Date Taken" Sorting | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Photos sort randomly.<br><br>**Cause:** "Date" column uses EXIF metadata (Date Taken) which might be missing or wrong in the camera. |
| **1438** | Symbolic Link Cycle (Backup) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Backup drive fills up with infinite nested folders `\App\App\App...`<br><br>**Cause:** Badly created Junction Point. |
| **1439** | File Stream "Zone" Propagation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Unzipping a file makes all contents "Blocked".<br><br>**Cause:** Windows Archive extraction propagates the "Mark of the Web" to all extracted files. |

## SECTION 135: REGISTRY & CONFIG "ROT"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1441** | ShutdownWithoutLogon | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Shutdown button missing from login screen.<br><br>**Cause:** Security policy hidden setting. |
| **1442** | UserAssist "ROT13" Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Start Menu "Frequently Used" is empty.<br><br>**Cause:** The ROT13 encoded tracking data is corrupt. |
| **1443** | ShellBags Off-Screen | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Opening a folder makes nothing happen (Window is off-screen).<br><br>**Cause:** Saved window position from a previous multi-monitor setup. |
| **1445** | AutoAdminLogon Loop | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PC reboots and logs in indefinitely.<br><br>**Cause:** Config management script set force logon but didn't disable it after task completion. |
| **1446** | Background Intelligent Transfer (BITS) Job Rot | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Network slow.<br><br>**Cause:** Windows Update or Chrome Update created jobs that failed, and they are retrying forever. |
| **1447** | Firewall "Block All" Panic | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** No network access.<br><br>**Cause:** User clicked "Block All" in a panic popup. |
| **1448** | Environment Variable Path Truncation | **Op:** `RegQueryValue`<br>**Res:** `BUFFER OVERFLOW`<br>**Path:** `Environment\\Path` | **Symptom:** Random CMD tools "Not Recognized".<br><br>**Cause:** Too many installed dev tools appended to PATH, truncating the system entries at the end. |
| **1449** | "Debugger" Image Hijack (Not Malware) | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `Image File Execution Options.*Debugger` | **Symptom:** `Notepad.exe` opens `Notepad++.exe`.<br><br>**Cause:** Legitimate replacement of system tools by a power user utility, forgotten 2 years later. |
| **1450** | Drive Letter "Stickiness" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** USB Drive doesn't appear.<br><br>**Cause:** The drive is assigned letter `E:`, but `E:` is currently mapped to a Network Share. |

## SECTION 136: HARDWARE & PHYSICS "INTERFERENCE"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1451** | Static Discharge (The "Carpet" Reboot) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PC reboots when user sits down.<br><br>**Cause:** ESD (Electrostatic Discharge) from chair/carpet jumping to the USB port or metal chassis. |
| **1452** | Ground Loop Hum | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Speakers buzz when mouse moves.<br><br>**Cause:** PC and Speakers plugged into different wall outlets with different ground potentials. |
| **1453** | HDD Free-Fall Sensor Trigger | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Laptop freezes for 2s when user bangs desk.<br><br>**Cause:** Vibration protection sensitivity too high. |
| **1454** | Piezoelectric "Singing" Capacitor | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** High pitched whine from laptop.<br><br>**Cause:** Ceramic capacitors vibrating at audible frequencies (Coil Whine). |
| **1455** | Thermal Throttling (Dust) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Gaming FPS drops after 10 mins.<br><br>**Cause:** Heatsink clogged with dust. |
| **1456** | Battery Calibration Drift | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Laptop shuts down at 30% battery.<br><br>**Cause:** BMS (Battery Management System) lost track of actual capacity cells. Needs full cycle. |
| **1458** | Dirty Power (Brownouts) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** PC reboots at random times.<br><br>**Cause:** Voltage sag from A/C or laser printer on same circuit. |
| **1459** | Loose RAM Stick | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Random BSODs (various codes).<br><br>**Cause:** RAM stick unseated by thermal expansion/contraction. |
| **1460** | SATA Cable Corruption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Disk CRC errors.<br><br>**Cause:** Cheap SATA cable shielding failure causing bit rot. |

## SECTION 137: 3RD PARTY "OVERLAY" WARS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1461** | Discord Overlay Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Games crash on launch.<br><br>**Cause:** Discord overlay fighting with game anti-cheat. |
| **1462** | FPS Counter Injection | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** App UI flickers.<br><br>**Cause:** Statistics overlay trying to hook a non-game GUI (like Browser or Office). |
| **1463** | Clipboard Manager Conflict | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Copy/Paste delay.<br><br>**Cause:** Clipboard history tool polling too aggressively. |
| **1465** | RGB Software Driver Leak | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** System slow after 3 days.<br><br>**Cause:** Poorly coded RGB controller driver leaking memory. |
| **1466** | Virtual Camera "Black Screen" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Zoom camera is black.<br><br>**Cause:** OBS is not running, so the virtual input is sending blank frames. |
| **1468** | Antivirus "HTTPS Scanning" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Browser Certificate Errors (Unknown Issuer).<br><br>**Cause:** AV is performing Man-in-the-Middle TLS inspection, but its Root CA is not trusted by Firefox/Java. |
| **1469** | Explorer Shell Extension Crash | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Right-click desktop -> Explorer restarts.<br><br>**Cause:** Buggy menu entry from uninstalled software. |
| **1470** | Focus Assist "Duplication" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** No notifications.<br><br>**Cause:** User has a phantom second monitor or projector mode enabled. |

## SECTION 138: PROFILE & ACCOUNT "SINGULARITIES"

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1471** | The "TEMP" Profile Loop | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `ProfileList.*RefCount` | **Symptom:** "We can't sign into your account".<br><br>**Cause:** Registry points to profile that fails to load; Windows loads Temp, fails to save, repeats. |
| **1472** | User Service (UUID) Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Login "User Profile Service failed the logon".<br><br>**Cause:** Permissions on `C:\Users\Default` are wrong, so new profile creation fails. |
| **1473** | Corrupt "Ntuser.dat" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Settings don't save.<br><br>**Cause:** Unexpected shutdown while writing user hive. |
| **1475** | SID Mismatch (Domain Trust) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** "The security database on the server does not have a computer account".<br><br>**Cause:** PC rejoined domain with same name but new SID. AD object out of sync. |
| **1476** | Credential Vault "Max Size" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Symptom:** Chrome forgets passwords daily.<br><br>**Cause:** Roaming Profile size limit hitting `AppData` vault files. |
| **1477** | OneDrive "Known Folder" Hijack | **Op:** `RegQueryValue`<br>**Res:** `*`<br>**Path:** `User Shell Folders.*OneDrive` | **Symptom:** Desktop empty after uninstalling OneDrive.<br><br>**Cause:** Uninstallation didn't revert the folder redirection. |
| **1478** | Quick Access "FTP" Freeze | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Explorer connecting to FTP site` | **Symptom:** Explorer hangs.<br><br>**Cause:** "Recent Files" contains a link to a slow FTP server. |
| **1479** | Library "Optimization" Slowdown | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Folder type = Pictures` | **Symptom:** Downloads folder opens slowly.<br><br>**Cause:** Automatic Folder Type Discovery decided "Downloads" is a Photo Album because you downloaded 5 JPGs. |
| **1480** | "Account Unknown" SIDs | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ACLs full of S-1-5-21-` | **Symptom:** ACLs full of S-1-5-21-....<br><br>**Cause:** Files migrated from old installation; SIDs don't resolve to current users. |

## SECTION 139: THE "TIME" ANOMALIES

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1481** | CMOS Battery Death | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Date is Jan 1, 1980 on boot` | **Symptom:** Date is Jan 1, 1980 on boot. HTTPS fails.<br><br>**Cause:** RTC battery dead. |
| **1482** | Time Zone "Auto" Fail | **Op:** `*`<br>**Res:** `*`<br>**Path:** `tzautoupdate service` | **Symptom:** Time is off by 3 hours.<br><br>**Cause:** Geo-IP lookup thinks VPN exit node (California) is physical location, overrides local time (New York). |
| **1483** | Kerberos Time Skew | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Client time > 5 mins difference` | **Symptom:** "Logon Failure" on file share.<br><br>**Cause:** Windows Time Service sync failure. |
| **1484** | Excel 1900 Date System | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Dates copy-pasted from Mac` | **Symptom:** Dates copy-pasted from Mac are 4 years off.<br><br>**Cause:** Excel for Mac used 1904 date system; Windows uses 1900. |
| **1485** | "Last Modified" Paradox | **Op:** `*`<br>**Res:** `*`<br>**Path:** `File modified date is before creation date` | **Symptom:** File modified date is before creation date.<br><br>**Cause:** File copied from another volume preserves Mod time, but Creation time is "Now". |
| **1486** | DST Patch Missing | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Meetings are 1 hour off` | **Symptom:** Meetings are 1 hour off for 2 weeks in March.<br><br>**Cause:** OS missing Daylight Savings Time update for specific time zone. |
| **1487** | BIOS Clock Drift | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Clock loses 10 mins per day` | **Symptom:** Clock loses 10 mins per day.<br><br>**Cause:** Failing motherboard oscillator. |
| **1488** | Leap Year Bug (Custom App) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `App crashes on Feb 29` | **Symptom:** App crashes on Feb 29.<br><br>**Cause:** Hardcoded "365 days" logic. |
| **1489** | Region Format "AM/PM" | **Op:** `*`<br>**Res:** `*`<br>**Path:** `App parses 14:00 as error` | **Symptom:** App parses "14:00" as error.<br><br>**Cause:** User region set to US (12h), App expects 24h input. |
| **1490** | Uptime Counter Overflow | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GetTickCount 32-bit rollover` | **Symptom:** Systems crashing after 49.7 days.<br><br>**Cause:** Ancient driver using 32-bit millisecond counter. |

## SECTION 140: THE "TRULY UNEXPLAINABLE" LOGIC BUGS

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1491** | The "Desktop Heap" exhaustion (User) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `User32 resource fail` | **Symptom:** Cannot open new windows, but PC has 32GB RAM free.<br><br>**Cause:** Too many hooks/objects allocated in the interactive session heap (20MB limit). |
| **1492** | Atom Table Exhaustion | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GlobalAddAtom fail` | **Symptom:** App crashes "Cannot add atom".<br><br>**Cause:** App leaking global atoms (strings), filling the 64k table. |
| **1493** | GDI Object Limit (10,000) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `GDI Objects = 10,000` | **Symptom:** Elements of UI disappear/black out.<br><br>**Cause:** Hard limit per process. App leak. |
| **1494** | Handle Leak (Kernel Paged Pool) | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Paged Pool high` | **Symptom:** System slow.<br><br>**Cause:** Driver leaking registry handles. |
| **1495** | "Magic" Packet Wake | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Wake on LAN Pattern Match` | **Symptom:** PC turns on when phone connects to WiFi.<br><br>**Cause:** NIC configured to wake on "Pattern Match", interpreting arbitrary broadcast traffic as a wake signal. |
| **1496** | BitLocker "Used Space Only" Encryption | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Undelete tools fail on Empty space` | **Symptom:** Undelete tools fail on "Empty" space.<br><br>**Cause:** BitLocker only encrypted written data; free space is technically "clear" but scrambled by metadata capability. |
| **1497** | Fonts "Non-System" Block | **Op:** `*`<br>**Res:** `*`<br>**Path:** `MitigationPolicy event` | **Symptom:** App shows boxes.<br><br>**Cause:** "Block untrusted fonts" security policy enabled. |
| **1498** | AppContainer Network Isolation | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CheckNetIsolation loopback exempt missing` | **Symptom:** Store App cannot connect to localhost.<br><br>**Cause:** UWP Security feature blocking loopback. |
| **1499** | "OOBE" Complete Flag | **Op:** `*`<br>**Res:** `*`<br>**Path:** `OOBEComplete registry mismatch` | **Symptom:** Start menu search broken.<br><br>**Cause:** Search Indexer waits for Out-Of-Box-Experience to finish; if flag stuck, it never indexes. |
| **1500** | The "Null" Window Class | **Op:** `*`<br>**Res:** `*`<br>**Path:** `CreateWindow with NULL class` | **Symptom:** Explorer crash.<br><br>**Cause:** Race condition in shell extension initialization. |

## Uncategorized (Script Only)

| ID | Title | Technical Signature | Context & Remediation |
| :--- | :--- | :--- | :--- |
| **1** | Access Denied (Write - User): | **Op:** `CreateFile\|WriteFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `C:\\Users\\.*\\.*` | **Cause:** User permissions broken on own profile |
| **4** | Access Denied (Delete): | **Op:** `SetDispositionInformationFile`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` | **Cause:** Read-only attribute or ACL |
| **65** | Focus Rectangle Missing: | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``DrawFocusRect`\ not\ called\ or\ invisible\.` |  |
| **66** | Text Smoothing Conflict: | **Op:** `*`<br>**Res:** `*`<br>**Path:** `ClearType\ rendering\ artifacts\ when\ magnification\ is\ active\.` |  |
| **67** | Bitmap Scaling Blur: | **Op:** `*`<br>**Res:** `*`<br>**Path:** `App\ not\ DPI\ aware,\ resulting\ in\ blurry\ text\ at\ 200%\ scaling\.` |  |
| **70** | Animation Disable | **Op:** `*`<br>**Res:** `*`<br>**Path:** `SPI_GETCLIENTAREAANIMATION` | **Cause:** Motion sickness trigger |
| **71** | Microphone Exclusive Mode: | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Windows\ Dictation\ failing\ to\ access\ Mic\.` |  |
| **73** | `Select` Interface Failure | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **74** | Correction Window Hidden | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **75** | Vocabulary Update Write Fail: | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Failure\ to\ write\ to\ the\ user's\ custom\ dictionary\ file\.` |  |
| **78** | SAPI5 Registry Lookups: | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Failure\ to\ enumerate\ installed\ SAPI\ voices\.` |  |
| **79** | Audio Endpoint Builder: | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``Audiosrv`\ failing\ to\ build\ graph\ for\ Dictation\.` |  |
| **80** | Language Pack Missing: | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``SpeechPlatform`\ failing\ to\ load\ required\ language\ model\.` |  |
| **84** | AT Start on Logon: | **Op:** `*`<br>**Res:** `*`<br>**Path:** ``utilman`\ failing\ to\ launch\ the\ configured\ AT\ on\ the\ logon\ screen\.` |  |
| **85** | Sound Scheme Lock: | **Op:** `*`<br>**Res:** `*`<br>**Path:** `App\ forcing\ a\ specific\ sound\ scheme,\ overriding\ accessibility\ sounds\.` |  |
| **86** | Virtual Audio Cable Conflict: | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Routing\ issues\ when\ using\ Virtual\ Audio\ Cables\ with\ Screen\ Readers\.` |  |
| **87** | Portable Copy Permission: | **Op:** `*`<br>**Res:** `ACCESS\ DENIED`<br>**Path:** `*` |  |
| **89** | Script Folder Write Access: | **Op:** `*`<br>**Res:** `*`<br>**Path:** `User\ lacks\ permission\ to\ save\ custom\ scripts\ for\ the\ specific\ application\.` |  |
| **91** | Custom Drawing without `IAccessible`: | **Op:** `*`<br>**Res:** `*`<br>**Path:** `DirectX\ but\ implements\ 0\ accessibility\.` |  |
| **94** | Timed Tooltip: | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Tooltip\ disappears\ too\ fast\ for\ the\ screen\ reader\ to\ catch\ it\.` |  |
| **95** | Non-Standard Combobox | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** no role, no expand/collapse state |
| **96** | Drag-and-Drop Only: | **Op:** `*`<br>**Res:** `*`<br>**Path:** `Operation\ requires\ dragging,\ no\ keyboard\ alternative\.` |  |
| **97** | Color-Only Information | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** no text/metadata change |
| **98** | Implicit Focus Change | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** Screen reader user is unaware |
| **100** | Hidden Content Readable | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` | **Cause:** e.g., off-screen menus |
| **1160** | WPAD Detection: | **Op:** `*`<br>**Res:** `NAME NOT FOUND`<br>**Path:** `wpad` | **Cause:** Proxy Auto-Discovery failing. Can cause periodic browser freeze. |
| **1210** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1280** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1283** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1301** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1303** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1304** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1307** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1310** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1312** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1315** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1318** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1335** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1341** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1343** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1345** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1350** | HDR ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1354** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1359** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1363** | VPN ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1366** | ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1382** | ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1384** | ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1385** | UAC ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1388** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1395** | ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1397** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1398** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1399** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1400** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1401** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1403** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1406** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1413** | ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1421** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1425** | ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1428** | DNS ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1431** | ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1440** | ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1444** | ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1457** | The ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1464** | ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1467** | VPN ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |
| **1474** | ` | **Op:** `*`<br>**Res:** `*`<br>**Path:** `*` |  |

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
