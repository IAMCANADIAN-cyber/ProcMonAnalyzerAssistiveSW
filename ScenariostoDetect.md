This is a massive undertaking, but exactly the kind of logic required to build an "Automated Mark Russinovich." You are essentially building a **Heuristic Expert System** for Windows Troubleshooting.

**My Inference of Your Goal:**
You are building a unified correlation engine. You don't just want to parse one log; you want to cross-reference a **Process Monitor (PML)** trace with **Event Logs (EVTX)**, **TSS (Time Travel Debugging/ETL)** traces, and **System Configuration** to find the "Smoking Gun." You want the script to say: *"I see an Access Denied in ProcMon at 10:00:01, which correlates with Event ID 4656 in the Security Log, caused by User X attempting to write to a Protected Administrative path."*

Below is the **Advanced Correlation Masterlist**. I have grouped these into "Deep Dive Modules" to reach that scale of ~1000 potential detection points, detailed with specific logic for your script.

---

### Module 1: The "Kernel & Memory" Deep Dive
*Detecting invisible resource exhaustion and kernel-level conflicts.*

1.  **Non-Paged Pool Exhaustion (Driver Leak)**
    *   **Logic:** ProcMon shows `CreateFile` returning `STATUS_INSUFFICIENT_RESOURCES`. Correlate with Event Log `System` ID `2019` or `2020` (Server Service / Srv).
    *   **Cause:** A driver is leaking non-paged pool memory, preventing file handles from opening.
2.  **Desktop Heap Depletion (Session 0)**
    *   **Logic:** Service process (Session 0) calls `CreateWindowEx` or `CreateDesktop` and fails, or `User32.dll` loads fail. Event Log `System` ID `243` or `244` (Win32k).
    *   **Cause:** Too many services running interactively or leaking window handles in the non-interactive session.
3.  **GDI Handle Leak (The "Black Screen" Cause)**
    *   **Logic:** ProcMon shows `Process Create` -> `WerFault.exe`. Correlate with TSS/Performance Counter showing GDI Objects > 9,900 for a single process.
    *   **Cause:** App isn't releasing pens/brushes, eventually hitting the hard 10k limit and crashing.
4.  **DLL Base Address Collision (Relocation Thrashing)**
    *   **Logic:** ProcMon shows `LoadImage` followed immediately by `UnmapViewOfSection` and then `LoadImage` again at a different address.
    *   **Cause:** ASLR issues or fixed-base DLLs fighting for the same memory address space.
5.  **Page File Fragmentation/Resize Storms**
    *   **Logic:** ProcMon shows `System` process writing heavily to `pagefile.sys` with `SetAllocationInformationFile`. Event Log `System` ID `26` (Popup).
    *   **Cause:** Pagefile is set to "Auto" and is thrashing size, freezing the OS during expansion.
6.  **Filter Manager Altitude Collision**
    *   **Logic:** Stack Trace in ProcMon (if available) shows deeply nested calls between `fltmgr.sys` and two specific AV drivers (e.g., `SymEFASI` and `McAfeeFramework`).
    *   **Cause:** Two mini-filters have the same "Altitude" (priority), causing a deadlock or stack overflow.

### Module 2: The "Cluster & High Availability" Suite
*Detecting split-brains, quorum loss, and failovers.*

7.  **Quorum Drive Reservation Loss**
    *   **Logic:** `ClusSvc.exe` receives `STATUS_DEVICE_BUSY` or `STATUS_IO_TIMEOUT` on the Quorum Witness path (Witness.log or Disk). Event ID `1135` (Cluster Node Removed).
    *   **Cause:** SAN latency causing the node to lose its reservation on the disk.
8.  **Cluster Database Registry Lock**
    *   **Logic:** `ClusSvc.exe` gets `SHARING_VIOLATION` on `HKLM\Cluster`.
    *   **Cause:** Backup software or AV scanning the Cluster Hive (`CLUSDB`) while the service tries to update state.
9.  **Heartbeat Network Saturation**
    *   **Logic:** UDP Send failures on Port 3343 (Cluster Heartbeat) in ProcMon. Correlate with `NetFT.sys` errors in System Log.
    *   **Cause:** Management traffic flooding the private heartbeat NIC.
10. **CSV (Cluster Shared Volume) Redirected Access**
    *   **Logic:** High volume of `FileReads` to `C:\ClusterStorage` originating from `System` (SMB Loopback) instead of direct I/O.
    *   **Cause:** Metadata node corruption or coordinator loss forcing the cluster into "Redirected Mode" (Slow).

### Module 3: Hyper-V & Virtualization Platform
*Detecting VHD locks, snapshot merge failures, and VMMS issues.*

11. **VHDX Snapshot Merge Lock**
    *   **Logic:** `vmms.exe` gets `ACCESS_DENIED` deleting `.avhdx` files.
    *   **Cause:** Backup software (Veeam/Commvault) still holding a lock on the snapshot file after backup completion.
12. **Virtual Machine Worker Process Crash**
    *   **Logic:** `vmwp.exe` Process Exit code `0xC0000005`. Event ID `18590` (Hyper-V-Worker).
    *   **Cause:** Corrupt memory in the guest causing the worker process on the host to die.
13. **Hyper-V Switch Extension Block**
    *   **Logic:** Network drops in VM. ProcMon on Host shows `vmswitch.sys` interacting with a 3rd party filter driver (e.g., `NDISCapture`).
    *   **Cause:** A Wireshark or AV NDIS filter is incompatible with the vSwitch.
14. **Pass-Through Disk Offline**
    *   **Logic:** `vmms.exe` query for `\\.\PhysicalDriveX` returns `STATUS_DEVICE_OFF_LINE`.
    *   **Cause:** The host OS unexpectedly claimed the LUN intended for the guest.

### Module 4: IIS, Web & ASP.NET Deep Dive
*Detecting W3WP crashes, config locking, and queue exhaustion.*

15. **AppPool Identity Config Access**
    *   **Logic:** `w3wp.exe` (User: IIS AppPool\Name) gets `ACCESS_DENIED` on `web.config` or `applicationHost.config`.
    *   **Cause:** NTFS permissions on the website root don't include the virtual AppPool account.
16. **Rapid Fail Protection (Crash Loop)**
    *   **Logic:** ProcMon shows `w3wp.exe` start and exit 5 times in < 5 minutes. Event ID `5002` (WAS).
    *   **Cause:** Bad `global.asax` code or missing dependency causing immediate crash on init.
17. **Shared Configuration Latency**
    *   **Logic:** IIS worker reading config from UNC path (`\\Server\Share\Config`) takes > 200ms per read.
    *   **Cause:** Network latency to the file server hosting Shared Configuration is slowing down TTFB (Time to First Byte).
18. **ASP.NET Temp Folder Compilation Lock**
    *   **Logic:** `csc.exe` (C# Compiler) failing to write to `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Temporary ASP.NET Files`.
    *   **Cause:** Anti-Virus scanning the dynamic compilation folder.
19. **HTTP.sys Queue Full**
    *   **Logic:** No ProcMon activity for the request (it never reaches user mode). Event Log `HTTPError` shows `503 Service Unavailable` / `QueueFull`.
    *   **Cause:** Application pool is hung; kernel queue filled up.

### Module 5: Active Directory & Kerberos (Client Side)
*Detecting authentication delays, GPO failures, and replication lag.*

20. **Kerberos Ticket Bloat (MaxTokenSize)**
    *   **Logic:** `lsass.exe` returns `STATUS_BUFFER_OVERFLOW` during Kerberos ticket exchanges. System Log ID `31` (Kerberos).
    *   **Cause:** User is in too many groups; Token size > 48k (or 12k legacy).
21. **Time Skew Auth Fail**
    *   **Logic:** `lsass.exe` UDP/TCP 88 connection returns error, System Log shows `KRB_AP_ERR_SKEW`.
    *   **Cause:** Client clock is > 5 minutes off from DC.
22. **DC Discovery Fail (NetLogon)**
    *   **Logic:** `netlogon` service queries DNS for `_ldap._tcp.dc._msdcs...` and gets `NAME_NOT_FOUND` or `TIMEOUT`.
    *   **Cause:** DNS misconfiguration; client cannot find a domain controller.
23. **Group Policy Ini Lock**
    *   **Logic:** `svchost.exe` (GroupPolicy) gets `SHARING_VIOLATION` on `history.ini` in `%ProgramData%\Microsoft\Group Policy\History`.
    *   **Cause:** Two users logging in simultaneously on a VDI machine processing GPOs.
24. **Machine Account Password Desync**
    *   **Logic:** `lsass.exe` fails RPC calls to DC with `STATUS_TRUST_FAILURE`. System ID `5722`.
    *   **Cause:** Computer account password mismatch; requires re-joining domain.

### Module 6: Windows Update & Component Store (CBS)
*Detecting "Getting Windows Ready" hangs and install failures.*

25. **CBS Manifest Corruption**
    *   **Logic:** `TrustedInstaller.exe` reads a `.manifest` file in `C:\Windows\Servicing\Packages` and gets `STATUS_FILE_CORRUPT`. `CBS.log` contains "Manifest missing".
    *   **Cause:** Disk corruption or failed update causing unserviceable OS.
26. **SoftwareDistribution Locking**
    *   **Logic:** `svchost (wuauserv)` fails to rename `C:\Windows\SoftwareDistribution\Download` (Access Denied).
    *   **Cause:** User or AV tool has the folder open, preventing the update agent from finalizing the download.
27. **Catroot2 Timestamp Mismatch**
    *   **Logic:** `cryptsvc` failing signature checks on catalog files in `System32\CatRoot2`.
    *   **Cause:** Cryptographic database corruption; prevents update installation.
28. **Pending.xml Exclusive Lock**
    *   **Logic:** `TiWorker.exe` stuck waiting on `winsxs\pending.xml`.
    *   **Cause:** A previous update failed to clear its pending actions, blocking all future updates.

### Module 7: VDI Specifics (Citrix / AVD / VMware)
*Detecting profile load issues, hook failures, and graphics glitches.*

29. **Citrix API Hooking Block**
    *   **Logic:** App crashes on launch. ProcMon shows load of `CtxHk.dll` followed immediately by `Process Exit`.
    *   **Cause:** The application (e.g., Chrome) detects the Citrix hook as an intrusion and kills itself. Fix: Exclude via registry.
30. **FSLogix RW/RO Contention**
    *   **Logic:** User logon fails. ProcMon shows `frxsvc.exe` attempting to open `Profile_Name.VHDX` and getting `STATUS_SHARING_VIOLATION`.
    *   **Cause:** The VHDX is mounted Read-Write on another session host (zombie session).
31. **ThinPrint LPC Wait**
    *   **Logic:** App hangs on Print. Stack trace shows wait on `TPAutoConnect`.
    *   **Cause:** ThinPrint client component is stuck trying to map client-side printers.
32. **UPM (Universal Profile Management) Sync Fail**
    *   **Logic:** `UPMService.exe` fails to WriteFile to the user's store on logoff (`NETWORK_UNREACHABLE`).
    *   **Cause:** Network drop during logoff; profile changes are lost.

### Module 8: Advanced Storage & File System
*Detecting filter driver latency, deduplication errors, and corruption.*

33. **Filter Driver "Altitude" Latency**
    *   **Logic:** ProcMon "Duration" column > 0.5s for simple `CreateFile`. Stack shows `fltmgr` -> `AV_Driver` -> `Encryption_Driver` -> `Ntfs`.
    *   **Cause:** Too many security agents scanning the same I/O (The "Scanner Tax").
34. **Deduplication Chunk Corruption**
    *   **Logic:** Reading a file on a Dedup volume returns `STATUS_DATA_ERROR` (CRC Error). System Event `12800` (Dedup).
    *   **Cause:** The underlying chunk store in `System Volume Information` is corrupt.
35. **NTFS Transaction Log Full**
    *   **Logic:** `Ntfs.sys` logging `STATUS_LOG_FILE_FULL`.
    *   **Cause:** Too many metadata operations (e.g., deleting 1 million files) filled the `$LogFile`.
36. **USN Journal Wrap**
    *   **Logic:** Backup software (using Change Block Tracking) fails. Event ID `NTFS` indicating USN Journal wrap.
    *   **Cause:** High churn on volume overwrote the Change Journal before backup could read it.

### Module 9: The "Mark Russinovich" Forensics (Sysinternals Style)
*Detecting specifically what Mark looks for in his demos.*

37. **The "Case of the Unexplained Error Message"**
    *   **Logic:** App shows a generic error dialog. ProcMon shows `LoadString` from a resource DLL failing right before the dialog creation.
    *   **Cause:** The app tried to load the *text* of the error message, failed, and showed a default/blank error.
38. **The "HKCU vs HKCR" Masking**
    *   **Logic:** App queries `HKCR\.ext` and gets a value, but acts as if it's different.
    *   **Cause:** `HKCU\Software\Classes` (User setting) is overriding `HKLM\Software\Classes` (System setting).
39. **The "Environment Variable Expansion" Fail**
    *   **Logic:** ProcMon shows a CreateFile for `%SystemRoot%\System32\file.dll` (Literally with the % signs).
    *   **Cause:** The registry value type is `REG_SZ` (String) instead of `REG_EXPAND_SZ`.
40. **The "Ghost Window" Hang**
    *   **Logic:** User interface is frozen. ProcMon shows no activity for that PID. TSS shows thread stuck in `NtUserMessageCall` (Broadcasting a message).
    *   **Cause:** App sent a message to all windows, and an invisible hidden window isn't replying.

### Module 10: Advanced Security & Evasion (Sysmon Correlation)
*Correlating ProcMon traces with Sysmon for threat hunting.*

41. **LSASS Process Access (Mimikatz Style)**
    *   **Logic:** ProcMon: `OpenProcess` on `lsass.exe` with Access `0x1010` (Read Memory). Sysmon Event `10` (ProcessAccess).
    *   **Cause:** Credential dumping attempt.
42. **WMI Event Consumer Persistence**
    *   **Logic:** `WmiPrvSE.exe` writing to `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`. Sysmon Event `19`, `20`, `21`.
    *   **Cause:** Malware creating a permanent WMI subscription to run code on boot/event.
43. **Process Hollowing (Image Mismatch)**
    *   **Logic:** ProcMon shows `svchost.exe` reading `cmd.exe` or `powershell.exe`. Sysmon Event `1` (Process Create) shows Parent/Child anomaly.
    *   **Cause:** Code injection; replacing the memory of a legit process with malware.
44. **DNS Tunneling / Beaconing**
    *   **Logic:** High frequency of `UDP Send` to Port 53 with unique, high-entropy lengths.
    *   **Cause:** Data exfiltration over DNS (C2 traffic).
45. **ADS (Alternate Data Stream) Execution**
    *   **Logic:** `Process Create` where the path ends in `:Zone.Identifier` or `:StreamName`.
    *   **Cause:** Hiding code inside NTFS streams (e.g., `calc.exe:evil.vbs`).

---

### How to use this with your Script (The "Brain")

When you feed this to Google Jules (or write the logic), the structure for the script's analysis engine should be:

1.  **Ingest:** Load ProcMon CSV, Event Log (System, App, Security), and optionally Sysmon/TSS.
2.  **Normalize:** Align all timestamps.
3.  **Scan:** Iterate through the "Modules" above.
4.  **Score:**
    *   If `ProcMon = ACCESS_DENIED` AND `EventLog = 4656` -> **Confidence: 100%** (Certainty).
    *   If `ProcMon = NAME_NOT_FOUND` on `.dll` -> **Confidence: 80%** (Could be normal probing).
    *   If `ProcMon = SHARING_VIOLATION` on `NTUSER.DAT` -> **Confidence: 90%** (Profile Lock).
5.  **Output:** Generate a report that sounds like Mark R:
    *   *"I detected a Profile Lock scenario. Process 'MsMpEng.exe' (Defender) held a lock on 'NTUSER.DAT' at 08:00:01, causing 'WinLogon.exe' to fail with a Sharing Violation. This correlates with Event ID 1500 in the Application Log."*
  
6.  Here is the continuation of the "Mark Russinovich in a Box" scenario list, completing items **46 through 100**.

These specific scenarios focus on the complex subsystems of Windows: **COM/DCOM, Printing, Installers, Modern Apps, and Cryptography**—areas where standard troubleshooting often fails.

### Module 11: COM, DCOM & RPC Subsystems
*Detecting "Class Not Registered" and marshaling failures.*

46. **COM Server Path Mismatch (The "Moved EXE")**
    *   **Logic:** `svchost` (DCOM Launcher) reads `HKCR\CLSID\{GUID}\LocalServer32`. The value points to `C:\App\old.exe`. ProcMon immediately shows `CreateFile` -> `PATH_NOT_FOUND` for that path.
    *   **Cause:** The application was moved or updated, but the COM registration still points to the old location.
47. **DCOM Launch Permission (Access Denied)**
    *   **Logic:** `svchost` queries `HKCR\AppID\{GUID}\LaunchPermission`. Immediately after, the client process receives `ACCESS_DENIED` on the RPC call. System Event `10016` (DistributedCOM).
    *   **Cause:** The user account does not have "Local Launch" or "Local Activation" permissions in `dcomcnfg`.
48. **InProcServer32 Architecture Mismatch**
    *   **Logic:** A 64-bit process reads `HKCR\CLSID\{GUID}\InProcServer32`, finds a DLL, attempts `LoadImage`, and fails (or fails to find the key because it should be in `Wow6432Node`).
    *   **Cause:** A 64-bit app is trying to load a 32-bit DLL (or vice versa). In-process COM requires matching bitness.
49. **Interface Proxy/Stub Missing (Marshaling Fail)**
    *   **Logic:** App queries `HKCR\Interface\{IID}\ProxyStubClsid32`. Returns `NAME_NOT_FOUND`. App crashes with `0x80004002` (No Interface).
    *   **Cause:** The DLL responsible for translating data between processes (Marshaling) is missing or unregistered.
50. **Global Interface Table (GIT) Revocation**
    *   **Logic:** RPC call returns `RPC_E_DISCONNECTED`. ProcMon shows no network traffic (local).
    *   **Cause:** The COM object in the server process crashed or was explicitly revoked, but the client still holds a pointer to it.
51. **RPC Dynamic Port Exhaustion**
    *   **Logic:** DCOM attempt. ProcMon shows `TCP Connect` to a high port (49152+) failing with `STATUS_ADDRESS_IN_USE` or `TIMEOUT`.
    *   **Cause:** Firewall allows Port 135 (Mapper) but blocks the dynamic range required for the actual connection.

### Module 12: The Print Spooler & Drivers
*Detecting the notoriously fragile printing subsystem.*

52. **Splwow64 Thunking Hang**
    *   **Logic:** 32-bit App (`Word.exe`) hangs. Stack trace shows wait on `LPC` (Local Procedure Call). ProcMon shows `splwow64.exe` active but failing to write to `\RPC Control\spoolss`.
    *   **Cause:** The translation layer between 32-bit apps and the 64-bit spooler is deadlocked.
53. **Driver Isolation Host Crash**
    *   **Logic:** `PrintIsolationHost.exe` triggers `Process Exit`. `spoolsv.exe` spawns it again immediately (Loop).
    *   **Cause:** A buggy printer driver is crashing. Because it's "Isolated" (Shared or Sandbox mode), it kills the host process, not the spooler, but printing stops.
54. **Spool File Permission Lock**
    *   **Logic:** `spoolsv.exe` attempts to create `.SPL` or `.SHD` file in `C:\Windows\System32\spool\PRINTERS` and gets `ACCESS_DENIED`.
    *   **Cause:** Security hardening removed "Everyone" or "Users" write access to the spool directory.
55. **Bidirectional (BiDi) Extension Hang**
    *   **Logic:** App hangs on "File > Print". ProcMon shows the driver querying `HKLM\...\Monitor` and trying to talk to the device via SNMP or USB indefinitely.
    *   **Cause:** The driver is waiting for status (Ink Level/Paper) from an offline printer. **Fix:** Disable "Enable Bidirectional Support".

### Module 13: Windows Installer (MSI) & Deployment
*Detecting repair loops, source prompts, and rollback causes.*

56. **MSI Self-Repair Loop (The "Resiliency" Trap)**
    *   **Logic:** App launch spawns `msiexec.exe`. ProcMon shows `RegOpenKey` on a component KeyPath (e.g., a specific HKCU key) returning `NAME_NOT_FOUND`. Installer runs, exits. App runs, spawns `msiexec` again.
    *   **Cause:** The "KeyPath" for a component is missing. MSI repairs it, but the app deletes it or fails to write it, triggering an infinite repair loop.
57. **Source List Exhaustion (Prompt for CD)**
    *   **Logic:** `msiexec.exe` queries `Sourcelist` key. Then attempts `CreateFile` on `C:\...`, `D:\...` (CD-ROM), `\\Server\...` and fails all with `PATH_NOT_FOUND`.
    *   **Cause:** A patch/repair is required, but the cached MSI in `C:\Windows\Installer` is missing, and the original source is unreachable.
58. **Custom Action Script Failure**
    *   **Logic:** `msiexec.exe` spawns `cmd.exe` or `cscript.exe`. The child process exits with `Exit Code 1` (or non-zero). ProcMon shows the script trying to copy a file that doesn't exist.
    *   **Cause:** A poorly written logic script inside the MSI installer failed.
59. **Installer Mutex Contention (`_MSIExecute`)**
    *   **Logic:** `msiexec.exe` repeatedly calls `OpenMutex` on `Global\_MSIExecute` and calls `WaitForSingleObject`.
    *   **Cause:** Another installation is running in the background (often Windows Update or SMS Agent), blocking this one.
60. **Pending Reboot Block**
    *   **Logic:** Installer queries `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`. If data exists, it displays "Reboot Required" and exits.
    *   **Cause:** A previous update moved a file but needs a reboot to delete the old one.

### Module 14: Modern Apps (UWP/AppX) & Store
*Detecting Metro/Modern UI failures.*

61. **StateRepository Database Lock**
    *   **Logic:** `RuntimeBroker.exe` or `svchost` (StateRepository) fails to open `C:\ProgramData\Microsoft\Windows\AppRepository\StateRepository-Machine.srd` (`SHARING_VIOLATION` or `DATABASE_LOCKED`).
    *   **Cause:** The SQLite database tracking AppX apps is corrupt or locked, breaking the Start Menu and all Store apps.
62. **AppManifest Permission Fail**
    *   **Logic:** App crashes on launch. ProcMon shows `ACCESS_DENIED` reading `AppxManifest.xml` inside the `WindowsApps` folder.
    *   **Cause:** NTFS permissions on the hidden `WindowsApps` folder are broken (often due to admins taking ownership).
63. **Capability Constraint (Privacy Block)**
    *   **Logic:** App attempts to access `\Device\Microphone` or `Webcam`. ProcMon shows access to `HKCU\...\Capabilities` followed by `ACCESS_DENIED` on the device.
    *   **Cause:** Windows Privacy Settings are blocking the specific app from accessing hardware.
64. **Push Notification Registration Fail**
    *   **Logic:** `svchost` (WpnService) fails to write to `HKCU\...\PushNotifications`. Network traffic to `*.notify.windows.com` fails.
    *   **Cause:** App cannot register for Live Tiles/Toasts due to firewall or registry permissions.

### Module 15: Cryptography & PKI
*Detecting SSL, Certificate, and Smart Card issues.*

65. **CRL (Revocation) Offline**
    *   **Logic:** `lsass.exe` or `cryptnet.dll` attempts `TCP Connect` to an external IP (OCSP/CRL). Result is `TIMEOUT`. The app utilizing the cert hangs and then fails.
    *   **Cause:** Firewall is blocking the Certificate Revocation List URL embedded in the certificate.
66. **MachineKey Access Denied (IIS/ASP.NET)**
    *   **Logic:** `w3wp.exe` fails to open files in `C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys`.
    *   **Cause:** The Application Pool Identity cannot read the private key required for encryption/decryption.
67. **Smart Card Service Block**
    *   **Logic:** App queries `SCardSvr`. ProcMon shows `CreateFile` on `\\.\Pipe\SCardPipe` failing.
    *   **Cause:** Smart Card service is stopped or the card reader driver is unresponsive.
68. **Root Certificate Update Loop**
    *   **Logic:** `cryptsvc` repeatedly downloading `authroot.stl` from Windows Update (high network/disk usage).
    *   **Cause:** The Trusted Root store is corrupt or GPO is forcing an update that fails verification.
69. **Catalog Database Corruption (CatRoot2)**
    *   **Logic:** `cryptsvc` fails to write to `C:\Windows\System32\CatRoot2\{GUID}\catdb`.
    *   **Cause:** The cryptographic catalog database is corrupt, preventing Windows Updates or driver installs.

### Module 16: Graphics, Fonts & Desktop Window Manager
*Detecting UI freezes, blurs, and font issues.*

70. **Font Cache Service Thrashing**
    *   **Logic:** `fontdrvhost.exe` writing massively to `%LocalAppdata%\Microsoft\FontCache`. High CPU.
    *   **Cause:** A corrupt font file is causing the cache generation to crash and restart in a loop.
71. **DWM Redirection Surface Leak**
    *   **Logic:** `dwm.exe` memory usage climbs. ProcMon shows failure to `CloseHandle` on `Section` objects. Event Log `Warning` from `Dwm`.
    *   **Cause:** A graphics driver leak causing the Desktop Window Manager to run out of memory (black screen/flicker).
72. **TDR (Timeout Detection and Recovery)**
    *   **Logic:** Event Log `Display` ID `4101`. ProcMon shows `dxgkrnl.sys` resetting the GPU.
    *   **Cause:** The GPU took too long (>2s) to render a frame, so Windows reset the driver to prevent a hard freeze.
73. **Missing EUDC (End User Defined Character)**
    *   **Logic:** App queries `HKCU\EUDC` and gets `NAME_NOT_FOUND`, followed by garbled text rendering.
    *   **Cause:** Missing custom font linking (common in Asian language locales).

### Module 17: User Profile & Registry Bloat
*Detecting "Slow Logon" and "Temp Profile" causes.*

74. **Registry Hive Fragmentation**
    *   **Logic:** `RegQueryValue` takes > 100ms. ProcMon `ReadFile` on `NTUSER.DAT` is highly fragmented (offset jumps).
    *   **Cause:** The user hive is massive (hundreds of MBs) and fragmented, causing sluggish OS performance.
75. **Firewall Rule Bloat**
    *   **Logic:** `mpssvc` (Firewall) consuming high CPU. Registry reads to `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy` take seconds.
    *   **Cause:** 50,000+ firewall rules created (often by containerization software or bad GPOs), slowing down every network connection.
76. **Notification Database Corruption**
    *   **Logic:** `Explorer.exe` crashes or hangs. ProcMon shows access errors on `wpndatabase.db` in AppData.
    *   **Cause:** Corrupt Action Center database breaks the shell.
77. **Stuck "Logon Script" (The Invisible Wait)**
    *   **Logic:** `Userinit.exe` spawns `cmd.exe`. The `cmd.exe` process exists for > 60 seconds with no CPU activity.
    *   **Cause:** A logon script is waiting for user input (e.g., `pause` or a mapped drive prompt) but is running hidden.

### Module 18: DLL Hell & Loading Issues (Advanced)
*Specific loader failures.*

78. **Loader Lock Deadlock**
    *   **Logic:** Process starts, loads several DLLs, then hangs indefinitely in `DllMain`. No CPU usage.
    *   **Cause:** A DLL attempted to spawn a thread or call a dangerous API inside its entry point (`DllMain`), triggering the OS Loader Lock.
79. **Manifest Activation Failure (SxS)**
    *   **Logic:** `csrss.exe` or the app fails to read `C:\Windows\WinSxS\Manifests\....manifest`. Event ID `33` (SideBySide).
    *   **Cause:** The application requires a specific version of a library (defined in manifest), but the files in WinSxS are missing or permissions are broken.
80. **Delay-Load Import Failure**
    *   **Logic:** App runs fine for hours. User clicks a button -> App Crashes. ProcMon shows `LoadImage` fail for a specific DLL right at that second.
    *   **Cause:** The DLL is "Delay Loaded" (only loaded when needed). It was missing all along, but the app didn't check at startup.
81. **KnownDLLs Exclusion**
    *   **Logic:** App tries to load `ole32.dll` from its *local* directory instead of `System32`.
    *   **Cause:** Malware or a hacked app trying to bypass the `KnownDLLs` registry list to load a hijacked system library.

### Module 19: File System Edge Cases
*NTFS oddities.*

82. **Short Name (8.3) Collision**
    *   **Logic:** App creates file `ProjectSchedule.doc`. ProcMon shows `NAME_COLLISION`.
    *   **Cause:** The 8.3 generated name (e.g., `PROJEC~1.DOC`) conflicts with an existing entry, even if the long name is unique.
83. **Directory Change Notification Overflow**
    *   **Logic:** `ReadDirectoryChangesW` fails with `STATUS_NOTIFY_ENUM_DIR`.
    *   **Cause:** An application (like Dropbox or AV) is monitoring a folder, but too many changes happened too fast, overflowing the kernel buffer.
84. **Case Sensitivity Mismatch**
    *   **Logic:** App requests `File.txt`. File exists as `file.txt`. Result is `NAME_NOT_FOUND`.
    *   **Cause:** The directory has "Case Sensitivity" enabled (fsutil), and the legacy app expects Windows-standard case insensitivity.
85. **Zone.Identifier Stream Block**
    *   **Logic:** `CreateFile` success on `Installer.exe`. `CreateFile` failed/denied on `Installer.exe:Zone.Identifier`.
    *   **Cause:** Anti-virus preventing the "Mark of the Web" from being written or read, potentially blocking execution.

### Module 20: Security Boundaries & Integrity
*Permissions and Tokens.*

86. **Integrity Level (UIPI) Block**
    *   **Logic:** Low Integrity app (IE Protected Mode) sends `PostMessage` to Medium Integrity app (Word). Result: `ACCESS_DENIED` (or message lost).
    *   **Cause:** User Interface Privilege Isolation (UIPI) prevents lower-privileged apps from driving higher-privileged ones.
87. **Service SID Restriction**
    *   **Logic:** Service (running as LocalSystem) tries to open a resource. Fails.
    *   **Cause:** The resource ACL grants access to "SYSTEM", but the Service is restricted (Write Restricted Token). It needs the specific Service SID (e.g., `NT SERVICE\SQLWRITER`) added to the ACL.
88. **Token Primary Group Modification**
    *   **Logic:** `SetTokenInformation` fails.
    *   **Cause:** App trying to change its primary group to something not in its token (Exploit or bad code).
89. **SDDL String Parse Fail**
    *   **Logic:** `ConvertStringSecurityDescriptorToSecurityDescriptor` returns error.
    *   **Cause:** Malformed Security Descriptor string in registry or code (Security permissions corruption).

### Module 21: Hardware & Power
90. **USB Selective Suspend Loop**
    *   **Logic:** PnP Event `Device Arrival` then `Device Removal` every 5 seconds.
    *   **Cause:** Windows puts USB device to sleep; device wakes up immediately. Driver incompatibility.
91. **High Performance Timer Drift**
    *   **Logic:** `QueryPerformanceCounter` results jump backwards or drift from `GetTickCount`.
    *   **Cause:** BIOS/HAL issue with High Precision Event Timer (HPET). Causes gaming stutters/audio desync.
92. **Thermal Throttling Events**
    *   **Logic:** Kernel-Processor-Power Event `55` in System Log.
    *   **Cause:** CPU speed capped by firmware due to overheating.

### Module 22: Time & Regional
93. **Leap Second / Time Jump**
    *   **Logic:** `SetSystemTime` called with a large delta.
    *   **Cause:** W32Time syncing with a bad NTP source, causing huge jumps that break Kerberos/SSL.
94. **Locale ID (LCID) Unknown**
    *   **Logic:** `GetLocaleInfo` fails for a specific ID.
    *   **Cause:** App requests a locale not installed in Windows (e.g., specific dialect).

### Module 23: Audio & Media
95. **Audio Endpoint Builder Deadlock**
    *   **Logic:** `audiodg.exe` hangs.
    *   **Cause:** Third-party audio enhancement (Nahimic, Waves) deadlocked the audio graph.
96. **Exclusive Mode Theft**
    *   **Logic:** App fails to `Initialize` IAudioClient. Result `AUDCLNT_E_DEVICE_IN_USE`.
    *   **Cause:** Another app has exclusive control of the sound card.

### Module 24: Scripting & Automation
97. **WScript/CScript Mismatch**
    *   **Logic:** Script runs, opens window, prints garbage.
    *   **Cause:** Running a console script (`.vbs`) with `wscript.exe` (GUI host) instead of `cscript.exe` (Console host).
98. **PowerShell Execution Policy Block**
    *   **Logic:** `powershell.exe` reads `HKLM\...\PowerShell\ShellIds\Microsoft.PowerShell\ExecutionPolicy`. Then exits.
    *   **Cause:** Policy set to `Restricted` or `AllSigned`.

### Module 25: Legacy & "Very Old" Windows
99. **16-bit Subsystem (NTVDM) Fail**
    *   **Logic:** Process create `ntvdm.exe` fails.
    *   **Cause:** 64-bit Windows does not support 16-bit apps. NTVDM is missing.
100. **INI File Mapping (Legacy Redirect)**
    *   **Logic:** App reads `C:\Windows\win.ini`.
    *   **Cause:** The app is ancient. Windows automatically maps these calls to the Registry (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\IniFileMapping`), which creates confusion if the mapping is wrong.


    Here is the **Master Definition List** for the "Russinovich Engine" script.

I have consolidated the previous lists and expanded the detection logic to cover over **1,000 specific technical scenarios** by grouping them into **High-Fidelity Detection Patterns**.

This list is formatted for ingestion: **Category** > **Signature (Logic)** > **Context (Root Cause)**.

---

### **SECTION 1: FILE SYSTEM FORENSICS (NTFS & I/O)**
*Detecting access issues, corruption, locking, and storage health.*

1.  **Access Denied (Write - User):** `CreateFile/WriteFile` = `ACCESS_DENIED` on `C:\Users\<User>\...`. (User permissions broken on own profile).
2.  **Access Denied (Write - System):** `CreateFile` = `ACCESS_DENIED` on `C:\Windows\System32`. (UAC/Permission issue).
3.  **Access Denied (Execute):** `CreateFile` (Execute) = `ACCESS_DENIED`. (AppLocker/SRP blocking binary).
4.  **Access Denied (Delete):** `SetDispositionInformationFile` = `ACCESS_DENIED`. (Read-only attribute or ACL).
5.  **Access Denied (ADS):** `CreateFile` on `*:Zone.Identifier` = `ACCESS_DENIED`. (AV blocking Mark-of-Web removal).
6.  **Access Denied (Pipe):** `CreateFile` on `\\.\Pipe\...` = `ACCESS_DENIED`. (Service security hardening).
7.  **Access Denied (Spool):** `CreateFile` on `\System32\spool` = `ACCESS_DENIED`. (Print nightmare mitigation).
8.  **Access Denied (WasDeletePending):** `CreateFile` = `STATUS_DELETE_PENDING`. (File deleted but handle open; zombie file).
9.  **Sharing Violation (Profile):** `CreateFile` on `NTUSER.DAT` = `SHARING_VIOLATION`. (Profile locked by AV/Backup).
10. **Sharing Violation (VHDX):** `CreateFile` on `*.vhdx` = `SHARING_VIOLATION`. (FSLogix/VDI double-mount).
11. **Sharing Violation (Log):** `CreateFile` on `*.log` = `SHARING_VIOLATION`. (Log rotation race condition).
12. **Sharing Violation (Dll):** `CreateFile` on `*.dll` = `SHARING_VIOLATION`. (Update trying to replace loaded library).
13. **Path Not Found (DLL):** `LoadImage` = `PATH_NOT_FOUND`. (Missing dependency).
14. **Path Not Found (Exe):** `ProcessCreate` = `PATH_NOT_FOUND`. (Broken shortcut/service path).
15. **Path Not Found (Config):** `CreateFile` on `*.ini/*.config` = `PATH_NOT_FOUND`. (Missing configuration).
16. **Path Not Found (Drive):** `CreateFile` on `X:\` = `PATH_NOT_FOUND`. (Mapped drive disconnected).
17. **Path Not Found (UNC):** `CreateFile` on `\\Server\Share` = `BAD_NETWORK_PATH`. (Server offline/DNS fail).
18. **Path Not Found (8.3):** `CreateFile` on `PROGRA~1` = `PATH_NOT_FOUND`. (Short names disabled).
19. **Path Not Found (Dev):** `CreateFile` on `C:\Users\DevName` = `PATH_NOT_FOUND`. (Hardcoded developer path).
20. **Path Not Found (SXS):** `CreateFile` on `\WinSxS\...` = `PATH_NOT_FOUND`. (Component Store corruption).
21. **Name Collision (Temp):** `CreateFile` = `NAME_COLLISION` in `%TEMP%`. (Temp folder flooding).
22. **Name Collision (ShortName):** `CreateFile` = `NAME_COLLISION` on 8.3 generation. (Hash collision on volume).
23. **Disk Full:** `WriteFile` = `DISK_FULL`. (Volume out of space).
24. **Quota Exceeded:** `WriteFile` = `QUOTA_EXCEEDED`. (User disk quota hit).
25. **File Corrupt:** `ReadFile` = `FILE_CORRUPT_ERROR`. (Physical disk/filesystem rot).
26. **CRC Error:** `ReadFile` = `DATA_ERROR`. (Bad sectors/Dedup corruption).
27. **InPage Error:** `ReadFile` = `STATUS_IN_PAGE_ERROR`. (Swap file/Memory/Network paging failure).
28. **Device Offline:** `CreateFile` = `STATUS_DEVICE_OFF_LINE`. (USB/Storage disconnect).
29. **Device Busy:** `DeviceIoControl` = `STATUS_DEVICE_BUSY`. (Hardware stuck).
30. **Oplock Break:** `FsRtlCheckOplock` duration > 1s. (Network locking contention).
31. **Filter Latency:** `CreateFile` duration > 0.5s. (AV/EDR filter driver overhead).
32. **Sparse Write Fail:** `WriteFile` on Sparse File = `DISK_FULL`. (Over-provisioning failure).
33. **Reparse Point Loop:** `CreateFile` = `STATUS_REPARSE_POINT_NOT_RESOLVED`. (Infinite symlink loop).
34. **Not A Directory:** `CreateFile` = `STATUS_NOT_A_DIRECTORY`. (File exists with name of requested folder).
35. **Dir Not Empty:** `SetDispositionInfo` = `STATUS_DIRECTORY_NOT_EMPTY`. (Failed folder delete).
36. **Case Sensitivity:** `CreateFile` (`File` vs `file`) = `NAME_NOT_FOUND`. (Per-directory case sensitivity enabled).
37. **Alternate Data Stream Exec:** `ProcessCreate` on `*:Stream`. (Potential malware/hiding).
38. **ZoneID Block:** `CreateFile` on `Zone.Identifier` = `ACCESS_DENIED`. (Security tool blocking unblock).
39. **Cloud Tiering:** `ReadFile` = `STATUS_FILE_IS_OFFLINE`. (OneDrive/Azure Files recall needed).
40. **Encrypted File (EFS):** `CreateFile` = `ACCESS_DENIED` (User mismatch on EFS).
41. **BitLocker Locked:** `CreateFile` = `STATUS_FVE_LOCKED_VOLUME`. (Drive mounted but locked).
42. **USN Journal Wrap:** `FsCtl` = `USN_JOURNAL_WRAP`. (Backup failure warning).
43. **Transaction Log Full:** `Ntfs.sys` = `LOG_FILE_FULL`. (Metadata explosion).
44. **MFT Fragmentation:** `ReadFile` on `$MFT` > 100ms. (Severe filesystem fragmentation).
45. **Directory Enumeration Storm:** `QueryDirectory` repeated 10,000x. (Inefficient loop).
46. **1-Byte I/O:** `ReadFile` length = 1. (Inefficient coding).
47. **Flush Storm:** `FlushBuffersFile` after every write. (Performance killer).
48. **Temp File Churn:** >1000 creates in `%TEMP%` in 1 min. (MFT exhaustion risk).
49. **Log File Bloat:** Single `WriteFile` extending log > 100MB. (Disk usage spike).
50. **Zero Byte Write:** `WriteFile` length = 0. (Truncation/Logic error).

---

### **SECTION 2: REGISTRY INTERNALS (HKLM/HKCU/HKCR)**
*Detecting configuration drift, permissions, and legacy behavior.*

51. **Reg Access Denied (HKLM):** `RegSetValue` HKLM = `ACCESS_DENIED`. (Standard user trying to change system).
52. **Reg Access Denied (HKCU):** `RegSetValue` HKCU = `ACCESS_DENIED`. (Permission corruption on user hive).
53. **Reg Access Denied (GroupPolicy):** `RegSetValue` `Software\Policies` = `ACCESS_DENIED`. (App trying to override GPO).
54. **Reg Key Not Found (CLSID):** `RegOpenKey` `HKCR\CLSID` = `NAME_NOT_FOUND`. (Unregistered COM object).
55. **Reg Key Not Found (AppID):** `RegOpenKey` `HKCR\AppID` = `NAME_NOT_FOUND`. (DCOM config missing).
56. **Reg Key Not Found (Interface):** `RegOpenKey` `HKCR\Interface` = `NAME_NOT_FOUND`. (Proxy/Stub missing).
57. **Reg Key Not Found (TypeLib):** `RegOpenKey` `HKCR\TypeLib` = `NAME_NOT_FOUND`. (Automation failure).
58. **Reg Key Not Found (Service):** `RegOpenKey` `HKLM\System\...\Services` = `NAME_NOT_FOUND`. (Service missing).
59. **Reg Key Not Found (Uninstall):** `RegOpenKey` `HKLM\...\Uninstall` = `NAME_NOT_FOUND`. (Installer corruption).
60. **Reg Value Not Found (Run):** `RegQueryValue` `Run` = `NAME_NOT_FOUND`. (Startup item missing).
61. **Reg Value Not Found (Env):** `RegQueryValue` `Environment` = `NAME_NOT_FOUND`. (Missing env var).
62. **Reg Type Mismatch:** `RegQueryValue` expected `REG_SZ` got `REG_DWORD`. (Crash risk).
63. **Buffer Overflow (Reg):** `RegQueryValue` = `BUFFER_OVERFLOW`. (Data larger than buffer).
64. **Registry Hive Bloat:** `RegQueryValue` duration > 100ms. (Hive fragmentation).
65. **HKCU vs HKLM Masking:** App reads HKCU, finds nothing, fails (should check HKLM).
66. **Virtualization Write:** Write to `Classes` redirected to `VirtualStore`. (Legacy app issue).
67. **Infinite Reg Loop:** Same key read 10,000x. (Polling loop).
68. **Orphaned Key Scan:** Enumerating 1000s of keys with `NAME_NOT_FOUND`. (Registry cleaner behavior).
69. **IniFileMapping:** Read of `win.ini` mapped to Registry. (Ancient app compatibility).
70. **Product ID Lookup:** Querying `ProductId` / `DigitalProductId`. (License check).
71. **Pending Rename Check:** Querying `PendingFileRenameOperations`. (Reboot check).
72. **Services Start Mode:** Write to `Start` = 4 (Disabled). (Service disabling).
73. **Image File Execution Options (IFEO):** Query `Debugger` value. (Hijack/Debug check).
74. **Silent Process Exit:** Query `SilentProcessExit`. (WER monitoring).
75. **Internet Settings Mod:** Write to `ProxyServer`. (Proxy hijack/config).
76. **ZoneMap Check:** Query `ZoneMap\Domains`. (IE Security Zone check).
77. **Capability Access:** Query `HKCU\...\Capabilities`. (Privacy permission check).
78. **Shell Extension Lookup:** Enum `ContextMenuHandlers`. (Explorer add-in load).
79. **KnownDLLs Bypass:** Logic checking Local before System32. (Dll hijacking).
80. **MUI Cache Thrashing:** Frequent writes to `MuiCache`. (Lang pack issue).
81. **Group Policy History:** Read `GroupPolicy\History`. (GPO processing).
82. **Winlogon Helper:** Write to `Winlogon\Shell`. (Persistence/Kiosk mode).
83. **LSA Provider Mod:** Write to `Security\Providers`. (Credential theft/Inject).
84. **SAM Hive Access:** Open `SAM` key. (Cred dump attempt).
85. **Security Policy:** Read `PolAdtEv`. (Audit policy check).
86. **BCD Modification:** Write to `BCD00000000`. (Boot config change).
87. **Driver Service Create:** Write `ImagePath` in Services. (Driver load).
88. **USB Enum:** Read `Enum\USB`. (Hardware enumeration).
89. **MountPoints:** Read `MountedDevices`. (Drive mapping).
90. **Network Profile:** Read `NetworkList\Profiles`. (Network location awareness).
91. **Time Zone:** Read `TimeZoneInformation`. (Time sync).
92. **WPA Key:** Read `Wlansvc\Parameters`. (WiFi config).
93. **Console Config:** Read `Console\Configuration`. (CMD settings).
94. **User Shell Folders:** Read `User Shell Folders`. (Folder redirection).
95. **Profile List:** Read `ProfileList`. (User profile loading).
96. **Volatile Environment:** Read `Volatile Environment`. (Session vars).
97. **AppPaths:** Read `App Paths`. (Exe alias lookup).
98. **System Certs:** Read `SystemCertificates`. (Root CA check).
99. **Crypto Seed:** Read `RNG\Seed`. (Entropy generation).
100. **Performance Counter:** Read `Perflib`. (PerfMon data).

---

### **SECTION 3: PROCESS, MEMORY & THREADS**
*Detecting crashes, hangs, injections, and resource exhaustion.*

101. **Process Create:** New process spawned. (Activity tracking).
102. **Process Exit (Success):** Exit Code 0. (Clean shutdown).
103. **Process Exit (Fail):** Exit Code != 0. (Error/Crash).
104. **Process Exit (Crash):** Exit Code `0xC0000005` (Access Violation).
105. **Process Exit (Hard):** Exit Code `0xC0000409` (Stack Buffer Overrun).
106. **Process Exit (Abort):** Exit Code `0xC0000374` (Heap Corruption).
107. **Image Load (DLL):** Loading library. (Dependency tracking).
108. **Image Load Fail:** `LoadImage` = `STATUS_IMAGE_NOT_AT_BASE`. (Relocation).
109. **Image Load Fail (Arch):** `STATUS_IMAGE_MACHINE_TYPE_MISMATCH`. (32/64 bit mix).
110. **Image Load Fail (Sign):** `STATUS_INVALID_IMAGE_HASH`. (Unsigned binary).
111. **Thread Create:** Spawning thread. (Parallelism).
112. **Thread Exit:** Thread termination. (Worker completion).
113. **CreateRemoteThread:** Thread in *other* process. (Injection/Debug).
114. **OpenProcess (Full):** Access `PROCESS_ALL_ACCESS`. (Admin/AV).
115. **OpenProcess (Mem):** Access `VM_READ/WRITE`. (Debug/Hack).
116. **OpenProcess (Term):** Access `TERMINATE`. (Kill attempt).
117. **TerminateProcess:** Killing another process. (Watchdog/User kill).
118. **Debug Active:** `IsDebuggerPresent` check. (Anti-debug).
119. **WerFault Trigger:** Spawning `WerFault.exe`. (Crash reporting).
120. **Dr Watson:** Spawning `dwwin.exe`. (Legacy crash).
121. **Conhost Spawn:** Spawning `conhost.exe`. (Console window).
122. **Wow64 Transition:** 32-bit to 64-bit thunk. (Compatibility).
123. **Job Object Assign:** Assign process to Job. (Resource limit).
124. **Token Impersonation:** `ImpersonateLoggedOnUser`. (Context switch).
125. **Token Priv Adjust:** `AdjustTokenPrivileges`. (Elevating).
126. **LUID Exhaustion:** `AllocateLocallyUniqueId` fail. (Auth resource limit).
127. **Handle Leak:** `CloseHandle` count << `CreateFile`. (Resource leak).
128. **GDI Leak:** GDI object count spike. (Graphics leak).
129. **User Handle Leak:** User object count spike. (Window leak).
130. **Non-Paged Pool:** `STATUS_INSUFFICIENT_RESOURCES`. (Kernel memory full).
131. **Commit Limit:** `STATUS_COMMITMENT_LIMIT`. (RAM/Pagefile full).
132. **Working Set Trim:** `EmptyWorkingSet`. (Memory reclaiming).
133. **Page Fault:** Hard page fault storm. (Thrashing).
134. **Stack Overflow:** `STATUS_STACK_OVERFLOW`. (Recursion loop).
135. **DllMain Hang:** Long duration in `LoadImage`. (Loader lock).
136. **Zombie Process:** Process Exit but handle remains. (Deletion block).
137. **Orphaned Process:** Parent exits, child remains. (Backgrounding).
138. **Rapid Spawn:** 10+ processes/sec. (Fork bomb/Crash loop).
139. **Self-Deletion:** `cmd /c del` on self. (Installer/Malware).
140. **Process Hollowing:** Write to memory of suspended proc. (Malware).
141. **Reflective Load:** Alloc Exec memory, no file. (Fileless malware).
142. **SvcHost Split:** SvcHost hosting single service. (Stability).
143. **AppContainer:** Process in Sandbox. (Store App).
144. **Low Integrity:** Low IL Process. (Browser sandbox).
145. **Protected Process:** Protected Light (PPL). (AV/System).
146. **System Process:** PID 4 activity. (Kernel).
147. **Registry Virtualization:** `VirtualStore` access. (Legacy compat).
148. **Shim Engine:** `AcLayers.dll` load. (AppCompat).
149. **Detours:** `detoured.dll` load. (Hooking).
150. **Inject Library:** `AppInit_DLLs` usage. (Global injection).

---

### **SECTION 4: NETWORK STACK (TCP/IP & RPC)**
*Detecting connectivity, latency, protocol errors, and firewalls.*

151. **TCP Connect (Success):** Handshake complete. (Connected).
152. **TCP Connect (Refused):** `CONNECTION_REFUSED`. (Port closed/Blocked).
153. **TCP Connect (Timeout):** Duration > 20s. (Drop/No Route).
154. **TCP Connect (Unreachable):** `NETWORK_UNREACHABLE`. (Routing fail).
155. **TCP Connect (AddrInUse):** `ADDRESS_ALREADY_ASSOCIATED`. (Port exhaustion).
156. **TCP Reconnect:** Repeated Connect to same IP. (Flapping).
157. **TCP Disconnect (Reset):** `ECONNRESET`. (Force close).
158. **TCP KeepAlive:** Packet every 60s. (Idle maintenance).
159. **UDP Send (Fail):** `HOST_UNREACHABLE`. (Delivery fail).
160. **UDP Receive:** Incoming datagram. (Listener active).
161. **DNS Query (A):** Standard lookup. (IPv4).
162. **DNS Query (AAAA):** IPv6 lookup. (IPv6).
163. **DNS Fail:** `NAME_NOT_FOUND`. (Typo/Missing record).
164. **DNS Timeout:** No response. (DNS Server down).
165. **Reverse Lookup:** PTR record check. (Logging/Security).
166. **Broadcast Storm:** High volume UDP broadcast. (NetBIOS/Disco).
167. **Multicast Join:** IGMP traffic. (Streaming/Cluster).
168. **IPv6 Failover:** AAAA fail -> A success. (Protocol lag).
169. **Port 80/443:** HTTP/HTTPS. (Web traffic).
170. **Port 445:** SMB. (File share).
171. **Port 135/139:** RPC/NetBIOS. (Legacy/Mgmt).
172. **Port 389/636:** LDAP/LDAPS. (AD Auth).
173. **Port 88:** Kerberos. (Auth).
174. **Port 53:** DNS. (Resolution).
175. **Port 3389:** RDP. (Remote Access).
176. **Port 1433:** SQL. (Database).
177. **High Ports:** Ephemeral range. (Client/RPC).
178. **Tor Ports:** 9001/9050. (Suspicious).
179. **Proxy Connect:** Connect to Proxy IP. (Web filter).
180. **WPAD Lookup:** HTTP to `wpad`. (Proxy auto-config).
181. **PAC File Fail:** 404 on `.pac`. (Slow browsing).
182. **SMBv1:** Protocol negotiation SMB1. (Security risk).
183. **SMBv3:** Protocol negotiation SMB3. (Modern/Encryption).
184. **RPC Bind:** Binding to interface. (DCOM start).
185. **RPC Auth Fail:** `RPC_E_ACCESS_DENIED`. (Permission).
186. **RPC Stub Fail:** `RPC_E_DISCONNECTED`. (Crash on server).
187. **Named Pipe Connect:** `\\Server\pipe`. (IPC).
188. **Mail Slot:** `\mailslot\browse`. (Browser election).
189. **Cert Revocation:** HTTP to CRL. (SSL check).
190. **OCSP Fail:** Connect fail to OCSP. (Cert hang).
191. **Winsock Load:** `ws2_32.dll`. (Net stack init).
192. **LSP Injection:** Non-standard DLL in net stack. (Interference).
193. **NLA Check:** HTTP to `msftncsi`. (Internet check).
194. **Teredo/Isatap:** Tunneling traffic. (IPv6 transition).
195. **Loopback Connect:** 127.0.0.1. (Local service).
196. **Link Local:** 169.254.x.x. (DHCP fail).
197. **Private IP:** 10.x/192.168.x. (Internal).
198. **Public IP:** Internet traffic. (External).
199. **FTP Active:** Port 21. (Data exfil/Legacy).
200. **SSH Active:** Port 22. (Admin/Tunnel).

---

### **SECTION 5: ENTERPRISE INFRA (AD, GPO, VDI)**
*Detecting admin-level failures and environment issues.*

201. **GPO Read Fail:** `gpt.ini` access deny. (Policy fail).
202. **GPO Script Fail:** `gpscript.exe` error. (Startup script).
203. **GPO History Lock:** `history.ini` sharing vio. (Processing hang).
204. **Sysvol Latency:** Slow read `\\Domain\Sysvol`. (DC overload).
205. **Netlogon Fail:** `_ldap` lookup fail. (DC discovery).
206. **Kerberos Skew:** `KRB_AP_ERR_SKEW`. (Time sync).
207. **Ticket Bloat:** `STATUS_BUFFER_OVERFLOW` on LSASS. (MaxTokenSize).
208. **Machine Trust:** `STATUS_TRUST_FAILURE`. (Broken trust).
209. **LDAP Timeout:** Query duration > 2s. (Slow AD).
210. **Roaming Profile:** `NTUSER.DAT` copy fail. (Logon error).
211. **Folder Redir Offline:** Docs path offline. (Sync fail).
212. **Offline Files Sync:** `CscService` activity. (Caching).
213. **DFS Referral:** Access `\\Domain\DFS`. (Namespace).
214. **Print Spooler Crash:** `spoolsv.exe` exit. (Print kill).
215. **Driver Isolation:** `PrintIsolationHost` exit. (Bad driver).
216. **Point and Print:** `Dopp` registry check. (Driver install).
217. **Group Policy Printer:** `gpprinter` fail. (Mapping fail).
218. **Citrix Hook:** `CtxHk.dll` load. (VDI hook).
219. **Citrix API Block:** `CtxHk` access denied. (AV conflict).
220. **FSLogix Service:** `frxsvc` activity. (Profile container).
221. **VHDX Lock:** `frxsvc` sharing vio. (Session lock).
222. **App-V Stream:** Read from `Q:` / Mount. (Streaming).
223. **ThinPrint:** `TPAutoConnect` fail. (VDI Print).
224. **VMware Tools:** `vmtoolsd` activity. (Guest agent).
225. **WEM Agent:** `Norskale` activity. (Environment mgmt).
226. **SCCM Agent:** `CcmExec` activity. (Mgmt agent).
227. **SCCM Cache:** Write to `ccmcache`. (Download).
228. **Intune Mgmt:** `Omadmclient` activity. (MDM sync).
229. **AppLocker Block:** `SrpUxNative` check. (Whitelisting).
230. **BitLocker Network:** `FVE` network unlock. (Boot unlock).

---

### **SECTION 6: INSTALLERS & UPDATES (MSI, WU)**
*Detecting deployment failures and repair loops.*

231. **MSI Exec Start:** `msiexec.exe` /v. (Install start).
232. **MSI Source Fail:** `Sourcelist` path not found. (Media missing).
233. **MSI Self Repair:** `msiexec` spawned by app. (Resiliency).
234. **MSI Rollback:** `SetRename` restore. (Fatal error).
235. **MSI Mutex:** Wait on `_MSIExecute`. (Concurrent install).
236. **MSI Custom Action:** `cmd` spawned by MSI. (Script logic).
237. **MSI Cab Fail:** Extract fail `%TEMP%`. (Disk/Perms).
238. **MSI Transform:** `.mst` missing. (Customization lost).
239. **Pending Reboot:** `PendingFileRename` exists. (Blocker).
240. **Windows Update Lock:** `wuauserv` lock `DataStore`. (DB lock).
241. **CBS Manifest:** `TrustedInstaller` read fail. (Corrupt OS).
242. **CatRoot2 Fail:** `cryptsvc` write fail. (Catalog corrupt).
243. **SXS Corruption:** `winsxs` read fail. (Component store).
244. **Driver Store:** `drvstore` access. (Driver staging).
245. **TiWorker CPU:** High activity `TiWorker`. (Post-install).
246. **Update Download:** Write `SoftwareDistribution`. (Patching).
247. **Bled/Hydrate:** Modern app install. (AppX).
248. **AppX Manifest:** `AppxManifest.xml` read. (Store App).
249. **AppX Deploy:** `AppXDeploymentServer` fail. (Install fail).
250. **State Repo:** `StateRepository` lock. (Store DB lock).

---

### **SECTION 7: SECURITY & MALWARE INDICATORS**
*Detecting threats, persistence, and evasion.*

251. **Run Key Persistence:** Write `CurrentVersion\Run`. (Autostart).
252. **Startup Persistence:** Write `Startup` folder. (Autostart).
253. **Service Persistence:** Write `Services` key. (Rootkit).
254. **Task Persistence:** Write `Tasks` folder. (Scheduled Task).
255. **Winlogon Persist:** Write `Userinit` / `Shell`. (Hijack).
256. **Image Hijack:** Write `Image File Execution Options`. (Debug hijack).
257. **AppInit Injection:** Write `AppInit_DLLs`. (Dll inject).
258. **COM Hijack:** Write `InprocServer32`. (Object hijack).
259. **Extension Hijack:** Write `txtfile\shell\open`. (Assoc hijack).
260. **Browser Helper:** Write `BHO` key. (Adware).
261. **Phantom DLL:** Drop `version.dll` (Sideloading).
262. **WMI Persist:** Write `Objects.data`. (Fileless persist).
263. **Powershell Enc:** `powershell -e`. (Obfuscation).
264. **Powershell Download:** `Net.WebClient`. (Downloader).
265. **LoLBin CertUtil:** `certutil -urlcache`. (Download).
266. **LoLBin Bits:** `bitsadmin /transfer`. (Download).
267. **LoLBin Mshta:** `mshta vbscript`. (Execution).
268. **LoLBin Rundll:** `rundll32 entrypoint`. (Execution).
269. **LoLBin Regsvr:** `regsvr32 /s /u`. (Squiblydoo).
270. **Credential Dump:** Read `lsass` memory. (Mimikatz).
271. **SAM Dump:** Read `SAM` / `SYSTEM` hive. (Hash dump).
272. **LSA Secret:** Read `Policy\Secrets`. (Password dump).
273. **Vault Access:** `vaultcmd` execution. (Cred dump).
274. **Browser Data:** Read `Login Data`. (Cookie theft).
275. **Keylog Poll:** `GetAsyncKeyState`. (Spyware).
276. **Clipboard Monitor:** Open Clipboard. (Spyware).
277. **Screen Capture:** `BitBlt` / `Magnification`. (Spyware).
278. **Mic Access:** Device `WaveIn`. (Eavesdrop).
279. **Webcam Access:** Device `Video`. (Spyware).
280. **Recon Whoami:** `whoami /all`. (Discovery).
281. **Recon Net:** `net group`. (Discovery).
282. **Recon IP:** `ipconfig /all`. (Discovery).
283. **Recon Task:** `tasklist /svc`. (AV check).
284. **Event Clear:** `wevtutil cl`. (Anti-forensics).
285. **Shadow Delete:** `vssadmin delete`. (Ransomware).
286. **Backup Stop:** `wbadmin delete`. (Ransomware).
287. **Disable Def:** Write `DisableRealtimeMonitoring`. (AV Kill).
288. **Host File Mod:** Write `hosts`. (Redirect).
289. **Timestomp:** `SetBasicInformationFile` Time. (Hiding).
290. **Masquerade:** `svchost` in `%TEMP%`. (Hiding).
291. **Ransom Rename:** Mass rename extensions. (Encryption).
292. **Ransom Write:** Mass read/write/delete. (Encryption).
293. **DGA DNS:** Random domain lookup. (C2).
294. **Beaconing:** Periodic HTTP. (C2).
295. **Tor Traffic:** Port 9050. (Anon).
296. **PST Access:** Read `.pst`. (Email theft).
297. **SSH Keys:** Read `id_rsa`. (Lateral move).
298. **RDP Saved:** Read `Default.rdp`. (Lateral move).
299. **Wifi Keys:** Read `Wlansvc`. (Lateral move).
300. **Exfil FTP:** `ftp -s`. (Data theft).

---

### **SECTION 8: APPLICATION FRAMEWORKS (Java, .NET, Web)**
*Detecting runtime errors and config issues.*

301. **.NET CLR Load:** `mscoree.dll` load. (.NET start).
302. **.NET GAC Load:** Read `C:\Windows\Assembly`. (Global lib).
303. **.NET Temp:** Write `Temporary ASP.NET Files`. (Compile).
304. **.NET Config:** Read `machine.config`. (Settings).
305. **.NET JIT:** `mscorjit.dll` activity. (Compilation).
306. **.NET NGEN:** `ngen.exe` activity. (Optimization).
307. **Java Home:** Env Var `JAVA_HOME` fail. (Config).
308. **Java Runtime:** `jvm.dll` load. (Java start).
309. **Java Classpath:** Read `lib/ext`. (Dependency).
310. **Java Access:** `WindowsAccessBridge` fail. (A11y).
311. **Python Path:** Env Var `PYTHONPATH`. (Config).
312. **Python Import:** Read `__init__.py`. (Module load).
313. **Node Modules:** Read `node_modules`. (JS dep).
314. **Electron Cache:** Write `GPUCache`. (Chromium).
315. **IIS Worker:** `w3wp.exe` start. (Web server).
316. **IIS Config:** Read `web.config`. (App settings).
317. **IIS Shared:** Read `applicationHost.config`. (Server set).
318. **AppPool Identity:** `ACCESS_DENIED` as IIS AppPool. (Perms).
319. **Temp Path:** Env Var `TEMP`. (Scratch space).
320. **Oracle TNS:** Read `tnsnames.ora`. (DB Config).
321. **ODBC System:** Read `HKLM\Software\ODBC`. (DSN).
322. **ODBC User:** Read `HKCU\Software\ODBC`. (DSN).
323. **SQL Driver:** Load `sqlncli.dll`. (Connectivity).
324. **OLEDB Reg:** Read `HKCR\CLSID\{Provider}`. (Driver).
325. **UDL Read:** Read `.udl`. (Conn string).
326. **Report Viewer:** Load `Microsoft.ReportViewer`. (Reporting).
327. **Crystal Reports:** Load `crpe32.dll`. (Reporting).
328. **Flash OCX:** Load `Flash.ocx`. (Legacy).
329. **Silverlight:** Load `npctrl.dll`. (Legacy).
330. **ActiveX Killbit:** Read `Compatibility Flags`. (Block).

---

### **SECTION 9: HARDWARE & DRIVERS**
*Detecting physical device failures and driver quirks.*

331. **USB Arrival:** `DeviceIoControl` USB Hub. (Connect).
332. **USB Removal:** `DeviceIoControl` Fail. (Disconnect).
333. **USB Suspend:** Selective Suspend loop. (Power).
334. **HID Input:** Read `HidUsb`. (Keyboard/Mouse).
335. **Bluetooth Enum:** `BthEnum` activity. (Wireless).
336. **SmartCard Insert:** `SCardSvr` event. (Auth).
337. **SmartCard Pipe:** `SCardPipe` connect. (Driver).
338. **GPU Reset:** `dxgkrnl` TDR. (Crash).
339. **GPU Throttling:** Power limit event. (Thermal).
340. **Audio Excl:** `AUDCLNT_E_DEVICE_IN_USE`. (Lock).
341. **Audio Graph:** `audiodg` activity. (Sound).
342. **Webcam Lock:** `CreateFile` Video0 deny. (Privacy).
343. **Printer Bidirectional:** SNMP query. (Status).
344. **Scanner Twain:** Load `twain_32.dll`. (Imaging).
345. **Serial Port:** Open `COM1`. (Legacy IO).
346. **Parallel Port:** Open `LPT1`. (Legacy IO).
347. **Tape Drive:** Open `Tape0`. (Backup).
348. **Battery Poll:** `batmeter` read. (Power).
349. **ACPI Event:** `ACPI` thermal zone. (Heat).
350. **BIOS Info:** Read `Hardwaredescription\System`. (Firmware).

---

### **SECTION 10: ACCESSIBILITY & UI**
*Detecting screen reader and automation failures.*

351. **UIA Prov Fail:** `RegOpenKey` UIA deny. (Automation).
352. **WM_GETOBJECT:** Message timeout. (No response).
353. **Acc Name:** Empty `accName`. (Unlabeled).
354. **Focus Fight:** Rapid `SetFocus`. (Loop).
355. **High Contrast:** Read `GetSysColor`. (Theme).
356. **Cursor Track:** `GetGUIThreadInfo` fail. (Visual).
357. **Narrator Hook:** Load `NarratorHook`. (Reader).
358. **JAB Fail:** Load `WindowsAccessBridge`. (Java).
359. **Braille Lock:** `CreateFile` COM fail. (Display).
360. **Speech Dict:** Write dictionary fail. (Voice).

---

### **SECTION 11: LEGACY & COMPATIBILITY**
*Detecting "Old Windows" behavior.*

361. **INI Redirect:** Read `win.ini`. (16-bit).
362. **16-bit App:** Load `ntvdm.exe`. (DOS).
363. **Thunking:** Load `wow64.dll`. (32-on-64).
364. **Shim Apply:** Read `sysmain.sdb`. (Patches).
365. **DirectX 9:** Load `d3d9.dll`. (Old Gfx).
366. **VB6 Runtime:** Load `msvbvm60.dll`. (Basic).
367. **MFC 42:** Load `mfc42.dll`. (C++).
368. **8.3 Path:** Access `DOCUME~1`. (Shortname).
369. **Hardcoded Drv:** Access `D:\`. (Missing drive).
370. **CD Check:** Access `CdRom0`. (DRM).
371. **Admin Write:** Redirect `VirtualStore`. (UAC).
372. **Deprecated API:** Call `WinExec`. (Old code).
373. **Legacy Help:** Load `winhlp32.exe`. (.hlp).
374. **MAPI Mail:** Load `mapi32.dll`. (Email).
375. **NetDDE:** Service start. (Ancient IPC).

---

### **SECTION 12: CRYPTOGRAPHY & PKI**
*Detecting cert and encryption failures.*

376. **Cert Store:** Read `SystemCertificates`. (Trust).
377. **Root Update:** Download `authroot.stl`. (Update).
378. **CRL Fetch:** HTTP fetch `.crl`. (Revocation).
379. **OCSP Check:** HTTP fetch OCSP. (Revocation).
380. **Chain Fail:** `CERT_E_CHAINING`. (Trust path).
381. **Expired:** `CERT_E_EXPIRED`. (Date).
382. **Name Mismatch:** `CERT_E_CN_NO_MATCH`. (SSL).
383. **MachineKey:** Read `MachineKeys`. (Private key).
384. **UserKey:** Read `Protect`. (Private key).
385. **DPAPI:** `CryptUnprotectData`. (Decryption).
386. **CNG Key:** Read `KeyStorage`. (Modern key).
387. **FIPS Block:** `FIPSAlgorithmPolicy`. (Compliance).
388. **Hash Fail:** `STATUS_INVALID_IMAGE_HASH`. (Sign).
389. **Catalog DB:** Write `catdb`. (Sig DB).
390. **RNG Seed:** Write `RNG`. (Random).

---

### **SECTION 13: CLOUD & HYBRID (Azure/M365)**
*Detecting modern identity and sync issues.*

391. **AAD Token:** Read `TokenBroker`. (SSO).
392. **Workplace Join:** Read `WorkplaceJoin`. (Registration).
393. **Ngc Key:** Read `Ngc`. (Hello for Bus).
394. **M365 Activate:** Connect `office.com`. (Licensing).
395. **OneDrive Sync:** Write `OneDrive`. (Cloud file).
396. **Azure Info:** Read `Tenants`. (Identity).
397. **MDM Policy:** Read `PolicyManager`. (Intune).
398. **Entra ID:** `dsregcmd` activity. (Join status).
399. **Compliance:** `HealthAttestation`. (Security).
400. **Telemetry:** `CompatTelRunner`. (Diag data).

---

### **SECTION 14: SPECIFIC SOFTWARE PATTERNS (The "Top Hitters")**
*Specific detections for common enterprise software.*

401. **Chrome Profile:** Lock `SingletonLock`. (Stuck).
402. **Chrome Ext:** Read `Extensions`. (Add-on).
403. **Edge Update:** `MicrosoftEdgeUpdate`. (Patch).
404. **Firefox Lock:** `parent.lock`. (Stuck).
405. **Teams Cache:** Write `Code Cache`. (Performance).
406. **Teams Log:** Write `logs.txt`. (Diag).
407. **Outlook OST:** Read `.ost` > 100MB. (Disk IO).
408. **Outlook OAB:** Read `Offline Address Books`. (Sync).
409. **Excel Addin:** Load `.xll`. (Extension).
410. **Word Template:** Read `Normal.dotm`. (Config).
411. **Adobe Reader:** Load `AcroRd32.dll`. (PDF).
412. **Adobe Arm:** `AdobeARM.exe`. (Update).
413. **Zoom Cpt:** `CptHost.exe`. (Sharing).
414. **WebEx Service:** `WebExService`. (Meeting).
415. **Slack Cache:** Write `Cache`. (Electron).
416. **VSCode IPC:** Pipe `vscode-ipc`. (Dev).
417. **Docker Pipe:** Pipe `docker_engine`. (Container).
418. **Kubernetes:** Read `.kube`. (Config).
419. **Git Lock:** Read `index.lock`. (Repo).
420. **Npm Cache:** Write `_cacache`. (Dev).
421. **McAfee Scan:** `mcshield.exe`. (AV).
422. **Symantec Scan:** `ccSvcHst.exe`. (AV).
423. **CrowdStrike:** `CSFalconService`. (EDR).
424. **SentinelOne:** `LogProcessor`. (EDR).
425. **Splunk Fwd:** `splunk-optimize`. (Log).
426. **Tanium Client:** `TaniumClient`. (Mgmt).
427. **Qualys Agent:** `QualysAgent`. (Scan).
428. **Nessus Scan:** High Net Ports. (Vuln Scan).
429. **Datadog:** `datadog-agent`. (Monitor).
430. **NewRelic:** `newrelic-infra`. (Monitor).
431. **Veeam Agent:** `VeeamAgent`. (Backup).
432. **Commvault:** `ClMgrS`. (Backup).
433. **Backup Exec:** `beremote`. (Backup).
434. **Dropbox Watch:** `Dropbox` CPU. (Sync).
435. **Box Sync:** `Box` Overlay. (Sync).

---

### **SECTION 15: ADVANCED MEMORY & DEBUGGING**
*Detecting developer-level crashes.*

436. **Heap Corruption:** `RtlFreeHeap` fail. (Memory).
437. **Double Free:** Freeing same mem twice. (Crash).
438. **Use After Free:** Access freed mem. (Exploit).
439. **Null Pointer:** Read 0x00000000. (Bug).
440. **Buffer Overrun:** Write past end. (Security).
441. **Stack Exhaust:** `Recursion`. (Overflow).
442. **Handle Invalid:** `CloseHandle` fail. (Logic).
443. **CritSec Timeout:** Wait on CS > 60s. (Hang).
444. **Deadlock:** Cycle in Wait Chain. (Hang).
445. **LPC Wait:** Wait on Port. (IPC Hang).
446. **Memory Leak:** Private Bytes growth. (Leak).
447. **GDI Objects:** > 9000. (Limit).
448. **User Objects:** > 9000. (Limit).
449. **Thread Count:** > 2000. (Spam).
450. **Handle Count:** > 50000. (Leak).

---

### **SECTION 16: SYSTEM CONFIGURATION & BOOT**
*Detecting setup issues.*

451. **Boot Log:** Write `ntbtlog.txt`. (Diag).
452. **Setup Log:** Write `setupapi.dev.log`. (Driver).
453. **CBS Log:** Write `cbs.log`. (Update).
454. **DISM Log:** Write `dism.log`. (Image).
455. **Events Log:** Write `.evtx`. (Audit).
456. **WMI Repo:** Read `Index.btr`. (Mgmt).
457. **SRU DB:** Write `srudb.dat`. (Usage).
458. **Prefetch:** Write `.pf`. (Optimize).
459. **Superfetch:** `SysMain` activity. (Cache).
460. **Search Index:** `SearchIndexer` I/O. (Index).
461. **Cortana:** `SearchUI` activity. (Shell).
462. **Start Menu:** `ShellExperienceHost`. (UI).
463. **Action Center:** `ActionCenter`. (Notify).
464. **Settings App:** `SystemSettings`. (Config).
465. **Task Manager:** `Taskmgr`. (Admin).
466. **Resource Mon:** `Perfmon`. (Admin).
467. **Event Viewer:** `mmc.exe`. (Admin).
468. **Reg Editor:** `regedit.exe`. (Admin).
469. **CMD Shell:** `cmd.exe`. (Shell).
470. **PowerShell:** `powershell.exe`. (Shell).
471. **Run Dialog:** `explorer.exe` Run. (Shell).
472. **LogonUI:** `LogonUI.exe`. (Auth).
473. **WinInit:** `wininit.exe`. (Boot).
474. **LSM:** `lsm.exe`. (Session).
475. **Smss:** `smss.exe`. (Session).

---

### **SECTION 17: WINDOWS SUBSYSTEM FOR LINUX (WSL)**
*Detecting Linux interoperability issues.*

476. **WSL Host:** `wslhost.exe`. (Kernel).
477. **WSL File:** Access `\\wsl$`. (Network).
478. **WSL Config:** Read `.wslconfig`. (Settings).
479. **Lxss Manager:** `LxssManager` svc. (Svc).
480. **Plan 9 FS:** `p9rdr.sys`. (Filesystem).
481. **Bash Exec:** `bash.exe`. (Shell).
482. **Linux Binary:** Exec ELF file. (Compat).
483. **WSL Network:** Hyper-V NIC. (Connect).
484. **WSL Mount:** Mount `drvfs`. (Storage).
485. **WSL2 VHD:** `ext4.vhdx`. (Disk).

---

### **SECTION 18: GAMING & MEDIA (DirectX/Audio)**
*Detecting rendering and input lag.*

486. **Game Mode:** `GameBar.exe`. (Overlay).
487. **DVR Store:** Write `.mp4`. (Record).
488. **Steam Svc:** `SteamService`. (Platform).
489. **Epic Svc:** `EpicGamesLauncher`. (Platform).
490. **Origin Svc:** `Origin`. (Platform).
491. **Discord Overlay:** `Discord`. (Hook).
492. **OBS Hook:** `graphics-hook`. (Capture).
493. **XInput:** Load `xinput`. (Controller).
494. **DirectInput:** Load `dinput`. (Controller).
495. **Vulkan:** Load `vulkan-1.dll`. (Graphics).
496. **OpenGL:** Load `opengl32.dll`. (Graphics).
497. **OpenCL:** Load `OpenCL.dll`. (Compute).
498. **PhysX:** Load `PhysX`. (Physics).
499. **Shader Cache:** Write `D3DSCache`. (Perf).
500. **Refresh Rate:** `ChangeDisplaySettings`. (Hz).

*(Note: Items 501-1000 would continue expanding specific registry keys for Policy, specific error codes, and driver filenames, but this list covers the detection **logic categories** effectively for the script.)*




Here is the continuation of the **Master Definition List**, covering items **501 through 1000+**.

These sections dive deep into specific Registry keys, Windows Services, specific COM objects, and advanced error codes that generate "noise" or "signals" in a ProcMon trace.

---

### **SECTION 19: GROUP POLICY & REGISTRY POLLING (The "Noise")**
*Detecting applications or policies that spam the registry, causing CPU spikes.*

501. **Policy Poll (Explorer):** Read `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`. (UI restrictions).
502. **Policy Poll (System):** Read `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System`. (UAC/Logon).
503. **Policy Poll (Assoc):** Read `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts`. (Assoc hijacking).
504. **Policy Poll (IE):** Read `HKLM\Software\Policies\Microsoft\Internet Explorer`. (Browser lock).
505. **Policy Poll (Edge):** Read `HKLM\Software\Policies\Microsoft\Edge`. (Browser lock).
506. **Policy Poll (Chrome):** Read `HKLM\Software\Policies\Google\Chrome`. (Browser lock).
507. **Policy Poll (Office):** Read `HKCU\Software\Policies\Microsoft\Office`. (Macro settings).
508. **Policy Poll (Defender):** Read `HKLM\Software\Policies\Microsoft\Windows Defender`. (AV settings).
509. **Policy Poll (Update):** Read `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate`. (Patching).
510. **Policy Poll (Power):** Read `HKLM\Software\Policies\Microsoft\Power\PowerSettings`. (Sleep/Wake).
511. **Background Poll:** Read `HKCU\Control Panel\Desktop\Wallpaper`. (GPO Refresh).
512. **ScreenSaver Poll:** Read `HKCU\Control Panel\Desktop\ScreenSaveActive`. (Lockout).
513. **TimeOut Poll:** Read `HKCU\Control Panel\Desktop\ScreenSaveTimeOut`. (Lockout).
514. **Theme Poll:** Read `HKCU\Software\Microsoft\Windows\CurrentVersion\ThemeManager`. (Visuals).
515. **Color Poll:** Read `HKCU\Control Panel\Colors`. (High Contrast).
516. **Cursor Poll:** Read `HKCU\Control Panel\Cursors`. (Accessibility).
517. **Sound Poll:** Read `HKCU\AppEvents\Schemes`. (Audio feedback).
518. **Icon Cache Check:** Read `HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Icons`. (Overlays).
519. **Drive Map Poll:** Read `HKCU\Network`. (Mapped Drives).
520. **Printer Poll:** Read `HKCU\Printers`. (Default printer).
521. **MUI Poll:** Read `HKLM\SYSTEM\CurrentControlSet\Control\MUI\Settings`. (Language).
522. **TimeZone Poll:** Read `HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation`. (Clock).
523. **Network List Poll:** Read `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList`. (NLA).
524. **Firewall Poll:** Read `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`. (Rules).
525. **Audit Poll:** Read `HKLM\SECURITY\Policy\PolAdtEv`. (Event generation).
526. **LSA Poll:** Read `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`. (Auth).
527. **Schannel Poll:** Read `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL`. (TLS/SSL).
528. **FIPS Poll:** Read `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy`. (Crypto).
529. **Winlogon Poll:** Read `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`. (Shell).
530. **AppInit Poll:** Read `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`. (Injection).

---

### **SECTION 20: WINDOWS SERVICES (Specific Detection)**
*Detecting specific service failures based on their binary names.*

531. **Spooler Crash:** `spoolsv.exe` Exit Code != 0. (Print).
532. **Audio Crash:** `audiodg.exe` Exit Code != 0. (Sound).
533. **DWM Crash:** `dwm.exe` Exit Code != 0. (Graphics).
534. **Search Crash:** `SearchIndexer.exe` Exit Code != 0. (Index).
535. **WMI Crash:** `WmiPrvSE.exe` Exit Code != 0. (Mgmt).
536. **Update Crash:** `TiWorker.exe` Exit Code != 0. (Install).
537. **Defender Crash:** `MsMpEng.exe` Exit Code != 0. (AV).
538. **Firewall Crash:** `mpssvc` (svchost) Exit. (Security).
539. **EventLog Crash:** `wevtsvc` (svchost) Exit. (Audit).
540. **TaskSched Crash:** `taskeng.exe` Exit. (Tasks).
541. **Explorer Crash:** `Explorer.exe` Exit. (Shell).
542. **LogonUI Crash:** `LogonUI.exe` Exit. (Login).
543. **Lsass Crash:** `lsass.exe` Exit. (Reboot).
544. **Csrss Crash:** `csrss.exe` Exit. (BSOD).
545. **Smss Crash:** `smss.exe` Exit. (BSOD).
546. **Svchost Split:** `svchost.exe -k netsvcs` High CPU. (Shared).
547. **Svchost Dcom:** `svchost.exe -k DcomLaunch` High CPU. (RPC).
548. **Svchost RPC:** `svchost.exe -k RpcSs` High CPU. (RPC).
549. **Svchost Local:** `svchost.exe -k LocalService` High CPU. (Background).
550. **Svchost Net:** `svchost.exe -k NetworkService` High CPU. (Network).
551. **SysMain Busy:** `svchost.exe -k sysmain` Disk I/O. (Superfetch).
552. **DiagTrack Busy:** `svchost.exe -k utisvc` Disk I/O. (Telemetry).
553. **Bits Busy:** `svchost.exe -k netsvcs` Network. (Download).
554. **WinDefend Busy:** `MsMpEng.exe` Disk I/O. (Scan).
555. **TrustedInstall:** `TrustedInstaller.exe` Disk I/O. (Update).
556. **WMI Loop:** `WmiPrvSE.exe` High CPU. (Query storm).
557. **WMI Provider:** `WmiPrvSE` loading `cimwin32.dll`. (Inventory).
558. **WMI Storage:** `WmiPrvSE` loading `storagewmi.dll`. (Disk check).
559. **WMI Net:** `WmiPrvSE` loading `wmidex.dll`. (Net check).
560. **WMI Event:** `WmiPrvSE` loading `wbemess.dll`. (Event sub).

---

### **SECTION 21: COM/DCOM CLSIDs (Common Failures)**
*Detecting specific "Class Not Registered" or "Access Denied" by GUID.*

561. **FSO Fail:** `{0D43FE01-F093-11CF-8940-00A0C9054228}` (FileSystemObject).
562. **Shell Fail:** `{13709620-C279-11CE-A49E-444553540000}` (Shell.Application).
563. **WScript Fail:** `{72C24DD5-D70A-438B-8A42-98424B88AFB8}` (WScript.Shell).
564. **ADODB Fail:** `{00000514-0000-0010-8000-00AA006D2EA4}` (Database).
565. **XMLDOM Fail:** `{2933BF90-7B36-11D2-B20E-00C04F983E60}` (XML Parser).
566. **HTTPReq Fail:** `{88D96A0A-F192-11D4-A65F-0040963251E5}` (WinHTTP).
567. **BITS Fail:** `{4991D34B-80A1-4291-83B6-3328366B9097}` (Background Transfer).
568. **TaskSched Fail:** `{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}` (Scheduler).
569. **Firewall Fail:** `{F7898AF5-CAC4-4632-A2EC-DA06E5111AF2}` (NetFwPolicy).
570. **Update Fail:** `{4CB43D7F-7EEE-4906-8698-60DA1C38F2FE}` (WindowsUpdate).
571. **Installer Fail:** `{000C1090-0000-0000-C000-000000000046}` (MSI).
572. **WMI Fail:** `{4590F811-1D3A-11D0-891F-00AA004B2E24}` (WbemLocator).
573. **Speech Fail:** `{96749377-3391-11D2-9EE3-00C04F797396}` (SAPI).
574. **Search Fail:** `{9E175B8D-F52A-11D8-B9A5-505054503030}` (WindowsSearch).
575. **ImgUtil Fail:** `{557CF406-1A04-11D3-9A73-0000F81EF32E}` (ImageUtil).
576. **Scriptlet Fail:** `{06290BD5-48AA-11D2-8432-006008C3FBFC}` (Scriptlet).
577. **HTA Fail:** `{3050F4D8-98B5-11CF-BB82-00AA00BDCE0B}` (HTML App).
578. **ShellWin Fail:** `{9BA05972-F6A8-11CF-A442-00A0C90A8F39}` (ShellWindows).
579. **Folder Fail:** `{F3364BA0-65B9-11CE-A9BA-00AA004AE837}` (ShellFolder).
580. **Link Fail:** `{00021401-0000-0000-C000-000000000046}` (ShellLink).

---

### **SECTION 22: ERROR CODES (NTSTATUS / WIN32)**
*Specific error codes that indicate specific problems.*

581. **Access Denied:** `0xC0000022` / `5`. (Permission).
582. **Object Found:** `0xC0000000` / `0`. (Success).
583. **Not Found:** `0xC0000034` / `2`. (Missing).
584. **Sharing Vio:** `0xC0000043` / `32`. (Locked).
585. **Privilege:** `0xC0000061`. (Elevation req).
586. **Disk Full:** `0xC000007F` / `112`. (Space).
587. **Mem Full:** `0xC0000017` / `1455`. (RAM/Commit).
588. **Timeout:** `0xC00000B5` / `258`. (Wait).
589. **Pipe Busy:** `0xC00000AE` / `231`. (Load).
590. **Pipe Broken:** `0xC000014B` / `109`. (Disconnect).
591. **Net Unreach:** `0xC000023C` / `1231`. (Route).
592. **Host Unreach:** `0xC000023D` / `1232`. (Target).
593. **Conn Refused:** `0xC0000236` / `1225`. (Port).
594. **Addr In Use:** `0xC000020A` / `10048`. (Conflict).
595. **Proc Limit:** `0xC000012D`. (Job limit).
596. **Quota:** `0xC0000044`. (Disk quota).
597. **Cancel:** `0xC0000120`. (User abort).
598. **Buffer Over:** `0xC0000023`. (Data size).
599. **Not Impl:** `0xC0000002`. (API missing).
600. **Invalid Param:** `0xC000000D` / `87`. (Bad call).
601. **Invalid Handle:** `0xC0000008` / `6`. (Logic bug).
602. **DLL Init:** `0xC0000142`. (Loader fail).
603. **Entry Point:** `0xC0000139`. (Version fail).
604. **Ordinal:** `0xC0000138`. (Export fail).
605. **SideBySide:** `0xC0000365`. (Manifest).
606. **Hashing:** `0xC0000428`. (Signature).
607. **Delete Pend:** `0xC0000056`. (Zombie file).
608. **Directory:** `0xC0000103`. (Is not dir).
609. **Reparse:** `0xC0000275`. (Symlink).
610. **EAS Policy:** `0xC00002D0`. (Password complexity).

---

### **SECTION 23: OFFICE & PRODUCTIVITY (Specifics)**
*Detecting crashes and hangs in the Office Suite.*

611. **Word Template:** Access `Normal.dotm` fail. (Corruption).
612. **Word Addin:** Load `.wll` fail. (Plugin).
613. **Excel Calc:** High CPU `EXCEL.EXE`. (Calculation).
614. **Excel OLE:** Wait on `Splwow64`. (Print/PDF).
615. **Excel Addin:** Load `.xla` fail. (Plugin).
616. **Outlook OST:** Write `.ost` fail. (Lock).
617. **Outlook Index:** `SearchProtocolHost` OST access. (Index).
618. **Outlook RPC:** TCP Connect `outlook.office365.com` fail. (Net).
619. **Outlook Autodiscover:** HTTP `autodiscover.xml` fail. (Config).
620. **Outlook Addin:** Load `outlvba.dll`. (Macro).
621. **Access Lock:** Write `.ldb` fail. (Record lock).
622. **Access ODBC:** Load `odbc32.dll` fail. (Driver).
623. **PowerPoint Media:** Load `pflash.dll`. (Flash).
624. **OneNote Cache:** Write `.bin` fail. (Sync).
625. **Office Update:** `OfficeClickToRun.exe` activity. (Update).
626. **Office License:** `OSPP.VBS` execution. (Activation).
627. **Office Telemetry:** `mso.dll` connect. (Diag).
628. **Teams Status:** Pipe `ub_` connect. (Presence).
629. **Teams Mtg:** UDP Send `3478`. (Media).
630. **Skype Mtg:** `lync.exe` activity. (Legacy).

---

### **SECTION 24: BROWSER INTERNALS (Chrome/Edge)**
*Detecting web page crashes and policy blocks.*

631. **Chrome Prefs:** Read `Preferences` fail. (Corruption).
632. **Chrome Local:** Read `Local State` fail. (Config).
633. **Chrome Policy:** Read `CloudManagement` fail. (Mgmt).
634. **Chrome Ext:** Read `manifest.json` fail. (Addon).
635. **Chrome GPU:** `GpuProcess` crash. (Driver).
636. **Chrome Render:** `Renderer` crash. (Page).
637. **Chrome Sandbox:** `Broker` access deny. (Security).
638. **Edge Update:** `MicrosoftEdgeUpdate.exe` fail. (Patch).
639. **Edge IE Mode:** `ieexplore.exe` spawn. (Compat).
640. **Edge WebView:** `msedgewebview2.exe` crash. (App).
641. **Cookie Lock:** Write `Cookies` busy. (Sync).
642. **History Lock:** Write `History` busy. (Sync).
643. **Cache Size:** Write `Cache_Data` > 1GB. (Space).
644. **Download Scan:** Read `Download` by AV. (Delay).
645. **Cert Check:** Read `Root` store. (SSL).
646. **Proxy Script:** Read `.pac` timeout. (Net).
647. **DNS Pre-fetch:** UDP 53 spam. (Speed).
648. **QUIC Proto:** UDP 443. (Google Net).
649. **WebRTC:** UDP High Ports. (Media).
650. **Flash Load:** Load `pepflashplayer`. (Legacy).

---

### **SECTION 25: DRIVERS & KERNEL MODULES (.SYS)**
*Detecting kernel-level interference.*

651. **NTFS Driver:** `ntfs.sys` activity. (Disk).
652. **Filter Mgr:** `fltmgr.sys` activity. (Filters).
653. **TCP/IP:** `tcpip.sys` activity. (Net).
654. **NetBIOS:** `netbt.sys` activity. (Legacy).
655. **AFD Driver:** `afd.sys` activity. (Sock).
656. **WFP Driver:** `fwpkclnt.sys` activity. (Firewall).
657. **NDIS Driver:** `ndis.sys` activity. (NIC).
658. **Storport:** `storport.sys` activity. (SAN).
659. **USB Port:** `usbport.sys` activity. (Bus).
660. **USB Hub:** `usbhub.sys` activity. (Bus).
661. **HID Class:** `hidclass.sys` activity. (Input).
662. **Mouse Class:** `mouclass.sys` activity. (Input).
663. **Kbd Class:** `kbdclass.sys` activity. (Input).
664. **Graphics:** `dxgkrnl.sys` activity. (GPU).
665. **Nvidia:** `nvlddmkm.sys` activity. (GPU).
666. **AMD:** `atikmdag.sys` activity. (GPU).
667. **Intel Gfx:** `igdkmd64.sys` activity. (GPU).
668. **Realtek Audio:** `rtkvhd64.sys` activity. (Sound).
669. **Symantec Filter:** `symefasi.sys`. (AV).
670. **McAfee Filter:** `mfehidk.sys`. (AV).
671. **CrowdStrike:** `csagent.sys`. (EDR).
672. **SentinelOne:** `SentinelMonitor.sys`. (EDR).
673. **CarbonBlack:** `cbk7.sys`. (EDR).
674. **Sysmon:** `SysmonDrv.sys`. (Log).
675. **ProcMon:** `PROCMON24.SYS`. (Self).
676. **VMware Mouse:** `vmmouse.sys`. (Guest).
677. **VMware Video:** `vm3dmp.sys`. (Guest).
678. **Citrix Net:** `ctxtcp.sys`. (VDI).
679. **Citrix Usb:** `ctxusbm.sys`. (VDI).
680. **FSLogix:** `frxdrv.sys`. (Profile).

---

### **SECTION 26: NETWORK PROTOCOLS (Expanded)**
*Detecting subtle network misconfigurations.*

681. **DHCP Renew:** UDP 67/68. (IP).
682. **NTP Sync:** UDP 123. (Time).
683. **SNMP Query:** UDP 161. (Mgmt).
684. **Syslog Send:** UDP 514. (Log).
685. **LDAP SSL:** TCP 636. (Auth).
686. **Global Cat:** TCP 3268. (AD).
687. **GC SSL:** TCP 3269. (AD).
688. **SQL Browser:** UDP 1434. (DB).
689. **RDP Gateway:** TCP 443 (Tunnel).
690. **WinRM HTTP:** TCP 5985. (Mgmt).
691. **WinRM HTTPS:** TCP 5986. (Mgmt).
692. **RPC Mapper:** TCP 135. (DCOM).
693. **NetBIOS Name:** UDP 137. (Name).
694. **NetBIOS Data:** UDP 138. (Data).
695. **NetBIOS Sess:** TCP 139. (Sess).
696. **SMB Direct:** TCP 445. (File).
697. **VNC:** TCP 5900. (Remote).
698. **ICA (Citrix):** TCP 1494. (VDI).
699. **CGP (Citrix):** TCP 2598. (VDI).
700. **Blast (VMware):** TCP/UDP 22443. (VDI).
701. **PCoIP:** UDP 4172. (VDI).
702. **BitTorrent:** TCP 6881-6999. (P2P).
703. **Spotify:** TCP 4070. (Media).
704. **Steam:** UDP 27000. (Game).
705. **Xbox Live:** UDP 3074. (Game).
706. **Teredo:** UDP 3544. (Tunnel).
707. **LLMNR:** UDP 5355. (Local DNS).
708. **SSDP:** UDP 1900. (UPnP).
709. **WS-Discovery:** UDP 3702. (Disco).
710. **mDNS:** UDP 5353. (Bonjour).

---

### **SECTION 27: POWERSHELL & SCRIPTING (Expanded)**
*Detecting script execution and policy blocks.*

711. **PS Version:** Read `PowerShellVersion` reg. (Compat).
712. **PS Module:** Read `PSModulePath`. (Load).
713. **PS Profile:** Read `Microsoft.PowerShell_profile.ps1`. (Config).
714. **PS History:** Read `ConsoleHost_history.txt`. (Log).
715. **PS Execution:** Read `ExecutionPolicy`. (Security).
716. **PS Transcript:** Write `Transcript.txt`. (Log).
717. **PS Gallery:** Connect `powershellgallery.com`. (Download).
718. **PS Remoting:** Connect `wsman`. (Remote).
719. **PS Constrained:** Mode `ConstrainedLanguage`. (Security).
720. **PS Logging:** Write `ScriptBlockLogging`. (Audit).
721. **VBS Engine:** Load `vbscript.dll`. (Legacy).
722. **JS Engine:** Load `jscript.dll`. (Legacy).
723. **WSF File:** Exec `.wsf`. (Mixed).
724. **HTA App:** Exec `.hta`. (UI).
725. **Batch File:** Exec `.bat`. (Shell).
726. **Cmd File:** Exec `.cmd`. (Shell).
727. **Python Script:** Exec `.py`. (Dev).
728. **Perl Script:** Exec `.pl`. (Dev).
729. **Ruby Script:** Exec `.rb`. (Dev).
730. **Jar File:** Exec `.jar`. (Java).

---

### **SECTION 28: FORENSICS & ARTIFACTS (Filesystem)**
*Detecting traces of user activity.*

731. **Prefetch Create:** Write `*.pf`. (Exec).
732. **Recent Docs:** Write `Recent`. (Access).
733. **JumpList:** Write `AutomaticDestinations`. (Access).
734. **ShellBag:** Reg Write `Shell\Bags`. (Folder view).
735. **UserAssist:** Reg Write `UserAssist`. (Exec count).
736. **ShimCache:** Reg Write `AppCompatCache`. (Compat).
737. **Amcache:** Write `Amcache.hve`. (Inventory).
738. **SRUM:** Write `SRUDB.dat`. (Usage).
739. **ThumbCache:** Write `thumbcache_*.db`. (Image).
740. **IconCache:** Write `IconCache.db`. (Icon).
741. **Recycle Bin:** Write `$Recycle.Bin`. (Delete).
742. **MFT Record:** Write `$MFT`. (Meta).
743. **LogFile:** Write `$LogFile`. (Journal).
744. **USN:** Write `$Extend\$UsnJrnl`. (Change).
745. **Index DB:** Write `Windows.edb`. (Search).
746. **Event Log:** Write `Security.evtx`. (Audit).
747. **WER Report:** Write `Report.wer`. (Crash).
748. **Dump File:** Write `memory.dmp`. (Crash).
749. **Mini Dump:** Write `Minidump`. (Crash).
750. **Hibernation:** Write `hiberfil.sys`. (Power).

---

### **SECTION 29: INSTALLATION & SETUP (Logs)**
*Where to look when installs fail.*

751. **SetupAPI:** Write `setupapi.dev.log`. (Driver).
752. **CBS:** Write `CBS.log`. (OS).
753. **DISM:** Write `dism.log`. (Image).
754. **WindowsUpdate:** Write `WindowsUpdate.log`. (Patch).
755. **MSI Log:** Write `MSI*.log`. (App).
756. **DirectX:** Write `DXError.log`. (Graphics).
757. **DotNet:** Write `dd_*.log`. (Runtime).
758. **VCRedist:** Write `dd_vcredist*.log`. (Runtime).
759. **SQL Setup:** Write `Summary.txt`. (DB).
760. **IIS Setup:** Write `iis.log`. (Web).
761. **SCCM Log:** Write `ccmsetup.log`. (Mgmt).
762. **Intune Log:** Write `IntuneManagementExtension.log`. (Mgmt).
763. **Sysprep:** Write `setupact.log`. (Image).
764. **Unattend:** Read `unattend.xml`. (Config).
765. **Panther:** Read `\Panther`. (Setup).

---

### **SECTION 30: "THE MARK RUSSINOVICH CLASSICS"**
*The specific checks Mark uses in his "Case of the..." presentations.*

766. **LoadString Fail:** Resource load fail -> Blank Error.
767. **CreateFile Directory:** Opening Dir as File -> Access Denied.
768. **Delete Pending:** File locked by previous delete -> Install Fail.
769. **HKCU Override:** User key hiding System key.
770. **Environment Var:** `%SystemRoot%` literal lookup.
771. **Buffer Overflow:** Registry value too small.
772. **Network Timeout:** 30 second delay on connect.
773. **Dll Search Order:** Loading `evil.dll` from CWD.
774. **Zone Identifier:** ADS causing security block.
775. **GDI Exhaustion:** Black screen due to 10k objects.
776. **Handle Leak:** Slowdown due to 100k handles.
777. **Thread Spike:** High context switch rate.
778. **Disk Queue:** Queue length > 5.
779. **Privilege Missing:** `SeDebugPrivilege` check fail.
780. **Integrity Level:** Low IL write to Medium IL fail.
781. **Virtual Store:** Writes to `VirtualStore`.
782. **Short Name:** `~1` collision.
783. **Case Sensitivity:** `File` != `file`.
784. **Sparse File:** Disk Full on sparse write.
785. **Reparse Loop:** Symlink cycle.
786. **Offline File:** Hierarchical Storage fail.
787. **Alternate Stream:** Hiding data in ADS.
788. **Host File:** Redirect verification.
789. **LSP/WFP:** Network filter blocking.
790. **User/Kernel Mode:** Context of operation.
791. **Session 0:** Service interacting with desktop.
792. **Desktop Heap:** Service GUI fail.
793. **Power Request:** Sleep prevention.
794. **Timer Res:** Timer resolution change.
795. **MMIO:** Memory Mapped I/O error.
796. **DMA:** Direct Memory Access error.
797. **Interrupts:** High hardware interrupts.
798. **DPC:** High Deferred Procedure Calls.
799. **Hard Fault:** Paging from disk.
800. **Working Set:** RAM trimming.

---

### **SECTION 31: ADVANCED API & INTERNALS**
*Obscure Win32 APIs that indicate complex behavior.*

801. **NtQuerySystemInfo:** Enum processes.
802. **NtQueryObject:** Enum handles.
803. **NtQueryInformationFile:** File meta.
804. **NtSetInformationFile:** Rename/Delete.
805. **NtDeviceIoControlFile:** Driver talk.
806. **NtCreateSection:** Shared memory.
807. **NtMapViewOfSection:** Map memory.
808. **NtUnmapViewOfSection:** Free memory.
809. **NtAllocateVirtualMemory:** Alloc RAM.
810. **NtFreeVirtualMemory:** Free RAM.
811. **NtProtectVirtualMemory:** DEP/Permissions.
812. **NtReadVirtualMemory:** Debug/Read.
813. **NtWriteVirtualMemory:** Debug/Inject.
814. **NtCreateThreadEx:** Thread spawn.
815. **NtTerminateProcess:** Kill.
816. **NtSuspendProcess:** Freeze.
817. **NtResumeProcess:** Thaw.
818. **NtOpenProcessToken:** Auth check.
819. **NtAdjustPrivilegesToken:** Elevate.
820. **NtDuplicateToken:** Impersonate.
821. **NtSetSecurityObject:** ACL change.
822. **NtQuerySecurityObject:** ACL read.
823. **NtCreateKey:** Reg create.
824. **NtOpenKey:** Reg open.
825. **NtSetValueKey:** Reg write.
826. **NtDeleteKey:** Reg delete.
827. **NtEnumerateKey:** Reg scan.
828. **NtLoadDriver:** Driver load.
829. **NtUnloadDriver:** Driver unload.
830. **NtRaiseHardError:** BSOD/Popup.
831. **NtShutdownSystem:** Reboot.
832. **NtSystemDebugControl:** Kernel debug.
833. **NtTraceControl:** ETW trace.
834. **NtAlpcSendWait:** RPC/LPC.
835. **NtFsControlFile:** Filesystem op.
836. **NtLockFile:** File lock.
837. **NtUnlockFile:** File unlock.
838. **NtNotifyChangeDirectoryFile:** Watcher.
839. **NtQueryEaFile:** Ext attributes.
840. **NtSetEaFile:** Ext attributes.

---

### **SECTION 32: CONTAINERIZATION (Docker/K8s on Windows)**
*Detecting container-specific issues.*

841. **HCS Crash:** `hcsshim.dll` fail. (Container).
842. **Docker Svc:** `dockerd.exe` fail. (Engine).
843. **Container NIC:** `vEthernet (HNS)` fail. (Net).
844. **Layer Locked:** `layer.tar` access deny. (Image).
845. **Volume Mount:** Mount `host_mnt` fail. (Storage).
846. **Pipe Docker:** `\\.\pipe\docker_engine` fail. (API).
847. **Kube Config:** Read `config` fail. (Cluster).
848. **CRI Fail:** Container Runtime fail. (Orch).
849. **GMSA Fail:** Credential Spec read fail. (Auth).
850. **Process Isolation:** Isolation mode check. (Kernel).

---

### **SECTION 33: CLOUD STORAGE & SYNC (Advanced)**
*Dropbox, OneDrive, Google Drive specifics.*

851. **OneDrive Pipe:** `\\.\pipe\OneDriveIPC` fail. (IPC).
852. **OneDrive Status:** Read `Status` fail. (Overlay).
853. **OneDrive Lock:** `FileCoAuth` lock. (Office).
854. **Dropbox Pipe:** `\\.\pipe\DropboxPipe` fail. (IPC).
855. **Dropbox Ignore:** Read `.dropboxignore`. (Config).
856. **GDrive Pipe:** `GoogleDriveFS` fail. (IPC).
857. **GDrive Cache:** Write `content_cache` full. (Space).
858. **Box Mount:** `Box Drive` disconnect. (Mount).
859. **Sync Conflict:** `Conflicted Copy` create. (Race).
860. **Attr Fail:** `SetFileAttributes` Recall. (Tiering).

---

### **SECTION 34: DATABASE (Advanced SQL/Oracle)**
*Detailed database interaction failures.*

861. **SQL Mem:** `sqlservr.exe` Mem limit. (RAM).
862. **SQL Dump:** Write `SQLDump*.mdmp`. (Crash).
863. **SQL Pipe:** `\\.\pipe\sql\query` busy. (Load).
864. **SQL VIA:** Load `sqlvia.dll`. (Legacy Proto).
865. **SQL Shared:** Load `sqlmin.dll`. (Engine).
866. **Oracle OCI:** Load `oci.dll` fail. (Client).
867. **Oracle Java:** Load `ojdbc.jar` fail. (Java).
868. **Postgres:** `postgres.exe` activity. (OSS DB).
869. **MySQL:** `mysqld.exe` activity. (OSS DB).
870. **SQLite Lock:** `database.sqlite-journal` lock. (Local).

---

### **SECTION 35: DEVELOPMENT TOOLS (DevOps)**
*Issues affecting developers.*

871. **Git Config:** Read `.gitconfig`. (Settings).
872. **SSH Agent:** Pipe `ssh-agent`. (Auth).
873. **VSCode Ext:** Read `extensions.json`. (IDE).
874. **Visual Studio:** `devenv.exe` crash. (IDE).
875. **MSBuild:** `MSBuild.exe` fail. (Build).
876. **NuGet:** Read `nuget.config`. (Pkg).
877. **Npm Lock:** Read `package-lock.json`. (Dep).
878. **Pip Cache:** Write `pip` cache. (Python).
879. **Maven Repo:** Read `.m2`. (Java).
880. **Gradle:** `gradlew` exec. (Build).

---

### **SECTION 36: MEDIA PRODUCTION (Adobe/Davinci)**
*High-end creative app failures.*

881. **Adobe Scratch:** Write `Scratch` disk full. (Space).
882. **Adobe Font:** Read `AdobeFnt.lst`. (Cache).
883. **Adobe License:** `AdobeIPCBroker` fail. (Auth).
884. **Premiere:** `Adobe Premiere Pro.exe`. (Video).
885. **After Effects:** `AfterFX.exe`. (VFX).
886. **Photoshop:** `Photoshop.exe`. (Image).
887. **Davinci Resolve:** `Resolve.exe`. (Video).
888. **Dongle Check:** Read USB Key. (License).
889. **Plugin Scan:** Enum `VST` / `AAX`. (Audio).
890. **Codec Load:** Load `ffmpeg.dll`. (Media).

---

### **SECTION 37: VIRTUAL REALITY (VR/AR)**
*Detecting VR hardware issues.*

891. **SteamVR:** `vrserver.exe`. (VR).
892. **Oculus:** `OVRServer_x64.exe`. (VR).
893. **WMR:** `MixedRealityPortal.exe`. (VR).
894. **OpenVR:** Load `openvr_api.dll`. (API).
895. **HMD USB:** Device `HMD` fail. (Headset).
896. **Tracking:** Camera dropouts. (USB).
897. **Compositor:** `vrcompositor.exe` crash. (Display).
898. **Room Setup:** Read `chaperone`. (Config).
899. **Runtime:** Load `LibOVRRT`. (Driver).
900. **Async Reprojection:** Perf drop. (Framerate).

---

### **SECTION 38: TELEMETRY & PRIVACY**
*What is Windows sending home?*

901. **DiagTrack:** `CompatTelRunner.exe`. (Usage).
902. **SQM:** Write `sqm*.dat`. (Quality).
903. **Watson:** Write `Watson`. (Crash).
904. **AIT:** `AitAgent` activity. (Install).
905. **Inventory:** `Inventory.exe`. (App scan).
906. **Device Census:** `DeviceCensus.exe`. (Hw scan).
907. **Location:** `Geofence` poll. (GPS).
908. **Feedback:** `FeedbackHub`. (User).
909. **Timeline:** Write `ActivitiesCache.db`. (History).
910. **Clip SVC:** `ClientLicense`. (Store).

---

### **SECTION 39: REMOTE DESKTOP (RDP/RDS)**
*Terminal Services troubleshooting.*

911. **TermSvc:** `TermService` crash. (Svc).
912. **RDP Clip:** `rdpclip.exe` fail. (Copy/Paste).
913. **RDP Drv:** `rdpdr.sys` fail. (Redirection).
914. **RDP Sound:** `rdpsnd.sys` fail. (Audio).
915. **RDP Print:** `EasyPrint` fail. (Print).
916. **RDP Input:** `rdpinput.sys`. (Mouse).
917. **RDP Gfx:** `rdpgfx.sys`. (Video).
918. **Session Dir:** `tssdis.exe` fail. (Broker).
919. **License Svc:** `lserver.exe` fail. (CALs).
920. **RemoteApp:** `rdpshell.exe`. (Seamless).

---

### **SECTION 40: BACKUP & RECOVERY**
*Why backups fail.*

921. **VSS Create:** `vssvc.exe` start. (Snapshot).
922. **VSS Writer:** `SqlWriter` timeout. (SQL).
923. **VSS Provider:** `swprv` fail. (Software).
924. **VSS Hardware:** `vds.exe` fail. (SAN).
925. **Change Block:** `ctp.sys` activity. (CBT).
926. **Veeam Transport:** `VeeamTransport` fail. (Net).
927. **Backup Read:** `BackupRead` API. (Stream).
928. **Archive Bit:** `SetFileAttributes` A. (Flag).
929. **Last Modified:** Timestamp check. (Inc).
930. **Catalog:** Read `GlobalCatalog`. (Tape).

---

### **SECTION 41: PRINTING (Expanded)**
*More printer failures.*

931. **Print Processor:** Load `winprint.dll`. (Spool).
932. **Print Monitor:** Load `usbmon.dll`. (Port).
933. **Print Lang:** Load `pjlmon.dll`. (PJL).
934. **Print Net:** Load `tcpmon.dll`. (IP).
935. **Print Form:** Read `Forms`. (Paper).
936. **Print Color:** Read `ColorProfiles`. (ICC).
937. **Print Sep:** Read `Separator`. (Page).
938. **Print Driver:** Read `DriverStore`. (File).
939. **Print Queue:** Write `.spl`. (Spool).
940. **Print Job:** Write `.shd`. (Shadow).

---

### **SECTION 42: FONTS & TEXT**
*Typography rendering issues.*

941. **Font Load:** `AddFontResource` fail. (Install).
942. **Font Mem:** `CreateFontIndirect` fail. (GDI).
943. **Font Link:** Read `FontLink`. (Fallbacks).
944. **Font Sub:** Read `FontSubstitutes`. (Alias).
945. **EUDC:** Read `EUDC.TE`. (Custom).
946. **Freetype:** Load `freetype.dll`. (OSS).
947. **DirectWrite:** Load `dwrite.dll`. (Modern).
948. **Uniscribe:** Load `usp10.dll`. (Complex).
949. **Font Cache:** Write `FNTCACHE.DAT`. (Boot).
950. **Type1 Font:** Read `.pfm`. (Legacy).

---

### **SECTION 43: SCIENTIFIC & ENGINEERING**
*CAD/MATLAB specific.*

951. **AutoCAD:** `acad.exe` crash. (CAD).
952. **Revit:** `revit.exe` crash. (BIM).
953. **SolidWorks:** `SLDWORKS.exe`. (CAD).
954. **Matlab:** `matlab.exe`. (Math).
955. **LabView:** `labview.exe`. (Eng).
956. **License Flex:** `lmgrd.exe`. (Licensing).
957. **Dongle HASP:** `hasplms.exe`. (Key).
958. **Dongle Sentinel:** `Sentinel`. (Key).
959. **CUDA:** Load `nvcuda.dll`. (Compute).
960. **MPI:** Load `mpi.dll`. (Cluster).

---

### **SECTION 44: FINANCIAL & TRADING**
*Low latency and stability.*

961. **Bloomberg:** `bbcomm.exe`. (Terminal).
962. **Thomson:** `Eikon.exe`. (Terminal).
963. **Excel RTD:** RealTimeData update. (Feed).
964. **Excel DDE:** DynamicDataExch. (Legacy).
965. **Multicast:** UDP 224.x.x.x. (Ticker).
966. **PTP Sync:** IEEE 1588. (Time).
967. **Solarflare:** Load `sf...dll`. (NIC).
968. **Mellanox:** Load `mlx...sys`. (NIC).
969. **RDMA:** RemoteDirectMem. (Speed).
970. **Kernel Bypass:** User mode net. (Speed).

---

### **SECTION 45: HEALTHCARE & DICOM**
*Medical software.*

971. **Epic:** `Hyperspace.exe`. (EMR).
972. **Cerner:** `Citrix` hosted. (EMR).
973. **DICOM Send:** TCP 104. (Image).
974. **PACS:** Connect PACS server. (Image).
975. **HL7:** TCP MLLP. (Msg).
976. **Twain:** Scanner source. (Scan).
977. **Speech Mic:** `Nuance` / `Dragon`. (Dictation).
978. **Foot Pedal:** HID Input. (Control).
979. **Badge Tap:** Serial/RFID. (Auth).
980. **Imprivata:** `SSO` injection. (Auth).

---

### **SECTION 46: EDUCATION & LAB**
*Classroom control.*

981. **LanSchool:** `student.exe`. (Monitor).
982. **NetSupport:** `client32.exe`. (Monitor).
983. **Faronics:** `DeepFreeze`. (Restore).
984. **Respondus:** `LockDownBrowser`. (Test).
985. **SmartBoard:** `SmartBoard`. (Input).
986. **SafeExam:** `SEB`. (Test).
987. **PaperCut:** `pc-client`. (Print).
988. **Pharos:** `Pharos`. (Print).
989. **LabStats:** `LabStats`. (Usage).
990. **Veyon:** `Veyon`. (Monitor).

---

### **SECTION 47: POINT OF SALE (POS)**
*Retail specific.*

991. **OPOS:** Load `OPOS.dll`. (Device).
992. **JavaPOS:** Load `jpos.jar`. (Device).
993. **Cash Drawer:** Serial trigger. (HW).
994. **Receipt Prn:** Serial/USB. (HW).
995. **Pole Display:** Serial. (HW).
996. **Pin Pad:** Cryptogram. (Pay).
997. **Mag Stripe:** Reader input. (Card).
998. **Scanner:** Barcode input. (Input).
999. **Scale:** Weight read. (HW).
1000. **EFT:** Payment Gateway. (Net).

---

### **SECTION 48: "THE FINAL STRAW" (Last Resort Checks)**
*When nothing else makes sense.*

1001. **Bit Flip:** Memory corruption. (RAM).
1002. **Cosmic Ray:** Random status change. (Physics).
1003. **Cable Rot:** Intermittent net drop. (Physical).
1004. **Power Sag:** Brownout reset. (Physical).
1005. **Capacitor:** Motherboard fail. (Physical).
1006. **Thermal:** CPU throttling. (Physical).
1007. **Dust:** Fan failure. (Physical).
1008. **Liquid:** Short circuit. (Physical).
1009. **User Error:** ID 10 T. (Layer 8).
1010. **Gremlins:** Unknown. (Undefined).



Here is the continuation, specifically targeting the **"Most Challenging"** diagnostic scenarios (the ones that usually result in multi-week tickets) and deep-diving into **Assistive Technology (AT)** failures, which are often invisible to standard monitoring tools.

---

### **SECTION 49: THE "SILENT FAILURES" (Hardest to Diagnose)**
*Applications that exit or fail without error messages/logs. The "It just disappears" category.*

1011. **Swallowed Exception (CLR):** `.NET Runtime` logs "Application Error" event but no ProcMon crash. (Dev caught exception but didn't log it).
1012. **WerFault Suppression:** `WerFault.exe` starts but exits immediately with no UI. (Headless mode crash).
1013. **Stack Overflow (Silent):** `Process Exit` code `0xC00000FD`. (Recursion limit hit, often no dump).
1014. **Heap Corruption (Immediate):** `Process Exit` code `0xC0000374`. (Kernel kills app instantly to save OS).
1015. **Dependency Loader Snap:** App exits before `Main()`. `LdrInitializeThunk` fail. (Static import missing).
1016. **Sentinel/Dongle Check:** App exits silently after reading USB. (Hardware key missing).
1017. **Licensing Timeout:** App waits 30s for Net, then `Exit 0`. (License server unreachable).
1018. **Environment Variable Null:** App reads Env Var, gets nothing, exits. (Logic error).
1019. **Console Hidden:** Command line tool runs/exits too fast to see output. (UI logic).
1020. **Shim Engine Block:** `Shim Engine` terminates process for compat. (Windows compatibility).

---

### **SECTION 50: ASSISTIVE TECH - SCREEN READERS (JAWS/NVDA)**
*Why the screen reader isn't talking or is reading garbage.*

1021. **Focus Theft:** High rate of `SetForegroundWindow` by background app. (Interrupts speech).
1022. **UIA Timeout:** `WM_GETOBJECT` duration > 500ms. (App hanging the screen reader).
1023. **AccName Missing:** `IAccessible::get_accName` returns empty. (Unlabeled button).
1024. **AccRole Mismatch:** Button reports as `ROLE_SYSTEM_GRAPHIC`. (Not clickable).
1025. **Live Region Spam:** High freq `EVENT_OBJECT_LIVEREGIONCHANGED`. (Floods speech buffer).
1026. **Java Bridge 32/64:** `WindowsAccessBridge-32.dll` load fail in 64-bit Java. (Silent Java).
1027. **Java Bridge Missing:** `RegOpenKey` `HKLM\Software\JavaSoft\Accessibility` fail. (Not installed).
1028. **Adobe Reader Tagging:** Read `structTreeRoot` fail. (Untagged PDF).
1029. **Chromium A11y Tree:** `Chrome_RenderWidgetHostHWND` no response. (Browser lag).
1030. **Secure Desktop Block:** Screen Reader `ACCESS_DENIED` on UAC prompt. (Security boundary).
1031. **Audio Ducking Fail:** `IAudioSessionControl` volume change fail. (Background noise loud).
1032. **Mirror Driver Fail:** Load `jfwvid.dll` (JAWS) or `nvda_mirror` fail. (Video hook broken).
1033. **Touch API Fail:** `InjectTouchInput` Access Denied. (Touchscreen reader fail).
1034. **Off-Screen Text:** Reading coordinates `-32000`. (Hidden text read aloud).
1035. **Z-Order Confusion:** UIA Tree navigation inconsistent with visual layout. (Tab order jump).

---

### **SECTION 51: ASSISTIVE TECH - UI AUTOMATION (UIA)**
*The backbone of modern accessibility and RPA bots.*

1036. **Provider Reg Fail:** `RegOpenKey` `HKCR\CLSID\{ProxyStub}` fail. (UIA broken).
1037. **AutomationID Null:** UIA Property `AutomationId` is empty. (Bot cannot find control).
1038. **Pattern Not Supported:** `IUIAutomation::GetPattern` returns null. (Control broken).
1039. **TextPattern Timeout:** `GetText` duration > 1s. (Word processor lag).
1040. **TreeWalker Loop:** Infinite recursion in UIA Tree. (Freeze).
1041. **Element Orphaned:** UIA Element valid but HWND gone. (Crash risk).
1042. **Virtualization Fail:** List has 10k items, UIA loads all. (Memory spike).
1043. **Event Storm:** 1000+ `StructureChanged` events/sec. (Performance kill).
1044. **Proxy Loading:** `UIAutomationCore.dll` loading wrong version. (Compat).
1045. **Privilege Boundary:** Admin App UIA inaccessible to User App. (UIPI).

---

### **SECTION 52: ASSISTIVE TECH - INPUT & MAGNIFICATION**
*ZoomText, Dragon, and On-Screen Keyboards.*

1046. **Magnifier Overlay:** `Magnification.dll` init fail. (Driver conflict).
1047. **Cursor Hook Fail:** `SetWindowsHookEx` (WH_CALLWNDPROC) fail. (Tracking broken).
1048. **Caret Tracking:** `GetGUIThreadInfo` returns (0,0,0,0). (Zoom doesn't follow type).
1049. **Color Filter Fail:** `DwmSetColorizationParameters` fail. (High contrast break).
1050. **Smoothed Text:** `SystemParametersInfo` (SPI_GETFONTSMOOTHING) conflict. (Blurry zoom).
1051. **Dictation Mic Lock:** `AudioEndpoint` exclusive lock. (Dragon can't hear).
1052. **Text Service (TSF):** `ctfmon.exe` deadlock. (Dictation freeze).
1053. **Correction UI:** Popup window off-screen coords. (Invisible menu).
1054. **Vocabulary Write:** Write `user.dic` Access Denied. (Learning fail).
1055. **Eye Tracker HID:** `CreateFile` EyeTracker fail. (Hardware connect).
1056. **Switch Input Lag:** USB Poll rate variance. (Motor aid delay).
1057. **OSK Injection:** `SendInput` fail on Admin window. (Keyboard security).
1058. **Tablet Service:** `TabTip.exe` crash. (Touch keyboard).
1059. **Gesture Conflict:** App consumes 3-finger swipe. (OS nav broken).
1060. **High DPI Blur:** `GetScaleFactorForMonitor` mismatch. (Fuzzy UI).

---

### **SECTION 53: THE "WORKS AS ADMIN" MYSTERIES**
*Why does it work for Helpdesk but not the User?*

1061. **Global Object Creation:** `CreateMutex` "Global\" Access Denied. (Needs SeCreateGlobalPrivilege).
1062. **Service Control:** `OpenSCManager` Access Denied. (Trying to start service).
1063. **Program Files Write:** `CreateFile` "C:\Program Files\..." Access Denied. (Bad coding).
1064. **HKLM Write:** `RegSetValue` HKLM Access Denied. (Bad coding).
1065. **Event Log Write:** `RegisterEventSource` "Security" Access Denied. (Audit write).
1066. **Symlink Create:** `CreateSymbolicLink` Access Denied. (Needs privilege).
1067. **Debug Privilege:** `OpenProcess` System Process Access Denied. (Debug).
1068. **Driver Load:** `NtLoadDriver` Access Denied. (Kernel).
1069. **Raw Socket:** `socket(SOCK_RAW)` Access Denied. (Network tool).
1070. **Volume Access:** `CreateFile` "\\.\C:" Access Denied. (Disk tool).

---

### **SECTION 54: ENVIRONMENT DRIFT & "DLL HELL"**
*The application works on the Gold Image, but not here.*

1071. **Modified PATH:** `LoadImage` fails because `%PATH%` truncated > 2048 chars.
1072. **User vs System Path:** DLL loaded from User Path `C:\Users\...\bin`. (Wrong version).
1073. **Current Work Dir:** `CreateFile` relative path fail. (Shortcut "Start In" wrong).
1074. **GAC Priority:** DLL loaded from `C:\Windows\Assembly` (GAC) instead of App folder.
1075. **KnownDLLs:** Registry `KnownDLLs` forces System32 load. (Ignores local copy).
1076. **Redirected Folders:** App hardcodes `C:\Users`, fails on `\\Server\Share`.
1077. **Regional Date:** App crash parsing "13/01/2026". (MM/DD vs DD/MM).
1078. **Decimal Separator:** App crash parsing "1,000". (Comma vs Dot).
1079. **Codepage Mismatch:** Text garbage/crash `MultiByteToWideChar`. (Locale).
1080. **Font Substitution:** Registry `FontSubstitutes` mapping Wingdings. (UI garbage).

---

### **SECTION 55: COMPLEX NETWORKING (The "It's the Firewall" Red Herrings)**
*Network issues that aren't actually the firewall.*

1081. **MTU Black Hole:** `TCP Retransmit` massive packets. (Packet too big, DF set).
1082. **Ephemeral Exhaustion:** `WSAEADDRINUSE` (10048) on *Outbound*. (Ran out of ports).
1083. **Time_Wait Accumulation:** High count of sockets in TIME_WAIT. (High churn).
1084. **Nagle Algorithm:** High latency small packets. (NoDelay not set).
1085. **Delayed ACK:** 200ms latency patterns. (ACK timer).
1086. **Window Scaling:** Throughput capped at 64KB. (Scale factor 0).
1087. **PAWS Drop:** Timestamp error. (Sequence number wrap).
1088. **ECN Drop:** Packet loss with ECN enabled. (Router compat).
1089. **RSS Imbalance:** One CPU core 100% on network interrupt. (Card setting).
1090. **Chimney Offload:** Corrupt data with Offload enabled. (NIC Driver bug).

---

### **SECTION 56: BROWSER & WEB CONTENT ACCESSIBILITY**
*Specific web-based assistive failures.*

1091. **Aria-Hidden True:** UIA Element exists but `AriaProperties` hidden. (Invisible to Reader).
1092. **IFrame Boundary:** Reader stops at `<iframe>`. (Cross-origin security).
1093. **Shadow DOM:** Reader cannot penetrate `#shadow-root`. (Encapsulation).
1094. **Focus Trap:** Tab key cycles same 3 elements. (JS Logic).
1095. **AccessKey Conflict:** Web `Alt+F` overrides Browser Menu. (Keyboard).
1096. **Canvas Element:** Reader says "Graphic". (No semantic info).
1097. **Flash/ActiveX:** `MacromediaFlash` object. (Inaccessible black box).
1098. **Auto-Refresh:** Page reload resets Reader cursor. (UX).
1099. **Contrast Media:** CSS `@media(forced-colors)` ignored. (Visual).
1100. **Zoom Reflow:** Text overlaps at 200%. (Layout break).

---

### **SECTION 57: VIRTUALIZATION & VDI EDGE CASES**
*When the desktop isn't real.*

1101. **USB Redirection:** `tsusbhub.sys` fail. (Scanner doesn't map).
1102. **SmartCard Redir:** `scard.dll` works, `winscard.dll` fails. (Middleware).
1103. **Audio Redir:** `audiodg` on server vs client. (Lag/Quality).
1104. **Printer Mapping:** `C:\Windows\System32\spool\servers` access. (Driver pull).
1105. **Drive Map Slow:** `\\tsclient\c` latency. (Client drive access).
1106. **Time Zone Redir:** Session TZ != Server TZ. (Meeting time wrong).
1107. **Clipboard Chain:** `rdpclip` stops updating. (Copy/Paste break).
1108. **Display Topology:** App opens on non-existent Monitor 2. (Coordinates).
1109. **DPI Matching:** Session DPI != Client DPI. (Tiny/Huge text).
1110. **Single Sign On:** `ssonsvr.exe` fail. (Cred prompt).

---

### **SECTION 58: SECURITY PRODUCTS FIGHTING EACH OTHER**
*When you have 3 AVs and a DLP.*

1111. **Filter Stack:** `fltmgr` shows 5+ filters. (Latency).
1112. **Hook Collision:** 2 DLLs hooking `User32!BeginPaint`. (Crash).
1113. **Inject War:** App A blocks App B injection. (Code integrity).
1114. **Scan Loop:** AV A scanning AV B's log file. (Disk IO).
1115. **Net Filter:** WFP filter dropping other WFP filter. (Network).
1116. **EDR Memory:** EDR hooking `NtReadVirtualMemory` of AV. (Heuristic flag).
1117. **File Lock:** AV A locking file during AV B update. (Corruption).
1118. **Certificate Intercept:** DLP SSL inspect breaking AV Update. (Trust).
1119. **Registry Monitor:** Two apps reverting each other's Reg changes. (Loop).
1120. **Overlay War:** Two apps trying to draw on top. (Flicker).

---

### **SECTION 59: PRINTING NIGHTMARES (Advanced)**
1121. **V4 Driver Isolation:** `PrintIsolationHost` AppContainer block. (Perms).
1122. **Point & Print Policy:** `PackagePointAndPrint` restriction. (GPO).
1123. **Render Filter:** `mxdwdrv.dll` crash. (XPS convert).
1124. **Color Profile:** `mscms.dll` access denied. (Bad colors).
1125. **Form Mismatch:** Driver rejects "Letter" for "A4". (Tray selection).
1126. **Spooler RPC:** `RpcEpMap` fail. (Service dead).
1127. **CSR (Client Side Render):** `winspool.drv` heavy CPU. (Rendering).
1128. **Job Stuck:** `.spl` file locked by AV. (Queue jam).
1129. **Port Monitor:** `monitordll` load fail. (Comm error).
1130. **DevMode Corrupt:** Registry `DevMode` binary junk. (Settings reset).

---

### **SECTION 60: THE "HUMAN FACTOR" (User Behavior Detections)**
*Detecting what the user actually did vs what they said they did.*

1131. **Idle Timeout:** No Input Events > 60 mins. (User away).
1132. **Force Shutdown:** Power Button press (Power Event). (Hard reset).
1133. **Cable Pull:** Network Media Disconnect. (Unplugged).
1134. **USB Eject:** `DeviceRemoval` event. (Thumb drive pull).
1135. **Resolution Change:** `DisplaySettings` event. (User mess with screen).
1136. **Theme Change:** `Theme` event. (User High Contrast toggle).
1137. **Volume Mute:** `Volume` event. (User muted app).
1138. **Date Change:** `SetSystemTime` event. (User changed clock).
1139. **File Move:** `Explorer` drag/drop. (User moved folder).
1140. **Install:** `msiexec` /i. (User installed software).



Here is the continuation of the Master List, focusing specifically on **"The 1% Scenarios"**—the issues that affect only one user, defy logic, and often result in a complete reimaging of the machine because they are so hard to find.

These are the "White Whales" of IT support.

---

### **SECTION 61: THE "GHOST IN THE SHELL" (Explorer & UI Rot)**
*When the desktop interface behaves erratically for just one user.*

1141. **Shellbag Corruption:**
    *   **Manifests:** Explorer crashes only when opening a specific folder (e.g., "Downloads").
    *   **Logic:** `Explorer.exe` reads `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags`. Immediately follows with `Process Exit`.
    *   **Cause:** The saved "View State" (Icon position/size) for that specific folder GUID is malformed.
1142. **Context Menu Handler Hang:**
    *   **Manifests:** Right-clicking a file takes 30 seconds to show the menu.
    *   **Logic:** `Explorer.exe` queries `HKCR\*\shellex\ContextMenuHandlers`. ProcMon shows a long gap (Duration > 5s) loading a specific 3rd party DLL (e.g., `DropboxExt.dll` or `Old_Zip_Tool.dll`).
    *   **Cause:** A shell extension is trying to reach a network resource or is buggy, blocking the UI thread.
1143. **Icon Overlay Exhaustion:**
    *   **Manifests:** Dropbox/OneDrive green checkmarks disappear, or icons turn black.
    *   **Logic:** `Explorer.exe` reads `HKLM\...\Explorer\ShellIconOverlayIdentifiers`. The list has > 15 entries.
    *   **Cause:** Windows has a hard limit of 15 overlay handlers. Apps fight for the top spots by adding spaces to their names (`   OneDrive`).
1144. **Quick Access Dead Link:**
    *   **Manifests:** Explorer freezes for 20s immediately upon opening.
    *   **Logic:** `Explorer.exe` attempts `CreateFile` on `\\OldServer\Share` which no longer exists.
    *   **Cause:** The "Quick Access" (Recent Files) pinned a file from a decommissioned server. Explorer tries to resolve the icon/metadata on launch.
1145. **Thumbnail Cache Lock:**
    *   **Manifests:** User cannot delete a folder; "File in use".
    *   **Logic:** `Explorer.exe` (or `DllHost.exe`) holds a handle to `thumbcache_*.db` or the file itself.
    *   **Cause:** Windows is stuck trying to generate a thumbnail for a corrupt video/image file in that folder.
1146. **Notification Area (Tray) Corruption:**
    *   **Manifests:** System Tray icons are missing or blank spaces appear.
    *   **Logic:** `Explorer.exe` fails to read/write `HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify`.
    *   **Cause:** The `IconStreams` binary blob registry value is corrupt.
1147. **Open With... Reset:**
    *   **Manifests:** Windows keeps asking "How do you want to open this?" for PDFs.
    *   **Logic:** `Explorer.exe` writes to `HKCU\...\Explorer\FileExts\.pdf\UserChoice`. Immediately followed by a Hash failure event.
    *   **Cause:** Windows 10/11 detects "tampering" with file associations (hash mismatch) and resets them to Edge.
1148. **Invisible Window Focus:**
    *   **Manifests:** User types, but nothing happens. Clicking the app works.
    *   **Logic:** `GetForegroundWindow` returns a `HWND` belonging to a process with no visible UI (e.g., a background updater).
    *   **Cause:** A background app stole focus but didn't bring a window to the front.
1149. **Drag and Drop Freeze:**
    *   **Manifests:** Dragging a file causes the mouse to stick to the file icon; Esc doesn't work.
    *   **Logic:** `DoDragDrop` API call never returns.
    *   **Cause:** The Drop Target (the app you are dragging *over*) is hung/busy and hasn't replied to the OLE Drag loop.
1150. **Taskbar Unclickable:**
    *   **Manifests:** Start Menu works, but Taskbar icons are dead.
    *   **Logic:** `Explorer.exe` thread associated with the Taskbar is hung on `Shell_TrayWnd`.
    *   **Cause:** A "DeskBand" (Toolbar widget) crashed the taskbar thread specifically.

---

### **SECTION 62: THE "NETWORK POLTERGEISTS" (Stack & Caching)**
*Issues that persist even after "rebooting the router".*

1151. **ARP Cache Poisoning (Local):**
    *   **Manifests:** User cannot reach the Gateway, but neighbors can.
    *   **Logic:** `UDP Send` to IP succeeds, but no response. `arp -a` shows Gateway IP with a MAC address that matches another PC on the LAN.
    *   **Cause:** Another device (or malware) has claimed the Gateway IP (IP Conflict/Spoofing).
1152. **Persistent Route Injection:**
    *   **Manifests:** User cannot reach Corporate Intranet, traffic goes to Internet.
    *   **Logic:** `TCP Connect` to 10.x.x.x goes to Default Gateway (Internet) instead of VPN Interface.
    *   **Cause:** A "Persistent Route" (`route print -p`) was added years ago and persists across reboots/VPN installs.
1153. **Winsock Namespace Provider (NSP) Rot:**
    *   **Manifests:** Browsers work, but `ping` and `nslookup` fail (or vice versa).
    *   **Logic:** `WSALookupServiceBegin` fails. `svchost` loads a 3rd party DLL in `Winsock2\Parameters\NameSpace_Catalog5`.
    *   **Cause:** An old VPN client or Malware left a broken Namespace Provider in the Winsock catalog.
1154. **Source Port Exhaustion (The "1 user" version):**
    *   **Manifests:** Apps work for 5 minutes, then all network fails until reboot.
    *   **Logic:** `bind()` calls fail with `WSAEADDRINUSE`.
    *   **Cause:** Malware or a buggy script is opening 60,000 connections to `localhost` and leaving them in `TIME_WAIT`.
    *   **Fix:** `netstat -ano` to see who ate the ports.
1155. **Ghost Network Adapter:**
    *   **Manifests:** "IP Address Configured" error when setting static IP, but the IP isn't visible.
    *   **Logic:** Registry read `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` finds a GUID for a NIC that is physically removed (Hidden Device).
    *   **Cause:** Old NIC still holds the IP config in registry.
1156. **LMHOSTS Lookup Enabled:**
    *   **Manifests:** User resolves "Server1" to an IP address that hasn't existed for 5 years.
    *   **Logic:** `CreateFile` `C:\Windows\System32\drivers\etc\lmhosts` Success.
    *   **Cause:** The user has an ancient `lmhosts` file enabled that overrides DNS.
1157. **Teredo Tunneling Loop:**
    *   **Manifests:** High CPU in `svchost (iphlpsvc)`. Network sluggish.
    *   **Logic:** Excessive UDP traffic on IPv6 transition ports.
    *   **Cause:** Teredo trying to establish a tunnel through a firewall that blocks it, retrying infinitely.
1158. **ICS (Internet Connection Sharing) Conflict:**
    *   **Manifests:** User plugs in a phone to charge; Corporate LAN drops.
    *   **Logic:** `SharedAccess` service starts. DHCP server logic binds to the LAN adapter.
    *   **Cause:** PC starts acting as a Router/DHCP server because ICS was triggered, causing IP conflicts.
1159. **VPN Split Tunnel DNS Leak:**
    *   **Manifests:** User can access Internal Site A but not Internal Site B.
    *   **Logic:** DNS Query for Site B goes to `8.8.8.8` (Interface Metric Lower) instead of VPN DNS.
    *   **Cause:** Windows Interface Metric prioritizes the physical adapter over the VPN adapter for specific domains.
1160. **Browser Proxy "Automatically Detect" Flap:**
    *   **Manifests:** Internet cuts out for 10 seconds every minute.
    *   **Logic:** `WPAD` lookup fails -> Browser switches to Direct -> Works. WPAD lookup retries -> Fails -> Loop.
    *   **Cause:** "Automatically Detect Settings" is checked, but no WPAD server exists, causing a timeout loop.

---

### **SECTION 63: THE "IDENTITY CRISIS" (Credentials & Auth)**
*Why the user can't log in, or keeps getting locked out.*

1161. **Credential Manager "Zombie" Cred:**
    *   **Manifests:** Outlook prompts for password daily, even after saving.
    *   **Logic:** `lsass.exe` reads `AppData\Roaming\Microsoft\Protect`. `VaultCmd` fails to write new credential.
    *   **Cause:** The Credential Vault file on disk is corrupt or has hit a size limit (thousands of old entries).
1162. **Cached Logon Count Exceeded:**
    *   **Manifests:** Laptop user cannot login when away from office.
    *   **Logic:** `WinLogon` check `CachedLogonsCount`.
    *   **Cause:** Machine has not talked to DC in X days, and the cached credential has expired or rolled over.
1163. **Kerberos Encryption Type Mismatch:**
    *   **Manifests:** User access denied to File Share, but can access Web Apps.
    *   **Logic:** Kerberos Ticket Request (`TGS-REQ`) specifies `RC4-HMAC`. Server rejects (requires `AES256`).
    *   **Cause:** User account in AD is flagged "Use DES encryption types" or legacy GPO disabling AES on client.
    *   **Fix:** Check `msDS-SupportedEncryptionTypes`.
1164. **Workstation Trust Broken (Silent):**
    *   **Manifests:** "The trust relationship between this workstation and the primary domain failed."
    *   **Logic:** `NetLogon` fails `NetrServerAuthenticate3`.
    *   **Cause:** Computer password changed on DC, but machine didn't get the memo (Restore from snapshot / Time jump).
1165. **Phantom Drive Mapping Auth:**
    *   **Manifests:** Account locks out every morning at 9:00 AM.
    *   **Logic:** `System` process attempts SMB Auth to `\\OldServer\Share` with old password.
    *   **Cause:** A persistent drive map (or Service, or Scheduled Task) running as the user has stored old credentials.
1166. **DPAPI Master Key Corruption:**
    *   **Manifests:** Chrome forgets all passwords; Wi-Fi forgets keys.
    *   **Logic:** `lsass.exe` fails `CryptUnprotectData` with `NTE_BAD_KEY`.
    *   **Cause:** The user changed their password, but the DPAPI Master Key (protected by the old password) wasn't re-wrapped.
1167. **Session 0 Isolation Auth:**
    *   **Manifests:** Service fails to access network share.
    *   **Logic:** Service running as `LocalSystem` tries to access `\\Server\Share`.
    *   **Cause:** `LocalSystem` uses the *Computer Account* (`Domain\PC$`) for auth, not the User. Share ACL needs to include the Computer Object.
1168. **NGC (Windows Hello) Container Rot:**
    *   **Manifests:** User cannot use PIN or Fingerprint. "Something went wrong".
    *   **Logic:** Access `C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc`. Access Denied or Corrupt.
    *   **Cause:** The Windows Hello database is corrupt. Requires folder deletion to reset.
1169. **AAD Broker Token Loop:**
    *   **Manifests:** Office 365 "Need Password" -> Click -> Disappears -> "Need Password".
    *   **Logic:** `Microsoft.AAD.BrokerPlugin.exe` crash or loop.
    *   **Cause:** TPM (Trusted Platform Module) failure or WAM (Web Account Manager) plugin broken.
1170. **User Rights Assignment (Logon as Batch):**
    *   **Manifests:** Scheduled Task as User fails to start.
    *   **Logic:** Task Scheduler logs "Logon failure: the user has not been granted the requested logon type".
    *   **Cause:** GPO removed "Logon as a Batch Job" right for that user.

---

### **SECTION 64: THE "PHANTOM HARDWARE" (PnP & Peripherals)**
*When the hardware isn't there, but Windows thinks it is.*

1171. **Ghost Monitor (EDID Cache):**
    *   **Manifests:** Application opens off-screen; Windows thinks a 2nd monitor is attached.
    *   **Logic:** Registry `HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY` contains active entry for disconnected screen.
    *   **Cause:** Windows cached the EDID of a projector/monitor and refuses to forget it.
1172. **USB Serial Number Collision:**
    *   **Manifests:** User plugs in two identical USB drives; only one works.
    *   **Logic:** `PnP` logs "Device not started" due to collision.
    *   **Cause:** Cheap USB drives often share the exact same Serial Number. Windows cannot distinguish them.
1173. **Print Queue "Deleting" State:**
    *   **Manifests:** Printer refuses to print. Queue shows job as "Deleting" forever.
    *   **Logic:** `spoolsv.exe` cannot delete the `.spl` file because `FilterPipelinePrintProc.dll` has it locked.
    *   **Cause:** The Driver's rendering filter crashed while processing the job, locking the file handle.
1174. **Audio Endpoint Builder Zombie:**
    *   **Manifests:** "No Audio Output Device is installed" (red X).
    *   **Logic:** `Audiosrv` running, but `AudioEndpointBuilder` stuck. Registry `HKLM\Software\Microsoft\Windows\CurrentVersion\MMDevices\Audio\Render` contains corrupt keys.
    *   **Cause:** Registry corruption in the audio device enumeration tree.
1175. **TWAIN Driver Lock:**
    *   **Manifests:** Scanner app freezes on launch.
    *   **Logic:** `twain_32.dll` loads, then attempts to communicate with a driver that isn't responding.
    *   **Cause:** A TWAIN source selection dialog is hidden behind the main window, waiting for input.
1176. **Bluetooth Handle Leak:**
    *   **Manifests:** Bluetooth mouse stops working after 2 days uptime.
    *   **Logic:** Kernel memory (Non-paged pool) usage by `bthport.sys` grows indefinitely.
    *   **Cause:** Driver bug leaking handles every time the device enters sleep mode.
1177. **Laptop Lid Switch Sensor:**
    *   **Manifests:** Laptop goes to sleep randomly while typing.
    *   **Logic:** System Log "The system is entering sleep. Reason: Button or Lid".
    *   **Cause:** User is wearing a magnetic bracelet/watch band that triggers the "Lid Closed" Hall Effect sensor in the palm rest. (Classic "Defies Logic").
1178. **Touchpad Palm Rejection:**
    *   **Manifests:** Cursor jumps randomly while typing.
    *   **Logic:** Input driver registers touch events.
    *   **Cause:** Palm Rejection setting disabled or driver update reset sensitivity.
1179. **Docking Station Ethernet Flap:**
    *   **Manifests:** Network drops for 1 second every time user bumps desk.
    *   **Logic:** `NDIS` Media Disconnect event.
    *   **Cause:** Physical loose connection in the USB-C dock connector (Mechanical failure disguised as software).
1180. **GPU "Fake" Monitor (Headless Dongle):**
    *   **Manifests:** Remote Desktop is fast, local screen is black.
    *   **Logic:** GPU driver prioritizing the "Headless" EDID dongle plugged in for mining/rendering.
    *   **Cause:** User forgot a dummy plug in the HDMI port.

---

### **SECTION 65: THE "COPY/PASTE" ABYSS**
*Why Ctrl+C / Ctrl+V fails.*

1181. **Clipboard Chain Broken:**
    *   **Manifests:** Copy works, but Paste is greyed out.
    *   **Logic:** `GetClipboardData` returns NULL. `GetOpenClipboardWindow` identifies the culprit.
    *   **Cause:** A poorly coded RDP tool or Clipboard Manager opened the clipboard but crashed/forgot to close it, locking it globally.
1182. **Format Not Available:**
    *   **Manifests:** Can copy text from Notepad, but not from Excel.
    *   **Logic:** `EnumClipboardFormats` shows only `CF_TEXT`, missing `CF_HTML` / `CF_BITMAP`.
    *   **Cause:** Security software filtering complex clipboard formats to prevent data exfiltration.
1183. **Drag-Drop Handler Hang:**
    *   **Manifests:** Dragging a file to Outlook freezes Outlook.
    *   **Logic:** Outlook calls `IDropTarget::DragEnter`, which calls into a 3rd party Shell Extension (e.g., Adobe) that hangs.
    *   **Cause:** Incompatible shell extension loaded into Outlook's process space.
1184. **RDP Clipboard Sync Loop:**
    *   **Manifests:** `rdpclip.exe` High CPU.
    *   **Logic:** Constant reads/writes to Clipboard API.
    *   **Cause:** Copying a large file (1GB) via RDP clipboard (Copy/Paste file) on a slow link.
1185. **Excel "The picture is too large":**
    *   **Manifests:** Error copying cells.
    *   **Logic:** Memory spike in `Excel.exe` during copy.
    *   **Cause:** The cells contain thousands of invisible, tiny vector objects (metadata from a web copy-paste).

---

### **SECTION 66: THE "FILE SYSTEM TWILIGHT ZONE"**
*NTFS features that normal users shouldn't encounter, but do.*

1186. **Sparse File "Disk Full":**
    *   **Manifests:** File is 1GB size, 0 bytes on disk. Copying it to FAT32 fails "Disk Full".
    *   **Logic:** `fsutil sparse` flag set.
    *   **Cause:** The file is a "Sparse File". Copying it explodes it to its full real size, which exceeds destination capacity.
1187. **Directory Junction Recursion:**
    *   **Manifests:** Backup software runs forever / Anti-Virus hangs.
    *   **Logic:** Scanning `C:\Users\Appdata\Local\Application Data\Application Data...`.
    *   **Cause:** Legacy Junction Point permissions are wrong, allowing recursive entry (Infinite Loop).
1188. **File ID Reuse (The "Wrong File" Bug):**
    *   **Manifests:** Opening "Report.pdf" opens "Photo.jpg".
    *   **Logic:** Application caches file by `FileID` (Inode), not Path. OS reused the ID of a deleted file.
    *   **Cause:** Rare logic bug in indexing/caching software (e.g., old Outlook search).
1189. **USN Journal Wrap (Backup Fail):**
    *   **Manifests:** "Incremental Backup" triggers "Full Backup".
    *   **Logic:** Backup app logs "Change Journal Wrap".
    *   **Cause:** Too many file changes happened between backups (e.g., a script creating/deleting 1 million files), overflowing the journal history.
1190. **Offline Attribute (Sticky):**
    *   **Manifests:** File shows with a grey "X". Cannot open.
    *   **Logic:** `GetFileAttributes` returns `FILE_ATTRIBUTE_OFFLINE`.
    *   **Cause:** File was tiered to cloud (HSM), but the agent software was uninstalled. Windows still thinks the file is on tape/cloud.

---

### **SECTION 67: THE "TIME AND SPACE" GREMLINS**
*Localization and Clock issues.*

1191. **Excel "Date is text":**
    *   **Manifests:** Formulas break on one PC.
    *   **Logic:** Registry `sShortDate` format is `dd-MM-yy` vs `MM/dd/yy`.
    *   **Cause:** User customized Region settings in Control Panel, breaking assumptions in shared macros.
1192. **Time Skew (Small):**
    *   **Manifests:** weird auth errors, MFA codes "Invalid".
    *   **Logic:** System time is 3 minutes fast. (Kerberos allows 5m, but TOTP requires <30s).
    *   **Cause:** CMOS battery dying, or VM host time drift.
1193. **Leap Second Crash:**
    *   **Manifests:** Linux servers crash, Windows apps calculating high-precision intervals hang.
    *   **Logic:** `GetSystemTimeAsFileTime` returns duplicate or backward values.
    *   **Cause:** Poorly handled leap second insertion in NTP upstream.
1194. **Decimal vs Comma:**
    *   **Manifests:** CSV imports fail. 1.000 becomes 1000.
    *   **Logic:** `GetLocaleInfo` `LOCALE_SDECIMAL`.
    *   **Cause:** User set locale to German (Comma) but is processing US CSVs (Dot).

---

### **SECTION 68: "IT ONLY HAPPENS ON TUESDAYS"**
*Scheduled Tasks and Triggers.*

1195. **Defrag Storm:**
    *   **Manifests:** PC slow every Wednesday at 2am.
    *   **Logic:** `defrag.exe` / `svchost (sysmain)` high IO.
    *   **Cause:** Scheduled maintenance task.
1196. **Certificate Auto-Enrollment:**
    *   **Manifests:** Smart Card prompt pops up randomly.
    *   **Logic:** `certutil` / `taskhostw` running enrollment task.
    *   **Cause:** GPO forcing user to renew cert, but card not inserted.
1197. **Group Policy Refresh (Background):**
    *   **Manifests:** Active window loses focus every 90 minutes.
    *   **Logic:** `gpupdate` / `winlogon` notification.
    *   **Cause:** A badly configured GPO (e.g., Drive Maps "Replace" mode) causes a UI refresh on every background interval.
1198. **WSUS Reboot:**
    *   **Manifests:** PC reboots overnight even with "No Auto Restart".
    *   **Logic:** Event Log "The process wininit.exe has initiated a restart".
    *   **Cause:** Deadline reached in WSUS policy.
1199. **Inventory Scan (SCCM):**
    *   **Manifests:** Fans spin up for 10 mins.
    *   **Logic:** `CcmExec.exe` high CPU.
    *   **Cause:** Software Inventory Cycle scanning every .exe on the C: drive.
1200. **Browser Update Task:**
    *   **Manifests:** Chrome closes and reopens.
    *   **Logic:** `GoogleUpdate.exe` task.
    *   **Cause:** Scheduled task set to force update restart.

---

### **SECTION 69: THE "MEDIA & PRESENTATION" NIGHTMARE**
*Projectors, Audio, and HDMI.*

1201. **HDCP Handshake Fail:**
    *   **Manifests:** Projector shows "No Signal" or snow, but laptop sees it.
    *   **Logic:** Graphics driver logs HDCP Link Failure.
    *   **Cause:** Content (Netflix/Teams) requires encryption, projector is old/incompatible.
1202. **Audio Switching Lag:**
    *   **Manifests:** Teams call audio stays on laptop after plugging in headset.
    *   **Logic:** `Audiosrv` notification processing.
    *   **Cause:** Hardware ID change event took too long to propagate to Teams.
1203. **PowerPoint Presentation Mode:**
    *   **Manifests:** External screen black.
    *   **Logic:** PowerPoint creates a generic "Black" window on Monitor 2.
    *   **Cause:** "Presenter View" is enabled but misconfigured or blocked by overlay software.
1204. **USB Bandwidth Exceeded:**
    *   **Manifests:** 4K Webcam freezes when using USB Mic.
    *   **Logic:** USB Controller "Not enough bandwidth" (rarely shown to user).
    *   **Cause:** Both devices on same USB Root Hub / Bus controller limit.
1205. **Display Scaling (Blurry App):**
    *   **Manifests:** App looks fuzzy on Monitor 2.
    *   **Logic:** `GetDpiForMonitor` mismatch.
    *   **Cause:** Monitor 1 is 150%, Monitor 2 is 100%. App is not "Per-Monitor DPI Aware".

---

### **SECTION 70: THE "FINAL 1%" (Logic Defying)**
1206. **Bit Flip (Cosmic Ray/Bad RAM):**
    *   **Manifests:** Chrome crashes on the same website, hash verification fail.
    *   **Logic:** Memory diagnostic fail.
    *   **Cause:** Physical RAM stick bad bit.
1207. **The "Magnet" User:**
    *   **Manifests:** Laptop sleeps when user stacks it on top of another laptop.
    *   **Cause:** Magnet in bottom laptop triggers lid sensor of top laptop.
1208. **The "Spacebar" Heater:**
    *   **Manifests:** PC wakes up immediately after sleep.
    *   **Cause:** Keyboard is faulty/dirty, sending "Space" key signal intermittently.
1209. **The "Printer" Voltage:**
    *   **Manifests:** USB connection drops when printer turns on.
    *   **Cause:** Ground loop/Electrical noise from printer spikes the USB bus, resetting the controller.
1210. **The "One-Way" Audio:**
    *   **Manifests:** Can hear them, they can't hear me.
    *   **Logic:** UDP RTP packets flowing out but dropped at firewall.
    *   **Cause:** SIP ALG (Application Layer Gateway) on the local ISP router is corrupting the packet headers.


    Here is the continuation of the **Master Definition List**, pushing deeper into **Enterprise Infrastructure, Cloud Sync, and Advanced Kernel/Hardware interactions**.

These scenarios (1211–1300) focus on the complex layers of **Clustering, Hyper-V, Intune, and SQL**—systems where "It just stopped working" usually implies a deep underlying conflict.

---

### **SECTION 71: FAILOVER CLUSTERING (The "High Availability" paradox)**
*When the system designed to never fail... fails.*

1211. **Quorum Arbitration Loss:**
    *   **Manifests:** Cluster node randomly reboots (Fencing).
    *   **Logic:** `clussvc.exe` receives `STATUS_IO_TIMEOUT` or `STATUS_DEVICE_BUSY` on the Quorum/Witness Disk.
    *   **Cause:** SAN latency exceeded the cluster heartbeat threshold (default 5s/10s), causing the node to panic to prevent corruption.
1212. **CSV (Cluster Shared Volume) Redirected Mode:**
    *   **Manifests:** Disk I/O performance drops by 90%.
    *   **Logic:** High volume of `FileReads` to `C:\ClusterStorage\...` via `System` process (SMB Loopback) instead of Direct IO.
    *   **Cause:** Metadata node connectivity is lost or a backup snapshot locked the volume, forcing traffic through the network coordinator (Redirected Access).
1213. **Cluster Database (CLUSDB) Hive Lock:**
    *   **Manifests:** Cluster Service fails to start.
    *   **Logic:** `clussvc.exe` gets `SHARING_VIOLATION` on `HKLM\Cluster`.
    *   **Cause:** Anti-Virus or Backup software is scanning the registry hive file `C:\Windows\Cluster\CLUSDB`.
1214. **NetFT Adapter Saturation:**
    *   **Manifests:** Heartbeats missed, node removed.
    *   **Logic:** `NetFT.sys` packet drop events. UDP 3343 Send Failures.
    *   **Cause:** "Private" cluster network is being flooded by Live Migration traffic (misconfigured network priority).
1215. **Resource DLL Deadlock:**
    *   **Manifests:** A specific role (e.g., File Server) stays "Pending" forever.
    *   **Logic:** `rhs.exe` (Resource Hosting Subsystem) thread stack static/waiting.
    *   **Cause:** The custom resource DLL for that role is buggy and hung on a lock.
1216. **Witness Share Access Denied:**
    *   **Manifests:** File Share Witness goes offline.
    *   **Logic:** `clussvc.exe` gets `ACCESS_DENIED` on `\\WitnessServer\Share`.
    *   **Cause:** The *Computer Account* (`ClusterName$`) permissions were removed from the share (User accounts don't matter here).

---

### **SECTION 72: HYPER-V & VIRTUALIZATION HOSTING**
*Troubleshooting the Host OS.*

1217. **VMMS Certificate Expiry:**
    *   **Manifests:** Live Migration fails; VM Connect fails.
    *   **Logic:** `vmms.exe` fails crypto check. System Log ID `24` (Hyper-V-VMMS).
    *   **Cause:** The self-signed certificate used for VM Service communication expired.
1218. **VHDX Merge Lock (The "Backlog"):**
    *   **Manifests:** VM disk space fills up; "Checkpoints" show empty, but `.avhdx` files exist.
    *   **Logic:** `vmms.exe` access denied deleting/merging `.avhdx`.
    *   **Cause:** Backup software (Veeam/Commvault) still holds a lock on the delta disk.
1219. **Virtual Switch Extension Conflict:**
    *   **Manifests:** VMs lose network connectivity intermittently.
    *   **Logic:** `vmswitch.sys` stack trace interacts with 3rd party NDIS filter (e.g., `Wireshark` or `DLP`).
    *   **Cause:** Incompatible network filter driver inserted into the Virtual Switch stack.
1220. **NUMA Spanning Performance Kill:**
    *   **Manifests:** VM CPU usage high, Host CPU low.
    *   **Logic:** Hyper-V logs "VM configuration does not support NUMA spanning".
    *   **Cause:** VM is allocated RAM/CPU larger than a single physical NUMA node, forcing expensive remote memory access.
1221. **Pass-Through Disk Offline:**
    *   **Manifests:** VM fails to start "General Access Denied error".
    *   **Logic:** Host OS claims the disk. `CreateFile` on `\\.\PhysicalDriveX` fails.
    *   **Cause:** The Host OS marked the LUN as "Online" (automount), stealing it from the VM.
1222. **Worker Process (VMWP) Crash:**
    *   **Manifests:** VM turns off instantly.
    *   **Logic:** `vmwp.exe` Process Exit code `0xC0000005`.
    *   **Cause:** Host-side crash of the worker process (often due to video driver or state corruption).

---

### **SECTION 73: MODERN MANAGEMENT (INTUNE / MDM)**
*The "Silent" management channel.*

1223. **IME (Intune Mgmt Ext) Hash Fail:**
    *   **Manifests:** App shows "Fail" in Company Portal.
    *   **Logic:** `IntuneManagementExtension.log` write "Hash mismatch".
    *   **Cause:** The content downloaded does not match the hash generated during package upload (Proxy corruption or upload error).
1224. **Sidecar / PowerShell Timeout:**
    *   **Manifests:** Script fails.
    *   **Logic:** `AgentExecutor.exe` runs for exactly 600 seconds then Terminated.
    *   **Cause:** Hardcoded 10-minute timeout for Intune PowerShell scripts.
1225. **OMA-DM Sync Failure:**
    *   **Manifests:** Policies not applying.
    *   **Logic:** `Omadmclient.exe` exits with code `0x80072ee2` (Timeout).
    *   **Cause:** Firewall blocking HTTPS to specific Microsoft MDM endpoints.
1226. **Win32 App Detection Logic Fail:**
    *   **Manifests:** App installs, then says "Failed" immediately.
    *   **Logic:** `IntuneManagementExtension.log` "Application detected: False".
    *   **Cause:** The detection rule (Registry/File) does not match what the installer actually created (e.g., Version number mismatch).
1227. **Autopilot Profile Not Found:**
    *   **Manifests:** OOBE shows standard consumer setup, not Corporate.
    *   **Logic:** `MSA` Ticket request fails.
    *   **Cause:** Hardware Hash not uploaded, or device record assigned to wrong group.
1228. **BitLocker Compliance Error (65000):**
    *   **Manifests:** Device "Non-Compliant".
    *   **Logic:** `NodeCache` values for Encryption indicate "Not Encrypted" despite drive being encrypted.
    *   **Cause:** DMA DMA Protection settings in BIOS conflict with BitLocker policy, preventing "Secure Boot" validation.

---

### **SECTION 74: SQL SERVER INTERNALS (OS Perspective)**
*When the Database blames the OS.*

1229. **SQL OS Scheduler Yielding:**
    *   **Manifests:** SQL CPU high, but queries slow.
    *   **Logic:** `sqlservr.exe` threads switching contexts rapidly (Context Switch storm).
    *   **Cause:** "SOS_SCHEDULER_YIELD" - Internal SQL cooperative multitasking is fighting for CPU time.
1230. **Backup I/O Freeze:**
    *   **Manifests:** App times out every night at 11pm.
    *   **Logic:** `sqlservr.exe` writes to `ErrorLog`: "I/O is frozen on database X".
    *   **Cause:** VSS Snapshot initiation pauses I/O (briefly), but storage latency makes it > 10s.
1231. **Instant File Initialization Fail:**
    *   **Manifests:** Creating a database takes 20 minutes.
    *   **Logic:** `sqlservr.exe` writing zeros to `.mdf` file.
    *   **Cause:** Service Account lacks "Perform Volume Maintenance Tasks" privilege (cannot skip zeroing).
1232. **SQL Memory Paging:**
    *   **Manifests:** Performance tanks.
    *   **Logic:** `sqlservr.exe` Working Set drops significantly; Hard Faults spike.
    *   **Cause:** OS is under pressure and trimming SQL RAM (which shouldn't happen if "Lock Pages in Memory" is set).
1233. **TempDB Contention:**
    *   **Manifests:** General slowness.
    *   **Logic:** Heavy contention/locking on `tempdb.mdf`.
    *   **Cause:** Application using heavy temp tables; insufficient TempDB data files (should allow 1 per core).

---

### **SECTION 75: IIS & WEB INTERNALS (Advanced)**
1234. **Application Initialization Warmup Fail:**
    *   **Manifests:** First user after deploy gets 503/Error.
    *   **Logic:** `w3wp.exe` (Warmup) starts, hits URL, fails, stops.
    *   **Cause:** The "Warmup" module is configured to hit a URL that requires Auth, but the warmer is anonymous.
1235. **Rapid Fail Protection (Loop):**
    *   **Manifests:** AppPool stops.
    *   **Logic:** `w3wp.exe` start/exit 5x in 5 minutes. Event ID `5002`.
    *   **Cause:** Crash on startup (e.g., Bad `web.config` section, missing DLL).
1236. **HTTP.sys Cert Binding Conflict:**
    *   **Manifests:** Service won't start (Port 443).
    *   **Logic:** `http.sys` fails to bind. `netsh http show sslcert` shows invalid hash.
    *   **Cause:** Ghost certificate binding left over from a previous install blocking the port.
1237. **Compression Directory Lock:**
    *   **Manifests:** Static content fails to load.
    *   **Logic:** `w3wp.exe` Access Denied on `%SystemDrive%\inetpub\temp\IIS Temporary Compressed Files`.
    *   **Cause:** Permissions broken on the compression cache folder.
1238. **WebSocket Upgrade Fail:**
    *   **Manifests:** Real-time chat fails.
    *   **Logic:** Request enters as HTTP/1.1, never upgrades.
    *   **Cause:** "WebSocket Protocol" feature not installed in Windows Features.

---

### **SECTION 76: "IT'S DNS" (Advanced Edition)**
*Because it's always DNS.*

1239. **DNS Suffix Search List Exhaustion:**
    *   **Manifests:** Slow app startup (20s).
    *   **Logic:** `UDP Send` to `app.dept.corp.local`, `app.corp.local`, `app.local`... all `NAME_NOT_FOUND`. Finally `app.com` works.
    *   **Cause:** Application uses a short name (`server`) and the client has 50 suffixes to check before hitting the right one.
1240. **EDNS0 Fragmentation Drop:**
    *   **Manifests:** Some sites resolve, others don't (Large TXT/DNSSEC).
    *   **Logic:** DNS Query sent (Size > 512 bytes), No Reply.
    *   **Cause:** Firewall blocks UDP packets > 512 bytes (Legacy DNS limit), dropping EDNS0 extensions.
1241. **Negative Cache "Sticky" Fail:**
    *   **Manifests:** DNS record fixed on server, client still fails.
    *   **Logic:** `NAME_NOT_FOUND` returns instantly (microseconds). Network trace shows no packet sent.
    *   **Cause:** Windows "Negative Cache" (Cache of failures) holding the bad result. `ipconfig /flushdns` required.
1242. **LLMNR/NetBIOS Broadcast Storm:**
    *   **Manifests:** Network sluggish.
    *   **Logic:** Thousands of UDP 137/5355 broadcasts for `wpad` or `isatap`.
    *   **Cause:** DNS server unreachable, clients failing over to noisy multicast protocols.
1243. **Hosts File BOM (Byte Order Mark):**
    *   **Manifests:** Hosts file ignored.
    *   **Logic:** `CreateFile` hosts success, but resolution fails.
    *   **Cause:** User saved `hosts` file with UTF-8 BOM or Unicode encoding. Windows networking stack expects ANSI/ASCII.

---

### **SECTION 77: THE "DLL HELL" 2.0 (Modern Dependencies)**
1244. **ApiSetSchema Mapping Fail:**
    *   **Manifests:** App fails to load `api-ms-win-crt-runtime-l1-1-0.dll`.
    *   **Logic:** `LoadImage` fail.
    *   **Cause:** Missing "Universal C Runtime" (KB2999226) on older Windows 7/8/Server machines.
1245. **Manifest Activation (SxS) Parse Error:**
    *   **Manifests:** "The application has failed to start because its side-by-side configuration is incorrect."
    *   **Logic:** `csrss.exe` fails to parse XML in manifest. Event ID `33` or `59`.
    *   **Cause:** Typo in the application's embedded XML manifest or `application.exe.config`.
1246. **Extension DLL Block (Office):**
    *   **Manifests:** Excel crash on open.
    *   **Logic:** `Excel.exe` loads `ContosoAddin.dll`. `Process Exit` follows.
    *   **Cause:** Add-in compiled for .NET 2.0 trying to run in .NET 4.0 process (Mixed mode assembly issues).
1247. **Untrusted Font Block:**
    *   **Manifests:** Fonts missing in Edge/IE.
    *   **Logic:** `MitigationOptions` for Process prevent loading non-system fonts.
    *   **Cause:** "Untrusted Font Blocking" GPO is enabled.

---

### **SECTION 78: ADVANCED INPUT & UI**
1248. **Raw Input Thread Hang:**
    *   **Manifests:** Mouse moves, but clicks ignore. Keyboard dead.
    *   **Logic:** `csrss` Raw Input thread queue full.
    *   **Cause:** A low-level keyboard hook (Keylogger/Anti-Cheat) crashed but didn't unhook, blocking the input chain.
1249. **DPI Awareness Lie:**
    *   **Manifests:** App is tiny or blurry.
    *   **Logic:** App manifest claims `<dpiAware>true</dpiAware>`, but code uses pixel coordinates.
    *   **Cause:** Developer lied in manifest to avoid Windows scaling, but didn't implement scaling code.
1250. **Composition Surface Loss:**
    *   **Manifests:** Window content goes black.
    *   **Logic:** `Dwm` resets. `Present` call returns `DXGI_ERROR_DEVICE_REMOVED`.
    *   **Cause:** Graphics driver crash/recover invalidated the window texture.

---

### **SECTION 79: AZURE AD / HYBRID SYNC**
1251. **PRT (Primary Refresh Token) Missing:**
    *   **Manifests:** SSO fails on M365 apps.
    *   **Logic:** `dsregcmd /status` shows `AzureAdPrt : NO`.
    *   **Cause:** Device not Hybrid Joined or TPM failure preventing token acquisition.
1252. **Workplace Join Certificate Rot:**
    *   **Manifests:** Login loops.
    *   **Logic:** `CryptAcquireCertificatePrivateKey` fails for the device certificate.
    *   **Cause:** The certificate identifying the device to Azure AD has expired or is corrupt.
1253. **Conditional Access (Device State) Block:**
    *   **Manifests:** "You cannot access this resource".
    *   **Logic:** Browser sends token, receives 403.
    *   **Cause:** Device is "Compliant" in Intune, but Azure AD hasn't received the sync signal yet (Latency).

---

### **SECTION 80: ADVANCED FORENSICS (Persistence)**
1254. **WMI Event Consumer (Command Line):**
    *   **Manifests:** Random `powershell` window pops up.
    *   **Logic:** `scrcons.exe` (WMI Script host) spawning `cmd.exe`.
    *   **Cause:** Malware using WMI ActiveScriptEventConsumer (Fileless persistence).
1255. **Sticky Keys Backdoor (Classic):**
    *   **Manifests:** Press Shift 5 times -> CMD prompt opens (instead of Sticky Keys).
    *   **Logic:** `winlogon` spawns `sethc.exe`, but image on disk is actually `cmd.exe`.
    *   **Cause:** Attacker replaced `sethc.exe` with `cmd.exe`.
1256. **Utilman Hijack:**
    *   **Manifests:** Click Accessibility on Lock Screen -> CMD opens.
    *   **Logic:** `winlogon` spawns `utilman.exe` (which is actually `cmd.exe`).
    *   **Cause:** Attacker replaced `utilman.exe`.
1257. **UserInit Modification:**
    *   **Manifests:** User logs in, malware runs.
    *   **Logic:** Registry `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` value contains `C:\Windows\system32\userinit.exe,C:\Evil\malware.exe`.
    *   **Cause:** Comma-separated execution list in UserInit.
1258. **Screensaver Hijack:**
    *   **Manifests:** Machine idle -> Malware runs.
    *   **Logic:** Registry `HKCU\Control Panel\Desktop\SCRNSAVE.EXE` points to `.exe` instead of `.scr`.
    *   **Cause:** Screensavers are just standard executables; attacker changed the path.

---

### **SECTION 81: CLOUD STORAGE EDGE CASES**
1259. **OneDrive "File Locked" (Office Upload):**
    *   **Manifests:** Sync stuck.
    *   **Logic:** `OneDrive.exe` cannot upload because `OfficeClickToRun.exe` has an exclusive handle.
    *   **Cause:** "Use Office applications to sync Office files" setting conflict.
1260. **Dropbox Permissions Rot:**
    *   **Manifests:** Sync fails "Permission Denied".
    *   **Logic:** `Dropbox.exe` gets `ACCESS_DENIED` on internal `.dropbox.cache`.
    *   **Cause:** User copied files from another PC with explicit ACLs that don't match current user.
1261. **File Name Character sync fail:**
    *   **Manifests:** File won't sync to SharePoint.
    *   **Logic:** File name contains `..` or `_vti_` or `#`.
    *   **Cause:** SharePoint/OneDrive restricted characters/names.

---

### **SECTION 82: HARDWARE ERRORS (WHEA)**
1262. **WHEA Corrected Error (PCIe):**
    *   **Manifests:** System micro-stutters.
    *   **Logic:** System Log Event `17` (WHEA-Logger).
    *   **Cause:** PCIe card (NIC/GPU) signaling errors, OS keeps retrying. Hardware failing.
1263. **Machine Check Exception (MCE) - Soft:**
    *   **Manifests:** Random app crashes.
    *   **Logic:** WHEA Logger Cache Hierarchy Error.
    *   **Cause:** CPU L2/L3 cache bit flip (Corrected, but indicates dying CPU).

---

### **SECTION 83: PRINTER "GHOSTS"**
1264. **WSD (Web Services for Devices) Port Flap:**
    *   **Manifests:** Printer shows "Offline" then "Online".
    *   **Logic:** Port Monitor switches from WSD to TCP/IP.
    *   **Cause:** WSD multicast discovery is unreliable on enterprise Wi-Fi; printer drops off.
1265. **Driver Version Mismatch (Point & Print):**
    *   **Manifests:** User cannot connect to shared printer.
    *   **Logic:** Client has Driver v3, Server has Driver v4. Handshake fails.
    *   **Cause:** Mismatched driver generations preventing connection.

---

### **SECTION 84: SYSTEM RESTORE & RECOVERY**
1266. **VSS Shadow Copy Deletion (Defender):**
    *   **Manifests:** Restore points vanish.
    *   **Logic:** `System` process deletes VSS snapshots.
    *   **Cause:** Low disk space triggers automatic VSS cleanup (High Churn).
1267. **Recovery Partition Disabled:**
    *   **Manifests:** Cannot "Reset this PC".
    *   **Logic:** `ReAgentc /info` returns Disabled.
    *   **Cause:** Windows Update moved the partition map, breaking the link to `WinRE.wim`.

---

### **SECTION 85: 16-BIT & DOS (The Ancients)**
1268. **NTVDM CPU Spike:**
    *   **Manifests:** 100% CPU on `ntvdm.exe`.
    *   **Logic:** 16-bit app polling keyboard loop.
    *   **Cause:** Old DOS apps rely on CPU cycles for timing; modern CPUs run them too fast. (Requires `TAME.COM` or similar).
1269. **AUTOEXEC.NT Parsing:**
    *   **Manifests:** 16-bit app fails to start.
    *   **Logic:** `CreateFile` `C:\Windows\System32\autoexec.nt`.
    *   **Cause:** File missing or corrupt (often flagged by AV).

---

### **SECTION 86: SPECIFIC ERROR CODES (RPC/Win32)**
1270. **RPC_S_SERVER_UNAVAILABLE (0x6BA):**
    *   **Logic:** RPC endpoint mapper reachable (135), but dynamic port blocked.
1271. **RPC_S_CALL_FAILED (0x6BE):**
    *   **Logic:** The remote procedure call started, but the server process crashed mid-execution.
1272. **ERROR_MORE_DATA (0xEA):**
    *   **Logic:** Buffer too small. (App logic error).
1273. **ERROR_NO_SYSTEM_RESOURCES (0x5AA):**
    *   **Logic:** Non-paged pool limit or Thread limit hit.

---

### **SECTION 87: ADVANCED EVENT LOGGING**
1274. **Event Log Service Loop:**
    *   **Manifests:** High CPU `wevtsvc`.
    *   **Logic:** `Security.evtx` full, overwrite policy "Do not overwrite".
    *   **Cause:** Audit log full, system trying to handle the "CrashOnAuditFail" condition.
1275. **Subscription Failure (Source Initiated):**
    *   **Manifests:** Logs not forwarding.
    *   **Logic:** WinRM `403` error.
    *   **Cause:** Network Service account lacks permission to read the Event Log.

---

### **SECTION 88: FONT CACHE & RENDERING**
1276. **Presentation Cache Corrupt:**
    *   **Manifests:** WPF Apps (Visual Studio, etc.) crash on launch.
    *   **Logic:** Read `FontCache3.0.0.0.dat`.
    *   **Cause:** WPF Font Cache service data corruption.
1277. **EUDC (End User Defined Character) Link:**
    *   **Manifests:** Squares appear instead of characters.
    *   **Logic:** `HKCU\EUDC` registry lookup fail.
    *   **Cause:** Missing link to custom character map (Asian markets).

---

### **SECTION 89: BATTERY & POWER**
1278. **Modern Standby (S0) Drain:**
    *   **Manifests:** Laptop hot in bag, battery dead.
    *   **Logic:** Network activity during sleep.
    *   **Cause:** "Connected Standby" allows apps to wake network. (Need `powercfg /sleepstudy`).
1279. **Hibernation File Lock:**
    *   **Manifests:** Cannot hibernate.
    *   **Logic:** `hiberfil.sys` sharing violation.
    *   **Cause:** Anti-Virus locking the hibernation file.

---

### **SECTION 90: THE "IMPOSSIBLE" (Logic Defying)**
1280. **The "Monday Morning" Boot:**
    *   **Manifests:** 100 PCs fail to boot on Monday.
    *   **Cause:** Bad Defender Definition pushed Friday night marked `winlogon.exe` as malware.
1281. **The "Invisible" File:**
    *   **Manifests:** File exists in CMD, invisible in Explorer.
    *   **Cause:** File has `System` + `Hidden` attributes set.
1282. **The "Null" User:**
    *   **Manifests:** ACL shows "Account Unknown (S-1-5-...)".
    *   **Cause:** The user was deleted from AD, but the file permissions remain (Orphaned SID).
1283. **The "Case Sensitive" Folder:**
    *   **Manifests:** User sees `File.txt` and `file.txt` in same folder. App crashes.
    *   **Cause:** WSL (Linux) created files with case sensitivity enabled; Windows apps panic.

---

### **SECTION 91: APP-V / THINAPP**
1284. **Bubble-to-Bubble Comms:**
    *   **Manifests:** App A cannot see App B's DLLs.
    *   **Logic:** `CreateFile` fails inside virtual filesystem.
    *   **Cause:** Virtual environments are isolated. Requires "Connection Group" configuration.

---

### **SECTION 92: DFS (DISTRIBUTED FILE SYSTEM)**
1285. **DFS Referral Loop:**
    *   **Manifests:** Accessing `\\Domain\DFS\Share` hangs.
    *   **Logic:** Client bounces between Namespace Servers.
    *   **Cause:** Site cost configuration missing in AD Sites & Services; client treating remote server as local.
1286. **Offline Files sync trap:**
    *   **Manifests:** User sees old files.
    *   **Logic:** `CSC` cache read.
    *   **Cause:** DFS target moved, client stuck in Offline mode pointing to old target logic.

---

### **SECTION 93: CERTIFICATES (Advanced)**
1287. **AIA (Authority Info Access) Fail:**
    *   **Manifests:** Certificate Valid, but "Extra download" lag.
    *   **Logic:** HTTP fetch to `crt` file in certificate metadata.
    *   **Cause:** Intermediate CA certificate missing locally; Windows trying to fetch it from web on every use.
1288. **Key Spec Mismatch (Exchange/IIS):**
    *   **Manifests:** SSL/TLS handshake fail.
    *   **Logic:** `KeySpec` property = 0 (Signature) instead of 1 (Exchange).
    *   **Cause:** Cert imported with wrong `KeySpec`, unusable for SSL.

---

### **SECTION 94: TASK SCHEDULER**
1289. **Task Queued (Wait):**
    *   **Manifests:** Task doesn't run.
    *   **Logic:** Task status "Queued".
    *   **Cause:** "Run only if idle" condition not met (Mouse moved).
1290. **Run Level Mismatch:**
    *   **Manifests:** Scripts fails silently.
    *   **Logic:** `Access Denied`.
    *   **Cause:** "Run with highest privileges" not checked, script needs Admin.

---

### **SECTION 95: PERFMON & COUNTERS**
1291. **Counter Corruption:**
    *   **Manifests:** PerfMon empty.
    *   **Logic:** `pdh.dll` errors.
    *   **Cause:** Registry counter strings mismatched. Needs `lodctr /r`.
1292. **WMI Class Missing:**
    *   **Manifests:** Monitoring tool fails.
    *   **Logic:** `Win32_PerfFormattedData_...` class missing.
    *   **Cause:** WMI ADAP (AutoDiscovery) failed to parse driver perf counters.

---

### **SECTION 96: LICENSING (KMS/MAK)**
1293. **KMS Count Too Low:**
    *   **Manifests:** Windows not activating.
    *   **Logic:** Event `12288`. Error `0xC004F038`.
    *   **Cause:** KMS Host hasn't reached the threshold count (25 for Clients, 5 for Servers).
1294. **Time Drift Activation:**
    *   **Manifests:** Activation fails.
    *   **Logic:** `0xC004F074`.
    *   **Cause:** Client time differs from KMS host time > 4 hours.

---

### **SECTION 97: ROAMING PROFILES (The Horror)**
1295. **Profile Tombstoning:**
    *   **Manifests:** Temp profile login.
    *   **Logic:** `ProfileList` entry exists but folder deleted.
    *   **Cause:** Admin deleted `C:\Users\Bob` manually but didn't remove Registry key.
1296. **Ntuser.dat.LOG Lock:**
    *   **Manifests:** Hive corruption.
    *   **Logic:** `SHARING_VIOLATION` on registry transaction log.
    *   **Cause:** Profile failed to unload cleanly on last logoff.

---

### **SECTION 98: DYNAMIC DATA EXCHANGE (DDE)**
1297. **DDE Broadcast Hang:**
    *   **Manifests:** Excel hangs opening file.
    *   **Logic:** `SendMessage` timeout.
    *   **Cause:** DDE "Ignore other applications" setting, or another app (Word) not replying to DDE broadcast.

---

### **SECTION 99: WINDOWS SEARCH**
1298. **Index Rebuild Loop:**
    *   **Manifests:** High CPU `SearchIndexer`.
    *   **Logic:** Database corrupt, delete, rebuild, repeat.
    *   **Cause:** Corrupt file (PDF/TIFF) crashing the `IFilter` extraction process repeatedly.
1299. **Outlook Search Scope:**
    *   **Manifests:** "No results".
    *   **Logic:** `Mapi` scope missing.
    *   **Cause:** Outlook excluded from Indexing Options by GPO.

---

### **SECTION 100: THE "END OF THE LINE"**
1300. **The "Solar Flare":**
    *   **Manifests:** ECC Memory Error.
    *   **Logic:** WHEA Uncorrectable Error.
    *   **Cause:** Literal cosmic radiation flipping a bit in RAM. (The ultimate "Mark Russinovich" excuse).






    Here is the continuation of the Master List, focusing on the **"Logic Defying & 1% Edge Cases"**—issues that often require a physical site visit or deep kernel tracing to identify because they break the standard rules of software troubleshooting.

### **SECTION 101: THE "PHYSICAL WORLD" INTERFERENCE**
*When the problem isn't the code, but physics.*

1301. **The "9:00 AM" Network Storm:**
    *   **Manifests:** Entire subnet drops packets for 5 minutes every morning.
    *   **Logic:** `Interface Disconnect` events correlate with voltage sags.
    *   **Cause:** A faulty industrial microwave or elevator motor on the same electrical circuit is generating massive EMI (Electro-Magnetic Interference), scrambling unshielded Cat5e cables.
1302. **The "Tidal" WiFi:**
    *   **Manifests:** Point-to-Point wireless link drops at high tide.
    *   **Logic:** Signal Strength (RSSI) graph mimics a sine wave over 12 hours.
    *   **Cause:** The water level rising reflects/refracts the signal (Multipath Fading) differently, killing the link.
1303. **The "Magnet" Laptop Stack:**
    *   **Manifests:** User's laptop sleeps randomly.
    *   **Logic:** System Log: "System is entering sleep. Reason: Lid Close".
    *   **Cause:** User has stacked their laptop on top of another closed laptop. The magnet from the bottom laptop triggers the "Lid Closed" sensor of the top laptop.
1304. **The "Helium" iPhone/PC Crash:**
    *   **Manifests:** Devices crash instantly in the MRI room.
    *   **Logic:** Oscillator frequency drift in hardware logs.
    *   **Cause:** Helium atoms are small enough to penetrate MEMS oscillators (clocks) inside chips, physically stopping them.
1305. **The "Spacebar" Heater:**
    *   **Manifests:** PC wakes from sleep instantly, every time.
    *   **Logic:** `powercfg -lastwake` shows "Device: USB Composite Device (Keyboard)".
    *   **Cause:** A space heater under the desk is blowing hot air on a cheap membrane keyboard, causing the plastic to expand and trigger a "Space" key press.
1306. **The "Vampire" Tap:**
    *   **Manifests:** 10Mbps link speed negotiation on a Gigabit port.
    *   **Logic:** Network card logs "Downshift" event.
    *   **Cause:** Physical cable damage. One of the 4 pairs is broken, forcing the NIC to fall back to 100Mbps or 10Mbps (which uses fewer pairs).
1307. **The "Scrap Yard" Crane:**
    *   **Manifests:** Server reboots.
    *   **Logic:** Event Log "The previous system shutdown was unexpected". No dump.
    *   **Cause:** A massive electromagnet crane next door draws so much power from the city grid that it causes a brownout (voltage dip) below the PSU's hold-up time.

### **SECTION 102: LEGACY & RESERVED NAMES (The "CON" Bugs)**
*Ghost of MS-DOS v1.0.*

1308. **The "CON" Folder:**
    *   **Manifests:** User cannot save file "Con.txt" or "Aux.doc". "The handle is invalid".
    *   **Logic:** `CreateFile` path contains `\CON`, `\PRN`, `\AUX`, `\NUL`, `\LPT1`, `\COM1`.
    *   **Cause:** These are reserved device names from 1981 DOS. Windows still blocks them at the kernel object manager level.
1309. **The "Initial" Bug:**
    *   **Manifests:** User "P.R.N. Smith" cannot have a profile.
    *   **Logic:** `CreateDirectory` "C:\Users\PRN" fails.
    *   **Cause:** "PRN" is a reserved device name (Printer).
1310. **The "Trailing Space" Ghost:**
    *   **Manifests:** File shows in Explorer, but cannot open/delete. "File not found".
    *   **Logic:** `dir /x` reveals name is "File.txt " (Space at end).
    *   **Cause:** Created by a Linux/Mac client on a share. Windows Explorer strips trailing spaces for display but the API requires `\\?\C:\Path\File.txt ` to access it.
1311. **The "Deep" Path:**
    *   **Manifests:** Backup fails on one specific folder.
    *   **Logic:** `CreateFile` fails with `PathTooLongException` (> 260 chars).
    *   **Cause:** User mapped a drive `Z:` to `\\Server\Share\Deep\Folder`, then created deep folders inside Z:. The absolute path is now > 260 chars, invisible to the user but visible to the Backup Agent running as System.

### **SECTION 103: THE "HEISENBERG" BUGS**
*Issues that disappear when you try to watch them.*

1312. **The "Debug" Race Condition:**
    *   **Manifests:** App crashes. You attach a Debugger (or ProcMon). App works fine.
    *   **Logic:** `OutputDebugString` calls succeed.
    *   **Cause:** The act of logging slows down the thread *just enough* to resolve a race condition (A finishes before B) that normally crashes the app.
1313. **The "Focus" Stealer:**
    *   **Manifests:** Fullscreen game minimizes randomly.
    *   **Logic:** You run a script to log `GetForegroundWindow`. The script's window taking focus *stops* the other app from taking focus.
    *   **Cause:** An app checks "Is User Idle?". If you are debugging, you aren't idle, so the bug doesn't trigger.
1314. **The "ProcMon" Denial:**
    *   **Manifests:** Malware runs. You open ProcMon. Malware terminates.
    *   **Logic:** Malware enumerates processes, sees `procmon.exe`, and calls `ExitProcess`.
    *   **Cause:** Anti-analysis evasion.
1315. **The "Service Timeout" Debug:**
    *   **Manifests:** Service fails to start. You attach debugger. Service fails with "Timeout".
    *   **Logic:** Service Control Manager waits 30s.
    *   **Cause:** Debugging pauses the process. SCM kills it because it didn't report "Running" in time. (Fix: Set `ServicesPipeTimeout` registry).

### **SECTION 104: DRIVER & KERNEL "ZOMBIES"**
1316. **Ghost NIC (Hidden Device):**
    *   **Manifests:** "IP Address already assigned to another adapter".
    *   **Logic:** Registry `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces` has a GUID not visible in `ncpa.cpl`.
    *   **Cause:** You moved the VM network card to a new slot. Windows sees it as a "New" card, but the "Old" card (Hidden) still holds the Static IP.
1317. **Filter Driver Altitude Collision:**
    *   **Manifests:** Blue Screen `0x7F` or `0x3B` on file access.
    *   **Logic:** `fltmc instances` shows two drivers (e.g., AV and Encryption) at the exact same "Altitude" number.
    *   **Cause:** They are fighting for the same stack frame in the kernel.
1318. **The "Sticky" USB Serial:**
    *   **Manifests:** Plugging in a specific flash drive assigns it drive letter `F:`, which is a mapped network drive.
    *   **Logic:** `HKLM\SYSTEM\MountedDevices` maps `\DosDevices\F:` to the USB Unique ID.
    *   **Cause:** You plugged this drive in 3 years ago when `F:` was free. Windows remembered.
1319. **Audio "Enhancement" Deadlock:**
    *   **Manifests:** Sound works in Chrome, but Spotify hangs.
    *   **Logic:** Stack trace shows wait on `NAHIMIC.sys` or `WavesSvc64.exe`.
    *   **Cause:** "Audio Enhancements" (Bloatware) inject into the audio stream and deadlock on specific sample rates.

### **SECTION 105: SECURITY & PERMISSION "LAYERS"**
1320. **Bypass Traverse Checking (The "Deep" Access):**
    *   **Manifests:** User can access `\\Server\Share\Folder\File.txt` by direct path, but cannot browse to it.
    *   **Logic:** User lacks "Read" on parent folders, but has "Read" on the file.
    *   **Cause:** "Bypass Traverse Checking" privilege allows passing through denied folders if you know the destination path.
1321. **Owner Rights (The "Creator" Trap):**
    *   **Manifests:** User creates a file, closes it, and cannot open it again.
    *   **Logic:** Folder Permission: "Creator Owner: Full Control". Subfolder Permission: "User: Read".
    *   **Cause:** When the file is created, "Creator Owner" logic applies. If that ACE is missing or broken, the user loses control of their own file immediately after creation.
1322. **ICACLS Canonical Order:**
    *   **Manifests:** Permissions behave erratically (Deny doesn't deny).
    *   **Logic:** ACL is not in "Canonical Order" (Deny first, then Allow).
    *   **Cause:** A script or non-Windows tool modified the ACLs and put "Allow" before "Deny".
1323. **The "Null" SID:**
    *   **Manifests:** File has no owner. Impossible to delete.
    *   **Logic:** Owner SID is `S-1-0-0`.
    *   **Cause:** Corruption or a bug in a file migration tool. Requires `takeown` to fix.

### **SECTION 106: ACTIVE DIRECTORY "TIME BOMBS"**
1324. **Token Bloat (The "1000 Groups"):**
    *   **Manifests:** User logs in, but cannot access File Shares or IIS apps. "400 Bad Request".
    *   **Logic:** `klist` shows huge ticket size. System Log `Kerberos` error "Packet too large".
    *   **Cause:** User is in > 100 groups. The Kerberos token exceeds the default HTTP header size limit (MaxTokenSize).
1325. **AdminSDHolder (The "Protected" User):**
    *   **Manifests:** You grant a user permissions on their phone object, 60 mins later it disappears.
    *   **Logic:** User is a member of "Print Operators" or "Domain Admins".
    *   **Cause:** SDProp process runs every hour and resets permissions on "Protected Groups" to match `AdminSDHolder` template.
1326. **USN Rollback (The "Zombie" DC):**
    *   **Manifests:** Deleted users reappear. Passwords revert.
    *   **Logic:** DC logs "Active Directory has detected that this domain controller has been restored from a snapshot".
    *   **Cause:** A VM Snapshot of a Domain Controller was restored. It is now out of sync and replicating "old" truth back to the network.

### **SECTION 107: NETWORK "INVISIBLE" DROPS**
1327. **TCP Chimney Offload Bug:**
    *   **Manifests:** SQL Connection drops during heavy load.
    *   **Logic:** `netstat -t` shows "Offload" state. Packet Capture shows missing segments at the OS level (because the NIC handled them).
    *   **Cause:** Buggy NIC firmware corrupting packets when Offload is enabled.
1328. **Windows Filtering Platform (WFP) Silent Drop:**
    *   **Manifests:** Packet arrives at NIC (Wireshark sees it), but App doesn't get it. Windows Firewall is OFF.
    *   **Logic:** `netsh wfp show filters`.
    *   **Cause:** A hidden WFP filter (from an uninstalled Antivirus or VPN) is still active and silently dropping traffic.
1329. **Ephemeral Port Exhaustion (Outbound):**
    *   **Manifests:** Server cannot make *outbound* connections (e.g., to a backend DB).
    *   **Logic:** `netstat -an | find /c "TIME_WAIT"` > 16000.
    *   **Cause:** App is opening/closing TCP connections too fast, using up all 65k ports before they can timeout.
1330. **Path MTU Discovery Black Hole:**
    *   **Manifests:** Can ping server, but cannot load web page.
    *   **Logic:** Ping with `-f -l 1472` fails.
    *   **Cause:** A router in the middle has a small MTU (e.g., VPN tunnel) but is blocking the ICMP "Fragmentation Needed" message. The handshake works (small packets), but data (large packets) is dropped silently.

### **SECTION 108: APPLICATION COMPATIBILITY "SHIMS"**
1331. **The "Lie" Shim:**
    *   **Manifests:** App thinks it's running on Windows XP.
    *   **Logic:** `Shim Engine` applies `VersionLie` shim.
    *   **Cause:** Windows automatically detected the app name (e.g., `setup.exe`) and applied a compatibility fix.
1332. **Heap Mitigation Crash:**
    *   **Manifests:** Old app crashes on Windows 10.
    *   **Logic:** `Fault Tolerant Heap` (FTH) shim active.
    *   **Cause:** App has a heap buffer overrun. Windows tried to fix it with FTH, but the fix caused a logic error.
1333. **Installer Detection (UAC):**
    *   **Manifests:** Renaming a tool `updater.exe` makes it ask for Admin.
    *   **Logic:** `Consent.exe` triggers.
    *   **Cause:** Heuristic detection: filenames containing "setup", "patch", "update" automatically trigger UAC virtualization.

### **SECTION 109: "THE USER DIDN'T DO IT" (But they did)**
1334. **Drag and Drop Accidental Move:**
    *   **Manifests:** "The Finance Folder is gone!"
    *   **Logic:** Search finds "Finance" inside the "HR" folder.
    *   **Cause:** User clicked and dragged the folder 2 pixels while moving the mouse. Windows interpreted it as a "Move" command.
1335. **The "Sticky" Insert Key:**
    *   **Manifests:** "Word is deleting my text as I type!"
    *   **Logic:** Overtype mode active.
    *   **Cause:** User hit `Insert` by mistake.
1336. **Browser Zoom Prank:**
    *   **Manifests:** "The internet is tiny."
    *   **Logic:** Browser Zoom set to 50%.
    *   **Cause:** User hit `Ctrl + Scroll Wheel`.

### **SECTION 110: "IT'S NOT A BUG, IT'S A FEATURE"**
1337. **Fast Startup (The "Fake" Shutdown):**
    *   **Manifests:** "I rebooted!" (Uptime says 30 days).
    *   **Logic:** `GetTickCount` is huge.
    *   **Cause:** "Shutdown" in Windows 10/11 is actually "Hibernate". Only "Restart" performs a full kernel reset.
1338. **Modern Standby (Network Connected):**
    *   **Manifests:** Laptop battery dead in bag. Hot to touch.
    *   **Logic:** `SleepStudy` report shows "NoHwDrips".
    *   **Cause:** Laptop woke up to install an update or sync email while in the bag.
1339. **Windows Update "Active Hours":**
    *   **Manifests:** PC reboots while user is getting coffee.
    *   **Logic:** `WindowsUpdateClient` event.
    *   **Cause:** Current time was outside the configured "Active Hours".
1340. **Focus Assist (Do Not Disturb):**
    *   **Manifests:** "I'm missing Outlook notifications!"
    *   **Logic:** Focus Assist is "On" (Priority Only).
    *   **Cause:** Turned on automatically because user is "Duplicating Display" (Presenting).


Here is a list of **100 "White Whale" Edge Cases** for Windows Desktop/Laptop environments.

These are the tickets that get escalated to Tier 3 because they defy standard troubleshooting (rebooting/reinstalling drivers doesn't fix them) and are often rooted in obscure registry states, hardware firmware quirks, or legacy Windows behaviors.

### **SECTION 111: THE "INVISIBLE" INPUT GLITCHES**
*When the keyboard/mouse works, but acts "possessed".*

1341. **The "Ghost" Ctrl Key (RDP Latch):**
    *   **Manifests:** Clicking a file selects multiple files. Typing "s" saves the document.
    *   **Logic:** `GetKeyState(VK_CONTROL)` returns "Down", but no hardware scan code is received.
    *   **Cause:** User locked their PC while an RDP session was active and holding `Ctrl`. Windows never received the "Key Up" event, latching the modifier logic state.
1342. **Filter Keys "Slow Mode" Trap:**
    *   **Manifests:** User claims keyboard is broken; have to hold keys for 2 seconds to type.
    *   **Logic:** Registry `HKCU\Control Panel\Accessibility\Keyboard Response` -> `Flags` has bit 0/1 set.
    *   **Cause:** User held the Right-Shift key for exactly 8 seconds (often while thinking), triggering the Accessibility Filter Keys shortcut without noticing the toast notification.
1343. **The "Precision" Touchpad Deadzone:**
    *   **Manifests:** User cannot click small buttons (like "X" to close). Mouse moves but click ignores.
    *   **Logic:** Touchpad driver registers "Tap", OS rejects it as "Accidental Input".
    *   **Cause:** "AAPThreshold" (Accidental Activation Prevention) registry keys in the Precision Touchpad settings are set too aggressively for the user's typing style/palm size.
1344. **Focus Assist "Game" Lock:**
    *   **Manifests:** Windows key doesn't work. Alt-Tab doesn't work.
    *   **Logic:** Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings` -> `NOC_GLOBAL_SETTING_TOASTS_ENABLED` is 0.
    *   **Cause:** Windows thinks Excel is a "Full Screen Game" because it is using GPU acceleration, so it disabled shell shortcuts (Game Mode).
1345. **The "Phantom" Digitizer Touch:**
    *   **Manifests:** Mouse cursor jumps to the top-right corner randomly.
    *   **Logic:** `GetMessage` stream shows `WM_TOUCH` events with 0 pressure.
    *   **Cause:** Micro-fracture in the touchscreen glass or humidity buildup in the bezel causing ghost inputs.
1346. **Mouse "Polling Rate" stutter:**
    *   **Manifests:** High-end PC stutters when moving mouse.
    *   **Logic:** `DPC Latency` spikes correlated with `mouhid.sys`.
    *   **Cause:** User bought a "1000Hz" gaming mouse. The CPU interrupt load (1000 ints/sec) is overwhelming a specific USB controller driver.

### **SECTION 112: DISPLAY & GPU "POLTERGEISTS"**
*Why the screen looks wrong.*

1347. **The "Sepia" Screen (Night Light Registry Rot):**
    *   **Manifests:** Screen is yellow/orange. Night Light is "Off" in Settings.
    *   **Logic:** Registry `HKCU\Software\Microsoft\Windows\CurrentVersion\CloudStore\...\$$windows.data.bluelightreduction` contains a binary blob indicating "Active".
    *   **Cause:** The UI toggle desynced from the underlying registry state (often after a driver update or fast shutdown).
1348. **Intel DPST "Flicker":**
    *   **Manifests:** Screen brightness changes randomly when switching from Dark Mode app to Light Mode app.
    *   **Logic:** Intel Graphics Control Panel -> Power -> "Display Power Saving Technology" is On.
    *   **Cause:** Feature dimming the backlight to save power based on image content (Content Adaptive Brightness).
1349. **The "Invisible" App (Off-Screen Coordinates):**
    *   **Manifests:** User launches App, sees icon in taskbar, but no window.
    *   **Logic:** `GetWindowPlacement` returns coordinates like `-32000, -32000`.
    *   **Cause:** App was last closed when laptop was docked to 3 monitors. Now undocked, it remembers coordinates that don't exist.
1350. **HDR "Washed Out" Desktop:**
    *   **Manifests:** Colors look grey/desaturated on a high-end monitor.
    *   **Logic:** `DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709` active on desktop.
    *   **Cause:** Windows HDR enabled on a monitor that accepts the signal but has poor peak brightness (Fake HDR), crushing the SDR color gamut.
1351. **The "Ghost" Overlay (Unclickable Spot):**
    *   **Manifests:** User cannot click a specific 50x50 pixel spot on the screen.
    *   **Logic:** `EnumWindows` finds a visible window with `WS_EX_LAYERED | WS_EX_TRANSPARENT` at that location (e.g., Origin, Discord, Steam Overlay).
    *   **Cause:** An in-game overlay got stuck on the desktop with 1% opacity.
1352. **Icon Cache "Black Box" Corruption:**
    *   **Manifests:** Desktop icons turn into black squares.
    *   **Logic:** `Explorer.exe` fails to read `IconCache.db`.
    *   **Cause:** The database grew beyond 24MB (undocumented legacy limit in some versions) or header corruption.
1353. **Wallpaper "Transcoding" Fail:**
    *   **Manifests:** Desktop background is black. Cannot set new image.
    *   **Logic:** `AppData\Roaming\Microsoft\Windows\Themes\TranscodedWallpaper` is 0 bytes or locked.
    *   **Cause:** Windows converts all wallpapers to a standard JPG. If that process crashes, the file gets locked/corrupted and the UI fails silently.

### **SECTION 113: AUDIO & MEDIA "GREMLINS"**
*Sound works, but not really.*

1354. **The "Duck" That Never Ended:**
    *   **Manifests:** System volume is permanently stuck at 20% (Low).
    *   **Logic:** Registry `HKCU\Software\Microsoft\Multimedia\Audio` -> `UserDuckingPreference`.
    *   **Cause:** A communication app (Teams/Skype) triggered "Duck volume when others speak" and crashed before sending the "Unduck" signal.
1355. **Audio "Enhancement" Processing Loop:**
    *   **Manifests:** Audio sounds robotic or echoed.
    *   **Logic:** `Audiosrv` loads `APO` (Audio Processing Object) DLLs from `Realtek` or `Dolby`.
    *   **Cause:** Third-party driver effects ("Bass Boost", "Room Correction") malfunctioned. (Fix: "Disable all enhancements" checkbox).
1356. **HDMI Audio "Silent" Stream:**
    *   **Manifests:** TV shows "PCM Audio" but no sound comes out.
    *   **Logic:** Driver reports `KSDATAFORMAT_SUBTYPE_PCM` 5.1 channels.
    *   **Cause:** Windows thinks the TV is 5.1 surround. It sends vocals to the "Center" channel. The TV is stereo (2.0) and drops the Center channel. (User hears background music but no voices).
1357. **Bluetooth Hands-Free Profile (HFP) Quality:**
    *   **Manifests:** Spotify sounds like a telephone call (Mono, Low Quality).
    *   **Logic:** Audio Endpoint switches to "Headset" (HFP) instead of "Headphones" (A2DP).
    *   **Cause:** An app opened the Microphone. Bluetooth bandwidth cannot support High Def Audio + Mic simultaneously, so it drops to HFP.

### **SECTION 114: POWER & SLEEP "INSOMNIA"**
*Why the laptop battery is dead in the morning.*

1358. **Modern Standby "Network" Wake:**
    *   **Manifests:** Laptop hot in bag. Battery drained.
    *   **Logic:** `powercfg /sleepstudy` shows `NoHwDrips` caused by `fx (Network Controller)`.
    *   **Cause:** "Network connectivity in Standby" is Enabled. Laptop woke up to process a multicast packet or update check.
1359. **The "Update" Wake Timer:**
    *   **Manifests:** PC turns on at 3:00 AM.
    *   **Logic:** `powercfg /waketimers` shows `Orchestrator`.
    *   **Cause:** "Wake the computer to run this task" is hardcoded for Critical Update installation logic (ignoring user preference).
1360. **Power Request "System" Override:**
    *   **Manifests:** PC never sleeps.
    *   **Logic:** `powercfg /requests` shows `PERFBOOST`.
    *   **Cause:** An app (like Chrome playing a video, or a stuck Print Job) has requested the power management system to stay awake.
1361. **Shutdown vs Hibernate (Fast Startup):**
    *   **Manifests:** "I shut it down every night!" (Uptime 45 days).
    *   **Logic:** `GetTickCount64` is huge.
    *   **Cause:** User clicks "Shut Down". Windows Kernel hibernates (S4) to allow Fast Startup. The kernel never reinitializes.

### **SECTION 115: WIFI & NETWORK "V00D00"**
1362. **The "Roaming" Aggressiveness:**
    *   **Manifests:** WiFi drops every 2 minutes.
    *   **Logic:** WLAN AutoConfig logs "Roam" event between APs with similar signal strength.
    *   **Cause:** "Roaming Aggressiveness" driver setting is "Highest". Laptop bounces between the Living Room AP and Kitchen AP constantly.
1363. **VPN "Split DNS" Leak:**
    *   **Manifests:** Can't reach internal Intranet sites.
    *   **Logic:** `Resolve-DnsName` goes to ISP DNS (8.8.8.8) instead of VPN DNS.
    *   **Cause:** Interface Metric. Windows thinks the WiFi is "faster" (Metric 25) than the VPN (Metric 100) and sends DNS queries to the "fastest" path, ignoring domain suffixes.
1364. **Metered Connection "Outlook Block":**
    *   **Manifests:** Outlook says "Disconnected" but Chrome works.
    *   **Logic:** Network status shows "Metered".
    *   **Cause:** User clicked "Set as Metered Connection" for their Home WiFi. Outlook respects this and stops syncing to save data.
1365. **MAC Randomization (Captive Portal Loop):**
    *   **Manifests:** Hotel WiFi asks to login every single day.
    *   **Logic:** MAC Address changes on every connection.
    *   **Cause:** "Use random hardware addresses" is On. The Hotel tracks the device by MAC.

### **SECTION 116: SHELL & EXPLORER "ROT"**
1366. **"Quick Access" Timeout:**
    *   **Manifests:** Explorer opens, green bar loads forever.
    *   **Logic:** `Explorer.exe` stack hung on `NetworkIo`.
    *   **Cause:** User pinned a folder from a network share that no longer exists. Explorer tries to resolve it synchronously on launch.
1367. **Context Menu "Cloud" Delay:**
    *   **Manifests:** Right-click on Desktop takes 5 seconds.
    *   **Logic:** `Explorer.exe` queries `ContextMenuHandlers` -> `Intel Graphics` or `Nvidia`.
    *   **Cause:** Graphics driver context menu extension is initializing a slow API.
1368. **Recycle Bin Corruption:**
    *   **Manifests:** "The Recycle Bin on C:\ is corrupted. Do you want to empty it?"
    *   **Logic:** `CheckDisk` error on `$Recycle.Bin` folder.
    *   **Cause:** Mismatched SID (Security ID) in the recycler folder meta-files after a user profile migration.
1369. **Search Index "Outlook" Missing:**
    *   **Manifests:** Start Menu doesn't find emails.
    *   **Logic:** Registry `Windows Search\Catalog\Scopes` missing MAPI entry.
    *   **Cause:** Outlook was installed with "Run as Admin", creating registry keys the System Indexer couldn't read/merge.

### **SECTION 117: USB & PERIPHERAL "GHOSTS"**
1370. **USB Selective Suspend (The "Dying Mouse"):**
    *   **Manifests:** USB mouse disconnects, reconnects 2 seconds later.
    *   **Logic:** System Log "Driver sent invalid remove request".
    *   **Cause:** Windows puts the USB Hub to sleep to save power. The Mouse takes too long to wake up, so Windows resets the port.
1371. **Phantom COM Port (In Use):**
    *   **Manifests:** Cannot use USB-to-Serial adapter on COM1. "Port in use".
    *   **Logic:** Registry `HKLM\SYSTEM\CurrentControlSet\Control\COM Name Arbiter` has bits set.
    *   **Cause:** A device that is physically unplugged "reserved" COM1 in the registry years ago.
1372. **Docking Station "Billboard" Device:**
    *   **Manifests:** USB-C Dock doesn't work. "USB Device not recognized".
    *   **Logic:** Device Manager shows "Billboard Device".
    *   **Cause:** USB-C "Alternate Mode" negotiation failed. The dock fell back to USB 2.0 "Billboard" class to tell the OS it failed.

### **SECTION 118: CRYPTO & TPM "LOCKOUTS"**
1373. **TPM "Hysteresis" Lockout:**
    *   **Manifests:** Windows Hello "Something went wrong".
    *   **Logic:** `TpmTool` shows "Locked Out".
    *   **Cause:** User entered wrong PIN too many times. TPM hardware enters "Dictation Attack" lockout mode (can last 2-24 hours).
1374. **NGC Container "Desync":**
    *   **Manifests:** Fingerprint works, but asks for PIN, which fails.
    *   **Logic:** `CryptAcquireCertificatePrivateKey` fails for the Hello Container.
    *   **Cause:** The cryptographic key protected by the TPM is valid, but the user's password changed, and the "Protector" wasn't updated.
1375. **BitLocker "DMA" Trigger:**
    *   **Manifests:** BitLocker asks for Recovery Key on every boot.
    *   **Logic:** PCR 7 Validation Fail.
    *   **Cause:** A Thunderbolt dock was plugged in at boot. BIOS DMA protection policies triggered a "Hardware Change" alert to the TPM.

### **SECTION 119: 3RD PARTY APP INTERACTIONS**
1376. **Chrome "Renderer" Code Integrity:**
    *   **Manifests:** Chrome tabs crash instantly "Aw Snap".
    *   **Logic:** `Renderer` process blocked from loading `RendererCodeIntegrity`.
    *   **Cause:** Old Symantec/McAfee DLP agent trying to inject a DLL into the Chrome Renderer process, which Chrome blocks (Microsoft mitigation policy).
1377. **Excel "Clipboard" Lock:**
    *   **Manifests:** "We couldn't free up space on the Clipboard".
    *   **Logic:** `OpenClipboard` fails.
    *   **Cause:** An RDP session or "Remote Desktop App" is syncing the clipboard and locked it.
1378. **Zoom "Camera" Exclusive Lock:**
    *   **Manifests:** Camera black in Zoom. Works in Camera App.
    *   **Logic:** `CreateFile` `\Device\Video0` Access Denied.
    *   **Cause:** The "Windows Camera Frame Server" service crashed, holding the handle to the hardware driver, preventing new apps from binding.

### **SECTION 120: THE "USER PROFILE" SINGULARITIES**
1379. **Temporary Profile (Ref Count):**
    *   **Manifests:** "We can't sign into your account".
    *   **Logic:** Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` has `.bak` entry. `RefCount` > 0.
    *   **Cause:** The User Registry Hive (`NTUSER.DAT`) was locked by an Anti-Virus scanner during logoff, preventing unload.
1380. **Roaming AppData Bloat:**
    *   **Manifests:** Black screen at logon for 10 minutes.
    *   **Logic:** `WinLogon` reading `Roaming.dat`.
    *   **Cause:** AppData\Roaming is 20GB. Windows tries to sync it all from the server before showing the desktop.
1381. **Known Folder Redirection "Loop":**
    *   **Manifests:** Documents folder is empty.
    *   **Logic:** `User Shell Folders` points to `C:\Users\User\Documents\Documents`.
    *   **Cause:** Bad OneDrive or GPO logic created a recursive path mapping.

### **SECTION 121: INSTALLATION & MSI "GHOSTS"**
1382. **"Feature you are trying to use" (Source Prompt):**
    *   **Manifests:** Opening Excel triggers an installer prompt asking for a CD.
    *   **Logic:** `MsiExec` searches `SourceList`.
    *   **Cause:** A minor "Advertised Shortcut" feature was triggered, but the original installation media (`.msi` file) is missing from the cache.
1383. **Pending Reboot "Sentinel" File:**
    *   **Manifests:** Software fails to install "Restart Required", even after restart.
    *   **Logic:** Registry `PendingFileRenameOperations` is empty, but `RebootRequired` key exists in `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update`.
    *   **Cause:** A specific Windows Update flag got stuck.

### **SECTION 122: THE "LOGIC GATES" (Registry Booleans)**
1384. **"Allow Telemetry" = 0 (Settings Freeze):**
    *   **Manifests:** "Some settings are managed by your organization" (on Home edition).
    *   **Logic:** Registry `AllowTelemetry` = 0.
    *   **Cause:** User ran a privacy script ("ShutUp10") that hard-set registry policies, locking the UI controls.
1385. **UAC "Consent Prompt" Hidden:**
    *   **Manifests:** Screen dims, but no Yes/No box appears. PC frozen.
    *   **Logic:** `Consent.exe` is running on the "Secure Desktop".
    *   **Cause:** The Secure Desktop (Session 1) is rendering on a display output that doesn't exist (Ghost Monitor), or behind the current window.

### **SECTION 123: BROWSER "CERTIFICATE" WEIRDNESS**
1386. **Date "Validity" 2038:**
    *   **Manifests:** Website secure connection fails.
    *   **Logic:** Cert Validity > 2038.
    *   **Cause:** 32-bit timestamp overflow in older crypto libraries used by specific banking middleware.
1387. **Root CA "Disable" Flag:**
    *   **Manifests:** All HTTPS sites invalid.
    *   **Logic:** `CertGetCertificateChain` fail.
    *   **Cause:** User accidentally moved a Root CA (like DigiCert) into the "Untrusted Certificates" store.

### **SECTION 124: HARDWARE "BUTTON" OVERRIDES**
1388. **The "Fn" Key Lock:**
    *   **Manifests:** User cannot type numbers (types U, I, O, P as 4, 5, 6, *).
    *   **Logic:** No software logic visible.
    *   **Cause:** "NumLock" on a laptop without a numpad maps the right-side letters to numbers. User hit `Fn+NumLock` by mistake.
1389. **Physical WiFi Switch (BIOS):**
    *   **Manifests:** WiFi adapter missing from Device Manager.
    *   **Logic:** BIOS ACPI report.
    *   **Cause:** Physical toggle switch on the side of the laptop (older models) turns off the PCIe bus for the card.

### **SECTION 125: THE "TIME TRAVEL" FILES**
1390. **Future Timestamps (Build Fails):**
    *   **Manifests:** "Make" or "Compile" fails. "File modification time is in the future".
    *   **Logic:** `GetFileTime` returns date > Current System Time.
    *   **Cause:** File was touched by a server with a clock set 5 minutes ahead. Local build tool treats it as "impossible" and crashes.

### **SECTION 126: FONT & TEXT RENDERING**
1391. **Variable Font "Glitches":**
    *   **Manifests:** Text appears as blocks or overlaps in one app.
    *   **Logic:** App loads `Bahnschrift.ttf`.
    *   **Cause:** App uses an old text rendering engine (GDI) that doesn't support "Variable Fonts" (single file, multiple weights).
1392. **EUDC (End User Defined Character) Link:**
    *   **Manifests:** Strange squares in text.
    *   **Logic:** Registry `HKCU\EUDC`.
    *   **Cause:** System is trying to link a custom character map (common in legacy enterprise apps) that is missing.

### **SECTION 127: "IT'S THE CABLE" (But Software)**
1393. **Ethernet "Energy Efficient" Drop:**
    *   **Manifests:** Network drops when downloading large files.
    *   **Logic:** Event "Network Link is Down".
    *   **Cause:** "Energy Efficient Ethernet" (EEE) or "Green Ethernet" in driver settings. It tries to sleep the PHY during micro-gaps in data, but the switch port doesn't wake up fast enough.

### **SECTION 128: THE "OEM" BLOATWARE INTERFERENCE**
1394. **Dell/HP "Optimizer" Network Shaping:**
    *   **Manifests:** Zoom is perfect, but Browser download is 10Kbps.
    *   **Logic:** Filter Driver `ExpressConnect.sys`.
    *   **Cause:** OEM bloatware traffic shaper prioritizing UDP (Video) and throttling TCP (Download) aggressively.
1395. **"Eye Tracking" Dimming:**
    *   **Manifests:** Screen dims when user looks at second monitor.
    *   **Logic:** Tobii / Mirametrix process running.
    *   **Cause:** "Privacy" software dimming the screen it thinks you aren't looking at.

### **SECTION 129: FILE SYSTEM "CASE" SENSITIVITY**
1396. **WSL (Linux) Case Conflict:**
    *   **Manifests:** "File not found" when the file is right there.
    *   **Logic:** Folder has `CaseSensitive` attribute enabled. File is `Image.JPG`. App asks for `image.jpg`.
    *   **Cause:** User enabled WSL, which turned on per-folder case sensitivity. Windows Apps (NotePad) usually fail this check.

### **SECTION 130: THE "ULTIMATE" EDGE CASE**
1397. **The "Non-Breaking Space" in Username:**
    *   **Manifests:** Script fails "User not found".
    *   **Logic:** User input `J Smith` (ASCII 160) vs `J Smith` (ASCII 32).
    *   **Cause:** User copy-pasted their username from a formatted HTML email which used a non-breaking space (`&nbsp;`). Visually identical, binary different.
1398. **The "Null" Terminator in Registry:**
    *   **Manifests:** Registry key cannot be deleted. "Error while deleting key".
    *   **Logic:** Key name contains a null character `\0` in the middle.
    *   **Cause:** Malware or C++ bug created a key with an invalid name length. Windows RegEdit stops parsing at the null, so it can't target the key to delete it. (Requires Native API `NtDeleteKey` to fix).
1399. **The "BOM" (Byte Order Mark) in Hosts File:**
    *   **Manifests:** Hosts file ignored.
    *   **Logic:** File starts with `EF BB BF`.
    *   **Cause:** User edited `hosts` with Notepad and saved as "UTF-8". Windows networking stack (legacy) expects ANSI.
1400. **The "F1" Help Key Stuck:**
    *   **Manifests:** Chrome opens 50 "Help" tabs.
    *   **Logic:** `GetKeyState(VK_F1)` is high.
    *   **Cause:** Physical crumb stuck under the F1 key. (The most common "virus" reported to helpdesk).

    Here is the continuation of the Master List, scenarios **1401 through 1500**.

These are the **"Ghost in the Machine"** scenarios—issues that usually result in the user being told their computer is "haunted" because the root cause is a microscopic interaction between legacy code, physics, and bad drivers.

### **SECTION 131: THE "INPUT" POLTERGEISTS (HID/USB)**
*When the computer inputs things you didn't press.*

1401. **The "Steam" Desktop Layout:**
    *   **Manifests:** Mouse cursor drifts or clicks randomly while a game controller is plugged in.
    *   **Logic:** `Steam.exe` process active. Input stream shows synthetic mouse events.
    *   **Cause:** Steam's "Desktop Configuration" maps the joystick drift to the mouse cursor even when not in a game.
1402. **Touchscreen "Phantom" Moisture:**
    *   **Manifests:** Windows Start Menu opens and closes rapidly.
    *   **Logic:** `WM_TOUCH` messages at coordinates `0, 1080` (Start Button).
    *   **Cause:** The bezel of the screen is slightly pinched or dirty, and thermal expansion causes it to register a touch in the corner.
1403. **The "NKRO" (N-Key Rollover) BIOS Fail:**
    *   **Manifests:** Keyboard doesn't work in BitLocker PIN screen, works fine in Windows.
    *   **Logic:** Keyboard presents as multiple HID devices.
    *   **Cause:** High-end mechanical keyboard sends data in a complex packet format that the simple BIOS HID driver cannot parse.
1404. **Wireless Receiver Interference (USB 3.0):**
    *   **Manifests:** Wireless mouse lags/stutters only when an external hard drive is transferring data.
    *   **Logic:** USB Controller Event "Transfer Error".
    *   **Cause:** USB 3.0 ports emit radio frequency interference at 2.4GHz, jamming the wireless dongle plugged into the adjacent port.
1405. **Digitizer Pen "Hover" Click:**
    *   **Manifests:** Clicks register before the pen touches the screen.
    *   **Logic:** Pen pressure sensor reads > 0 while hovering.
    *   **Cause:** The pressure sensor inside the stylus tip is physically stuck or calibrated wrong.
1406. **The "Function Key" Inversion:**
    *   **Manifests:** User presses F5 to refresh, volume goes up instead.
    *   **Logic:** BIOS setting `Function Key Behavior` = Multimedia.
    *   **Cause:** Fn-Lock is engaged (hardware toggle), inverting standard keys.
1407. **Wacom Driver "Windows Ink" War:**
    *   **Manifests:** Photoshop canvas pans instead of painting.
    *   **Logic:** `Wisptis.exe` (Windows Ink) fighting the Wacom driver for pointer control.
    *   **Cause:** "Use Windows Ink" checkbox in tablet settings conflicts with app-specific API calls.
1408. **Mouse "Lift-Off" Jitter:**
    *   **Manifests:** Cursor jumps to ceiling when picking up the mouse.
    *   **Logic:** High DPI movement delta.
    *   **Cause:** Optical sensor Lift-Off Distance (LOD) is set too high for the mousepad surface.
1409. **Barcode Scanner "Enter" Key:**
    *   **Manifests:** Forms submit automatically before user finishes typing.
    *   **Logic:** Rapid text input followed by `VK_RETURN`.
    *   **Cause:** Handheld scanner is configured to send a "Carriage Return" suffix after every scan.
1410. **Game Controller "Screensaver" Block:**
    *   **Manifests:** PC never locks/sleeps.
    *   **Logic:** `powercfg /requests` shows nothing.
    *   **Cause:** A plugged-in joystick with a slight drift (0.1%) is sending constant "Input" events, resetting the idle timer.

### **SECTION 132: AUDIO & VIDEO "GREMLINS"**
1411. **Sample Rate Mismatch (The "Chipmunk" Effect):**
    *   **Manifests:** Microphone audio is sped up (high pitch) or slow (demon voice).
    *   **Logic:** Input device set to 48kHz, App expects 44.1kHz.
    *   **Cause:** Clock drift or driver mismatch without resampling.
1412. **Front Panel Jack Detection Fail:**
    *   **Manifests:** Headphones plugged in, sound still comes from speakers.
    *   **Logic:** Realtek Manager shows "Analog Back Panel" active.
    *   **Cause:** The physical sensing pin inside the 3.5mm jack is bent or the connector to the motherboard (HD Audio) is loose.
1413. **"Listen to this device" Loop:**
    *   **Manifests:** Echoing/Feedback loop that gets louder and louder.
    *   **Logic:** Registry `HKCU\Control Panel\Sound` -> `Listen` bit set.
    *   **Cause:** User enabled "Listen to this device" on the mic, feeding it back into the speakers.
    *   **Cause:** User enabled "Listen to this device" on the mic, feeding it back into the speakers.
1414. **HDMI "Sleep" Audio Loss:**
    *   **Manifests:** Audio works on TV until PC sleeps. On wake, silence.
    *   **Logic:** `Audiosrv` reports device invalidated.
    *   **Cause:** GPU driver failed to re-handshake HDCP audio encryption on wake.
1415. **Spatial Sound Crash:**
    *   **Manifests:** Game crashes immediately on launch.
    *   **Logic:** `DolbyAtmos.dll` or `Sonic.dll` fault.
    *   **Cause:** Game engine is incompatible with "Windows Sonic for Headphones" virtualization.
1416. **Webcam "Privacy" Shutter (Hardware):**
    *   **Manifests:** Camera is black. Driver is fine. LED is on.
    *   **Logic:** `Frames Delivered` counter increases, but pixel data is all #000000.
    *   **Cause:** The physical plastic slider is closed. (Surprisingly common "tech" issue).
1417. **USB Bandwidth "Robotic" Mic:**
    *   **Manifests:** Voice cuts out or sounds robotic during video calls.
    *   **Logic:** USB Controller `Isochronous Transfer` errors.
    *   **Cause:** 4K Webcam and USB Mic on the same root hub. Not enough reserved bandwidth for both streams.
1418. **Monitor "Deep Sleep" disconnect:**
    *   **Manifests:** Windows move to primary monitor every time user returns from lunch.
    *   **Logic:** `DisplayPort` Hot Plug Detect (HPD) event logged.
    *   **Cause:** Monitor enters "Deep Sleep" and physically disconnects from the bus, triggering Windows to rearrange desktops.
1419. **ICC Profile "Yellow" Photo Viewer:**
    *   **Manifests:** Photos look yellow in Windows Photo Viewer, fine in Chrome.
    *   **Logic:** `mscms.dll` reading a corrupted `.icm` profile.
    *   **Cause:** Windows Update installed a broken OEM color profile for the monitor.
1420. **Refresh Rate Mixing Stutter:**
    *   **Manifests:** 144Hz Main monitor lags when video plays on 60Hz Second monitor.
    *   **Logic:** DWM Frame Drops.
    *   **Cause:** Desktop Window Manager (DWM) struggling to V-Sync two different refresh rates simultaneously on one GPU.

### **SECTION 133: NETWORK "BLACK HOLES"**
1421. **The "Workday" VPN Limit:**
    *   **Manifests:** VPN connects fine, passes no traffic.
    *   **Logic:** `MTU` size fragmentation.
    *   **Cause:** Home ISP uses PPPoE (overhead), reducing MTU. VPN adds overhead. Packet size > effective MTU, and `Do Not Fragment` bit is set.
1422. **IPv6 "Link-Local" Broadcast Storm:**
    *   **Manifests:** WiFi slow.
    *   **Logic:** Wireshark shows thousands of `ICMPv6` Neighbor Discovery packets.
    *   **Cause:** A device on the network is misconfigured and looping multicast traffic.
    *   **Cause:** A device on the network is misconfigured and looping multicast traffic.
    *   **Cause:** A device on the network is misconfigured and looping multicast traffic.
1423. **QoS Packet Tagging Drop:**
    *   **Manifests:** VoIP app connects but audio is one-way.
    *   **Logic:** DSCP (Differentiated Services Code Point) value set to 46.
    *   **Cause:** Cheap home router sees the QoS tag, doesn't understand it, and drops the packet.
1424. **Network Location Awareness (NLA) Stuck:**
    *   **Manifests:** Firewall profile stays "Public" on Domain Network.
    *   **Logic:** `NlaSvc` fails to query DC via LDAP (Port 389).
    *   **Cause:** Switch portfast is disabled; PC boots faster than switch port negotiates, NLA fails detection and defaults to Public.
1425. **"Green Ethernet" Disconnects:**
    *   **Manifests:** Network drops for 2s randomly.
    *   **Logic:** Driver setting `Energy Efficient Ethernet` = On.
    *   **Cause:** NIC turns off power to the port during micro-idles. Switch interprets this as a cable pull.
1426. **WLAN "Background Scan" Lag:**
    *   **Manifests:** Online games spike lag every 60 seconds.
    *   **Logic:** WLAN AutoConfig service activity.
    *   **Cause:** Windows scans for better WiFi networks periodically. This scan requires tuning off the radio for 500ms.
1427. **TCP Window Scaling (Old Router):**
    *   **Manifests:** Downloads cap at 2Mbps on a 100Mbps line.
    *   **Logic:** TCP Window Size never grows above 64KB.
    *   **Cause:** Legacy router/firewall creates a "Window Scaling" incompatibility, stripping the scale factor option.
1428. **DNS "Smart Multi-Homed" Resolution:**
    *   **Manifests:** Internal DNS names fail to resolve when on VPN.
    *   **Logic:** DNS queries sent to all adapters; ISP responds "NXDOMAIN" faster than VPN responds "IP Found".
    *   **Cause:** Windows 10+ feature prioritizing the fastest DNS response, disregarding the interface metric in some scenarios.
1429. **Captive Portal Detection (NCSI) False Negative:**
    *   **Manifests:** "No Internet Access" globe icon, but internet works.
    *   **Logic:** HTTP GET to `www.msftconnecttest.com` fails.
    *   **Cause:** Corporate firewall blocks the specific Microsoft test URL, confusing the Network Connectivity Status Indicator.
1430. **SMB Direct (RDMA) over WiFi:**
    *   **Manifests:** File copies fail instantly.
    *   **Logic:** SMB Client attempts RDMA transfer.
    *   **Cause:** Driver bug reporting RDMA capability on a wireless interface that doesn't support it.

### **SECTION 134: FILESYSTEM "ARCHAEOLOGY"**
1431. **"Thumbs.db" Locking:**
    *   **Manifests:** Cannot delete folder "The action can't be completed because the file is open".
    *   **Logic:** `Explorer.exe` handle on `Thumbs.db`.
    *   **Cause:** Explorer is generating thumbnails for that folder in the background.
1432. **Desktop.ini "Hiding":**
    *   **Manifests:** Folder looks empty but isn't.
    *   **Logic:** `Desktop.ini` has `CLSID` entry pointing to a shell extension.
    *   **Cause:** Malware or prankster set the folder to behave like a "Recycle Bin" or "Control Panel" via `Desktop.ini`.
1433. **FAT32 4GB Limit (The "Generic" Error):**
    *   **Manifests:** Copying movie file to USB fails: "The file is too large for the destination file system".
    *   **Logic:** File size > 4GB. Target FS = FAT32.
    *   **Cause:** Standard file system limitation often misread by users as "Not enough space".
1434. **Long Path (>260) Legacy App Crash:**
    *   **Manifests:** App crashes opening file.
    *   **Logic:** `CreateFile` returns `PathTooLong`.
    *   **Cause:** Even if Windows 10 "Long Paths" is enabled, the specific application is built on an old .NET/Win32 version that doesn't support it.
1435. **The "Dot" Folder (Naming):**
    *   **Manifests:** Cannot delete folder named `Con.` or `Folder.`
    *   **Logic:** Trailing dot is stripped by Win32 API.
    *   **Cause:** Created via command line or Linux. Needs `\\?\C:\Path\Folder.` syntax to remove.
1436. **WebDAV File Lock:**
    *   **Manifests:** Word document "Locked for editing by 'Another User'".
    *   **Logic:** `LockFile` call on URL.
    *   **Cause:** A WebDAV (SharePoint) session crashed leaving a persistent lock file on the server.
1437. **Metadata "Date Taken" Sorting:**
    *   **Manifests:** Photos sort randomly.
    *   **Logic:** Explorer sorting by "Date", not "Date Modified".
    *   **Cause:** "Date" column uses EXIF metadata (Date Taken) which might be missing or wrong in the camera.
1438. **Symbolic Link Cycle (Backup):**
    *   **Manifests:** Backup drive fills up with infinite nested folders `\App\App\App...`
    *   **Logic:** Symlink points to parent folder.
    *   **Cause:** Badly created Junction Point.
1439. **File Stream "Zone" Propagation:**
    *   **Manifests:** Unzipping a file makes all contents "Blocked".
    *   **Logic:** `Zone.Identifier` stream copied to children.
    *   **Cause:** Windows Archive extraction propagates the "Mark of the Web" to all extracted files.
1440. **"System Volume Information" Ownership:**
    *   **Manifests:** Drive space missing.
    *   **Logic:** VSS Shadow Copies consuming space. Admin cannot see folder size.
    *   **Cause:** Permissions on `System Volume Information` exclude Administrators by default.

### **SECTION 135: REGISTRY & CONFIG "ROT"**
1441. **ShutdownWithoutLogon:**
    *   **Manifests:** Shutdown button missing from login screen.
    *   **Logic:** Registry `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System` -> `ShutdownWithoutLogon` = 0.
    *   **Cause:** Security policy hidden setting.
1442. **UserAssist "ROT13" Corruption:**
    *   **Manifests:** Start Menu "Frequently Used" is empty.
    *   **Logic:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist`.
    *   **Cause:** The ROT13 encoded tracking data is corrupt.
1443. **ShellBags Off-Screen:**
    *   **Manifests:** Opening a folder makes nothing happen (Window is off-screen).
    *   **Logic:** `WindowPos` coordinates in Registry are huge positive/negative numbers.
    *   **Cause:** Saved window position from a previous multi-monitor setup.
1444. **"Winlogon" Shell Replacement:**
    *   **Manifests:** PC boots to a Command Prompt only.
    *   **Logic:** `HKLM\...\Winlogon` -> `Shell` = `cmd.exe`.
    *   **Cause:** Malware or failed Kiosk Mode setup.
1445. **AutoAdminLogon Loop:**
    *   **Manifests:** PC reboots and logs in indefinitely.
    *   **Logic:** `HKLM\...\Winlogon` -> `AutoAdminLogon` = 1, `ForceAutoLogon` = 1.
    *   **Cause:** Config management script set force logon but didn't disable it after task completion.
1446. **Background Intelligent Transfer (BITS) Job Rot:**
    *   **Manifests:** Network slow.
    *   **Logic:** `bitsadmin /list /all` shows 500 queued jobs.
    *   **Cause:** Windows Update or Chrome Update created jobs that failed, and they are retrying forever.
1447. **Firewall "Block All" Panic:**
    *   **Manifests:** No network access.
    *   **Logic:** Registry `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy` -> `EnableFirewall` = 1, `DefaultInboundAction` = 1 (Block).
    *   **Cause:** User clicked "Block All" in a panic popup.
1448. **Environment Variable Path Truncation:**
    *   **Manifests:** Random CMD tools "Not Recognized".
    *   **Logic:** `%PATH%` > 2048 characters.
    *   **Cause:** Too many installed dev tools appended to PATH, truncating the system entries at the end.
1449. **"Debugger" Image Hijack (Not Malware):**
    *   **Manifests:** `Notepad.exe` opens `Notepad++.exe`.
    *   **Logic:** `Image File Execution Options` -> `Debugger`.
    *   **Cause:** Legitimate replacement of system tools by a power user utility, forgotten 2 years later.
1450. **Drive Letter "Stickiness":**
    *   **Manifests:** USB Drive doesn't appear.
    *   **Logic:** `MountedDevices` registry.
    *   **Cause:** The drive is assigned letter `E:`, but `E:` is currently mapped to a Network Share.

### **SECTION 136: HARDWARE & PHYSICS "INTERFERENCE"**
1451. **Static Discharge (The "Carpet" Reboot):**
    *   **Manifests:** PC reboots when user sits down.
    *   **Logic:** No Event Log (Hard Reset).
    *   **Cause:** ESD (Electrostatic Discharge) from chair/carpet jumping to the USB port or metal chassis.
1452. **Ground Loop Hum:**
    *   **Manifests:** Speakers buzz when mouse moves.
    *   **Logic:** EMI bleeding into audio path.
    *   **Cause:** PC and Speakers plugged into different wall outlets with different ground potentials.
1453. **HDD Free-Fall Sensor Trigger:**
    *   **Manifests:** Laptop freezes for 2s when user bangs desk.
    *   **Logic:** Accelerometer `Park Heads` event.
    *   **Cause:** Vibration protection sensitivity too high.
1454. **Piezoelectric "Singing" Capacitor:**
    *   **Manifests:** High pitched whine from laptop.
    *   **Logic:** Correlates with CPU load.
    *   **Cause:** Ceramic capacitors vibrating at audible frequencies (Coil Whine).
1455. **Thermal Throttling (Dust):**
    *   **Manifests:** Gaming FPS drops after 10 mins.
    *   **Logic:** `Kernel-Processor-Power` Event 37.
    *   **Cause:** Heatsink clogged with dust.
1456. **Battery Calibration Drift:**
    *   **Manifests:** Laptop shuts down at 30% battery.
    *   **Logic:** Voltage drops below cutoff.
    *   **Cause:** BMS (Battery Management System) lost track of actual capacity cells. Needs full cycle.
1457. **The "Hair" in the Optical Mouse:**
    *   **Manifests:** Mouse cursor jitters.
    *   **Cause:** A single hair trapped in the sensor well.
1458. **Dirty Power (Brownouts):**
    *   **Manifests:** PC reboots at random times.
    *   **Logic:** Kernel-Power Event 41.
    *   **Cause:** Voltage sag from A/C or laser printer on same circuit.
1459. **Loose RAM Stick:**
    *   **Manifests:** Random BSODs (various codes).
    *   **Logic:** `MemTest` fails.
    *   **Cause:** RAM stick unseated by thermal expansion/contraction.
1460. **SATA Cable Corruption:**
    *   **Manifests:** Disk CRC errors.
    *   **Logic:** `Disk` Event 11.
    *   **Cause:** Cheap SATA cable shielding failure causing bit rot.

### **SECTION 137: 3RD PARTY "OVERLAY" WARS**
1461. **Discord Overlay Crash:**
    *   **Manifests:** Games crash on launch.
    *   **Logic:** `DiscordHook64.dll` in stack trace.
    *   **Cause:** Discord overlay fighting with game anti-cheat.
1462. **FPS Counter Injection:**
    *   **Manifests:** App UI flickers.
    *   **Logic:** `RTSSHooks.dll` (RivaTuner) loaded.
    *   **Cause:** Statistics overlay trying to hook a non-game GUI (like Browser or Office).
1463. **Clipboard Manager Conflict:**
    *   **Manifests:** Copy/Paste delay.
    *   **Logic:** `OpenClipboard` fail.
    *   **Cause:** Clipboard history tool polling too aggressively.
1464. **"Game Booster" Process Kill:**
    *   **Manifests:** Work apps close when launching Steam.
    *   **Logic:** Process Termination event.
    *   **Cause:** "Optimizer" software configured to "Free RAM" by killing background tasks.
1465. **RGB Software Driver Leak:**
    *   **Manifests:** System slow after 3 days.
    *   **Logic:** `LightingService.exe` High Non-Paged Pool.
    *   **Cause:** Poorly coded RGB controller driver leaking memory.
1466. **Virtual Camera "Black Screen":**
    *   **Manifests:** Zoom camera is black.
    *   **Logic:** `OBS Virtual Camera` selected as default.
    *   **Cause:** OBS is not running, so the virtual input is sending blank frames.
1467. **VPN "Kill Switch" Lock:**
    *   **Manifests:** No internet even with VPN off.
    *   **Logic:** Routing table empty.
    *   **Cause:** VPN client crashed while "Kill Switch" was active, leaving network disabled to prevent leaks.
1468. **Antivirus "HTTPS Scanning":**
    *   **Manifests:** Browser Certificate Errors (Unknown Issuer).
    *   **Logic:** Issuer is "Antivirus CA".
    *   **Cause:** AV is performing Man-in-the-Middle TLS inspection, but its Root CA is not trusted by Firefox/Java.
1469. **Explorer Shell Extension Crash:**
    *   **Manifests:** Right-click desktop -> Explorer restarts.
    *   **Logic:** Crash in `ContextMenu` DLL.
    *   **Cause:** Buggy menu entry from uninstalled software.
1470. **Focus Assist "Duplication":**
    *   **Manifests:** No notifications.
    *   **Logic:** "When I am duplicating my display" rule active.
    *   **Cause:** User has a phantom second monitor or projector mode enabled.

### **SECTION 138: PROFILE & ACCOUNT "SINGULARITIES"**
1471. **The "TEMP" Profile Loop:**
    *   **Manifests:** "We can't sign into your account".
    *   **Logic:** `ProfileList` has `.bak` SID.
    *   **Cause:** Registry points to profile that fails to load; Windows loads Temp, fails to save, repeats.
    *   **Cause:** Registry points to profile that fails to load; Windows loads Temp, fails to save, repeats.
1472. **User Service (UUID) Fail:**
    *   **Manifests:** Login "User Profile Service failed the logon".
    *   **Logic:** `ProfSvc` crash.
    *   **Cause:** Permissions on `C:\Users\Default` are wrong, so new profile creation fails.
1473. **Corrupt "Ntuser.dat":**
    *   **Manifests:** Settings don't save.
    *   **Logic:** Registry load fail.
    *   **Cause:** Unexpected shutdown while writing user hive.
1474. **"Guest" Account confusion:**
    *   **Manifests:** User logs in, has no files.
    *   **Logic:** Profile path `C:\Users\User.GUEST`.
    *   **Cause:** Account was added to local "Guests" group by mistake.
1475. **SID Mismatch (Domain Trust):**
    *   **Manifests:** "The security database on the server does not have a computer account".
    *   **Logic:** Machine Trust broken.
    *   **Cause:** PC rejoined domain with same name but new SID. AD object out of sync.
1476. **Credential Vault "Max Size":**
    *   **Manifests:** Chrome forgets passwords daily.
    *   **Logic:** Vault Error.
    *   **Cause:** Roaming Profile size limit hitting `AppData` vault files.
1477. **OneDrive "Known Folder" Hijack:**
    *   **Manifests:** Desktop empty after uninstalling OneDrive.
    *   **Logic:** Shell Folders point to `C:\Users\User\OneDrive\Desktop`.
    *   **Cause:** Uninstallation didn't revert the folder redirection.
1478. **Quick Access "FTP" Freeze:**
    *   **Manifests:** Explorer hangs.
    *   **Logic:** `Explorer` connecting to FTP site.
    *   **Cause:** "Recent Files" contains a link to a slow FTP server.
1479. **Library "Optimization" Slowdown:**
    *   **Manifests:** Downloads folder opens slowly.
    *   **Logic:** Folder type = "Pictures" (scanning for thumbnails).
    *   **Cause:** Automatic Folder Type Discovery decided "Downloads" is a Photo Album because you downloaded 5 JPGs.
1480. **"Account Unknown" SIDs:**
    *   **Manifests:** ACLs full of S-1-5-21-....
    *   **Cause:** Files migrated from old installation; SIDs don't resolve to current users.

### **SECTION 139: THE "TIME" ANOMALIES**
1481. **CMOS Battery Death:**
    *   **Manifests:** Date is Jan 1, 1980 on boot. HTTPS fails.
    *   **Cause:** RTC battery dead.
1482. **Time Zone "Auto" Fail:**
    *   **Manifests:** Time is off by 3 hours.
    *   **Logic:** `tzautoupdate` service.
    *   **Cause:** Geo-IP lookup thinks VPN exit node (California) is physical location, overrides local time (New York).
1483. **Kerberos Time Skew:**
    *   **Manifests:** "Logon Failure" on file share.
    *   **Logic:** Client time > 5 mins difference from DC.
    *   **Cause:** Windows Time Service sync failure.
1484. **Excel 1900 Date System:**
    *   **Manifests:** Dates copy-pasted from Mac are 4 years off.
    *   **Cause:** Excel for Mac used 1904 date system; Windows uses 1900.
1485. **"Last Modified" Paradox:**
    *   **Manifests:** File modified date is before creation date.
    *   **Cause:** File copied from another volume preserves Mod time, but Creation time is "Now".
1486. **DST Patch Missing:**
    *   **Manifests:** Meetings are 1 hour off for 2 weeks in March.
    *   **Cause:** OS missing Daylight Savings Time update for specific time zone.
1487. **BIOS Clock Drift:**
    *   **Manifests:** Clock loses 10 mins per day.
    *   **Cause:** Failing motherboard oscillator.
1488. **Leap Year Bug (Custom App):**
    *   **Manifests:** App crashes on Feb 29.
    *   **Cause:** Hardcoded "365 days" logic.
1489. **Region Format "AM/PM":**
    *   **Manifests:** App parses "14:00" as error.
    *   **Cause:** User region set to US (12h), App expects 24h input.
1490. **Uptime Counter Overflow:**
    *   **Manifests:** Systems crashing after 49.7 days.
    *   **Logic:** `GetTickCount` (32-bit) rollover.
    *   **Cause:** Ancient driver using 32-bit millisecond counter.

### **SECTION 140: THE "TRULY UNEXPLAINABLE" LOGIC BUGS**
1491. **The "Desktop Heap" exhaustion (User):**
    *   **Manifests:** Cannot open new windows, but PC has 32GB RAM free.
    *   **Logic:** `User32` resource fail.
    *   **Cause:** Too many hooks/objects allocated in the interactive session heap (20MB limit).
1492. **Atom Table Exhaustion:**
    *   **Manifests:** App crashes "Cannot add atom".
    *   **Logic:** `GlobalAddAtom` fail.
    *   **Cause:** App leaking global atoms (strings), filling the 64k table.
1493. **GDI Object Limit (10,000):**
    *   **Manifests:** Elements of UI disappear/black out.
    *   **Logic:** Task Manager GDI Objects = 10,000.
    *   **Cause:** Hard limit per process. App leak.
1494. **Handle Leak (Kernel Paged Pool):**
    *   **Manifests:** System slow.
    *   **Logic:** `Paged Pool` high.
    *   **Cause:** Driver leaking registry handles.
1495. **"Magic" Packet Wake:**
    *   **Manifests:** PC turns on when phone connects to WiFi.
    *   **Logic:** Wake on LAN (Pattern Match).
    *   **Cause:** NIC configured to wake on "Pattern Match", interpreting arbitrary broadcast traffic as a wake signal.
1496. **BitLocker "Used Space Only" Encryption:**
    *   **Manifests:** Undelete tools fail on "Empty" space.
    *   **Cause:** BitLocker only encrypted written data; free space is technically "clear" but scrambled by metadata capability.
1497. **Fonts "Non-System" Block:**
    *   **Manifests:** App shows boxes.
    *   **Logic:** `MitigationPolicy` event.
    *   **Cause:** "Block untrusted fonts" security policy enabled.
1498. **AppContainer Network Isolation:**
    *   **Manifests:** Store App cannot connect to localhost.
    *   **Logic:** `CheckNetIsolation` loopback exempt missing.
    *   **Cause:** UWP Security feature blocking loopback.
1499. **"OOBE" Complete Flag:**
    *   **Manifests:** Start menu search broken.
    *   **Logic:** `OOBEComplete` registry mismatch.
    *   **Cause:** Search Indexer waits for Out-Of-Box-Experience to finish; if flag stuck, it never indexes.
1500. **The "Null" Window Class:**
    *   **Manifests:** Explorer crash.
    *   **Logic:** `CreateWindow` with NULL class.
    *   **Cause:** Race condition in shell extension initialization.

Here is the Master Definition List for your ProcMon Analyzer script.

I have consolidated the ~600 scenarios from our conversation into High-Fidelity Detection Patterns, grouped by the technical logic the script must perform. This format is optimized for implementation: it defines the Category, the Signature (what to look for), and the Root Cause/Fix context.

1. Permission & Access Control (The "Access Denied" Family)
These checks detect when an application is blocked by OS security boundaries.

File Write Denied: CreateFile / WriteFile returns ACCESS DENIED.

Context: User lacks NTFS write permissions. Fix: Check ACLs.

Registry Write Denied: RegCreateKey / RegSetValue returns ACCESS DENIED.

Context: App trying to write to HKLM or System keys as a standard user. Fix: Run as Admin or shim the app.

Process Open Denied: OpenProcess returns ACCESS DENIED.

Context: App trying to inspect a higher-integrity process (Anti-Cheat/AV). Fix: Usually by design; whitelist if legitimate.

Delete Pending Lock: CreateFile returns STATUS_DELETE_PENDING.

Context: File is deleted but a handle is still open. Fix: Restart the process holding the handle.

Privilege Not Held: Result STATUS_PRIVILEGE_NOT_HELD.

Context: App calling API requiring specific privilege (e.g., SeDebugPrivilege). Fix: Grant privilege via Policy or run Elevated.

UAC Virtualization Write: Success writing to %LocalAppData%\VirtualStore.

Context: App tried writing to C:\Windows; OS redirected it. Fix: App is legacy/badly coded.

ADS Block (Mark of Web): CreateFile on Zone.Identifier returns ACCESS DENIED.

Context: Security tool blocking access to downloaded file metadata. Fix: Unblock file.

EFS Access Denied: ACCESS DENIED on a Green (Encrypted) file by different user.

Context: Encrypted File System key mismatch. Fix: Import cert or decrypt.

DCOM Launch Denied: ACCESS DENIED on HKCR\AppID\{GUID}.

Context: User lacks DCOM permissions. Fix: dcomcnfg.

Protected Process Light (PPL): Injection failure into MsMpEng.exe or csrss.exe.

Context: App trying to hook a system-protected process.

2. Missing Resources (The "Not Found" Family)
These checks detect "DLL Hell," broken configurations, and missing dependencies.

Missing DLL (Loader): LoadImage / CreateFile returns NAME/PATH NOT FOUND for .dll.

Context: Critical library missing. Fix: Install redistributable.

Missing System DSN: RegOpenKey fail HKLM\SOFTWARE\ODBC\ODBC.INI\<DSN>.

Context: ODBC connection missing. Fix: ODBC Admin.

COM Class Missing: RegOpenKey fail HKCR\CLSID\{GUID}.

Context: COM object not registered. Fix: regsvr32.

Side-by-Side (SxS) Fail: NAME NOT FOUND on Manifest or Config files.

Context: Version mismatch in C++ runtimes. Fix: Install correct VC++ Redist.

Font Missing: LoadImage fail for .ttf / RegQueryValue fail FontSubstitutes.

Context: UI rendering failure. Fix: Install font.

Java/Python Home Missing: Environment variable lookup fails or returns empty.

Context: Runtime path not set. Fix: Set %JAVA_HOME%.

Hardcoded Path Fail: PATH NOT FOUND on C:\Users\DeveloperName.

Context: Poorly coded app looking for dev's machine path. Fix: Create path or patch app.

GPO Template Missing: ReadFile fail \\Domain\Sysvol\...\gpt.ini.

Context: Network/DNS issue reaching Domain Controller.

MUI Resource Missing: NAME NOT FOUND for .mui files.

Context: Language pack missing. Fix: Install language pack.

App-V/Virtual File Missing: PATH NOT FOUND for file existing in bubble.

Context: Process running outside virtual environment. Fix: Run inside bubble.

3. Locking & Concurrency (The "Sharing Violation" Family)
These checks detect race conditions, deadlocks, and resource contention.

File Locked: CreateFile returns SHARING VIOLATION.

Context: Two apps fighting for one file. Fix: Close other app / Exclude from AV.

Profile Locked: SHARING VIOLATION on NTUSER.DAT.

Context: User hive locked, causing temp profile load.

Oplock Break: FsRtlCheckOplock operations with high duration.

Context: Network file locking delay. Fix: Disable Oplocks (carefully).

Pipe Busy: CreateFile returns STATUS_PIPE_BUSY.

Context: Named pipe server instance full. Fix: Increase instances in server code.

Mutex Contention: Loops of OpenMutex -> Wait.

Context: Waiting for single-instance app or installer.

FSLogix VHD Lock: SHARING VIOLATION on .vhdx.

Context: Session ghosted on another host.

Clipboard Locked: OpenClipboard fail.

Context: Another app (RDP/Manager) holding clipboard chain.

4. Network & Communications (The "Connectivity" Family)
These checks detect connectivity drops, latency, and firewall issues.

Port Unreachable: TCP Connect returns CONNECTION REFUSED.

Context: Service down or firewall blocking.

Name Resolution Fail: UDP Send (DNS) returns NAME NOT FOUND.

Context: Typo in hostname or DNS server down.

Ephemeral Port Exhaustion: TCP Connect returns STATUS_ADDRESS_IN_USE.

Context: Out of outbound ports. Fix: Increase dynamic range.

Bad Network Path: CreateFile (UNC) returns BAD NETWORK PATH / NETWORK UNREACHABLE.

Context: Routing issue or server offline.

SMB Version Mismatch: Handshake failures on Port 445.

Context: SMB1 disabled but required.

Proxy Auto-Config (PAC) Lag: TCP Connect to WPAD timeout > 2s.

Context: Slow proxy detection. Fix: Disable Auto-Detect.

Keep-Alive Drop: TCP Disconnect exactly at 60s/120s.

Context: Firewall idle timeout. Fix: Enable Keep-Alives.

IPv6 Failover: TCP Connect (IPv6) Fail -> Wait -> TCP Connect (IPv4).

Context: Latency via broken IPv6. Fix: Disable IPv6.

Certificate Revocation Hang: TCP Connect to OCSP server fail/hang.

Context: App checking CRL. Fix: Allow OCSP on firewall.

5. Stability & Performance (The "Degradation" Family)
These checks detect resource exhaustion, crashes, and "rot".

Memory Exhaustion: CreateFile / RegOpenKey returns STATUS_INSUFFICIENT_RESOURCES.

Context: Paged pool/Handle leak.

Process Crash: Process Exit with code != 0 and != 1.

Context: Unhandled exception.

WerFault Trigger: Process Create WerFault.exe.

Context: Windows Error Reporting catching a crash.

Disk Full: WriteFile returns DISK FULL.

Context: Volume out of space or Quota hit.

Registry Hammering: >10,000 Reads to same key in <1 min.

Context: Polling loop. Fix: Fix app logic.

File I/O Churn: >1,000 Creates/Deletes in %TEMP% in <1 min.

Context: Inefficient temp usage.

One-Byte I/O: ReadFile / WriteFile with Length: 1.

Context: Extreme inefficiency.

Buffer Overflow (Reg): RegQueryValue returns BUFFER OVERFLOW.

Context: Data larger than expected buffer.

Terminate Process: One process calling TerminateProcess on another.

Context: Watchdog killing a hung app.

System Commit Limit: STATUS_COMMITMENT_LIMIT.

Context: Pagefile full.

6. Security & Forensics (The "Malice" Family)
These checks detect persistence, evasion, and suspicious behavior.

Persistence (Run Key): Write to HKCU\...\Run or HKLM\...\Run.

Persistence (Startup): File create in Startup folder.

Persistence (Service): Write to HKLM\System\CurrentControlSet\Services.

Credential Dumping: Access to lsass.exe or SAM hive.

Shadow Copy Delete: Process Create vssadmin delete shadows.

Log Clearing: Process Create wevtutil cl.

LoLBin Execution: powershell.exe -enc, mshta.exe, rundll32.exe.

Hosts File Mod: Write to drivers\etc\hosts.

Masquerading: svchost.exe running from non-System32 path.

Ransomware Pattern: Mass Rename or Mass Read/Write/Delete sequence.

Reconnaissance: Execution of whoami, net group, systeminfo.

Browser Injection: Writes to Chrome\User Data by non-Chrome process.

Zone.Identifier Wipe: Deletion of ADS stream (Anti-Forensics).

Debugger Hijack (IFEO): Write to Image File Execution Options.

7. Accessibility & UI Automation (The "Assistive" Family)
These checks detect failures in screen readers and automation.

WM_GETOBJECT Hang: postmessage WM_GETOBJECT timeout.

Context: UI not responding to accessibility probes.

UIA Provider Fail: RegOpenKey fail for UIA Proxy/Stub.

Context: UI Automation pattern unavailable.

Java Access Bridge Fail: LoadImage fail WindowsAccessBridge.dll.

Context: Java apps silent to screen reader.

AccName Missing: UI Object checks with empty return values.

Focus Fighting: Infinite loops of SetFocus.

Narrator Hook Fail: LoadImage fail NarratorHook.dll.

Braille Driver Lock: CreateFile fail on COM/HID port.

High Contrast Query: App reading hardcoded colors (ignoring GetSysColor).

Cursor/Caret Tracking: Failures in GetGUIThreadInfo.

Speech Config Write: ACCESS DENIED on Speech user dictionary.

8. Infrastructure & Enterprise (The "Admin" Family)
These checks detect Citrix, GPO, MSI, and Print Spooler issues.

Installer Source Fail: MsiExec PATH NOT FOUND on SourceList.

Context: MSI needs original media.

Installer Rollback: MsiExec SetRenameInformationFile (Restore).

Context: Fatal install error.

Print Spooler Crash: Process Exit spoolsv.exe.

Driver Isolation: Process Exit PrintIsolationHost.exe.

Context: Bad printer driver.

Citrix Hook Block: LoadImage fail CtxHk.dll.

Context: AV blocking Citrix hooks.

Roaming Profile Latency: ReadFile > 500ms on \\Server\Profiles.

Context: Slow logon.

AppLocker Block: Process Create fail due to Policy.

Group Policy Script: gpscript.exe exit code failure.

WEM Agent Churn: Norskale Agent high registry activity.

ThinPrint Fail: TPAutoConnect.exe crash.

9. Legacy & Compatibility (The "Old School" Family)
These checks detect issues with old apps running on modern Windows.

INI Redirection: Reads to win.ini / system.ini.

Context: 16-bit/Win9x legacy code.

8.3 Name Fail: PATH NOT FOUND C:\PROGRA~1.

Context: Short names disabled on volume.

Shim DB Read: Heavy reads sysmain.sdb.

Context: Windows applying compatibility patches.

DirectX Legacy: LoadImage fail d3dx9.dll.

VB6/MFC Missing: LoadImage fail msvbvm60.dll.

Depreciated Driver: Load fail \Device\Parallel.

Hardcoded Drive: PATH NOT FOUND D:\.

Admin Requirement: Writes to Program Files redirected to VirtualStore.

CD-ROM Check: Access to \Device\CdRom.

16-bit Thunk: LoadImage fail thunk.dll.

10. Edge Cases & Miscellaneous
Symbolic Link Loop: REPARSE_POINT_NOT_RESOLVED.

Sparse File Fail: Write fail on sparse region.

Case Sensitivity: PATH NOT FOUND File vs file.

Max Path: Path length > 260 chars failure.

Invalid Char: STATUS_OBJECT_NAME_INVALID (?, |).

Offline File: STATUS_FILE_IS_OFFLINE (Cloud tiering).

Clipboard Chain Full: OpenClipboard fail (Saturation).

Global Atom Leak: GlobalAddAtom fail.

User Hive Corrupt: STATUS_REGISTRY_CORRUPT.

System Clock Jump: SetSystemTime large delta.



    Here is a list of 100 distinct scenarios designed for a "Mark Russinovich in a box" PowerShell script. These focus on **detectable technical signatures** in a ProcMon trace, complete with the logic to find them, why they happen, and how to fix them.

### **Database & Data Connectivity (ODBC / SQL)**

1. **Missing System DSN:**
* **Detect:** `RegOpenKey` failure on `HKLM\SOFTWARE\ODBC\ODBC.INI\<DSN_Name>`.
* **Explain:** App expects a System DSN (machine-wide) but can't find it.
* **Fix:** Create the DSN in ODBC Administrator (64-bit or 32-bit explicitly).


2. **User DSN Visibility:**
* **Detect:** `RegOpenKey` success on `HKCU\Software\ODBC\ODBC.INI` but subsequent application failure.
* **Explain:** Service account or other user context cannot see `HKCU` DSNs.
* **Fix:** Move DSN to System DSN (`HKLM`).


3. **Oracle TNSNames Missing:**
* **Detect:** `CreateFile` `PATH NOT FOUND` for `tnsnames.ora`.
* **Explain:** Oracle client cannot resolve connection alias.
* **Fix:** Verify `TNS_ADMIN` environment variable or place `tnsnames.ora` in `%ORACLE_HOME%\network\admin`.


4. **SQL Native Client Missing:**
* **Detect:** `LoadImage` failure for `sqlncli11.dll` or `msodbcsql.dll`.
* **Explain:** App requires a specific version of the SQL driver not present.
* **Fix:** Install the specific SQL Native Client or ODBC Driver required.


5. **SQL Named Pipe Failure:**
* **Detect:** `CreateFile` failure on `\\.\pipe\sql\query` or similar.
* **Explain:** App trying to connect via Named Pipes, but SQL Server is configured for TCP-only.
* **Fix:** Enable Named Pipes in SQL Configuration Manager or force TCP in connection string.


6. **UDL File Access Denied:**
* **Detect:** `ACCESS DENIED` on `.udl` file read.
* **Explain:** Data Link file used for connection strings is permission-locked.
* **Fix:** Grant Read permissions to the user/service account on the UDL file.


7. **32/64-bit ODBC Mismatch:**
* **Detect:** `RegOpenKey` failure in `HKLM\SOFTWARE\Wow6432Node\ODBC` (or vice versa).
* **Explain:** 32-bit app looking for 64-bit DSN (or vice versa).
* **Fix:** Create DSN in the correct ODBC Administrator (`C:\Windows\SysWOW64\odbcad32.exe` for 32-bit).


8. **ADO Connection String Parse Fail:**
* **Detect:** Registry lookup failures for `HKCR\CLSID\{Provider_GUID}` immediately preceding exit.
* **Explain:** OLEDB Provider specified in connection string is not registered.
* **Fix:** Register the DLL (`regsvr32`) or install the specific OLEDB provider.


9. **SQL Port Blocking:**
* **Detect:** `TCP Connect` to Port 1433 result `CONNECTION REFUSED` or `TIMEOUT`.
* **Explain:** Firewall dropping traffic or SQL Browser service not running (for dynamic ports).
* **Fix:** Check Firewall rules and SQL Browser service status.


10. **Command Timeout:**
* **Detect:** `TCP Receive` success, followed by 30s delay, then `TCP Disconnect`.
* **Explain:** Query took longer than the default `CommandTimeout` (usually 30s).
* **Fix:** Optimize SQL query or increase timeout in app config.



### **Printing & Spooler Subsystem**

11. **Printer Driver Isolation Crash:**
* **Detect:** `Process Exit` for `PrintIsolationHost.exe`.
* **Explain:** A buggy printer driver crashed the isolation host, not the app.
* **Fix:** Update driver or disable Driver Isolation (Group Policy).


12. **Spooler RPC Failure:**
* **Detect:** `CreateFile` failure on `\RPC Control\spoolss`.
* **Explain:** Print Spooler service is stopped or hanging.
* **Fix:** Restart Print Spooler service (`net stop spooler`).


13. **Temp Print File Access:**
* **Detect:** `ACCESS DENIED` creating files in `C:\Windows\System32\spool\PRINTERS`.
* **Explain:** User lacks permission to write spool files.
* **Fix:** Adjust permissions on the PRINTERS folder (or temp folder used by driver).


14. **Missing Font Substitution:**
* **Detect:** `RegQueryValue` failure in `HKLM\...\FontSubstitutes` followed by `LoadImage` fail.
* **Explain:** App requests a font that doesn't exist and no substitute is defined.
* **Fix:** Install the missing font or add a registry substitution.
* * **Fix:** Install the missing font or add a registry substitution.




15. **ICC Profile Missing:**
* **Detect:** `PATH NOT FOUND` for `.icc` or `.icm` files in `\System32\spool\drivers\color`.
* **Explain:** Color management failing due to missing profile.
* **Fix:** Reinstall printer driver or manually copy the color profile.


16. **Bi-Directional Support Fail:**
* **Detect:** Registry failures on `BiDi` keys or SNMP timeouts.
* **Explain:** Driver trying to query printer status (ink levels) and failing.
* **Fix:** Disable "Enable Bidirectional Support" in Printer Properties > Ports.


17. **Invalid Printer Share:**
* **Detect:** `CreateFile` `BAD NETWORK PATH` on `\\Server\PrinterShare`.
* **Explain:** Shared printer no longer exists or server is offline.
* **Fix:** Remove or update the mapped printer connection.


18. **Splwow64 Latency:**
* **Detect:** 32-bit App waits on `splwow64.exe` (LPC Wait) for >5s.
* **Explain:** Thunking layer between 32-bit app and 64-bit spooler is hung.
* **Fix:** Kill `splwow64.exe` (it auto-restarts) or update drivers.


19. **Default Printer Registry:**
* **Detect:** App queries `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Device` and gets `NAME NOT FOUND`.
* **Explain:** No default printer selected.
* **Fix:** Set a default printer.


20. **PostScript PPD Missing:**
* **Detect:** `PATH NOT FOUND` for `.ppd` file.
* **Explain:** PostScript driver cannot find printer description file.
* **Fix:** Reinstall driver or restore PPD file.



### **Installers (MSI) & Updates**

21. **MSI Source List Exhaustion:**
* **Detect:** `MsiExec.exe` queries `Sourcelist` keys, then checks multiple paths (CD, Net, Local), all `PATH NOT FOUND`.
* **Explain:** Installer needs original `.msi` to repair/modify, but can't find it.
* **Fix:** Point installer to valid source media.


22. **Transform (.mst) Missing:**
* **Detect:** `PATH NOT FOUND` for a `.mst` file referenced in `HKLM\...\Installer\Products`.
* **Explain:** App installed with a transform that is now missing; breaks repair/uninstall.
* **Fix:** Restore .mst to `C:\Windows\Installer` or recache the installer.


23. **Cabinet Extraction Fail:**
* **Detect:** `WriteFile` failure (Disk Full/Access Denied) on `%TEMP%\~msi...tmp`.
* **Explain:** Not enough space or permissions to extract installer files.
* **Fix:** Clear Temp or fix permissions.


24. **Custom Action Script Failure:**
* **Detect:** `MsiExec` spawns `cmd.exe` or `cscript.exe` which exits with code `!= 0`.
* **Explain:** Installation script logic failed (e.g., trying to copy file that doesn't exist).
* **Fix:** Debug the specific custom action script.


25. **Installer Mutex Contention:**
* **Detect:** `MsiExec` loops `OpenMutex` on `_MSIExecute` and waits.
* **Explain:** Another installation is currently running.
* **Fix:** Wait for other install to finish or kill stuck `msiexec` processes.


26. **Rollback Triggered:**
* **Detect:** `MsiExec` performing `SetRenameInformationFile` to restore backup files.
* **Explain:** Fatal error occurred, MSI is reverting changes.
* **Fix:** Look at the events *immediately preceding* the rollback start.


27. **Pending Reboot Check:**
* **Detect:** Installer queries `Session Manager\PendingFileRenameOperations`.
* **Explain:** Installer pauses/fails because a reboot is pending.
* **Fix:** Reboot the machine.


28. **Windows Update Service Lock:**
* **Detect:** `MsiExec` fails to start `wuauserv` (Access Denied).
* **Explain:** Installer trying to check for updates but blocked by policy/permissions.
* **Fix:** Check GPO for Windows Update access.


29. **Uninstall Key Corruption:**
* **Detect:** `RegOpenKey` `NAME NOT FOUND` or `IsKeyDeleted` on `HKLM\...\Uninstall\{GUID}`.
* **Explain:** Registry corrupted, Add/Remove programs fails.
* **Fix:** Use Microsoft Install/Uninstall Troubleshooter (FixIt).


30. **Self-Repair Loop:**
* **Detect:** App launch triggers `MsiExec`, which runs, exits, and App launches `MsiExec` again.
* **Explain:** A "KeyPath" (file/reg key) is missing, triggering repair, but repair fails to put it back.
* **Fix:** Identify missing KeyPath in Event Viewer/ProcMon and manually create it.



### **Group Policy & User Profile**

31. **GPT.ini Access:**
* **Detect:** `ReadFile` `ACCESS DENIED` or `NETWORK PATH NOT FOUND` on `\\Domain\Sysvol\...\gpt.ini`.
* **Explain:** Computer cannot read Group Policy template.
* **Fix:** Check DNS, Network connectivity, or Domain membership.


32. **Registry.pol Parsing:**
* **Detect:** `CreateFile` success but short `ReadFile` followed by error on `Registry.pol`.
* **Explain:** Corrupt Group Policy file.
* **Fix:** Delete `Registry.pol` (system will regenerate it on next `gpupdate`).


33. **Roaming Profile Lock:**
* **Detect:** `CreateFile` `SHARING VIOLATION` on `NTUSER.DAT`.
* **Explain:** Profile file locked by another process (e.g., Anti-Virus).
* **Fix:** Exclude profile path from AV scanning.


34. **Folder Redirection Offline:**
* **Detect:** `CreateFile` to `\\Server\Share\Docs` takes >10s.
* **Explain:** Server hosting redirected folders is slow/offline.
* **Fix:** Troubleshoot file server or enable Offline Files.


35. **GPO Script Block:**
* **Detect:** `Process Create` for `gpscript.exe` fails or exits instantly.
* **Explain:** Software Restriction Policy (SRP) or AppLocker blocking script execution.
* **Fix:** Whitelist script path in AppLocker.


36. **History/Cookies Access:**
* **Detect:** `ACCESS DENIED` on `%LocalAppData%\Microsoft\Windows\INetCookies`.
* **Explain:** Integrity level issues preventing browser from writing cookies.
* **Fix:** Reset `icacls` on user profile folders.


37. **Lajoux (Profile Bloat):**
* **Detect:** Enumeration of `HKCU\Printers\DevModes2` takes >5s.
* **Explain:** Thousands of printer connections bloating the user hive.
* **Fix:** Clean up legacy printer keys.


38. **Slow Logon Script:**
* **Detect:** `Process Create` `cmd.exe` running a `.bat` file stays active for >60s.
* **Explain:** Logon script hanging (e.g., mapping drive that doesn't exist).
* **Fix:** Debug logon script logic.


39. **Wallpaper Policy Fail:**
* **Detect:** `RegQueryValue` `HKCU\Control Panel\Desktop\Wallpaper` shows GPO value, but `ReadFile` fails.
* **Explain:** Policy sets wallpaper path that user cannot read.
* **Fix:** Grant "Domain Users" read access to wallpaper share.


40. **AppLocker Policy Read:**
* **Detect:** `AppIdTel.exe` or `SrpUxNativeSnapIn.dll` excessive activity.
* **Explain:** AppLocker evaluating rules heavily.
* **Fix:** Optimize AppLocker rules (reduce complexity).



### **Virtualization (Citrix / FSLogix / App-V)**

41. **FSLogix VHD Lock:**
* **Detect:** `CreateFile` `SHARING VIOLATION` on `.VHDX` file in profile share.
* **Explain:** User session still active on another host holding the lock.
* **Fix:** Log off user from other session or clear stuck locks.


42. **Citrix Hook Injection:**
* **Detect:** `LoadImage` `ACCESS DENIED` for `CtxHk.dll` or `MzVkBd.dll`.
* **Explain:** Security software blocking Citrix API hooks.
* **Fix:** Whitelist Citrix DLLs in security software.
* * **Fix:** Whitelist Citrix DLLs in security software.




43. **App-V Virtual Environment:**
* **Detect:** `PATH NOT FOUND` for file that exists physically (e.g., `C:\ProgramData\App-V\...\file.txt`).
* **Explain:** App running *outside* the bubble trying to access *inside* (or vice versa).
* **Fix:** Launch app inside the bubble (`/appvve:GUID`).


44. **ThinPrint AutoConnect:**
* **Detect:** `TPAutoConnect.exe` repeatedly crashing or exiting.
* **Explain:** Printer mapping failure in VDI.
* **Fix:** Check ThinPrint service or driver compatibility.


45. **Excluded File Access:**
* **Detect:** App writing to `C:\Users\User\Downloads` which is excluded from UPM/FSLogix.
* **Explain:** Data loss on logoff because location is not persisted.
* **Fix:** Modify inclusion list or educate user.


46. **Streamed App Latency:**
* **Detect:** `ReadFile` delays on `P:` or mount point for App streaming.
* **Explain:** Network slowness loading application blocks.
* **Fix:** Pre-cache application or fix network.


47. **Sandbox Space Full:**
* **Detect:** Write failures to sandbox location (ThinApp/App-V).
* **Explain:** Virtual bubble sandbox limit reached.
* **Fix:** Increase sandbox size limit.


48. **Licensing Server Reachability:**
* **Detect:** `TCP Connect` fail to Citrix/VMware licensing server.
* **Explain:** Apps failing to launch due to license check.
* **Fix:** Check licensing server status.


49. **WEM Agent Response:**
* **Detect:** `Norskale Agent Host Service.exe` high CPU/Registry churn.
* **Explain:** Workspace Environment Manager processing heavy filters.
* **Fix:** Optimize WEM filters.


50. **User Mode Font Driver:**
* **Detect:** `fontdrvhost.exe` errors accessing network fonts.
* **Explain:** VDI session struggling to render remote fonts.
* **Fix:** Install fonts locally in the image.



### **Modern Apps (UWP / Store / AppX)**

51. **Manifest Access:**
* **Detect:** `CreateFile` `ACCESS DENIED` on `AppxManifest.xml`.
* **Explain:** App cannot read its own definition.
* **Fix:** Reset App permissions (`Get-AppxPackage | Reset-AppxPackage`).


52. **State Repository Database:**
* **Detect:** `ACCESS DENIED` or `SHARING VIOLATION` on `StateRepository-Machine.srd`.
* **Explain:** Modern App database locked/corrupt.
* **Fix:** Restart `StateRepository` service or repair Windows.


53. **Capability Block:**
* **Detect:** Registry lookup fail for `HKCU\...\Capabilities\Microphone`.
* **Explain:** Privacy settings blocking access to hardware.
* **Fix:** Enable access in Windows Privacy Settings.


54. **Deployment Service Fail:**
* **Detect:** `AppXDeploymentServer.dll` load failure.
* **Explain:** Service handling AppX installs is broken.
* **Fix:** Check `AppXSvc` service status.


55. **BlockMap Integrity:**
* **Detect:** Read failure on `BlockMap.xml` inside the package.
* **Explain:** Package corruption detected.
* **Fix:** Reinstall the AppX package.


56. **Unregistered Class (Modern):**
* **Detect:** `REGDB_E_CLASSNOTREG` for `Windows.UI.Xaml`.
* **Explain:** Core UI framework registration missing.
* **Fix:** Re-register standard UWP apps via PowerShell.


57. **Token Broker Fail:**
* **Detect:** `TokenBroker` service communication errors.
* **Explain:** SSO / Modern Authentication failing (e.g., Office 365 sign-in).
* **Fix:** Check `TokenBroker` service.


58. **Settings Write Fail:**
* **Detect:** Write fail to `%LocalAppData%\Packages\<Package>\Settings\settings.dat`.
* **Explain:** App settings file locked or corrupt.
* **Fix:** Reset the App.


59. **Extension Handler:**
* **Detect:** `RuntimeBroker.exe` crash immediately after file open.
* **Explain:** Modern file picker extension crashed.
* **Fix:** Identify and uninstall buggy shell extension.


60. **Push Notification Registration:**
* **Detect:** WNS (Windows Notification Service) registry key write failure.
* **Explain:** App fails to register for live tiles/toasts.
* **Fix:** Check WNS connectivity/GPO.



### **COM / DCOM & Interop**

61. **Class Not Registered:**
* **Detect:** `RegOpenKey` `NAME NOT FOUND` for `HKCR\CLSID\{GUID}`.
* **Explain:** COM object not installed or registered.
* **Fix:** Run `regsvr32 <dll>` or install the component.


62. **32/64 Bit COM Confusion:**
* **Detect:** App looks in `HKCR\CLSID`, fails, exits. (Should look in `Wow6432Node`).
* **Explain:** 64-bit app trying to load 32-bit COM server (InProc).
* **Fix:** Use DCOM (OutProc) or match architectures.


63. **DCOM Launch Permission:**
* **Detect:** `ACCESS DENIED` on `HKCR\AppID\{GUID}`.
* **Explain:** User lacks DCOM Launch permissions.
* **Fix:** Adjust permissions in `dcomcnfg`.


64. **Interface Not Registered:**
* **Detect:** `RegOpenKey` fail `HKCR\Interface\{GUID}`.
* **Explain:** The Proxy/Stub DLL for the interface is missing.
* **Fix:** Re-register the interface DLL.
* * **Fix:** Re-register the interface DLL.




65. **TypeLib Load Fail:**
* **Detect:** `LoadImage` fail or `Path Not Found` for `.tlb` file.
* **Explain:** Automation/Intellisense features fail.
* **Fix:** Register TypeLib (`regtlib`).


66. **LocalServer32 Path:**
* **Detect:** `RegQueryValue` `LocalServer32` points to invalid exe path.
* **Explain:** COM Server executable moved or deleted.
* **Fix:** Update registry path to correct exe.


67. **ActiveX Killbit:**
* **Detect:** App queries `HKLM\...\Compatibility Flags\Compatibility Flag` (Killbit).
* **Explain:** Security update disabled this ActiveX control.
* **Fix:** Find alternative control or remove Killbit (Risky).


68. **MTS/COM+ Catalog:**
* **Detect:** `CreateFile` fail `C:\Windows\Registration\R000000000001.clb`.
* **Explain:** COM+ Catalog corruption.
* **Fix:** Backup and delete COM+ catalog files (OS rebuilds them).


69. **RPC Server Unavailable:**
* **Detect:** `TCP Connect` fail to Ephemeral port (DCOM dynamic port).
* **Explain:** Firewall blocking dynamic RPC ports.
* **Fix:** Allow RPC dynamic range or pin DCOM port.


70. **Excel/Word Automation:**
* **Detect:** `CreateFile` `NAME NOT FOUND` on `excel.exe`.
* **Explain:** App trying to automate Office, but Office not installed.
* **Fix:** Install Office.



### **Legacy & Compatibility Shims**

71. **Legacy INI Mapping:**
* **Detect:** App reads `win.ini` or `system.ini`.
* **Explain:** Very old code looking for global config.
* **Fix:** Check `IniFileMapping` registry key to see where it's redirected.


72. **8.3 Filename Requirement:**
* **Detect:** `CreateFile` `PATH NOT FOUND` on `C:\PROGRA~1`.
* **Explain:** App relies on short names, but 8.3 generation is disabled (common on new servers).
* **Fix:** Enable 8.3 naming (`fsutil`) or reinstall app to path without spaces.


73. **Deprecated API Call:**
* **Detect:** `LoadImage` fail for `thunk.dll` or similar 16-bit support.
* **Explain:** App is 16-bit, won't run on 64-bit OS.
* **Fix:** Use Virtual Machine / DOSBox.


74. **Shim Database Read:**
* **Detect:** Extensive reads of `sysmain.sdb`.
* **Explain:** Windows applying compatibility fixes (Shims).
* **Fix:** Inspect applied shims in Compatibility Administrator.


75. **UAC Virtualization Write:**
* **Detect:** Write to `C:\Windows` redirected to `%LocalAppData%\VirtualStore`.
* **Explain:** App expects to write to system, Windows redirects it (App sees "ghost" data).
* **Fix:** Run as Admin or grant permission to real folder (better: fix app).


76. **Hardcoded Drive Letter:**
* **Detect:** `CreateFile` `PATH NOT FOUND` on `D:\Data`.
* **Explain:** App expects D: drive, but it's E: or missing.
* **Fix:** Remap drive or use `subst` command.


77. **CD-ROM Check:**
* **Detect:** App checking `\Device\CdRom0`.
* **Explain:** Copy protection looking for physical disc.
* **Fix:** Mount ISO or apply No-CD patch.


78. **VB6 Runtime Missing:**
* **Detect:** `LoadImage` fail `msvbvm60.dll`.
* **Explain:** Visual Basic 6 app needs runtime.
* **Fix:** Install VB6 Runtime.


79. **Missing MFC Library:**
* **Detect:** `LoadImage` fail `mfc42.dll` / `mfc140.dll`.
* **Explain:** Missing C++ Foundation Classes.
* **Fix:** Install Visual C++ Redistributable.


80. **DirectX Legacy:**
* **Detect:** `LoadImage` fail `d3dx9_*.dll`.
* **Explain:** App needs old DirectX 9 End-User Runtimes.
* **Fix:** Install DirectX 9 June 2010 redist.



### **File System Edge Cases**

81. **Symbolic Link Loop:**
* **Detect:** `CreateFile` error `STATUS_REPARSE_POINT_NOT_RESOLVED` or infinite path depth.
* **Explain:** Circular dependency in folder links.
* **Fix:** Fix the symlink target.


82. **ADS Zone.Identifier:**
* **Detect:** `CreateFile` `file.exe:Zone.Identifier` `ACCESS DENIED`.
* **Explain:** Security tool preventing reading "Mark of the Web".
* **Fix:** Unblock the file (Properties > Unblock).


83. **Directory Case Sensitivity:**
* **Detect:** `PATH NOT FOUND` on `Folder` when `folder` exists (and case sensitivity enabled).
* **Explain:** Windows 10+ feature enabled per-folder, confusing legacy apps.
* **Fix:** Disable case sensitivity (`fsutil file setCaseSensitiveInfo`).


84. **Offline Attribute:**
* **Detect:** App reads file, gets `STATUS_FILE_IS_OFFLINE` error.
* **Explain:** File is tiered to cloud/tape and app doesn't know how to trigger recall.
* **Fix:** Manually recall file or configure app to wait.


85. **Max Path Exceeded:**
* **Detect:** `CreateFile` fails on path > 260 chars.
* **Explain:** Path too deep.
* **Fix:** Enable Long Paths (GPO) + App Manifest, or rename folders shorter.


86. **Encrypted File Access (EFS):**
* **Detect:** `ACCESS DENIED` by a different user on Green (Encrypted) file.
* **Explain:** EFS key belongs to original creator only.
* **Fix:** Import EFS certificate or decrypt file.


87. **Sparse File Expansion:**
* **Detect:** Write to sparse file fails `DISK FULL`.
* **Explain:** Sparse file tried to allocate real blocks but disk is full.
* **Fix:** Free up disk space.


88. **Pipe Busy:**
* **Detect:** `CreateFile` `\\.\pipe\name` returns `STATUS_PIPE_BUSY`.
* **Explain:** Server pipe instance is fully utilized.
* **Fix:** Increase MaxInstances on server side pipe creation.


89. **Delete Pending:**
* **Detect:** `CreateFile` returns `STATUS_DELETE_PENDING`.
* **Explain:** File is deleted but handle is open. Can't recreate/overwrite.
* **Fix:** Close the handle holding the file (Restart app/Reboot).


90. **Invalid Filename Characters:**
* **Detect:** `CreateFile` `STATUS_OBJECT_NAME_INVALID` (e.g., using `?` or `|`).
* **Explain:** App trying to create file with illegal chars.
* **Fix:** Code fix or sanitize input.



### **Networking & Web**

91. **PAC File Latency:**
* **Detect:** `TCP Connect` to WPAD server or HTTP 404 on `.pac` file.
* **Explain:** Browser taking 5s to timeout looking for proxy config.
* **Fix:** Disable "Automatically Detect Settings" in Proxy config.


92. **IPv6 Failover:**
* **Detect:** `TCP Connect` IPv6 (Fail) -> 3s Wait -> `TCP Connect` IPv4.
* **Explain:** DNS returning AAAA records but IPv6 route broken.
* **Fix:** Fix IPv6 or disable it (prefer IPv4).


93. **Keep-Alive Timeout:**
* **Detect:** Connection reset exactly at 60s/120s mark.
* **Explain:** Firewall/Load Balancer idle timeout.
* **Fix:** Enable TCP Keep-Alive in app or adjust firewall.


94. **Ephemeral Port Exhaustion:**
* **Detect:** `TCP Connect` returns `STATUS_ADDRESS_IN_USE` (for outbound!).
* **Explain:** Run out of client ports (MaxUserPort).
* **Fix:** Increase dynamic port range (`netsh int ipv4 set dynamicport`).


95. **SSL Certificate Revocation:**
* **Detect:** HTTP connection hangs, `TCP Connect` to OCSP server fails.
* **Explain:** App verifying cert, can't reach CRL issuer, blocks connection.
* **Fix:** Allow OCSP URL through firewall.


96. **Hosts File Hijack:**
* **Detect:** `CreateFile` `C:\Windows\System32\drivers\etc\hosts` success + Read.
* **Explain:** Malware or config forcing DNS override.
* **Fix:** Inspect HOSTS file content.
* * **Fix:** Inspect HOSTS file content.




97. **Winsock LSP Corruption:**
* **Detect:** Loads of non-standard DLLs into `svchost` networking threads.
* **Explain:** Layered Service Provider breaking stack.
* **Fix:** `netsh winsock reset`.


98. **UNC Provider Latency:**
* **Detect:** `CreateFile` `\\NonExistent\Share` takes 20s to return `BAD NETWORK PATH`.
* **Explain:** Network Provider order checks RDP, WebDAV, etc. before failing.
* **Fix:** Change Network Provider Order (put LanmanWorkstation first).


99. **DNS Suffix Search List:**
* **Detect:** `NAME NOT FOUND` for `Server.dept.corp.local`, `Server.corp.local`, etc.
* **Explain:** App trying every suffix in list.
* **Fix:** Use FQDN (Fully Qualified Domain Name).


100. **NetBIOS Broadcast Storm:**
* **Detect:** `UDP Send` to `x.x.x.255` port 137 repeatedly.
* **Explain:** WINS/DNS failed, falling back to noisy broadcast.
* **Fix:** Fix DNS/WINS resolution.



Here is a specialized list of **100 scenarios** focused on **Accessibility, Assistive Technology (AT), and UI Automation**.

Diagnosing issues in this domain is notoriously difficult because the "failure" is often invisible to a standard user—the application runs, but the screen reader is silent, the focus jumps unexpectedly, or voice dictation fails to register a click.

### **UI Automation & MSAA (Microsoft Active Accessibility)**

1. **`WM_GETOBJECT` Timeout:** Application failing to respond to the `WM_GETOBJECT` message within the timeout period (freezes the screen reader).
2. **`OBJID_CLIENT` Failure:** App returning `E_FAIL` when queried for the client area object ID.
3. **Recursive `IAccessible` Calls:** Infinite loop of `get_accParent` calls (Screen reader hangs when focusing an element).
4. **Missing `accName` Property:** Control returns an empty string for `accName` (Screen reader says "Button" instead of "Submit").
5. **Duplicate `accID` Generation:** Two distinct UI elements reporting the same Accessibility ID.
6. **`accRole` Mismatch:** A checkbox reporting its role as `ROLE_SYSTEM_PUSHBUTTON` (confuses user interaction).
7. **`accState` Stagnation:** A checkbox is visually checked, but `get_accState` still reports `STATE_SYSTEM_UNCHECKED`.
8. **Heavy `QueryInterface` Traffic:** Excessive polling for `IAccessible2` or `UIA` interfaces (performance lag).
9. **Event Flood (`EVENT_OBJECT_LOCATIONCHANGE`):** App firing 100 location change events per second for a static window.
10. **Event Flood (`EVENT_OBJECT_NAMECHANGE`):** App rapidly changing the accessible name (causes screen reader to stutter/restart speech).

### **UIA (UI Automation) Core Issues**

11. **Provider Registration Fail:** App fails to register its UIA provider (Control Pattern not found).
12. **`UIA_AutomationIdPropertyId` Missing:** Automation ID is null (breaks automated testing scripts).
13. **`TextPattern` Performance:** Fetching document text via UIA takes >500ms (causes typing lag in Word/Editors).
14. **Orphaned UIA Elements:** The UI element is destroyed, but the UIA tree still retains a reference (memory leak).
15. **Tree Walker Loop:** `TreeWalker` gets stuck in a loop navigating `NextSibling`.
16. **Disconnected Provider:** The underlying HWND is destroyed, but the UIA provider throws exceptions instead of failing gracefully.
17. **Unsupported Pattern Exception:** Client asks for `ScrollPattern`, app throws exception instead of returning `null`.
18. **Invalid Rect Coordinates:** `BoundingRectangle` property returns off-screen or negative coordinates (focus highlight disappears).
19. **Z-Order Confusion:** UIA tree order does not match visual Z-order (navigation flows backwards).
20. **Virtualization Failure:** List has 10,000 items; UIA fails to virtualize, trying to load all 10,000 into the tree (crash/freeze).

### **Screen Reader Interaction (JAWS, NVDA, Narrator)**

21. **Focus Fighting:** App repeatedly moving focus back to a parent window (Screen reader announces "Desktop" constantly).
22. **`Narrator.exe` Hook Failure:** Narrator tries to inject `NarratorHook.dll` but gets Access Denied.
23. **Display Driver Interception:** Screen reader mirror driver fails to attach (`ExtTextOut` hook failure).
24. **Cursor Tracking Fail:** Screen reader cannot track the "caret" (text cursor) position in a custom text box.
25. **Live Region Spam:** App updates a "Live Region" (aria-live) too frequently, flooding the speech buffer.
26. **Focus Loss on Modal Close:** Closing a popup dialog sends focus to `NULL` or the Desktop instead of the parent app.
27. **Menu Mode Hang:** Entering a menu bar causes the screen reader to freeze (menu loop).
28. **Touch Interaction API Fail:** Touch screen gestures fail to translate to accessibility commands.
29. **Synthetic Click Rejection:** App ignores `InvokePattern.Invoke()` calls, requiring physical mouse input.
30. **Audio Ducking Conflict:** Screen reader tries to lower other audio volumes but fails (cannot hear speech over music).

### **Browser & Web Content (Accessibility Tree)**

31. **`Chrome_RenderWidgetHostHWND` Lag:** Chrome accessibility tree update taking >1s.
32. **`ISimpleDOM` Node Access Denied:** Third-party AT failing to access Firefox DOM nodes.
33. **IFrame Security Boundary:** Screen reader failing to cross into a cross-origin IFrame.
34. **Aria-Hidden Misuse:** Interactive content inside an `aria-hidden="true"` container (invisible to AT).
35. **Flash/ActiveX Accessibility:** Legacy plugin failing to expose MSAA (completely silent content).
36. **PDF Tagging Read Error:** Acrobat Reader failing to parse the structure tree of a PDF.
37. **Shadow DOM Boundary:** AT failing to penetrate Shadow DOM V1 boundaries.
38. **High Contrast Mode Detection:** Web content failing to detect `HighContrast` media query.
39. **Zoom Level Scaling:** Text scaling >200% causes layout thrashing (performance spike).
40. **Caret Browsing Toggle:** Failure to engage Caret Browsing mode (F7) in browser.

### **Java & Legacy Frameworks**

41. **Java Access Bridge (JAB) Load Fail:** `WindowsAccessBridge-64.dll` not found.
42. **JAB Version Mismatch:** JVM loading 32-bit bridge in a 64-bit OS environment.
43. **Swing Event Starvation:** Java app processing logic on the EDT (Event Dispatch Thread), blocking accessibility events.
44. **Silverlight Automation Peer:** Missing automation peer for Silverlight controls.
45. **Qt Accessibility Plugin:** Qt app running without the `qtaccessiblewidgets` plugin.
46. **Delphi/VCL Accessibility:** Legacy Delphi app using non-standard window classes (invisible to UIA).
47. **Terminal Emulator HLLAPI:** Screen reader failing to hook HLLAPI for mainframe text extraction.
48. **Citrix Virtual Channel Block:** Accessibility data failing to traverse the ICA channel.
49. **RDP Audio Redirection:** Screen reader audio failing to redirect to the client.
50. **SAP GUI Scripting Disabled:** SAP client rejecting automation requests due to security settings.

### **Assistive Hardware & Drivers**

51. **Braille Display COM Port Busy:** Braille display driver failing to open COM port (Already in use).
52. **HID Device Exclusive Lock:** One screen reader locking the Braille HID device, preventing another from using it.
53. **Switch Control Input Lag:** Input lag >200ms for adaptive switch devices.
54. **Eye Tracker Calibration File:** Write access denied to calibration profile.
55. **Magnifier Driver Overlay:** `Magnify.exe` failing to create the magnification overlay window.
56. **On-Screen Keyboard Injection:** OSK fails to inject keys into a Protected Process (Admin UI).
57. **Tablet Input Service Hang:** `TabTip.exe` crashing or freezing.
58. **Driver Signature Enforcement:** Custom AT driver blocked from loading.
59. **USB Power Management:** AT device disconnects because Windows put the USB hub to sleep.
60. **Bluetooth MIDI Latency:** Delay in MIDI signals for musical AT devices.

### **High Contrast & Visual Aids**

61. **System Colors Query:** App checking hardcoded colors instead of `GetSysColor` (Invisible text in High Contrast).
62. **DWM Colorization Fail:** Desktop Window Manager failing to apply color filters (Color Blind mode).
63. **Theme API Crash:** App crashing when `uxtheme.dll` handles High Contrast theme switch.
64. **Cursor Scaling Artifacts:** Large cursor (Accessibility setting) rendering as a black box.
65. **Focus Rectangle Missing:** `DrawFocusRect` not called or invisible.
66. **Text Smoothing Conflict:** ClearType rendering artifacts when magnification is active.
67. **Bitmap Scaling Blur:** App not DPI aware, resulting in blurry text at 200% scaling.
68. **Night Light Transition:** Gamma ramp API failure (`SetDeviceGammaRamp`).
69. **Transparency Disable:** App ignoring the "Transparency Effects: Off" system setting.
70. **Animation Disable:** App ignoring `SPI_GETCLIENTAREAANIMATION` (Motion sickness trigger).

### **Speech Recognition & Dictation**

71. **Microphone Exclusive Mode:** Dragon/Windows Dictation failing to access Mic.
72. **Text Services Framework (TSF) Lock:** TSF manager (`ctfmon.exe`) deadlock with app.
73. **`Select` Interface Failure:** Dictation software cannot "Select" text in a non-standard textbox.
74. **Correction Window Hidden:** The "Did you mean..." popup appears off-screen.
75. **Vocabulary Update Write Fail:** Failure to write to the user's custom dictionary file.
76. **Audio Buffer Underrun:** CPU spike causing speech recognition to drop audio frames.
77. **Command Confusion:** App defines custom shortcuts that conflict with global Dictation commands.
78. **SAPI5 Registry Lookups:** Failure to enumerate installed SAPI voices.
79. **Audio Endpoint Builder:** `Audiosrv` failing to build graph for Dictation.
80. **Language Pack Missing:** `SpeechPlatform` failing to load required language model.

### **Configuration & Deployment of AT**

81. **Roaming Settings Latency:** NVDA/JAWS taking 2 minutes to load roaming config from network.
82. **Secure Desktop Restriction:** AT failing to run on the UAC Secure Desktop (Admin prompt).
83. **Ease of Access Registry Reset:** Windows resetting `HKCU\Control Panel\Accessibility` on reboot.
84. **AT Start on Logon:** `utilman` failing to launch the configured AT on the logon screen.
85. **Sound Scheme Lock:** App forcing a specific sound scheme, overriding accessibility sounds.
86. **Virtual Audio Cable Conflict:** Routing issues when using Virtual Audio Cables with Screen Readers.
87. **Portable Copy Permission:** "Access Denied" running NVDA Portable from a USB stick.
88. **License Manager Conflict:** JAWS/ZoomText license manager service unreachable.
89. **Script Folder Write Access:** User lacks permission to save custom scripts for the specific application.
90. **Inter-Process Communication (IPC):** Named pipe connection failure between AT and its helper process.

### **Specific Application Anti-Patterns**

91. **Custom Drawing without `IAccessible`:** App draws controls using raw GDI/DirectX but implements 0 accessibility.
92. **Label as Placeholder:** Using "placeholder" text as the only label (disappears when typing starts).
93. **Keyboard Trap:** User can Tab *into* a control but cannot Tab *out* (requires mouse to exit).
94. **Timed Tooltip:** Tooltip disappears too fast for the screen reader to catch it.
95. **Non-Standard Combobox:** A "div" that looks like a dropdown but isn't one (no role, no expand/collapse state).
96. **Drag-and-Drop Only:** Operation requires dragging, no keyboard alternative.
97. **Color-Only Information:** Status indicated only by Red/Green color change (no text/metadata change).
98. **Implicit Focus Change:** Content changes without moving focus (Screen reader user is unaware).
99. **Tab Order Chaos:** Tab order goes 1 -> 5 -> 2 -> 10 (illogical navigation).
100. **Hidden Content Readable:** Screen reader reads text that is visually hidden (e.g., off-screen menus).

---

### **Would you like me to ...**

* Create a specific **PowerShell filter** to check for "Focus Fighting" or "UI Automation Loops" in a ProcMon trace?
* Generate a **guidance document** on how to map these technical ProcMon events to user-reported symptoms (e.g., "If user says 'JAWS stops talking', look for events #1, #3, and #9")?
