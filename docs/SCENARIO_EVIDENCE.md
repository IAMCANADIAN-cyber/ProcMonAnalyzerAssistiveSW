
---

## 🛠️ Section 117: Additional Detectors (Script Modules)
*Specific logic modules implemented in `ProcMon-Enterprise-Unified.ps1`.*

### 1508. Hook Injection (Third-Party DLLs)
*   **ID:** 1508 (Custom Script Logic)
*   **Detection Logic in Script:**
    *   **Function:** `Detect-HookInjection`
    *   **Operation:** `Load Image`
    *   **Filter:** `Suspicious_DLL_Regex` (CrowdStrike, Citrix, McAfee, etc.) loaded into AT Process.
*   **Evidence / Citation:**
    *   **Source:** [Microsoft Learn: Raymond Chen on Detours](https://devblogs.microsoft.com/oldnewthing/20040202-00/?p=40793)
    *   **Proof:** DLL Injection (Detouring) modifies the in-memory code of the target process. If the injector is buggy or conflicts with another hook (like JAWS video intercept), the process crashes or hangs. Identifying these modules is the first step in "Vendor Conflict" resolution.
*   **Script Implementation Verification:**
    *   Matches `Detect-HookInjection` logic.

### 1509. Thread Profiling (CPU Hotspot)
*   **ID:** 1509 (Custom Script Logic)
*   **Detection Logic in Script:**
    *   **Function:** `Detect-ThreadProfiling`
    *   **Operation:** `Thread Profiling`
*   **Evidence / Citation:**
    *   **Source:** [ProcMon: Profiling Events](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)
    *   **Proof:** ProcMon can generate thread profiling events (sampling the CPU). A cluster of these events indicates a CPU hotspot (high computation) in that specific thread/process, verifying "It's not I/O, it's CPU".
*   **Script Implementation Verification:**
    *   Matches `Detect-ThreadProfiling` logic.

### 1510. Filter Conflict (Altitude Collision)
*   **ID:** 1510 (Custom Script Logic)
*   **Detection Logic in Script:**
    *   **Function:** `Detect-FilterConflict`
    *   **Result:** `INSTANCE_ALTITUDE_COLLISION`
*   **Evidence / Citation:**
    *   **Source:** [Microsoft Learn: Load Order Groups and Altitudes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)
    *   **Proof:** File System Minifilters have assigned altitudes. If two drivers try to claim the exact same altitude, the Filter Manager returns a collision error. This indicates a configuration error or incompatible security products.
*   **Script Implementation Verification:**
    *   Matches `Detect-FilterConflict` logic.

### 1511. Legacy Bridge (Accessibility)
*   **ID:** 1511 (Custom Script Logic)
*   **Detection Logic in Script:**
    *   **Function:** `Detect-LegacyBridge`
    *   **Path Filter:** `uiautomationcore.dll`, `oleacc.dll`
    *   **Result:** `NAME NOT FOUND`
*   **Evidence / Citation:**
    *   **Source:** [Microsoft Learn: UI Automation and Microsoft Active Accessibility](https://learn.microsoft.com/en-us/windows/win32/winauto/uiauto-msaa)
    *   **Proof:** These DLLs are the bridge between applications and Screen Readers. If an app tries to load them and fails (e.g., looking in the wrong folder or SxS issue), accessibility features will silently fail.
*   **Script Implementation Verification:**
    *   Matches `Detect-LegacyBridge` logic.

### 1512. Clipboard Lock (Contention)
*   **ID:** 1512 (Custom Script Logic)
*   **Detection Logic in Script:**
    *   **Function:** `Detect-ClipboardLock`
    *   **Result:** `ACCESS DENIED` or `PIPE BUSY` on `clip` / `clipboard`
*   **Evidence / Citation:**
    *   **Source:** [Raymond Chen: The Clipboard is a shared resource](https://devblogs.microsoft.com/oldnewthing/20080604-00/?p=22023)
    *   **Proof:** Only one window can open the clipboard at a time. If `rdpclip.exe` or a clipboard manager holds it open (and crashes/hangs), no other app can copy/paste. This detector identifies the specific process holding the lock.
*   **Script Implementation Verification:**
    *   Matches `Detect-ClipboardLock` logic.

### 1513. Audio Ducking (Stream Stomp)
*   **ID:** 1513 (Custom Script Logic)
*   **Detection Logic in Script:**
    *   **Function:** `Detect-AudioDucking`
    *   **Process:** `audiodg.exe`
    *   **Result:** `ACCESS DENIED` on `MMDevices`
*   **Evidence / Citation:**
    *   **Source:** [Microsoft Learn: Default Ducking Experience](https://learn.microsoft.com/en-us/windows/win32/coreaudio/default-ducking-experience)
    *   **Proof:** Windows automatically lowers volume (Ducking) when a communication stream is active. If the Audio Service cannot access the policy keys to restore volume (due to permissions/locking), the "Duck" sticks, leaving the user with low/no volume.
*   **Script Implementation Verification:**
    *   Matches `Detect-AudioDucking` logic.

### 1514. MFA Block (Identity Network)
*   **ID:** 1514 (Custom Script Logic)
*   **Detection Logic in Script:**
    *   **Function:** `Detect-MfaBlock`
    *   **Path Filter:** `login.microsoftonline.com`
    *   **Result:** `TIMEOUT` or `CONNECTION RESET`
*   **Evidence / Citation:**
    *   **Source:** [Microsoft Entra ID: Network connectivity](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-ports)
    *   **Proof:** If the authentication endpoints are unreachable (blocked by firewall/proxy), apps will hang or loop during sign-in. This detector specifically looks for TCP failures to known Identity providers.
*   **Script Implementation Verification:**
    *   Matches `Detect-MfaBlock` logic.

### 1515. OCR Fail (Model Missing)
*   **ID:** 1515 (Custom Script Logic)
*   **Detection Logic in Script:**
    *   **Function:** `Detect-OcrFail`
    *   **Path Filter:** `OCR`, `tessdata`
    *   **Result:** `PATH NOT FOUND`
*   **Evidence / Citation:**
    *   **Source:** [Microsoft Learn: OCR in Windows](https://learn.microsoft.com/en-us/uwp/api/windows.media.ocr)
    *   **Proof:** Screen Readers rely on OCR to read images. If the OCR engine (Windows.Media.Ocr) or its language data files are missing/blocked, the feature fails silently or throws generic errors.
*   **Script Implementation Verification:**
    *   Matches `Detect-OcrFail` logic.
