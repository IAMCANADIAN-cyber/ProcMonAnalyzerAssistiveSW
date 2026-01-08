# 🧪 Scenario Detection Library (V1300)

This library defines the deterministic and heuristic patterns used to identify system instability.

## 1. Security & Lock Contention (Core Pillar - V1300 Enhanced)
| Scenario | Logic Pattern | User Experience |
| :--- | :--- | :--- |
| **Security Lock (GSB)** | `[Sec_Proc]` touches `[Path]` -> `< 0.5s` later `[AT_Proc]` fails `[Path]` with `DENIED/SHARING`. | System "hiccups" or JAWS speech skips. |
| **OpLock Break** | Result `OPLOCK_NOT_GRANTED` or `FAST_IO_DISALLOWED` followed immediately by slow I/O. | Significant lag when opening large Word/PDF docs. |
| **Hook Injection** | `Load Image` of a suspicious DLL (security/VDI) into an AT process. | JAWS becomes "silent" or crashes in specific apps. |
| **Access Denied** | Direct `ACCESS DENIED` on critical AT paths. | Configuration fails to save; profiles corrupt. |

## 2. Microsoft 365 & Enterprise Productivity
| Scenario | Logic Pattern | User Experience |
| :--- | :--- | :--- |
| **Accessibility Tagger Fail** | `WINWORD.EXE` loops `RegQuery` on `HKCU\...\Accessibility\Checker` > 500 times in 1s. | Word becomes "Not Responding" when JAWS tries to read. |
| **Modern Comment Deadlock** | `OUTLOOK.EXE` threads spike followed by `UIA` failure. | Outlook freezes when navigating an email with many comments. |
| **Excel Calc-Chain Lag** | `EXCEL.EXE` duration on `Pipe Write` to JAWS > 1.0s during a `Calculate` operation. | JAWS lags significantly when numbers change in a sheet. |
| **Teams WebView2 Crash** | `msedgewebview2.exe` exit code != 0 correlated with `Teams.exe` focus bounce. | Teams UI turns "White" or "Grey" and JAWS loses focus. |

## 3. Chromium & Web Interoperability (Edge/Chrome)
| Scenario | Logic Pattern | User Experience |
| :--- | :--- | :--- |
| **v134 Copy/Paste Bug** | `msedge.exe` (v134+) correlated with `RegQuery` on `ClipboardHistory` + `ACCESS_DENIED`. | "Copy" command works but JAWS fails to announce it. |
| **Renderer Loop** | `msedge.exe --type=renderer` process creation/termination loop (3+ events in 5s). | Browser focus jumps constantly; screen reader keeps re-reading page. |
| **Virtual Buffer Crash** | `jfw.exe` `LoadImage` on `fsdom.dll` fails with `FILE_LOCKED_WITH_ONLY_READERS`. | JAWS cannot read the web; "Virtual Buffer" never loads. |

## 4. Kernel & System Subsystems
| Scenario | Logic Pattern | User Experience |
| :--- | :--- | :--- |
| **Heap Corruption** | `Process Exit` with code `0xC0000374`. | Sudden, silent closure of AT software. |
| **Stack Overrun** | `Process Exit` with code `0xC0000409`. | App crashes when performing a specific task (e.g., OCR). |
| **Filter Altitude War** | `0xC01C001F` on any `DeviceIoControl` involving `fs_mirror.sys`. | System BSOD or Video Intercept failure (Black screen). |
| **Reparse Loop** | >8 `REPARSE` results on a single `OneDrive` or `SharePoint` path pattern. | Explorer hangs; CPU spikes to 100%. |
