# 🧪 Scenario Detection Library (V1300)

This library defines the deterministic and heuristic patterns used to identify system instability.

## 1. Security & Lock Contention (Core Pillar)
| Scenario | Logic Pattern | User Experience |
| :--- | :--- | :--- |
| **Global Lock (GSB)** | `[Sec_Proc]` touches `[Path]` -> `< 0.5s` later `[AT_Proc]` fails `[Path]` with `SHARING_VIOLATION`. | System "hiccups" or JAWS speech skips. |
| **OpLock Break** | Result `OPLOCK_NOT_GRANTED` followed immediately by a non-cached `ReadFile` with `Duration > 0.5s`. | Significant lag when opening large Word/PDF docs. |
| **Hook Integrity** | `RegSetValue` on `AppInit_DLLs` by a non-Microsoft process while `jfw.exe` is active. | JAWS becomes "silent" in specific apps but works in others. |
| **MIDA Scout** | `OpenProcess` with `PROCESS_TERMINATE` rights on `jfw.exe` originating from `powershell.exe` or `cmd.exe`. | JAWS disappears instantly during a security scan or script run. |

## 2. Microsoft 365 & Enterprise Productivity
| Scenario | Logic Pattern | User Experience |
| :--- | :--- | :--- |
| **Accessibility Tagger Fail** | `WINWORD.EXE` loops `RegQuery` on `HKCU\...\Accessibility\Checker` > 500 times in 1s. | Word becomes "Not Responding" when JAWS tries to read. |
| **Modern Comment Deadlock** | `OUTLOOK.EXE` creates `Thread Create` events in rapid succession (10+) followed by `UIA_ELEMENT_NOT_AVAILABLE`. | Outlook freezes when navigating an email with many comments. |
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
| **ETW Starvation** | `STATUS_INSUFFICIENT_RESOURCES` on `TraceLog` paths. | JAWS starts but "UIA" support is broken (cannot read ribbons/menus). |
| **Reparse Loop** | >500 `REPARSE` results on a single `OneDrive` or `SharePoint` path pattern. | Explorer hangs; CPU spikes to 100%. |

## 5. Advanced Edge Cases (V1300 Additions)
| Scenario | Logic Pattern | User Experience |
| :--- | :--- | :--- |
| **Quick Access FTP Freeze** | `Explorer` connecting to FTP site in Recent Files. | Explorer hangs on open. |
| **Time Zone Auto Fail** | `RegSetValue` on `ActiveTimeBias` by `tzautoupdate`. | Time Zone update service fighting with location. |
| **OOBE Complete Flag** | `RegQueryValue` on `OOBEComplete` registry key. | Search Indexer waiting for Out-Of-Box-Experience to finish. |
