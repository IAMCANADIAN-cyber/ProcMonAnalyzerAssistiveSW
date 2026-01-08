# 🧪 Scenario Detection Library

This document defines the specific event patterns the engine must detect. Use this to validate any logic changes.

## 🔴 Kernel & Driver Layer (The "Hard" Crashes)
| Scenario | Event Pattern | Severity |
| :--- | :--- | :--- |
| **Heap Corruption** | `Process Exit` with Detail `-1073740940` (0xC0000374). | **Critical** |
| **Stack Overrun** | `Process Exit` with Detail `-1073740791` (0xC0000409). | **Critical** |
| **Filter Collision** | Result `0xC01C001F` (FLT_INSTANCE_ALTITUDE_COLLISION). | **Critical** |

## 🟠 OS & Accessibility Layer (The "Soft" Failures)
| Scenario | Event Pattern | Severity |
| :--- | :--- | :--- |
| **Secure Desktop** | Process `LogonUI` or `Consent` -> Path `FreedomScientific` -> Result `DENIED`. | **Critical** |
| **Legacy Bridge** | `RegOpenKey` on CLSID `BF71...` -> Result `NOT FOUND` / `DENIED`. | **High** |
| **Clipboard Jam** | Path `\RPC Control\CLIP` or `ClipboardHistory` -> Result `DENIED`. | **Medium** |
| **UIA Zombie** | Result `ELEMENT_NOT_AVAILABLE` (UI Automation failure). | **Medium** |

## 🟡 Application Config & Dependencies
| Scenario | Event Pattern | Severity |
| :--- | :--- | :--- |
| **VC++ Missing** | `LoadImage` on `vcruntime140.dll` -> Result `NOT FOUND`. | **Critical** |
| **Font Blocking** | Process Create -> Detail `BlockNonMicrosoftBinaries`. | **High** |
| **MIDA Attack** | `OpenProcess` on `jfw.exe` -> Detail `TERMINATE` -> Source != System/Security. | **Critical** |

## 🔵 Performance & Network Layer
| Scenario | Event Pattern | Severity |
| :--- | :--- | :--- |
| **OpLock Break** | Result `OPLOCK_NOT_GRANTED` + Duration > 0.5s. | **High** |
| **Fast I/O Fail** | Result `FAST_IO_DISALLOWED` + Duration > 0.5s. | **High** |
| **Packet Storm** | >100 `TCP Send` events with Length < 100 bytes in < 1 second. | **Medium** |
| **Reparse Loop** | >500 `REPARSE` results on OneDrive/SharePoint paths. | **High** |
