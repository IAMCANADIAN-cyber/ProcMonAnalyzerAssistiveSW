# 🧪 Test Suite for ProcMon-Enterprise

This directory contains test generators and chaos testing scripts to validate the robustness of `ProcMon-Enterprise-Unified.ps1`.

## Strategy
Since the main engine is designed to run in air-gapped, high-stress environments, it must be resilient to:
1.  **Data Corruption:** Malformed CSVs (RFC 4180 violations), broken JSONs, zero-byte files.
2.  **Resource Contention:** Locked files, read-only paths.
3.  **Scale:** Large datasets (simulated).

## Fixtures
The script `Generate-Chaos-Fixtures.ps1` creates the following artifacts in `tests/fixtures/`:
*   `Chaos_MalformedRows.csv`: Contains rows with variable column counts.
*   `Chaos_Empty.csv`: 0 bytes.
*   `Chaos_BadEncoding.csv`: Binary garbage masked as CSV.
*   `Chaos_CorruptOracle.json`: Invalid JSON syntax.
*   `Valid_Small.csv`: A correct, minimal ProcMon export for baseline verification.

## Execution
To run the verification suite (which executes the main script against these fixtures):

```powershell
.\Verify-ErrorHandling.ps1
```

## Goals
*   **Zero Unhandled Exceptions:** The script should never crash to the shell red text. It should log an error and continue or exit gracefully.
*   **Report Integrity:** Even with partial data failure, the HTML report should still generate.
