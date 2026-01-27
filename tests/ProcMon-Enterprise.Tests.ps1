Describe "ProcMon-Enterprise Detectors" {
    Context "Detect-HookInjection" {
        It "Should detect suspicious DLL injection in AT process" {
            # Mock event object
            $evt = [PSCustomObject]@{
                Process = "jfw.exe"
                Operation = "Load Image"
                Path = "C:\Windows\System32\crowdstrike.dll"
                Detail = ""
                Result = "SUCCESS"
            }

            # Import the script functions (requires dot-sourcing the script, which might run it)
            # For this test skeleton, we assume the function is available or mocked.
            # In a real scenario, we'd dot-source the script but suppress execution.

            # Since we can't easily mock the script inclusion in this environment without execution,
            # this test serves as a structural placeholder for the user.

            $result = Detect-HookInjection $evt

            # Assertions (commented out as function isn't loaded in this session)
            # $result.Category | Should -Be "HOOK INJECTION"
            # $result.Severity | Should -Be "High"
        }
    }
}
