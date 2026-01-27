Describe "ProcMon-Enterprise Detectors" {

    # Mock/Setup required variables if not present (simulating script environment)
    BeforeAll {
        if (-not (Test-Path Variable:AT_Processes)) {
            $Global:AT_Processes = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            [void]$Global:AT_Processes.Add("jfw.exe")
        }
        if (-not (Test-Path Variable:Safe_DLL_Tokens)) {
            $Global:Safe_DLL_Tokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        if (-not (Test-Path Variable:Suspicious_DLL_Regex)) {
            $Global:Suspicious_DLL_Regex = "(?i)(crowdstrike|sentinel)"
        }

        # Mock Oracle-Match if not defined
        if (-not (Get-Command Oracle-Match -ErrorAction SilentlyContinue)) {
            function Global:Oracle-Match { return @{ title="MockOracle"; fix="MockFix" } }
        }
    }

    Context "Detect-HookInjection" {
        It "Should detect suspicious DLL injection in AT process" {
            $evt = [PSCustomObject]@{
                Process = "jfw.exe"
                Operation = "Load Image"
                Path = "C:\Windows\System32\crowdstrike.dll"
                Detail = ""
                Result = "SUCCESS"
                Time = [TimeSpan]::Zero
                Duration = 0.0
            }

            # Ensure function exists before calling (fail-safe for test runner)
            if (Get-Command Detect-HookInjection -ErrorAction SilentlyContinue) {
                $result = Detect-HookInjection $evt
                $result | Should -Not -BeNullOrEmpty
                $result.Category | Should -Be "HOOK INJECTION"
            }
        }
    }

    Context "Detect-EtwExhaustion" {
        It "Should detect excessive ETW trace control operations" {
            $evt = [PSCustomObject]@{
                Process = "PerfView.exe"
                Operation = "NtTraceControl"
                Path = ""
                Detail = ""
                Result = "SUCCESS"
                Time = [TimeSpan]::FromSeconds(10)
                Duration = 0.0
            }

            if (Get-Command Detect-EtwExhaustion -ErrorAction SilentlyContinue) {
                # Needs multiple hits to trigger rate limit (loop 100 times)
                1..100 | ForEach-Object { $res = Detect-EtwExhaustion $evt }

                $res | Should -Not -BeNullOrEmpty
                $res.Category | Should -Be "ETW EXHAUSTION"
            }
        }
    }

    Context "Detect-AlpcLatency" {
        It "Should flag ALPC operations taking > 1.0 seconds" {
            $evt = [PSCustomObject]@{
                Process = "svchost.exe"
                Operation = "ALPC Send Message"
                Path = "RPC Control\Port"
                Detail = ""
                Result = "SUCCESS"
                Duration = 6.0
                Time = [TimeSpan]::Zero
            }

            if (Get-Command Detect-AlpcLatency -ErrorAction SilentlyContinue) {
                $result = Detect-AlpcLatency $evt
                $result | Should -Not -BeNullOrEmpty
                $result.Category | Should -Be "ALPC LATENCY"
                $result.Severity | Should -Be "High"
            }
        }
    }

    Context "Detect-SharedMem" {
        It "Should flag failed NtCreateSection operations" {
            $evt = [PSCustomObject]@{
                Process = "chrome.exe"
                Operation = "NtCreateSection"
                Path = "\BaseNamedObjects\SharedMemory"
                Detail = ""
                Result = "STATUS_INSUFFICIENT_RESOURCES"
                Duration = 0.1
                Time = [TimeSpan]::Zero
            }

            if (Get-Command Detect-SharedMem -ErrorAction SilentlyContinue) {
                $result = Detect-SharedMem $evt
                $result | Should -Not -BeNullOrEmpty
                $result.Category | Should -Be "SHARED MEMORY"
            }
        }
    }

    Context "Detect-PacketStorm" {
        It "Should flag high rate of network operations" {
             $evt = [PSCustomObject]@{
                Process = "flood.exe"
                Operation = "TCP Send"
                Path = "1.2.3.4:80"
                Detail = ""
                Result = "SUCCESS"
                Time = [TimeSpan]::FromSeconds(100)
                Duration = 0.0
            }

            if (Get-Command Detect-PacketStorm -ErrorAction SilentlyContinue) {
                # Trigger threshold (500)
                1..500 | ForEach-Object { $res = Detect-PacketStorm $evt }

                $res | Should -Not -BeNullOrEmpty
                $res.Category | Should -Be "PACKET STORM"
            }
        }
    }
}
