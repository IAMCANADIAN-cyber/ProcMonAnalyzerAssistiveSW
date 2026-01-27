import re
import sys

def main():
    input_file = "ScenariostoDetect.md"

    # Read the markdown content
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return

    scenarios = []

    # Pattern for the main scenario line
    # 1. **Title:** Logic...
    pattern = re.compile(r'^\s*(\d+)\.\s+\*\*(.*?):\*\*(.*)$')

    lines = content.split('\n')

    # Track used IDs to ensure uniqueness
    seen_ids = set()
    global_id_counter = 10000

    for line in lines:
        line = line.strip()
        match = pattern.match(line)
        if match:
            s_id_raw = match.group(1)
            title = match.group(2).strip()
            rest = match.group(3).strip()

            # Skip documentation headers
            if title in ["Ingest", "Normalize", "Scan", "Score", "Output"]:
                continue

            op = ""
            res = ""
            path = ""

            # Extract items in backticks
            backticks = re.findall(r'`([^`]*)`', rest)

            # Heuristic mapping
            ops = []
            results = []
            paths = []

            # Common Ops
            known_ops = ["CreateFile", "WriteFile", "ReadFile", "RegOpenKey", "RegQueryValue", "RegSetValue", "LoadImage", "Process Create", "Process Exit", "TCP Connect", "UDP Send", "DeviceIoControl", "FsRtlCheckOplock", "FlushBuffersFile", "QueryDirectory", "SetDispositionInformationFile", "SetBasicInformationFile", "OpenProcess", "TerminateProcess", "NtQuerySystemInfo", "NtQueryObject", "NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection", "NtAllocateVirtualMemory", "NtFreeVirtualMemory", "NtProtectVirtualMemory", "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtCreateThreadEx", "NtOpenProcessToken", "NtAdjustPrivilegesToken", "NtDuplicateToken", "NtSetSecurityObject", "NtQuerySecurityObject", "NtCreateKey", "NtOpenKey", "NtSetValueKey", "NtDeleteKey", "NtEnumerateKey", "NtLoadDriver", "NtUnloadDriver", "NtRaiseHardError", "NtShutdownSystem", "NtSystemDebugControl", "NtTraceControl", "NtAlpcSendWait", "NtFsControlFile", "NtLockFile", "NtUnlockFile", "NtNotifyChangeDirectoryFile", "NtQueryEaFile", "NtSetEaFile"]

            # Common Results
            known_res = ["ACCESS_DENIED", "NAME_NOT_FOUND", "PATH_NOT_FOUND", "SHARING_VIOLATION", "SUCCESS", "BUFFER_OVERFLOW", "DISK_FULL", "QUOTA_EXCEEDED", "FILE_CORRUPT_ERROR", "DATA_ERROR", "STATUS_IN_PAGE_ERROR", "STATUS_DEVICE_OFF_LINE", "STATUS_DEVICE_BUSY", "STATUS_REPARSE_POINT_NOT_RESOLVED", "STATUS_NOT_A_DIRECTORY", "STATUS_DIRECTORY_NOT_EMPTY", "NAME_COLLISION", "STATUS_FILE_IS_OFFLINE", "STATUS_FVE_LOCKED_VOLUME", "USN_JOURNAL_WRAP", "LOG_FILE_FULL", "STATUS_IMAGE_NOT_AT_BASE", "STATUS_IMAGE_MACHINE_TYPE_MISMATCH", "STATUS_INVALID_IMAGE_HASH", "STATUS_INSUFFICIENT_RESOURCES", "STATUS_COMMITMENT_LIMIT", "STATUS_STACK_OVERFLOW", "ECONNRESET", "HOST_UNREACHABLE", "NETWORK_UNREACHABLE", "CONNECTION_REFUSED", "ADDRESS_ALREADY_ASSOCIATED", "TIMEOUT", "BAD_NETWORK_PATH", "STATUS_TRUST_FAILURE", "STATUS_BUFFER_OVERFLOW", "STATUS_DELETE_PENDING", "STATUS_PIPE_BUSY", "STATUS_OBJECT_NAME_INVALID"]
            known_res_spaced = [r.replace("_", " ") for r in known_res]

            for token in backticks:
                token_clean = token.strip()

                # Split combined ops like "CreateFile/WriteFile"
                sub_tokens = []
                if "/" in token_clean and "\\" not in token_clean: # Assume / is separator if no backslash (paths usually have backslash on windows, or dots)
                     # Check if parts look like Ops
                     parts = token_clean.split('/')
                     valid_split = True
                     for p in parts:
                         if " " in p and p not in known_res_spaced: # Ops usually don't have spaces unless specific
                             # e.g. "TCP Connect"
                             pass
                     sub_tokens.extend(parts)
                else:
                     sub_tokens.append(token_clean)

                for t in sub_tokens:
                    t = t.strip()
                    if not t: continue

                    if t in known_ops or "Create" in t or "Write" in t or "Read" in t or "Load" in t or "Exec" in t or "Connect" in t or "Send" in t or "Open" in t or "Query" in t or "Set" in t:
                         # Filter out paths that might look like ops?
                         # Paths usually contain \ or . or :
                         if "\\" not in t and "/" not in t and ":" not in t:
                            ops.append(t)
                    elif t in known_res or t.upper() in known_res or t.upper().replace(" ", "_") in known_res:
                         results.append(t)
                    elif "\\" in t or "/" in t or "." in t or ":" in t:
                         paths.append(t)

            if not results:
                 for r in known_res + known_res_spaced:
                      if r in rest or r.title() in rest:
                           results.append(r)
                           break

            # Dedupe ops
            ops = sorted(list(set(ops)))

            op = "|".join(ops)
            res = "|".join(results).upper().replace(" ", "_")
            path = "|".join(paths)

            if not op and not res and not path:
                continue

            # Extract Cause
            cause = ""
            cause_match = re.search(r'\((.*?)\)\s*$', rest)
            if cause_match:
                 cause = cause_match.group(1)
            else:
                 cause = rest

            def escape_ps_string(s):
                s = s.replace("`", "``")
                s = s.replace('"', '`"')
                return s

            cause_escaped = escape_ps_string(cause)

            # Construct Regex for Path
            path_regex = path.replace("\\", "\\\\").replace(".", "\\.").replace("*", ".*").replace("?", ".")
            path_regex = path_regex.replace("\\.\\.\\.", ".*")
            path_regex = path_regex.replace("<User>", "[^\\\\]+")

            op_regex = op.replace("|", "|")
            res_regex = res.replace("_", " ")

            lookup_val = res.replace("_", " ")

            s_id = s_id_raw
            if s_id in seen_ids:
                 s_id = str(global_id_counter)
                 global_id_counter += 1
            seen_ids.add(s_id)

            ps_object = f'    @{{ Id=\'{s_id}\'; Title="{title}"; Op="{op_regex}"; Res="{res_regex}"; Lookup="{lookup_val}"; Path="{path_regex}"; Cause="{cause_escaped}" }},'
            scenarios.append(ps_object)

    print("$StartScenarios = @(")
    for s in scenarios:
        print(s)
    print(")")

if __name__ == "__main__":
    main()
