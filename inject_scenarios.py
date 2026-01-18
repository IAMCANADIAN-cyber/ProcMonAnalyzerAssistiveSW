import re

def inject_scenarios(script_path, new_scenarios_path):
    with open(script_path, 'r', encoding='utf-8') as f:
        script_lines = f.readlines()

    with open(new_scenarios_path, 'r', encoding='utf-8') as f:
        new_lines = f.readlines()

    # extract existing IDs to dedupe
    existing_ids = set()
    id_pattern = re.compile(r"Id='(\d+)'")

    for line in script_lines:
        match = id_pattern.search(line)
        if match:
            existing_ids.add(match.group(1))

    print(f"Found {len(existing_ids)} existing scenarios.")

    # Filter new lines
    lines_to_add = []
    for line in new_lines:
        match = id_pattern.search(line)
        if match:
            if match.group(1) not in existing_ids:
                lines_to_add.append(line)

    print(f"Adding {len(lines_to_add)} new scenarios.")

    # Find insertion point
    # We look for the closing parenthesis of $StartScenarios
    # It starts at line ~1082: $StartScenarios = @(
    # We scan forward from there.

    start_index = -1
    for i, line in enumerate(script_lines):
        if "$StartScenarios = @(" in line:
            start_index = i
            break

    if start_index == -1:
        print("Could not find start of scenarios array.")
        return

    insert_index = -1
    # naive approach: find the next ')' that starts a line (indented or not)
    # but we need to be careful. The array closes with ')' usually on its own line.

    for i in range(start_index, len(script_lines)):
        if script_lines[i].strip() == ")":
            insert_index = i
            break

    if insert_index != -1:
        # Insert before the closing parenthesis
        script_lines[insert_index:insert_index] = lines_to_add

        with open(script_path, 'w', encoding='utf-8') as f:
            f.writelines(script_lines)
        print("Injection successful.")
    else:
        print("Could not find insertion point.")

inject_scenarios('ProcMon-Enterprise-Unified.ps1', 'new_scenarios.txt')
