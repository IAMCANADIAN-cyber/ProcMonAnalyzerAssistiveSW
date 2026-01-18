import re
import json

def parse_markdown(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    scenarios = []
    current_scenario = {}

    # Regex for start of scenario: "1234. **Title:**"
    id_pattern = re.compile(r"^(\d+)\.\s*\*\*(.+?)\*\*")

    for line in lines:
        line = line.strip()

        # New Scenario
        match = id_pattern.match(line)
        if match:
            if current_scenario:
                scenarios.append(current_scenario)

            id_val = match.group(1)
            title_val = match.group(2).strip().rstrip(':')
            rest_of_line = line[match.end():].strip()

            current_scenario = {
                'Id': id_val,
                'Title': title_val,
                'Manifests': '',
                'Logic': '',
                'Cause': ''
            }

            # If the line continues with text, treat it as "Cause" or "Logic" if no bullets follow
            if rest_of_line:
                # heuristic: if it looks like a description, put it in Cause
                current_scenario['Cause'] = rest_of_line
                current_scenario['Logic'] = rest_of_line # Backup for lookup

            continue

        # Parse Details (Bulleted)
        if not current_scenario:
            continue

        if line.startswith('*   **Manifests:**'):
            current_scenario['Manifests'] = line.replace('*   **Manifests:**', '').strip()
        elif line.startswith('*   **Logic:**'):
            current_scenario['Logic'] = line.replace('*   **Logic:**', '').strip()
            # If we overwrite the single-line logic, that's fine
        elif line.startswith('*   **Cause:**'):
            current_scenario['Cause'] = line.replace('*   **Cause:**', '').strip()

    if current_scenario:
        scenarios.append(current_scenario)

    return scenarios

def generate_powershell(scenarios):
    ps_lines = []
    for s in scenarios:
        id = s['Id']
        title = s['Title'].replace('"', "'")
        cause = s['Cause'].replace('"', "'")
        logic = s['Logic'].replace('"', "'")

        # Heuristics for Op/Res/Path/Lookup
        op = ""
        res = ""
        path = ""
        lookup = ""

        if "Reg" in logic or "Registry" in logic:
            op = "RegQueryValue"
        elif "CreateFile" in logic or "WriteFile" in logic:
            op = "CreateFile"
        elif "LoadImage" in logic:
            op = "Load Image"

        if "ACCESS DENIED" in logic or "ACCESS_DENIED" in logic:
            res = "ACCESS DENIED"
        elif "NOT FOUND" in logic or "NAME_NOT_FOUND" in logic:
            res = "NAME NOT FOUND"
        elif "SHARING VIOLATION" in logic:
            res = "SHARING VIOLATION"

        # Lookup is a keyword from Logic to match against Detail/Path in ProcMon
        # We'll take the first significant word or just a generic substring
        # Clean up logic string for lookup
        lookup = logic.replace('`', '').replace('*', '')[:60].replace('\\', '\\\\')

        ps_line = f'    @{{ Id=\'{id}\'; Title="{title}:"; Op="{op}"; Res="{res}"; Lookup="{lookup}"; Path="{path}"; Cause="{cause}" }},'
        ps_lines.append(ps_line)

    return ps_lines

scenarios = parse_markdown('ScenariostoDetect.md')
# Filter for 1000+
scenarios = [s for s in scenarios if int(s['Id']) >= 1000]

ps_output = generate_powershell(scenarios)

with open('new_scenarios.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(ps_output))

print(f"Generated {len(ps_output)} scenarios.")
