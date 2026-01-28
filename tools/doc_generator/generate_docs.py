
import re

def parse_markdown_metadata(filepath):
    metadata = {}
    current_section = "Uncategorized"
    current_id = None

    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()

        if line.startswith("### **SECTION") or line.startswith("### Module"):
            clean_line = line.replace("#", "").replace("*", "").strip()
            current_section = clean_line

        m_item = re.match(r'^(\d+)\.\s+\*\*(.*?)\:\*\*', line)
        if m_item:
            current_id = int(m_item.group(1))
            title = m_item.group(2).strip()
            if current_id not in metadata:
                metadata[current_id] = {
                    'Section': current_section,
                    'Title': title,
                    'Manifests': "",
                    'Logic': "",
                    'Cause': ""
                }
            continue

        if current_id:
            m_manifest = re.match(r'\*\s+\*\*Manifests:\*\*\s*(.*)', line)
            if m_manifest:
                metadata[current_id]['Manifests'] = m_manifest.group(1).strip()
                continue

            m_logic = re.match(r'\*\s+\*\*Logic:\*\*\s*(.*)', line)
            if m_logic:
                metadata[current_id]['Logic'] = m_logic.group(1).strip()
                continue

            m_cause = re.match(r'\*\s+\*\*Cause:\*\*\s*(.*)', line)
            if m_cause:
                metadata[current_id]['Cause'] = m_cause.group(1).strip()
                continue

    for line in lines:
        line = line.strip()
        m_item = re.match(r'^(\d+)\.\s+\*\*(.*?)\:\*\*\s*(.*)', line)
        if m_item:
            sid = int(m_item.group(1))
            tail = m_item.group(3)
            if sid in metadata and tail:
                if not metadata[sid]['Cause'] and not metadata[sid]['Manifests']:
                    m_cause_short = re.search(r'\(([^)]+)\)\.?$', tail)
                    if m_cause_short:
                        metadata[sid]['Cause'] = m_cause_short.group(1)
                        metadata[sid]['Logic'] = tail[:m_cause_short.start()].strip()
                    else:
                        metadata[sid]['Logic'] = tail

    return metadata

def parse_evidence_citations(filepath):
    """Parses SCENARIO_EVIDENCE.md to extract citations/URLs per ID."""
    citations = {} # ID -> URL/Citation

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Sections are like ### 1508. Hook Injection
    # Followed by * **Evidence / Citation:**
    # * **Source:** [Title](URL)

    # Split by ### ID.
    parts = re.split(r'###\s+(\d+)\.', content)

    # parts[0] is header
    # parts[1] is ID, parts[2] is body, parts[3] is ID, parts[4] is body...

    for i in range(1, len(parts), 2):
        sid = int(parts[i])
        body = parts[i+1]

        # Look for Source URL
        m_url = re.search(r'\*\*Source:\*\*.*?\((http.*?)\)', body)
        if m_url:
            citations[sid] = m_url.group(1)
        else:
            # Maybe just text?
            m_source = re.search(r'\*\*Source:\*\*\s*(.*)', body)
            if m_source:
                citations[sid] = m_source.group(1).strip()

    return citations

def parse_ps1_scenarios(filepath):
    scenarios = {}
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith("@{") and "Id=" in line:
            m_id = re.search(r"Id='(\d+)'", line)
            if not m_id: continue
            sid = int(m_id.group(1))

            def get_val(key):
                p = key + r'="((?:[^"]|`.)*)"'
                m = re.search(p, line)
                if m:
                    return m.group(1).replace('`"', '"')
                return ""

            scenarios[sid] = {
                'Id': sid,
                'Title': get_val('Title'),
                'Op': get_val('Op'),
                'Res': get_val('Res'),
                'Path': get_val('Path'),
                'Process': get_val('Process'),
                'Cause': get_val('Cause'),
            }

    return scenarios

def tokenize(text):
    return set(re.findall(r'\w+', text.lower()))

def titles_match(t1, t2):
    if not t1 or not t2: return False
    t1_clean = re.sub(r'\(.*?\)', '', t1)
    t2_clean = re.sub(r'\(.*?\)', '', t2)

    tokens1 = tokenize(t1_clean)
    tokens2 = tokenize(t2_clean)

    if not tokens1 or not tokens2: return False

    overlap = tokens1.intersection(tokens2)
    if not overlap: return False

    significant_overlap = [w for w in overlap if len(w) > 3]
    if significant_overlap: return True

    ratio = len(overlap) / max(len(tokens1), len(tokens2))
    return ratio >= 0.3

def generate_markdown(ps1_scenarios, md_metadata, evidence_citations, output_path):
    all_ids = sorted(ps1_scenarios.keys())
    grouped = {}

    for sid in all_ids:
        s_ps1 = ps1_scenarios[sid]
        s_md = md_metadata.get(sid, {})

        match = False
        if s_md:
            match = titles_match(s_ps1['Title'], s_md['Title'])

        if not match:
            s_md = {}

        section = s_md.get('Section', "Uncategorized (Script Only)")

        if section not in grouped: grouped[section] = []

        title = s_ps1['Title']
        if match and s_md.get('Title'): title = s_md['Title']

        op = s_ps1['Op'].replace("|", "\\|") if s_ps1['Op'] else "*"
        res = s_ps1['Res'].replace("|", "\\|") if s_ps1['Res'] else "*"
        path = s_ps1['Path'].replace("|", "\\|") if s_ps1['Path'] else "*"
        proc = f"`{s_ps1['Process']}` " if s_ps1['Process'] else ""

        tech_sig = f"**Op:** `{op}`<br>**Res:** `{res}`<br>**Path:** `{path}`"
        if proc: tech_sig = f"**Proc:** {proc}<br>" + tech_sig

        context_parts = []
        if s_md.get('Manifests'):
            context_parts.append(f"**Symptom:** {s_md['Manifests']}")

        cause = s_md.get('Cause') or s_ps1['Cause']
        if cause:
            context_parts.append(f"**Cause:** {cause}")
        elif s_md.get('Logic'):
             context_parts.append(f"**Context:** {s_md['Logic']}")

        # Inject URL if available in Evidence
        if sid in evidence_citations:
            context_parts.append(f"**Ref:** {evidence_citations[sid]}")

        context = "<br><br>".join(context_parts)

        grouped[section].append({
            'Id': sid,
            'Title': title,
            'Sig': tech_sig,
            'Context': context
        })

    sorted_sections = sorted(grouped.keys(), key=lambda k: grouped[k][0]['Id'] if grouped[k] else 9999)
    if "Uncategorized (Script Only)" in sorted_sections:
        sorted_sections.remove("Uncategorized (Script Only)")
        sorted_sections.append("Uncategorized (Script Only)")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# 📚 Scenario Library (Automated Catalog)\n\n")
        f.write("This document defines the detection logic for `ProcMon-Enterprise-Unified.ps1`.\n")
        f.write("It correlates technical signatures (Operations/Results) with User Experiences and Root Causes.\n\n")
        f.write("## 🔎 How to Read\n")
        f.write("- **ID:** Unique identifier in the script engine.\n")
        f.write("- **Title:** The name of the detection scenario.\n")
        f.write("- **Technical Signature:** The specific ProcMon Operation, Result, and Path pattern that triggers the detection.\n")
        f.write("- **Context & Remediation:** Explanation of the root cause, symptoms, and potential fixes.\n\n")
        f.write("---\n\n")

        for sec in sorted_sections:
            f.write(f"## {sec}\n\n")
            f.write("| ID | Title | Technical Signature | Context & Remediation |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            for item in grouped[sec]:
                f.write(f"| **{item['Id']}** | {item['Title']} | {item['Sig']} | {item['Context']} |\n")
            f.write("\n")

        f.write("## 🧩 Dynamic Detectors (Heuristic Modules)\n\n")
        f.write("These advanced modules run code logic beyond simple signature matching.\n\n")
        f.write("| Module | Logic Pattern | User Experience |\n")
        f.write("| :--- | :--- | :--- |\n")
        f.write("| **Global Lock (GSB)** | `[Sec_Proc]` touches `[Path]` -> `< 0.5s` later `[AT_Proc]` fails `[Path]` with `SHARING_VIOLATION`. | System 'hiccups' or AT speech skips. Detects 'Security Fratricide'. |\n")
        f.write("| **Hook Injection** | `LoadImage` of suspicious DLLs (CrowdStrike, Citrix) into AT Process. | Application crash on startup or focus loss. |\n")
        f.write("| **Thread Profiling** | High frequency of `Thread Profiling` events (>100/s). | CPU-bound freezing (not I/O bound). |\n")
        f.write("| **Filter Conflict** | `INSTANCE_ALTITUDE_COLLISION` error in Minifilter driver. | File operations fail with strange errors; BSOD risk. |\n")
        f.write("| **Clipboard Lock** | `ACCESS_DENIED` on `\\Device\\NamedPipe\\Clipboard` or `rdpclip`. | Copy/Paste stops working. Identifies the process holding the lock. |\n")
        f.write("| **Audio Ducking** | `ACCESS_DENIED` on `MMDevices` by `audiodg.exe`. | Volume drops and doesn't recover. |\n")
        f.write("| **MFA Block** | `TCP Connect` fail to `login.microsoftonline.com`. | Sign-in loop or prompt spam. |\n")
        f.write("| **OCR Fail** | `PATH NOT FOUND` for `Windows.Media.Ocr` / `tessdata`. | Screen reader cannot read images/PDFs. |\n")
        f.write("| **Packet Storm** | >500 Network Ops/sec by a single process. | Network sluggishness or DoS condition. |\n")
        f.write("| **Browser Loop** | Browser Parent spawning Child Renderer repeatedly (>20x). | Browser tabs crash 'Aw Snap'. |\n")

def main():
    ps1_path = "ProcMon-Enterprise-Unified.ps1"
    md_path = "ScenariostoDetect.md"
    ev_path = "docs/SCENARIO_EVIDENCE.md"
    out_path = "docs/SCENARIO_LIBRARY.MD"

    print(f"Parsing {ps1_path}...")
    ps1_data = parse_ps1_scenarios(ps1_path)

    print(f"Parsing {md_path}...")
    md_data = parse_markdown_metadata(md_path)

    print(f"Parsing {ev_path} for citations...")
    ev_data = parse_evidence_citations(ev_path)

    print(f"Generating {out_path}...")
    generate_markdown(ps1_data, md_data, ev_data, out_path)
    print("Done.")

if __name__ == "__main__":
    main()
