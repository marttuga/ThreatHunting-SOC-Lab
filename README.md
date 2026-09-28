# Threat Hunting SOC Lab - MITRE ATT&CK

Hybrid SOC lab built as the postgraduate final project for **SWitCH Cyber (ISEP), 2025/2026**, by a team of 3. It detects a simulated multi-stage attack - from initial macro execution to lateral movement - end to end, and automates the response pipeline from raw log to analyst notification.

**My contribution:** Wazuh detection rules, the Shuffle SOAR pipeline (alert normalization → TheHive case creation → email notification), the TheHive case template and integration, and the incident response playbooks.

> This repo shares the detection-engineering and automation artifacts (rules, playbooks, SOAR logic, case templates, agent configs). It does not include the VM images or Active Directory lab itself - those aren't shareable, but every artifact here is what actually ran against them.

## Attack chain detected

```
T1204.002  User Execution: Malicious File        (Word macro)
    ↓
T1059.001  Command & Scripting: PowerShell
    ↓
T1687      Exploitation for Defense Impairment    (disables Microsoft Defender)
T1686.003  Disable/Modify Firewall: Windows
    ↓
T1021.006  Remote Services: WinRM   ─┐
T1021.004  Remote Services: SSH     ─┴─ lateral movement (Kali → Finance01)
    ↓
T1110.001  Password Guessing: Brute Force
```

7 techniques validated across 4 ATT&CK tactics (Execution, Defense Evasion, Lateral Movement, Credential Access), with zero event loss across all test scenarios.

## Pipeline

```
Endpoint (Sysmon + Wazuh Agent)
   → Wazuh Manager (correlation, 20 custom rules, group "grupo3_isep")
   → Shuffle SOAR (webhook → normalize → decide incident vs. detection)
       ├──> TheHive  (POST /api/v1/alert, auto case from template)
       └──> Notification → Email (SMTP STARTTLS, structured summary to analyst)
```

See [`diagrams/shuffle_branch.png`](diagrams/shuffle_branch.png) for the full Shuffle workflow diagram.

## Repository structure

| Path | Contents |
|---|---|
| `rules/local_rules.xml` | 20 custom Wazuh detection rules (IDs 100101-100170), including the multi-event correlation rule (firewall change + inbound connection within 300s → incident, level 15). |
| `agent-configs/` | `ossec.conf` for the two monitored hosts (`Finance01` - victim endpoint, `Grupo3DC` - domain controller), with the stock config changes needed for TTP visibility: PowerShell Script Block Logging, Windows Defender operational log, Security log EventID 5145, Task Scheduler operational log, real-time FIM on `%WINDIR%\Temp` and `%PUBLIC%`. |
| `soar/shuffle/shuffle_node_alert.py` | Core Shuffle automation node: normalizes the raw Wazuh webhook payload, decides incident vs. isolated detection, maps MITRE technique → tactic, builds the TheHive alert payload (title, description, severity, tags, procedures) with a deterministic `sourceRef` to prevent duplicate cases. |
| `soar/thehive/case_template_threat_hunting.json` | TheHive 5 case template (`TH-ThreatHunting`): 13 tasks across triage → investigation → containment → eradication → lessons learned, plus the custom fields required for MITRE/host/rule metadata. |
| `soar/thehive/thehive_alert_payload.json` | Shuffle → TheHive node body, mapping normalized fields into the `/api/v1/alert` request. |
| `playbooks/` | Threat hunting playbooks per technique (hypothesis, telemetry sources, DQL hunt query, expected artifacts). Currently T1059.001 and T1687. |
| `diagrams/` | Shuffle workflow diagram (source `.tex` + rendered `.png`). |

## Detection engineering notes

- **Rule correlation:** rule `100170` (level 15, "cadeia confirmada") fires only when a firewall-change event and an inbound-connection event are seen for the same host within a 300-second window - isolated detections stay at their native Wazuh level (1-3 in the SOAR's severity mapping).
- **Alert deduplication:** `sourceRef` is a SHA-1 hash of `rule_id | host | timestamp`, so TheHive rejects re-sent duplicates from the same underlying event.
- **Known false positive:** rule for T1687 (Defense Impairment) can fire on legitimate Windows Update activity (`TiWorker.exe`); planned fix is filtering by parent process.

## Stack

Wazuh Manager | Wazuh Agent + Sysmon | TheHive 5.2 | Shuffle SOAR | Docker Compose (Ubuntu Server 24.04) | Windows 11 / Windows Server 2022 (VMware, host-only network) | Kali Linux (attacker) | Python

## Team

Sara Bastos | Marta Portugal | José Rodrigues - SWitCH Cyber, ISEP, 2025/2026
