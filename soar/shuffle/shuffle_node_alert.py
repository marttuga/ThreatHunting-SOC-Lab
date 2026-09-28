import json
import hashlib
import time

# ===========================================================================
# ENTRADA — esta e a UNICA linha que liga ao Shuffle.
# Apaguem o $exec.all_fields e usem o AUTOCOMPLETE: Webhook -> all_fields.
# (o r"""...""" aguenta as barras invertidas dos caminhos do Windows)
# ===========================================================================
alert = json.loads(r"""$exec.all_fields""")

# ----------------------------- CONFIGURACAO --------------------------------
CASE_TEMPLATE = "TH-ThreatHunting"
ALERT_TYPE = "wazuh"
ALERT_SOURCE = "Wazuh"

INCIDENT_RULES = {"100170"}
INCIDENT_GROUPS = {"correlation", "active_incident", "kill_chain"}
INCIDENT_LEVEL = 14

TTP_TACTIC = {
    "T1204.002": "Execution",
    "T1059.001": "Execution",
    "T1687":     "Defense Evasion",
    "T1686.003": "Defense Evasion",
    "T1021.006": "Lateral Movement",
    "T1021.004": "Lateral Movement",
}

# Nome curto da tatica no formato que o TheHive usa nos procedures.
TACTIC_SHORTNAME = {
    "Execution": "execution",
    "Defense Evasion": "defense-evasion",
    "Lateral Movement": "lateral-movement",
}


# ------------------------------- HELPERS -----------------------------------
def _get(d, path, default=None):
    cur = d
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def _int(value, default=0):
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return default


# ----------------------------- NORMALIZACAO --------------------------------
def normalize(a):
    win = _get(a, "data.win") or _get(a, "text.win") or {}
    system = win.get("system", {}) if isinstance(win, dict) else {}
    eventdata = win.get("eventdata", {}) if isinstance(win, dict) else {}

    mitre_ids = _get(a, "rule.mitre.id", []) or []
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]

    return {
        "host": system.get("computer", _get(a, "agent.name", "")),
        "machine_ip": _get(a, "agent.ip", ""),
        "user": eventdata.get("user", eventdata.get("targetUserName", "")),
        "timestamp": a.get("timestamp", ""),
        "rule_id": str(_get(a, "rule.id", "")),
        "rule_level": _get(a, "rule.level", 0),
        "rule_desc": _get(a, "rule.description", ""),
        "rule_groups": _get(a, "rule.groups", []) or [],
        "mitre_ids": mitre_ids,
        "command_line": eventdata.get("commandLine", ""),
    }


# ------------------------------- DECISAO -----------------------------------
def is_incident(ev):
    groups = set(g.lower() for g in ev.get("rule_groups", []))
    return (
        ev.get("rule_id", "") in INCIDENT_RULES
        or bool(groups & INCIDENT_GROUPS)
        or _int(ev.get("rule_level")) >= INCIDENT_LEVEL
    )


def severity_from(ev, incident):
    level = _int(ev.get("rule_level"))
    if incident:
        return 4
    if level >= 12:
        return 3
    if level >= 8:
        return 2
    return 1


def source_ref(ev):
    raw = "|".join([ev.get("rule_id", ""), ev.get("host", ""), str(ev.get("timestamp", ""))])
    return "wz-" + hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def build_payload(ev):
    incident = is_incident(ev)
    groups = list(ev.get("rule_groups", []))
    mitre = [t for t in ev.get("mitre_ids", []) if t in TTP_TACTIC] or ev.get("mitre_ids", [])
    tactics = sorted({TTP_TACTIC[t] for t in mitre if t in TTP_TACTIC})

    prefix = "[INCIDENTE] Cadeia confirmada" if incident else "[DETECAO] Evento isolado"
    mitre_label = ", ".join(mitre) if mitre else "n/d"
    title = f"{prefix} [{mitre_label}] - {ev.get('rule_desc') or ev.get('host') or 'sem descricao'}"

    description = (
        f"Regra Wazuh {ev.get('rule_id','')} (nivel {ev.get('rule_level','')}) | "
        f"Host: {ev.get('host','')} ({ev.get('machine_ip','')}) | "
        f"Utilizador: {ev.get('user','')} | "
        f"MITRE: {', '.join(mitre) or 'n/d'} | "
        f"Comando: {ev.get('command_line','')}"
    )

    tags = ["wazuh", "grupo3"]
    tags += [f"mitre:{t}" for t in mitre]
    tags += [f"tactic:{t.replace(' ', '-').lower()}" for t in tactics]
    tags += groups
    tags = list(dict.fromkeys(tags))

    # TTPs (procedures) -> preenchem o separador TTPs do alerta/caso.
    # So enviamos os que estao no catalogo MITRE (in-scope), com a tatica conhecida.
    now_ms = int(time.time() * 1000)
    procedures = [
        {
            "patternId": tid,
            "occurDate": now_ms,
            "tactic": TACTIC_SHORTNAME.get(TTP_TACTIC.get(tid, ""), ""),
        }
        for tid in mitre if tid in TTP_TACTIC
    ]

    return {
        "type": ALERT_TYPE,
        "source": ALERT_SOURCE,
        "sourceRef": source_ref(ev),
        "title": title,
        "description": description,
        "severity": int(severity_from(ev, incident)),
        "tlp": 2,
        "pap": 2,
        "flag": bool(incident),
        "tags": tags,
        "procedures": procedures,
        "caseTemplate": CASE_TEMPLATE,
        "status": "New",
    }


# =============================== SAIDA =====================================
# O print e o que o no seguinte (TheHive) vai receber.
print(json.dumps(build_payload(normalize(alert))))