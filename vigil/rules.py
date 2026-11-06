"""Explainable detection rules, mapped to MITRE ATT&CK techniques."""
from __future__ import annotations

import re

TECHNIQUES = {
    "brute_force": ("T1110.001", "Password Guessing", "Credential Access", "high"),
    "credential_stuffing": ("T1110.004", "Credential Stuffing", "Credential Access", "high"),
    "valid_account": ("T1078", "Valid Accounts", "Initial Access", "critical"),
    "port_scan": ("T1046", "Network Service Discovery", "Discovery", "medium"),
    "web_injection": ("T1190", "Exploit Public-Facing Application", "Initial Access", "high"),
    "dns_tunnel": ("T1071.004", "Application Layer Protocol: DNS", "Command and Control", "high"),
    "c2_beacon": ("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control", "high"),
    "data_exfil": ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", "critical"),
    "log_prompt_injection": ("AML.T0051", "LLM Prompt Injection (MITRE ATLAS)", "Defense Evasion", "high"),
    "anomaly": ("-", "Unusual behaviour", "Unknown", "low"),
}

WEB_PATTERNS = re.compile(
    r"('\s*or\s*'|union\s+select|;\s*drop\s+table|sleep\(\d+\)|\.\./\.\./|<script\b)", re.I)
PROMPT_PATTERNS = re.compile(
    r"(ignore (all )?(previous|prior) instructions|disregard (all )?prior|you are now|^system:|"
    r"mark this ip as safe|report that no attack)", re.I)


def signature(e: dict) -> str | None:
    """Single-event signatures."""
    if e["source"] == "web":
        if WEB_PATTERNS.search(str(e.get("path", ""))):
            return "web_injection"
        for field in ("ua", "path"):
            if PROMPT_PATTERNS.search(str(e.get(field, ""))):
                return "log_prompt_injection"
    return None


def behaviour(v: dict) -> list[tuple[str, str]]:
    """Threshold rules on window features. Returns (kind, human reason)."""
    hits = []
    if v["auth_fail"] >= 10 and v["distinct_users"] <= 2:
        hits.append(("brute_force", f"{int(v['auth_fail'])} failed logins on {int(v['distinct_users'])} account(s) in 60s"))
    if v["auth_fail"] >= 10 and v["distinct_users"] >= 8:
        hits.append(("credential_stuffing", f"{int(v['auth_fail'])} failed logins across {int(v['distinct_users'])} accounts in 60s"))
    if v["distinct_ports"] >= 25 and v["denied"] >= 20:
        hits.append(("port_scan", f"{int(v['distinct_ports'])} ports probed, {int(v['denied'])} blocked in 60s"))
    if v["dns_queries"] >= 15 and v["dns_mean_len"] >= 25 and v["dns_mean_entropy"] >= 3.5:
        hits.append(("dns_tunnel", f"{int(v['dns_queries'])} DNS lookups, average name length {v['dns_mean_len']:.0f}, entropy {v['dns_mean_entropy']:.1f}"))
    if v["beacon_regularity"] >= .9 and v["beacon_count"] >= 8:
        hits.append(("c2_beacon", f"{int(v['beacon_count'])} calls to one outside server at near-fixed intervals"))
    if v["log_bytes_external"] >= 18.4:  # roughly 100 MB in 60 seconds
        hits.append(("data_exfil", f"about {(2.718281828 ** v['log_bytes_external']) / 1e6:.0f} MB sent to outside servers in 60s"))
    return hits
