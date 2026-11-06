"""Streaming detection: events in, alerts out, grouped into incidents."""
from __future__ import annotations

from dataclasses import dataclass, field

from .features import FEATURES, SHORT, WindowTracker
from .rules import TECHNIQUES, behaviour, signature
from .simulator import USER_HOME

TICK = 5.0
COOLDOWN = 120.0
SEVERITY = ["low", "medium", "high", "critical"]
CORRELATION_WINDOW = 1800.0
SHARED_INFRA = {"10.20.0.5", "10.20.0.8", "10.20.0.12"}


@dataclass
class Incident:
    id: str
    first_ts: float
    last_ts: float
    entities: set = field(default_factory=set)
    alert_ids: list = field(default_factory=list)
    kinds: list = field(default_factory=list)
    tactics: list = field(default_factory=list)
    severity: str = "low"

    def to_dict(self) -> dict:
        return {"id": self.id, "first_ts": self.first_ts, "last_ts": self.last_ts,
                "entities": sorted(self.entities), "alert_ids": self.alert_ids, "kinds": self.kinds,
                "tactics": self.tactics, "severity": self.severity, "title": incident_title(self.kinds)}


def incident_title(kinds: list[str]) -> str:
    k = set(kinds)
    if {"data_exfil"} & k and k & {"valid_account", "credential_stuffing", "c2_beacon", "brute_force"}:
        return "Account takeover leading to data theft"
    if "valid_account" in k:
        return "Account takeover"
    names = {"brute_force": "Password guessing", "credential_stuffing": "Credential stuffing", "port_scan": "Port scan",
             "web_injection": "Web injection attack", "dns_tunnel": "DNS tunneling", "c2_beacon": "Malware beaconing",
             "data_exfil": "Data exfiltration", "log_prompt_injection": "Prompt injection against the AI analyst",
             "anomaly": "Unusual behaviour"}
    return names.get(kinds[0], kinds[0]) if len(k) == 1 else f"{names.get(kinds[0], kinds[0])} and related activity"


class Engine:
    def __init__(self, detector=None, use_ml: bool = True) -> None:
        self.tracker = WindowTracker()
        self.detector = detector if use_ml else None
        self.last_eval: dict[str, float] = {}
        self.last_alert: dict[tuple, float] = {}
        self.alerts: list[dict] = []
        self.incidents: list[Incident] = []
        self.compromised: dict[str, set] = {}
        self.user_ips: dict[str, str] = {}
        self.events_seen = 0

    def process(self, e: dict) -> list[dict]:
        self.events_seen += 1
        self.tracker.add(e)
        out: list[dict] = []
        self._track_accounts(e, out)
        kind = signature(e)
        if kind:
            detail = "Hidden instructions found in a log field" if kind == "log_prompt_injection" else "Attack pattern in a web request"
            out += self._raise(e, kind, "signature", detail, 0.99, sample=_sample(e))
        ip = e["src_ip"]
        if e["ts"] - self.last_eval.get(ip, -1e9) >= TICK:
            self.last_eval[ip] = e["ts"]
            vec = self.tracker.vector(ip, e["ts"])
            named = dict(zip(FEATURES, vec))
            fired = set()
            for k, reason in behaviour(named):
                fired.add(k)
                out += self._raise(e, k, "rule", reason, 0.95)
            if self.detector and vec[0] >= 3:
                k, p, anomalous = self.detector.score(vec)
                if k != "benign" and p >= self.detector.threshold and k not in fired:
                    out += self._raise(e, k, "ml", f"Behaviour model: {p:.0%} match for {k.replace('_', ' ')}", p)
                elif k == "benign" and anomalous and not fired:
                    out += self._raise(e, "anomaly", "ml", "Behaviour unlike anything in the normal baseline", .6)
        return out

    def _track_accounts(self, e: dict, out: list) -> None:
        if e["source"] != "auth" or e.get("action") != "login_ok":
            return
        user, ip = e.get("user"), e["src_ip"]
        recent = e["ts"] - 300
        fails = sum(1 for x in self.tracker.windows[ip] if x.get("action") == "login_fail" and x["ts"] >= recent)
        self.user_ips[user] = ip
        if fails >= 8 and ip != USER_HOME.get(user):  # typos on your own machine are not a takeover
            self.compromised.setdefault(user, set()).add(ip)
            out += self._raise(e, "valid_account", "rule", f"Login succeeded as {user} after {fails} failures from this source", .97)
        elif user in self.compromised and ip not in self.compromised[user] and ip != USER_HOME.get(user):
            # The owner's own machine is not evidence. A new machine using a stolen account is.
            self.compromised[user].add(ip)
            for inc in self.incidents:
                if user in inc.entities:
                    inc.entities.add(ip)

    def _raise(self, e: dict, kind: str, method: str, reason: str, confidence: float, sample: str | None = None) -> list[dict]:
        key = (e["src_ip"], kind)
        if e["ts"] - self.last_alert.get(key, -1e9) < COOLDOWN:
            for a in reversed(self.alerts[-200:]):
                if a["src_ip"] == e["src_ip"] and a["kind"] == kind:
                    a["hits"] += 1
                    a["last_ts"] = e["ts"]
                    if method == "rule" and a["method"] == "ml":  # plain-language evidence beats a score
                        a["reason"], a["method"], a["confidence"] = reason, "rule+ml", max(a["confidence"], confidence)
                    break
            return []
        self.last_alert[key] = e["ts"]
        tech, name, tactic, sev = TECHNIQUES[kind]
        entities = {e["src_ip"]} - SHARED_INFRA
        if e.get("user") and (kind == "valid_account" or e["user"] in self.compromised):
            entities.add(e["user"])
        for user, ips in self.compromised.items():
            if e["src_ip"] in ips:
                entities.add(user)
        a = {"id": f"A-{len(self.alerts) + 1:04d}", "ts": e["ts"], "last_ts": e["ts"], "kind": kind, "method": method,
             "reason": reason, "confidence": round(confidence, 2), "severity": sev, "src_ip": e["src_ip"],
             "technique": tech, "technique_name": name, "tactic": tactic, "entities": sorted(entities),
             "hits": 1, "sample": sample}
        self.alerts.append(a)
        self._correlate(a)
        return [a]

    def _correlate(self, a: dict) -> None:
        ents = set(a["entities"])
        matches = [i for i in self.incidents if i.entities & ents and a["ts"] - i.last_ts <= CORRELATION_WINDOW]
        if matches:
            inc = matches[0]
            for other in matches[1:]:
                inc.entities |= other.entities
                inc.alert_ids += other.alert_ids
                inc.kinds += [k for k in other.kinds if k not in inc.kinds]
                inc.tactics += [t for t in other.tactics if t not in inc.tactics]
                inc.first_ts = min(inc.first_ts, other.first_ts)
                self.incidents.remove(other)
        else:
            inc = Incident(id=f"INC-{len(self.incidents) + 1:03d}", first_ts=a["ts"], last_ts=a["ts"])
            self.incidents.append(inc)
        inc.entities |= ents
        inc.last_ts = a["ts"]
        inc.alert_ids.append(a["id"])
        if a["kind"] not in inc.kinds:
            inc.kinds.append(a["kind"])
        if a["tactic"] not in inc.tactics and a["tactic"] != "Unknown":
            inc.tactics.append(a["tactic"])
        rank = max(SEVERITY.index(self.alert(x)["severity"]) for x in inc.alert_ids)
        if len(inc.tactics) >= 3:
            rank = 3
        inc.severity = SEVERITY[rank]
        a["incident_id"] = inc.id

    def alert(self, alert_id: str) -> dict:
        return next(a for a in self.alerts if a["id"] == alert_id)


def _sample(e: dict) -> str:
    return str(e.get("ua") if e.get("ua") and "Mozilla" not in e["ua"] and "sqlmap" not in e["ua"] else e.get("path", ""))[:200]
