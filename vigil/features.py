"""Sliding-window behaviour features, one vector per source IP."""
from __future__ import annotations

import ipaddress
import math
from collections import defaultdict, deque
from statistics import mean, pstdev

from .simulator import entropy

SHORT = 60.0
LONG = 900.0

FEATURES = ["events", "auth_fail", "auth_ok", "fail_ratio", "distinct_users", "denied", "distinct_ports",
            "web_reqs", "web_err_ratio", "distinct_paths", "log_bytes_external", "dns_queries",
            "dns_mean_len", "dns_mean_entropy", "beacon_regularity", "beacon_count", "ok_after_fails"]


def is_internal(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private and not ip.startswith(("203.0.113", "198.51.100", "192.0.2"))
    except ValueError:
        return False


class WindowTracker:
    def __init__(self) -> None:
        self.windows: dict[str, deque] = defaultdict(deque)

    def add(self, e: dict) -> None:
        w = self.windows[e["src_ip"]]
        w.append(e)
        while w and w[0]["ts"] < e["ts"] - LONG:
            w.popleft()

    def vector(self, ip: str, now: float) -> list[float]:
        all_ev = [e for e in self.windows.get(ip, ()) if e["ts"] <= now]
        ev = [e for e in all_ev if e["ts"] >= now - SHORT]
        auth = [e for e in ev if e["source"] == "auth"]
        fails = sum(e.get("action") == "login_fail" for e in auth)
        oks = sum(e.get("action") == "login_ok" for e in auth)
        net = [e for e in ev if e["source"] == "net"]
        web = [e for e in ev if e["source"] == "web"]
        dns = [e for e in ev if e["source"] == "dns"]
        names = [e["query"].split(".")[0] for e in dns]
        external = sum(e.get("bytes_out", 0) for e in net if not is_internal(e.get("dst_ip", "")))
        groups: dict[str, list[float]] = defaultdict(list)
        for e in all_ev:
            if e["source"] == "net" and not is_internal(e.get("dst_ip", "")):
                groups[e["dst_ip"]].append(e["ts"])
        regular, count = 0.0, 0
        for times in groups.values():
            if len(times) >= 6:
                gaps = [b - a for a, b in zip(times, times[1:])]
                if mean(gaps) > 5:
                    score = 1 - min(pstdev(gaps) / mean(gaps), 1)
                    if score > regular:
                        regular, count = score, len(times)
        long_auth = [e for e in all_ev if e["source"] == "auth"]
        ok_after = 0.0
        if long_auth and long_auth[-1].get("action") == "login_ok":
            ok_after = math.log1p(sum(e.get("action") == "login_fail" for e in long_auth))
        return [len(ev), fails, oks, fails / len(auth) if auth else 0, len({e.get("user") for e in auth}),
                sum(e.get("action") == "deny" for e in net), len({e.get("dst_port") for e in net}), len(web),
                sum(e.get("status", 0) >= 400 for e in web) / len(web) if web else 0,
                len({e.get("path") for e in web}), math.log1p(external), len(dns),
                mean(len(q) for q in names) if names else 0, mean(entropy(q) for q in names) if names else 0,
                regular, count, ok_after]

    def active(self, since: float) -> list[str]:
        return [ip for ip, w in self.windows.items() if w and w[-1]["ts"] >= since]
