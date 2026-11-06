"""Plays every fake attack through the detector and prints a pass/fail table.

Usage:  python scripts/attack_test.py
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vigil import simulator as sim  # noqa: E402
from vigil.engine import Engine  # noqa: E402
from vigil.server import load_detector  # noqa: E402

MUST_FIND = {"full_intrusion": {"credential_stuffing", "valid_account", "data_exfil"}}


def main() -> int:
    detector = load_detector()
    failures = 0
    print(f"{'ATTACK':<24}{'RESULT':<9}{'DETECTED IN':<14}{'WRONGLY BLAMED':<16}INCIDENT")
    for seed, name in enumerate(sim.SCENARIOS, 100):
        rng = random.Random(seed)
        attack = list(sim.GENERATORS[name](120.0, rng))
        bad = {e["src_ip"] for e, _ in attack}
        start, end = attack[0][0]["ts"], attack[-1][0]["ts"] + 60
        engine = Engine(detector)
        first, wrong, kinds = None, 0, set()
        for e, _ in sim.merged(iter(attack), sim.normal_traffic(0, end, rng)):
            for a in engine.process(e):
                if a["src_ip"] in bad:
                    kinds.add(a["kind"])
                    first = a["ts"] - start if first is None else first
                else:
                    wrong += 1
        need = MUST_FIND.get(name, {name})
        ok = need <= kinds and wrong == 0
        failures += not ok
        incident = max(engine.incidents, key=lambda i: len(i.alert_ids), default=None)
        seen = f"{first:.1f}s" if first is not None else "never"
        title = f"{incident.severity}: {incident.to_dict()['title']}" if incident else "-"
        print(f"{name:<24}{'PASS' if ok else 'FAIL':<9}{seen:<14}{wrong:<16}{title}")
    rng = random.Random(1)
    engine = Engine(detector)
    for e, _ in sim.merged(sim.normal_traffic(0, 3600, rng), sim.hard_negatives(0, 3600, rng)):
        engine.process(e)
    quiet = len(engine.alerts) <= 1
    failures += not quiet
    print(f"\nOne simulated hour of normal work, including tricky cases: {len(engine.alerts)} false alert(s), "
          f"target at most 1 ({'PASS' if quiet else 'FAIL'})")
    print("Times are simulated seconds." + (" All checks passed." if not failures else f" {failures} check(s) failed."))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
