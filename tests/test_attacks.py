"""The attack test: each fake attack must be caught, and normal work must stay quiet."""
import random

import pytest

from vigil import simulator as sim
from vigil.engine import Engine

EXPECTED = {"brute_force": "brute_force", "credential_stuffing": "credential_stuffing", "port_scan": "port_scan",
            "web_injection": "web_injection", "dns_tunnel": "dns_tunnel", "c2_beacon": "c2_beacon",
            "data_exfil": "data_exfil", "log_prompt_injection": "log_prompt_injection"}


def play(name, seed, detector):
    rng = random.Random(seed)
    attack = list(sim.GENERATORS[name](120.0, rng))
    bad = {e["src_ip"] for e, _ in attack}
    length = attack[-1][0]["ts"] + 60
    eng = Engine(detector)
    for e, _ in sim.merged(iter(attack), sim.normal_traffic(0, length, rng)):
        eng.process(e)
    return eng, bad


@pytest.mark.parametrize("name", EXPECTED)
@pytest.mark.parametrize("seed", [11, 12, 13])
def test_attack_is_detected(name, seed, detector):
    eng, bad = play(name, seed, detector)
    kinds = {a["kind"] for a in eng.alerts if a["src_ip"] in bad}
    assert EXPECTED[name] in kinds


@pytest.mark.parametrize("name", EXPECTED)
def test_attack_does_not_blame_bystanders(name, detector):
    eng, bad = play(name, 21, detector)
    assert [a for a in eng.alerts if a["src_ip"] not in bad] == []


@pytest.mark.parametrize("seed", [31, 32])
def test_full_intrusion_becomes_one_critical_incident(seed, detector):
    rng = random.Random(seed)
    attack = list(sim.full_intrusion(100.0, rng))
    eng = Engine(detector)
    for e, _ in sim.merged(iter(attack), sim.normal_traffic(0, attack[-1][0]["ts"] + 30, rng)):
        eng.process(e)
    main = max(eng.incidents, key=lambda i: len(i.kinds))
    assert {"credential_stuffing", "valid_account", "data_exfil"} <= set(main.kinds)
    assert main.severity == "critical"
    assert len(main.tactics) >= 3
    assert len(eng.incidents) == 1
    machines = {x for x in main.entities if x.startswith("10.")}
    assert len(machines) == 1, "only the machine the attacker used may be blamed"
    assert not any(a["kind"] == "anomaly" for a in eng.alerts)


def test_normal_work_raises_no_alerts(detector):
    rng = random.Random(41)
    eng = Engine(detector)
    for e, _ in sim.merged(sim.normal_traffic(0, 1800, rng), sim.hard_negatives(0, 1800, rng)):
        eng.process(e)
    assert eng.alerts == []


def test_detection_never_reads_ground_truth():
    for module in ("engine", "features", "rules"):
        source = open(f"vigil/{module}.py", encoding="utf-8").read()
        assert "label" not in source.lower()


def test_generated_addresses_can_never_be_real():
    rng = random.Random(5)
    for name, gen in sim.GENERATORS.items():
        for e, _ in gen(0, rng):
            for ip in (e["src_ip"], e.get("dst_ip", "10.20.0.1")):
                assert ip.startswith(("10.20.", "203.0.113.", "198.51.100."))
            if e["source"] == "dns":
                assert e["query"].endswith(".example")
