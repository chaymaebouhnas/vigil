"""Train the model and write an honest evaluation to reports/."""
import json
import multiprocessing
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sklearn.metrics import classification_report  # noqa: E402

from vigil import model as M  # noqa: E402
from vigil import simulator as sim  # noqa: E402
from vigil.engine import Engine  # noqa: E402

EXPECT = {"full_intrusion": {"credential_stuffing", "valid_account", "data_exfil"}}


def run_scenario(name, seed, intensity, detector, use_ml=True):
    rng = random.Random(seed)
    attack = list(sim.GENERATORS[name](300.0, rng, intensity))
    bg = sim.merged(sim.normal_traffic(0, 1500, rng), sim.hard_negatives(0, 1500, rng))
    bad_ips = {e["src_ip"] for e, _ in attack}
    eng = Engine(detector, use_ml=use_ml)
    first, kinds, false_alerts = None, set(), 0
    for e, _ in sim.merged(iter(attack), iter(bg)):
        for a in eng.process(e):
            if a["src_ip"] in bad_ips and a["ts"] >= attack[0][0]["ts"] and a["kind"] != "anomaly":
                kinds.add(a["kind"])
                if a["kind"] in EXPECT.get(name, {name}):  # the right attack, not just any alert
                    first = first if first is not None else a["ts"] - attack[0][0]["ts"]
            else:
                false_alerts += 1
    return first, kinds, false_alerts, len(eng.incidents)


def false_alert_rate(detector, use_ml, hours=2):
    n = 0
    for seed in range(9000, 9000 + 3):
        rng = random.Random(seed)
        eng = Engine(detector, use_ml=use_ml)
        for e, _ in sim.merged(sim.normal_traffic(0, hours * 3600, rng), sim.hard_negatives(0, hours * 3600, rng)):
            n += len(eng.process(e))
    return n / (3 * hours)


_det = None


def _init():
    global _det
    _det = M.Detector.load()


def _job(job):
    name, label, intensity, use_ml = job
    hits, ttd, false = 0, [], 0
    for seed in range(7000, 7008):
        first, kinds, fa, _ = run_scenario(name, seed, intensity, _det, use_ml)
        ok = first is not None and EXPECT.get(name, {name}) <= kinds
        hits += ok
        false += fa
        if ok:
            ttd.append(first)
    print(name, label, use_ml, hits, flush=True)
    return {"scenario": name, "strength": label, "engine": "rules+ml" if use_ml else "rules", "detected": hits, "runs": 8,
            "median_seconds_to_detect": round(statistics.median(ttd), 1) if ttd else None, "false_alerts": false}


def main():
    t0 = time.time()
    det = M.train()
    det.save()
    print("trained", round(time.time() - t0), flush=True)
    X, y = M.build_dataset(range(5000, 5006))
    window = classification_report(y, det.forest.predict(X), output_dict=True, zero_division=0)
    out = {"window_level_holdout": {k: {"precision": round(v["precision"], 3), "recall": round(v["recall"], 3), "support": int(v["support"])}
                                    for k, v in window.items() if isinstance(v, dict) and k != "weighted avg"}}
    jobs = [(n, lab, i, ml) for n in sim.SCENARIOS for lab, i in [("normal", 1.0), ("stealthy", .35)] for ml in (False, True)]
    with multiprocessing.Pool(2, initializer=_init) as pool:
        rows = pool.map(_job, jobs, chunksize=1)
    out["scenario_detection"] = rows
    out["false_alerts_per_simulated_hour"] = {"rules": round(false_alert_rate(det, False), 2), "rules+ml": round(false_alert_rate(det, True), 2)}
    unseen = []
    for held in M.ML_LABELS:
        d2 = M.train(seeds=range(1000, 1006), labels=[x for x in M.ML_LABELS if x != held])
        got = 0
        for seed in range(7100, 7110):
            rng = random.Random(seed)
            attack = list(sim.GENERATORS[held](300.0, rng, 1.0))
            bad = {e["src_ip"] for e, _ in attack}
            eng = Engine(d2)
            found = False
            for e, _ in sim.merged(iter(attack), sim.normal_traffic(0, 900, rng)):
                found |= any(a["src_ip"] in bad and a["method"] == "ml" for a in eng.process(e))
            got += found
        unseen.append({"attack_never_trained_on": held, "ml_flagged": got, "runs": 10})
    out["unseen_attack_test"] = unseen
    out["seconds"] = round(time.time() - t0)
    Path(ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "metrics.json").write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=1)[:200])
    for r in rows:
        print(r)
    print(out["false_alerts_per_simulated_hour"], unseen, out["seconds"])


if __name__ == "__main__":
    main()
