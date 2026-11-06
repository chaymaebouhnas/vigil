"""Behaviour model: a random forest for known attacks, an isolation forest for the unknown."""
from __future__ import annotations

import random
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from . import simulator as sim
from .engine import TICK
from .features import LONG, SHORT, WindowTracker

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "behaviour.joblib"
ML_LABELS = ["brute_force", "credential_stuffing", "port_scan", "web_injection", "dns_tunnel", "c2_beacon", "data_exfil"]


class Detector:
    def __init__(self, forest, iso, iso_cut: float, threshold: float = 0.8) -> None:
        self.forest, self.iso, self.iso_cut, self.threshold = forest, iso, iso_cut, threshold

    def score(self, vec: list[float]) -> tuple[str, float, bool]:
        x = np.array([vec])
        proba = self.forest.predict_proba(x)[0]
        best = int(proba.argmax())
        anomalous = bool(self.iso.decision_function(x)[0] < self.iso_cut)
        return str(self.forest.classes_[best]), float(proba[best]), anomalous

    def save(self, path: Path = MODEL_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"forest": self.forest, "iso": self.iso, "iso_cut": self.iso_cut, "threshold": self.threshold}, path)

    @classmethod
    def load(cls, path: Path = MODEL_PATH) -> "Detector":
        d = joblib.load(path)
        return cls(d["forest"], d["iso"], d["iso_cut"], d["threshold"])


def windows_from(stream: list, min_activity: int = 3) -> tuple[list, list]:
    """Replay a labeled stream exactly as the engine sees it, one vector per evaluation."""
    tracker, last_eval, last_attack = WindowTracker(), {}, {}
    X, y = [], []
    for e, label in stream:
        ip = e["src_ip"]
        tracker.add(e)
        if label != "benign":
            last_attack[ip] = (e["ts"], label)
        if e["ts"] - last_eval.get(ip, -1e9) < TICK:
            continue
        last_eval[ip] = e["ts"]
        vec = tracker.vector(ip, e["ts"])
        if vec[0] < min_activity:
            continue
        seen = last_attack.get(ip)
        horizon = LONG if seen and seen[1] == "c2_beacon" else SHORT
        X.append(vec)
        y.append(seen[1] if seen and e["ts"] - seen[0] <= horizon else "benign")
    return X, y


def training_stream(seed: int, attacks: list[str]) -> list:
    rng = random.Random(seed)
    streams = [sim.normal_traffic(0, 3000, rng), sim.hard_negatives(0, 3000, rng)]
    t = 60.0
    for name in attacks:
        streams.append(sim.GENERATORS[name](t, rng, rng.uniform(.3, 1.0)))
        t += rng.uniform(40, 140)
    return sim.merged(*streams)


def build_dataset(seeds, labels=ML_LABELS) -> tuple[np.ndarray, np.ndarray]:
    X, y = [], []
    for seed in seeds:
        order = list(labels)
        random.Random(seed).shuffle(order)
        a, b = windows_from(training_stream(seed, order))
        X += a
        y += b
    return np.array(X), np.array(y)


def train(seeds=range(1000, 1016), labels=ML_LABELS) -> Detector:
    X, y = build_dataset(seeds, labels)
    forest = RandomForestClassifier(n_estimators=60, max_depth=14, class_weight="balanced_subsample",
                                    random_state=7, n_jobs=-1).fit(X, y)
    benign = X[y == "benign"]
    iso = IsolationForest(n_estimators=60, contamination="auto", random_state=7, n_jobs=-1).fit(benign)
    scores = iso.decision_function(benign)
    forest.n_jobs = iso.n_jobs = 1  # one row at a time at runtime; threads only slow that down
    return Detector(forest, iso, float(np.quantile(scores, .0005)))
