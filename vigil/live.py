"""Runs the simulation in real time: a virtual clock feeds events into the engine."""
from __future__ import annotations

import asyncio
import heapq
import itertools
import random
import time
from collections import deque

from . import simulator as sim
from .analyst import Analyst
from .engine import Engine

BUCKET = 10.0
CHUNK = 120.0


class Live:
    def __init__(self, detector, speed: float = 15.0, seed: int | None = None) -> None:
        self.detector, self.speed, self.seed = detector, speed, seed
        self.subscribers: set[asyncio.Queue] = set()
        self.reset()

    def reset(self) -> None:
        self.rng = random.Random(self.seed)
        self.engine = Engine(self.detector)
        self.analyst = Analyst(self.engine)
        self.now = 0.0
        self.horizon = 0.0
        self.heap: list = []
        self.counter = itertools.count()
        self.feed: deque = deque(maxlen=60)
        self.buckets: dict[int, list[int]] = {}
        self.attacks: list[dict] = []
        self.attack_ips: dict[str, dict] = {}
        self._extend()

    def _extend(self) -> None:
        start = self.horizon
        self.horizon += CHUNK
        self._push(sim.normal_traffic(start, CHUNK, self.rng))
        if self.rng.random() < .3:
            self._push(sim.hard_negatives(start, CHUNK, self.rng))

    def _push(self, items) -> None:
        for e, _ in items:
            heapq.heappush(self.heap, (e["ts"], next(self.counter), e))

    def launch(self, name: str) -> dict:
        items = list(sim.GENERATORS[name](self.now + 1, self.rng))
        record = {"id": len(self.attacks) + 1, "scenario": name, "description": sim.SCENARIO_INFO[name], "started": items[0][0]["ts"],
                  "ends": items[-1][0]["ts"], "events": len(items), "detected_after": None}
        self.attacks.append(record)
        for e, _ in items:
            self.attack_ips.setdefault(e["src_ip"], record)
        self._push(items)
        return record

    def step(self, dt: float) -> dict:
        self.now += dt * self.speed
        if self.now + 10 > self.horizon:
            self._extend()
        events, alerts = [], []
        while self.heap and self.heap[0][0] <= self.now:
            _, _, e = heapq.heappop(self.heap)
            new = self.engine.process(e)
            alerts += new
            for a in new:
                rec = self.attack_ips.get(a["src_ip"])
                if rec and rec["detected_after"] is None:
                    rec["detected_after"] = round(a["ts"] - rec["started"], 1)
            flagged = bool(new) or self._flagged(e)
            b = self.buckets.setdefault(int(e["ts"] // BUCKET), [0, 0])
            b[1 if flagged else 0] += 1
            row = {"ts": e["ts"], "source": e["source"], "src_ip": e["src_ip"], "text": _line(e), "flagged": flagged}
            self.feed.append(row)
            events.append(row)
        return {"events": events[-14:], "alerts": alerts, "state": self.state() if events or alerts else None}

    def _flagged(self, e: dict) -> bool:
        last = self.engine.last_alert
        return any(ip == e["src_ip"] and e["ts"] - t < 120 for (ip, _), t in last.items())

    def state(self) -> dict:
        e = self.engine
        keys = sorted(self.buckets)[-48:]
        for k in sorted(self.buckets)[:-60]:
            del self.buckets[k]
        return {"now": round(self.now, 1), "speed": self.speed, "events_seen": e.events_seen, "alert_count": len(e.alerts),
                "incidents": [i.to_dict() for i in sorted(e.incidents, key=lambda i: -i.last_ts)],
                "attacks": self.attacks[-9:], "analyst": self.analyst.mode,
                "traffic": [{"t": k * BUCKET, "normal": self.buckets[k][0], "flagged": self.buckets[k][1]} for k in keys]}

    def publish(self, msg: dict) -> None:
        for q in list(self.subscribers):
            if q.full():
                q.get_nowait()
            q.put_nowait(msg)

    async def run(self) -> None:
        last = time.monotonic()
        while True:
            await asyncio.sleep(.2)
            now = time.monotonic()
            out = self.step(min(now - last, 1.0))
            last = now
            if out["state"]:
                self.publish(out)


def _line(e: dict) -> str:
    s = e["source"]
    if s == "auth":
        return f"{e.get('action')} user={e.get('user')}"
    if s == "web":
        return f"{e.get('method')} {str(e.get('path'))[:60]} {e.get('status')}"
    if s == "dns":
        return f"query {e.get('query', '')[:60]}"
    return f"{e.get('action')} {e.get('dst_ip')}:{e.get('dst_port')} {e.get('bytes_out', 0):,}B"
