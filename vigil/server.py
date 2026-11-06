"""HTTP API and static dashboard. Binds to localhost only (see run.py)."""
from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import simulator as sim
from .live import Live
from .model import MODEL_PATH, Detector, train

DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"


class Launch(BaseModel):
    scenario: str


class Chat(BaseModel):
    question: str = Field(min_length=1, max_length=500)


class Speed(BaseModel):
    speed: float = Field(ge=1, le=120)


def load_detector() -> Detector:
    if MODEL_PATH.exists():
        return Detector.load()
    detector = train()
    detector.save()
    return detector


def create_app(live: Live | None = None, run_loop: bool = True) -> FastAPI:
    state = live or Live(load_detector())

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        task = asyncio.create_task(state.run()) if run_loop else None
        yield
        if task:
            task.cancel()

    app = FastAPI(title="Vigil", lifespan=lifespan)
    app.state.live = state

    @app.get("/api/state")
    def get_state():
        return {**state.state(), "feed": list(state.feed)[-14:], "alerts": state.engine.alerts[-50:],
                "scenarios": sim.SCENARIO_INFO}

    @app.get("/api/incidents/{incident_id}")
    def incident(incident_id: str):
        report = state.analyst.report(incident_id)
        if not report:
            raise HTTPException(404, "Unknown incident")
        return report

    @app.post("/api/simulate")
    def simulate(body: Launch):
        if body.scenario not in sim.GENERATORS:
            raise HTTPException(400, "Unknown scenario")
        return state.launch(body.scenario)

    @app.post("/api/speed")
    def speed(body: Speed):
        state.speed = body.speed
        return {"speed": state.speed}

    @app.post("/api/chat")
    def chat(body: Chat):
        return state.analyst.chat(body.question)

    @app.post("/api/reset")
    def reset():
        state.reset()
        return {"ok": True}

    @app.get("/api/stream")
    async def stream():
        q: asyncio.Queue = asyncio.Queue(maxsize=50)
        state.subscribers.add(q)

        async def gen():
            try:
                while True:
                    try:
                        msg = await asyncio.wait_for(q.get(), 15)
                        yield f"data: {json.dumps(msg)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
            finally:
                state.subscribers.discard(q)

        return StreamingResponse(gen(), media_type="text/event-stream")

    if DIST.exists():
        app.mount("/", StaticFiles(directory=DIST, html=True), name="ui")
    return app
