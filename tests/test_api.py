from fastapi.testclient import TestClient

from vigil.live import Live
from vigil.server import create_app


def client(detector):
    live = Live(detector, seed=9)
    return TestClient(create_app(live, run_loop=False)), live


def test_launch_detect_report_and_chat(detector):
    c, live = client(detector)
    rec = c.post("/api/simulate", json={"scenario": "brute_force"}).json()
    for _ in range(30):
        live.step(1)
    assert rec["scenario"] == "brute_force"
    state = c.get("/api/state").json()
    assert state["incidents"] and state["attacks"][0]["detected_after"] is not None
    rep = c.get(f"/api/incidents/{state['incidents'][0]['id']}").json()
    assert rep["timeline"]
    answer = c.post("/api/chat", json={"question": "tell me about " + rep["id"]}).json()
    assert answer["refs"] == [rep["id"]] and rep["id"] in answer["answer"]


def test_bad_input_is_rejected(detector):
    c, _ = client(detector)
    assert c.post("/api/simulate", json={"scenario": "rm -rf"}).status_code == 400
    assert c.get("/api/incidents/INC-999").status_code == 404
    assert c.post("/api/chat", json={"question": ""}).status_code == 422
    assert c.post("/api/chat", json={"question": "x" * 501}).status_code == 422


def test_reset_clears_everything(detector):
    c, live = client(detector)
    c.post("/api/simulate", json={"scenario": "port_scan"})
    for _ in range(10):
        live.step(1)
    c.post("/api/reset")
    assert c.get("/api/state").json()["alert_count"] == 0
