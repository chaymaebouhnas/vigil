"""Start Vigil:  python run.py  (add --no-browser to skip opening a tab)."""
import sys
import threading
import webbrowser

import uvicorn

from vigil.model import MODEL_PATH
from vigil.server import create_app

HOST, PORT = "127.0.0.1", 8765


def main() -> None:
    if not MODEL_PATH.exists():
        print("First run: training the behaviour model (about a minute)...")
    app = create_app()
    url = f"http://{HOST}:{PORT}"
    print(f"Vigil is running at {url}")
    if "--no-browser" not in sys.argv:
        threading.Timer(1.5, webbrowser.open, [url]).start()
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")


if __name__ == "__main__":
    main()
