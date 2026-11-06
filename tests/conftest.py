import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vigil.model import train  # noqa: E402


@pytest.fixture(scope="session")
def detector():
    return train(seeds=range(1000, 1008))
