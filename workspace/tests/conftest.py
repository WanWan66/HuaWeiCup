import pytest
from secretradar.detectors.rules import Detector
from secretradar.storage.sqlite import Store

@pytest.fixture
def detector():
    return Detector(b"TEST_ONLY_NOT_A_SECRET_HMAC_KEY_000000")

@pytest.fixture
def store(tmp_path):
    return Store(tmp_path/"results.db")
