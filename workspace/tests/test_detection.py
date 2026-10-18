import json
import pytest
from secretradar.detectors.rules import Detector
from secretradar.evaluation.fixtures import samples

@pytest.mark.parametrize("name,text,expected",samples(),ids=[x[0] for x in samples()])
def test_ground_truth(detector,name,text,expected):
    results=detector.detect(text,synthetic=True)
    assert {r.kind for r in results}==expected
    assert all(r.classification=="synthetic_test" for r in results)

def test_no_automatic_validity_claim(detector):
    result=detector.detect(samples()[0][1])[0]
    assert result.classification=="suspected_exposure"
    assert "valid" not in result.__dict__

def test_raw_not_in_findings(detector):
    token=samples()[0][1].split("=")[1]
    result=detector.detect(samples()[0][1])
    assert token not in repr(result)
    assert token not in json.dumps([x.__dict__ for x in result])

def test_hmac_is_keyed(detector):
    second=Detector(b"TEST_ONLY_DIFFERENT_KEY_000000000000")
    assert detector.fingerprint("same")!=second.fingerprint("same")

def test_missing_key_rejected():
    with pytest.raises(ValueError):
        Detector(b"")

def test_rule_vs_context(detector):
    baseline=Detector(detector._key,False)
    assert baseline.detect(samples()[7][1])
    assert not detector.detect(samples()[7][1])

def test_ssh_is_rule_match(detector):
    assert detector.detect(samples()[4][1])[0].classification=="rule_match"

def test_content_marker_does_not_override_real_mode(detector):
    assert detector.detect("SR_TEST_ONLY\n"+samples()[0][1])[0].classification=="suspected_exposure"
