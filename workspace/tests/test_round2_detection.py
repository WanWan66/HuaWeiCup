import base64
import random
import pytest
from secretradar.evaluation.round2_dataset import key_block
from secretradar.evaluation.fixtures import samples
from secretradar.detectors.rules import Detector

def alerts(detector,text):
    return [x for x in detector.detect(text) if x.severity!="info"]
def test_marker_is_informational(detector):
    result=detector.detect("Documentation: -----BEGIN OPENSSH PRIVATE KEY-----")
    assert not alerts(detector,"Documentation: -----BEGIN OPENSSH PRIVATE KEY-----")
    assert result[0].kind=="ssh_private_key_marker" and result[0].severity=="info"
def test_complete_outer_structure(detector):
    result=alerts(detector,key_block(random.Random(2)))
    assert [x.kind for x in result]==["ssh_private_key"]
    assert result[0].reason=="complete_outer_structure_only"
def test_invalid_base64_body(detector):
    text="-----BEGIN RSA PRIVATE KEY-----\n"+"!"*100+"\n-----END RSA PRIVATE KEY-----"
    assert not alerts(detector,text)
@pytest.mark.parametrize("field",["build_id","request_id","release_id","artifact_digest","base64_document","compressed_payload","commit_hash"])
def test_benign_entropy(detector,field):
    text=field+"=Q9w2E7r4T8y1U6i3O5p0A2s7D9f4G8h1"
    findings=detector.detect(text)
    assert findings and all(x.severity=="info" for x in findings)
def test_sensitive_entropy_retained(detector):
    assert alerts(detector,"signing_secret=Q9w2E7r4T8y1U6i3O5p0A2s7D9f4G8h1")[0].kind=="high_entropy"
def test_bare_entropy_candidate_not_claimed_credential(detector):
    findings=detector.detect("Q9w2E7r4T8y1U6i3O5p0A2s7D9f4G8h1")
    assert findings[0].classification=="entropy_candidate"
def test_far_pair_within_bound(detector):
    text="aws_access_key_id=AKIA7B2D9F4H6J8L3N5P\n"+("# harmless\n"*12)+"aws_secret_access_key=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD"
    assert [x.kind for x in alerts(detector,text)]==["cloud_key_pair"]
def test_cross_section_not_paired(detector):
    text="[a]\naws_access_key_id=AKIA7B2D9F4H6J8L3N5P\n[b]\naws_secret_access_key=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD"
    assert "cloud_key_pair" not in {x.kind for x in alerts(detector,text)}
def test_ambiguous_pairs_not_cartesian(detector):
    text="aws_access_key_id=AKIA7B2D9F4H6J8L3N5P\naws_access_key_id=AKIA7B2D9F4H6J8L3N5Q\naws_secret_access_key=AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCD"
    findings=alerts(detector,text)
    assert "cloud_key_pair" not in {x.kind for x in findings}
    assert any(x.reason=="ambiguous_pair_not_combined" for x in findings)
def test_repeat_candidate_once(detector):
    t=samples()[0][1]
    assert len(alerts(detector,t+"\n"+t))==1
@pytest.mark.parametrize("field",['"API_TOKEN" : ', "'api_key' =\n", "Api_Token\t=\t"])
def test_quoted_and_multiline(detector,field):
    assert alerts(detector,field+"'SRTEST_7xQ2mP9vB4nL6cD8jF3sH5aK'")[0].kind=="api_token"
def test_url_encoded_password_canonical_hmac(detector):
    a=alerts(detector,"postgresql://unit:SRTEST_7xQ2mP9v%40test@localhost/x")[0]
    assert a.fingerprint==detector.fingerprint("SRTEST_7xQ2mP9v@test")
def test_long_input_bounded(detector):
    with pytest.raises(ValueError):detector.detect("x"*(1024*1024+1))
def test_non_text_rejected(detector):
    with pytest.raises(ValueError):detector.detect(None)
