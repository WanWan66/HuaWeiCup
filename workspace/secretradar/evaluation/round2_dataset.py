"""Frozen synthetic truth: labels are authored here, never derived from detector output."""
import base64
import hashlib
import json
import random
import string
from pathlib import Path
from urllib.parse import quote
VERSION="sr-r2-corpus-v1"
SEEDS={"development":410271,"holdout":902813}
VARIANTS=16
def key_block(rng, label="OPENSSH"):
    raw=(b"openssh-key-v1\0" if label=="OPENSSH" else b"\x30\x82") + rng.randbytes(96)
    encoded=base64.b64encode(raw).decode()
    kind=(label+" " if label else "")+"PRIVATE KEY"
    return "-----BEGIN "+kind+"-----\n"+"\n".join(encoded[i:i+64] for i in range(0,len(encoded),64))+"\n-----END "+kind+"-----"
def corpus(split):
    if split not in SEEDS:raise ValueError("unknown split")
    rng=random.Random(SEEDS[split]);samples=[]
    for variant in range(VARIANTS):
        token="SRTEST_"+ "".join(rng.choices(string.ascii_letters+string.digits,k=32))
        ak="AKIA"+"".join(rng.choices(string.ascii_uppercase+string.digits,k=16))
        sk="".join(rng.choices(string.ascii_letters+string.digits,k=40))
        ident="".join(rng.choices(string.ascii_letters+string.digits,k=44))
        padding="\n".join("# configuration context "+str(i) for i in range(7+variant%6))
        if split=="development":
            cases=[
                ("api_assignment","api_token = '"+token+"'",["api_token"]),
                ("oauth_assignment","client_secret = "+token,["oauth_client_secret"]),
                ("db_assignment","db_password="+token,["database_password"]),
                ("postgres_uri","postgresql://test:"+token+"@localhost/unit",["database_uri"]),
                ("pair_near","aws_access_key_id="+ak+"\naws_secret_access_key="+sk,["cloud_key_pair"]),
                ("pair_far","[dev]\naws_access_key_id="+ak+"\n"+padding+"\naws_secret_access_key="+sk,["cloud_key_pair"]),
                ("standalone_ak","aws_access_key_id="+ak,["cloud_access_key"]),
                ("private_outer",key_block(rng),["ssh_private_key"]),
                ("entropy_context","signing_secret="+ident,["high_entropy"]),
                ("repeat_token","api_token="+token+"\napi_token="+token,["api_token"]),
                ("marker_document","Documentation names -----BEGIN OPENSSH PRIVATE KEY----- only.",[]),
                ("build_id","build_id="+ident,[]),
                ("commit_hash","commit_hash="+hashlib.sha256(ident.encode()).hexdigest(),[]),
                ("uuid","request_id=be413c6a-52d6-4782-a2a1-"+str(variant).zfill(12),[]),
                ("encoded_blob","compressed_payload="+base64.b64encode(rng.randbytes(72)).decode(),[]),
                ("placeholder","api_token=your_example_api_token_replace_me",[]),
                ("normal_prose","Read the developer handbook for deployment instructions.",[]),
                ("docs_example","# Example configuration\napi_token=EXAMPLE_NOT_A_REAL_SECRET",[]),
                ("quoted_marker","print('-----BEGIN RSA PRIVATE KEY-----')",[]),
                ("asset_hash","integrity=sha256-"+base64.b64encode(rng.randbytes(32)).decode(),[]),
            ]
        else:
            cases=[
                ("api_json",'{"API_KEY" : "'+token+'"}',["api_token"]),
                ("oauth_multiline","'OAUTH_CLIENT_SECRET' :\n   '"+token+"'",["oauth_client_secret"]),
                ("db_quoted",'"DATABASE_PASSWORD" : "'+token+'"',["database_password"]),
                ("mysql_escaped","mysql://review:"+quote(token+"!@:/",safe="")+"@localhost/sandbox",["database_uri"]),
                ("pair_section","[profile review]\nAWS_ACCESS_KEY_ID = '"+ak+"'\n"+padding+"\nAWS_SECRET_ACCESS_KEY = '"+sk+"'",["cloud_key_pair"]),
                ("pair_json",'{"aws_access_key_id":"'+ak+'",\n"region":"unit",\n"aws_secret_access_key":"'+sk+'"}',["cloud_key_pair"]),
                ("standalone_secret",'"cloud_secret_key": "'+sk+'"',["cloud_secret_key"]),
                ("private_pem",key_block(rng,"RSA"),["ssh_private_key"]),
                ("entropy_private","private_material : '"+ident+"'",["high_entropy"]),
                ("multiple_tokens","api_token="+token+"\nclient_secret="+token,["api_token","oauth_client_secret"]),
                ("pem_guide","The page explains -----BEGIN EC PRIVATE KEY----- without a body.",[]),
                ("release_identifier",'{"release_id":"'+ident+'"}',[]),
                ("artifact_sha","artifact_digest="+hashlib.sha512(ident.encode()).hexdigest(),[]),
                ("opaque_identifier","correlation_id: '"+ident+"'",[]),
                ("base64_document","base64_document = "+base64.b64encode(rng.randbytes(96)).decode(),[]),
                ("oauth_placeholder","client_secret=CHANGEME_PLACEHOLDER_VALUE",[]),
                ("ordinary_comments","# Nothing sensitive is stored in this configuration.",[]),
                ("template_token","auth_token = <YOUR_ACCESS_TOKEN>",[]),
                ("truncated_private","-----BEGIN OPENSSH PRIVATE KEY-----\nnot_base64",[]),
                ("cdn_identifier","asset_build_fingerprint='"+ident+"'",[]),
            ]
        for name,text,expected in cases:
            samples.append({"id":split+"-"+name+"-"+str(variant),"family":name,"split":split,
                            "text":text,"expected":expected,"synthetic":True})
    return samples
def manifest():
    return {"version":VERSION,"seeds":SEEDS,"variants_per_template":VARIANTS,
            "label_method":"manually specified synthetic category sets; never detector generated",
            "split_method":"disjoint presentation templates and PRNG seeds; synthetic grammar still shared",
            "samples":[{"id":s["id"],"family":s["family"],"split":s["split"],
                        "expected":s["expected"],"text_sha256":hashlib.sha256(s["text"].encode()).hexdigest(),
                        "bytes":len(s["text"].encode())}
                       for split in SEEDS for s in corpus(split)]}
def freeze(path):
    path=Path(path);value=manifest()
    value["generator_sha256"]=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    if path.exists():raise FileExistsError("Frozen dataset must not be overwritten")
    path.write_text(json.dumps(value,indent=2),encoding="utf-8")
    return value
