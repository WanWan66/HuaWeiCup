import base64
import hashlib
import hmac
import math
from pathlib import Path
import re
from dataclasses import dataclass, replace
from urllib.parse import unquote

RULE_VERSION="sr2-"+hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:16]
def assignment(names,value):
    return re.compile(r"(?<![\w])['\"]?(?:"+names+r")['\"]?\s*[:=]\s*['\"]?("+value+r")",re.I)
RULES=[
 ("database_uri",re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^\s:@/]+:([^\s@/]+)@[^\s'\"<>]+",re.I),"high"),
 ("oauth_client_secret",assignment(r"(?:oauth_)?client_secret",r"[A-Za-z0-9_./+!%=\-]{12,}"),"high"),
 ("api_token",assignment(r"api[_-]?(?:token|key)|access_token|auth_token",r"[A-Za-z0-9_./+!%=\-]{16,}"),"medium"),
 ("cloud_access_key",re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),"medium"),
 ("cloud_secret_key",assignment(r"aws_secret_access_key|cloud_secret_key|secret_access_key",r"[A-Za-z0-9/+=]{32,64}"),"high"),
 ("database_password",assignment(r"db_password|database_password|mysql_password",r"[^\s'\";,}{]{10,}"),"high")]
MARKER=re.compile(r"-----BEGIN (?:(OPENSSH|RSA|EC|DSA) )?PRIVATE KEY-----")
ENTROPY=re.compile(r"(?<![\w])([A-Za-z0-9_+/\-]{24,128}={0,2})(?![\w])")
PLACEHOLDER=re.compile(r"^(?:your[_-]|replace[_-]|changeme|placeholder|example(?:_|$)|dummy(?:_|$)|<|\$\{)",re.I)
BENIGN=re.compile(r"(?:\b(?:build|release|request|correlation|artifact|asset|commit|trace)[\w-]*|hash|digest|checksum|fingerprint|integrity|compressed|base64)",re.I)
SENSITIVE=re.compile(r"secret|password|private[_-]?material|signing[_-]?key|credential|bearer",re.I)

@dataclass(frozen=True)
class Finding:
    kind:str
    classification:str
    severity:str
    fingerprint:str
    masked:str
    line:int
    reason:str="typed_rule"

def entropy(value):
    return -sum((n/len(value))*math.log2(n/len(value)) for c in set(value) if (n:=value.count(c)))

class Detector:
    version=RULE_VERSION
    def __init__(self,key:bytes,context_filter=True,enable_entropy=True):
        if len(key)<32:raise ValueError("HMAC key must contain at least 32 UTF-8 bytes")
        self._key=key;self.context_filter=context_filter;self.enable_entropy=enable_entropy
    def fingerprint(self,value):
        return hmac.new(self._key,value.encode("utf-8"),hashlib.sha256).hexdigest()
    def detect(self,text,synthetic=False):
        if not isinstance(text,str):raise ValueError("invalid_document_type")
        if len(text.encode("utf-8"))>1024*1024:raise ValueError("document_size_limit")
        candidates=[];occupied=[];positions={}
        def add(kind,value,start,end,severity,classification,reason):
            f=Finding(kind,"synthetic_test" if synthetic and severity!="info" else classification,
                      severity,self.fingerprint(value),"[REDACTED]",text.count("\n",0,start)+1,reason)
            candidates.append(f);occupied.append((start,end));positions[(kind,f.fingerprint,f.line)]=start
        for marker in MARKER.finditer(text):
            label=(marker.group(1)+" " if marker.group(1) else "")+"PRIVATE KEY"
            footer="-----END "+label+"-----"
            end=text.find(footer,marker.end(),marker.end()+16384)
            complete=False
            if end>=0:
                body="".join(text[marker.end():end].split())
                try:
                    raw=base64.b64decode(body,validate=True)
                    complete=len(body)>=64 and len(raw)>=48 and (
                        raw.startswith(b"openssh-key-v1\0") if marker.group(1)=="OPENSSH" else raw.startswith(b"\x30"))
                except (ValueError,base64.binascii.Error):pass
            if complete:
                add("ssh_private_key",text[marker.start():end+len(footer)],marker.start(),end+len(footer),
                    "high","rule_match","complete_outer_structure_only")
            else:
                add("ssh_private_key_marker",marker.group(),marker.start(),marker.end(),
                    "info","marker_only","missing_or_invalid_body")
        for kind,pattern,severity in RULES:
            for m in pattern.finditer(text):
                if any(m.start()<b and m.end()>a for a,b in occupied):continue
                value=m.group(1) if m.lastindex else m.group()
                if kind=="database_uri":value=unquote(value)
                if self.context_filter and self._placeholder(value,kind):continue
                add(kind,value,m.start(),m.end(),severity,"rule_match" if kind=="cloud_access_key" else "suspected_exposure","typed_rule")
        boundaries=[m.start() for m in re.finditer(r"(?m)^\s*(?:\[[^\]\n]+\]|---)\s*$",text)]
        def section(item):
            position=positions[(item.kind,item.fingerprint,item.line)]
            return sum(p<=position for p in boundaries)
        aks=[x for x in candidates if x.kind=="cloud_access_key"]
        sks=[x for x in candidates if x.kind=="cloud_secret_key"]
        removed=set()
        for group in set(map(section,aks+sks)):
            ga={x.fingerprint:x for x in aks if section(x)==group}
            gs={x.fingerprint:x for x in sks if section(x)==group}
            if len(ga)!=1 or len(gs)!=1:
                if ga and gs:
                    candidates=[replace(x,reason="ambiguous_pair_not_combined") if x.kind in {"cloud_access_key","cloud_secret_key"} and section(x)==group else x for x in candidates]
                continue
            a,s=next(iter(ga.values())),next(iter(gs.values()))
            ap=positions[(a.kind,a.fingerprint,a.line)];sp=positions[(s.kind,s.fingerprint,s.line)]
            if abs(a.line-s.line)>32 or abs(ap-sp)>8192:continue
            removed.update([(a.kind,a.fingerprint),(s.kind,s.fingerprint)])
            candidates.append(Finding("cloud_key_pair","synthetic_test" if synthetic else "suspected_exposure","high",
                self.fingerprint(a.fingerprint+":"+s.fingerprint),"[REDACTED PAIR]",min(a.line,s.line),"unique_pair_same_section_within_32_lines"))
        for m in (ENTROPY.finditer(text) if self.enable_entropy else []):
            if any(m.start()<b and m.end()>a for a,b in occupied):continue
            value=m.group(1)
            if entropy(value)<4.2 or not all((any(c.isdigit() for c in value),any(c.isupper() for c in value),any(c.islower() for c in value))):continue
            if self.context_filter and self._placeholder(value,"high_entropy"):continue
            line_start=text.rfind("\n",0,m.start())+1
            context=text[line_start:m.start()][-128:]
            sensitive=bool(SENSITIVE.search(context))
            benign=bool(BENIGN.search(context)) and not sensitive
            classification="suspected_exposure" if sensitive else "entropy_candidate"
            add("high_entropy",value,m.start(),m.end(),"medium" if sensitive else "info",
                classification,"sensitive_assignment" if sensitive else ("benign_identifier_context" if benign else "untyped_entropy_candidate"))
        result=[];seen=set()
        for item in candidates:
            key=(item.kind,item.fingerprint)
            if key in removed or key in seen:continue
            seen.add(key);result.append(item)
        return result
    @staticmethod
    def _placeholder(value,kind):
        return bool(PLACEHOLDER.search(value)) or len(set(value))<=3
