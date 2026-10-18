import hashlib
import hmac
import math
import re
from dataclasses import dataclass

# Capture values in memory; public Finding deliberately has no raw-value field.
RULES = [
    ("ssh_private_key", re.compile(r"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----"), "high"),
    ("database_uri", re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^\s:@/]+:([^\s@/]+)@[^\s'\"<>]+", re.I), "high"),
    ("oauth_client_secret", re.compile(r"\b(?:oauth_)?client_secret\s*[:=]\s*['\"]?([A-Za-z0-9_./+!=\-]{12,})", re.I), "high"),
    ("api_token", re.compile(r"\b(?:api[_-]?(?:token|key)|access_token|auth_token)\s*[:=]\s*['\"]?([A-Za-z0-9_./+\-=]{16,})", re.I), "medium"),
    ("cloud_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "medium"),
    ("cloud_secret_key", re.compile(r"\b(?:aws_secret_access_key|cloud_secret_key|secret_access_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{32,64})", re.I), "high"),
    ("database_password", re.compile(r"\b(?:db_password|database_password|mysql_password)\s*[:=]\s*['\"]?([^\s'\";]{10,})", re.I), "high"),
]
ENTROPY = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z0-9_+/=\-]{24,128})(?![A-Za-z0-9_])")
PLACEHOLDER = re.compile(r"example|placeholder|changeme|your[_-]|replace[_-]|<[^>]*>|dummy", re.I)

@dataclass(frozen=True)
class Finding:
    kind: str
    classification: str
    severity: str
    fingerprint: str
    masked: str
    line: int

def entropy(value):
    return -sum((n / len(value)) * math.log2(n / len(value))
                for c in set(value) if (n := value.count(c)))

class Detector:
    def __init__(self, key: bytes, context_filter=True, enable_entropy=True):
        if len(key) < 32:
            raise ValueError("HMAC key must contain at least 32 UTF-8 bytes")
        self._key = key
        self.context_filter = context_filter
        self.enable_entropy = enable_entropy

    def fingerprint(self, value):
        return hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def detect(self, text, synthetic=False):
        candidates, occupied = [], []
        for kind, pattern, severity in RULES:
            for match in pattern.finditer(text):
                value = match.group(1) if match.lastindex else match.group()
                if self.context_filter and self._placeholder(value, kind):
                    continue
                occupied.append(match.span())
                classification = "synthetic_test" if synthetic else (
                    "rule_match" if kind in {"ssh_private_key", "cloud_access_key"} else "suspected_exposure")
                candidates.append(Finding(kind, classification, severity, self.fingerprint(value),
                                          "[REDACTED]", text.count("\n", 0, match.start()) + 1))
        for match in (ENTROPY.finditer(text) if self.enable_entropy else []):
            if any(match.start() < end and match.end() > start for start, end in occupied):
                continue
            value = match.group(1)
            # Avoid ordinary long identifiers; require multiple character classes.
            if entropy(value) < 4.2 or not any(c.isdigit() for c in value) or not any(c.isupper() for c in value) or not any(c.islower() for c in value):
                continue
            if self.context_filter and self._placeholder(value, "high_entropy"):
                continue
            candidates.append(Finding("high_entropy", "synthetic_test" if synthetic else "rule_match",
                                      "low", self.fingerprint(value), "[REDACTED]",
                                      text.count("\n", 0, match.start()) + 1))
        # Pair keys within a bounded same-line/nearby context; this is a heuristic.
        access = [f for f in candidates if f.kind == "cloud_access_key"]
        secret = [f for f in candidates if f.kind == "cloud_secret_key"]
        paired = set()
        for ak in access:
            for sk in secret:
                if abs(ak.line - sk.line) <= 3:
                    paired.add((ak.fingerprint, ak.line))
                    paired.add((sk.fingerprint, sk.line))
                    candidates.append(Finding("cloud_key_pair", "synthetic_test" if synthetic else "suspected_exposure",
                                              "high", self.fingerprint(ak.fingerprint + ":" + sk.fingerprint),
                                              "[REDACTED PAIR]", min(ak.line, sk.line)))
        result, seen = [], set()
        for item in candidates:
            if (item.fingerprint, item.line) in paired:
                continue
            key = (item.kind, item.fingerprint, item.line)
            if key not in seen:
                result.append(item)
                seen.add(key)
        return result

    @staticmethod
    def _placeholder(value, kind):
        if PLACEHOLDER.search(value):
            return True
        return kind != "ssh_private_key" and len(set(value)) <= 3
