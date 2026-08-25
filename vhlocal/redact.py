"""Secret / PII redaction for scan artifacts, applied at write time.

vhlocal never egresses, but its reports are shared and archived — and scanning a
payments codebase surfaces card numbers, SSNs, and credentials verbatim in the
model's quoted evidence. This masks them in the written artifacts (report,
findings.json, SARIF, HTML) so a secret *found* is never a secret *leaked*. A
finding still keeps its location, CWE, and description — only the literal secret
value is replaced with a token. Stdlib only, deterministic.

Design: conservative by intent. Card matches must pass Luhn *and* carry a
major-network IIN prefix, so a random 16-digit identifier is not masked. Off by
default (opt-in per scan) since vhlocal reports are usually read locally.
"""

import re
from typing import Any, List, Tuple

CARD_TOKEN = "[REDACTED-CARD]"
SSN_TOKEN = "[REDACTED-SSN]"
SECRET_TOKEN = "[REDACTED-SECRET]"
KEY_TOKEN = "[REDACTED-KEY]"

# A digit run 13-19 long, allowing single spaces/hyphens between digits (card
# groupings). Bounded so it doesn't swallow adjacent text.
_CARD_RE = re.compile(r"(?<![\w.])(?:\d[ -]?){13,19}\d(?![\w.])")
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")

# Well-known credential token shapes.
_KEY_RES = [
    re.compile(r"\bA(?:KIA|SIA|GPA|IDA|ROA|IPA|NPA|NVA)[0-9A-Z]{12,}\b"),   # AWS ids
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),                                # OpenAI-style
    re.compile(r"\bgh[posur]_[A-Za-z0-9]{30,}\b"),                           # GitHub
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),                         # Slack
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b"),  # JWT
]
_PEM_RE = re.compile(
    r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----.*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----",
    re.S)

# key = "value" / key: value credential assignments. The value is masked, the
# key name is kept so the finding still reads.
_ASSIGN_RE = re.compile(
    r"(?i)(\b(?:api[_-]?key|secret|token|password|passwd|pwd|access[_-]?key|"
    r"client[_-]?secret|private[_-]?key|auth[_-]?token)\b\s*[:=]\s*)"
    r"(['\"]?)([^\s'\"]{6,})(\2)")

# Major-network IIN prefixes (Visa, Mastercard, Amex, Discover, Diners, JCB).
_IIN = ("4", "34", "37", "6011", "65", "300", "301", "302", "303", "304", "305",
        "36", "38", "3528", "3529", "35")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _iin_ok(digits: str) -> bool:
    if digits.startswith(("51", "52", "53", "54", "55")):
        return True   # Mastercard
    if "2221" <= digits[:4] <= "2720":
        return True   # Mastercard 2-series
    return digits.startswith(_IIN)


def _redact_cards(s: str, counter: List[int]) -> str:
    def repl(m):
        raw = m.group(0)
        digits = re.sub(r"\D", "", raw)
        if 13 <= len(digits) <= 19 and _luhn_ok(digits) and _iin_ok(digits):
            counter[0] += 1
            return CARD_TOKEN
        return raw
    return _CARD_RE.sub(repl, s)


def redact_text(s: str) -> Tuple[str, int]:
    """Return (redacted, count). Order matters: structured secrets first, then
    the greedy card/SSN passes."""
    if not s:
        return s, 0
    counter = [0]
    out = s
    out, n = _PEM_RE.subn(KEY_TOKEN, out); counter[0] += n
    for pat in _KEY_RES:
        out, n = pat.subn(KEY_TOKEN, out); counter[0] += n
    # keep the key name, mask the value
    out, n = _ASSIGN_RE.subn(lambda m: m.group(1) + m.group(2) + SECRET_TOKEN + m.group(4), out)
    counter[0] += n
    out, n = _SSN_RE.subn(SSN_TOKEN, out); counter[0] += n
    out = _redact_cards(out, counter)
    return out, counter[0]


# Finding string fields that can carry quoted secret evidence. IDs, CWE, and
# severity are excluded — they never hold secrets and masking them would corrupt
# the taxonomy / SARIF mapping.
_FIELDS = ("title", "location", "entry_point", "data_flow", "poc", "exploit_test",
           "fix", "source", "status", "description", "exploitability", "reference")


def redact_file(path) -> int:
    """Redact a text artifact in place; return the number of masked values. A
    missing/binary file is a no-op."""
    from pathlib import Path
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except (OSError, ValueError, UnicodeDecodeError):
        return 0
    new, n = redact_text(text)
    if n:
        try:
            p.write_text(new, encoding="utf-8")
        except OSError:
            return 0
    return n


def redact_findings(findings: List[Any]) -> int:
    """Mask secret values in each finding's text fields, in place. Works on both
    Finding objects and plain dicts. Returns the number of masked values."""
    total = 0
    for f in findings:
        is_dict = isinstance(f, dict)
        for name in _FIELDS:
            val = f.get(name) if is_dict else getattr(f, name, None)
            if not isinstance(val, str) or not val:
                continue
            new, n = redact_text(val)
            if n:
                total += n
                if is_dict:
                    f[name] = new
                else:
                    setattr(f, name, new)
    return total
