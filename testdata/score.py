"""Score a vulnhunt-local run against the planted ground truth."""
import re
import sys
from pathlib import Path

RUN = Path(sys.argv[1] if len(sys.argv) > 1 else "run1")

# (id, description, sink file:line signature, accept-if-any-of these keywords)
TRUTH = [
    ("VULN-A", "SQLi via q",            r"db\.py",    ["sql", "injection", "cwe-89"]),
    ("VULN-B", "SQLi via status",       r"db\.py",    ["sql", "injection", "cwe-89"]),
    ("VULN-C", "Path traversal name",   r"files\.py", ["traversal", "path", "cwe-22"]),
    ("VULN-D", "Command injection src", r"files\.py", ["command", "os.system", "cwe-78"]),
    ("VULN-E", "Broken authz order_id", r"main\.py",  ["authoriz", "idor", "ownership", "cwe-639", "cwe-285", "access control"]),
]
DECOY_MARKERS = ["find_user_safe", "/api/users"]


def load_corpus():
    parts = {}
    for name in ["phase2b_output.md", "phase3_output.md", "phase3d_output.md", "README.md"]:
        p = RUN / name
        parts[name] = p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""
    res = RUN / "results"
    hunt = ""
    if res.is_dir():
        for f in sorted(res.glob("*.md")):
            hunt += "\n\n===== {0} =====\n".format(f.name) + f.read_text(encoding="utf-8", errors="replace")
    parts["results/"] = hunt
    return parts


def main():
    parts = load_corpus()
    # Precision is judged on the post-falsification set; recall on hunt+verify.
    confirmed = (parts["phase2b_output.md"] + parts["README.md"] + parts["phase3_output.md"]).lower()
    everything = ("".join(parts.values())).lower()

    print("=" * 68)
    print("GROUND TRUTH SCORING —", RUN)
    print("=" * 68)
    for name, text in parts.items():
        print("  {0:24s} {1:>7,} chars {2}".format(name, len(text), "" if text else "  <MISSING>"))
    print()

    hunt_hits = confirmed_hits = 0
    print("{0:8s} {1:22s} {2:9s} {3:9s}".format("ID", "DESCRIPTION", "IN HUNT", "CONFIRMED"))
    print("-" * 68)
    for vid, desc, filesig, keys in TRUTH:
        in_hunt = any(k in everything for k in keys) and re.search(filesig, everything, re.I) is not None
        in_conf = any(k in confirmed for k in keys) and re.search(filesig, confirmed, re.I) is not None
        hunt_hits += bool(in_hunt)
        confirmed_hits += bool(in_conf)
        print("{0:8s} {1:22s} {2:9s} {3:9s}".format(
            vid, desc, "YES" if in_hunt else "no", "YES" if in_conf else "no"))

    print("-" * 68)
    print("recall (hunt)      : {0}/{1}".format(hunt_hits, len(TRUTH)))
    print("recall (confirmed) : {0}/{1}".format(confirmed_hits, len(TRUTH)))
    print()

    # The decoy is a parameterized query. Being *mentioned* is fine (the input
    # inventory lists it); being reported as a vulnerability is a false positive.
    decoy_flagged = False
    for marker in DECOY_MARKERS:
        for m in re.finditer(re.escape(marker.lower()), confirmed):
            window = confirmed[max(0, m.start() - 400): m.start() + 400]
            if re.search(r"vuln-\d|sql injection|exploitab|cwe-89", window):
                if "safe" not in window and "not vulnerable" not in window and "parameteri" not in window:
                    decoy_flagged = True
    print("decoy (/api/users, parameterized): {0}".format(
        "FALSE POSITIVE" if decoy_flagged else "correctly not reported"))
    print("=" * 68)


if __name__ == "__main__":
    main()
