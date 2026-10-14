"""
Run the fingerprinting detector on every capture listed in captures/labels.csv
and check it against the labels.

    python fingerprinting/test_against_captures.py

Expected:
  evil_twin_only / combined_attack -> flags exactly the evil_twin_bssid
  deauth_only / benign_home        -> flags nothing
"""
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from shared.pcap_parser import parse_pcap                              # noqa: E402
from fingerprinting.detector import build_trusted, detect_evil_twin    # noqa: E402


def main():
    with open(os.path.join(ROOT, "captures", "labels.csv"), newline="") as fh:
        rows = list(csv.DictReader(fh))

    ok_count = 0
    ran = 0
    for r in rows:
        path = os.path.join(ROOT, "captures", r["filename"])
        if not os.path.exists(path):
            print("SKIP %s (file not found)" % r["filename"])
            continue
        ran += 1
        frames = list(parse_pcap(path))
        trusted = build_trusted(frames, r["real_bssid"])
        if not trusted:
            print("FAIL %s: no named beacon from real_bssid %s, cannot build trusted profile"
                  % (r["filename"], r["real_bssid"]))
            continue

        alerts = detect_evil_twin(frames, trusted)
        flagged = {a.bssid for a in alerts}
        twin = (r.get("evil_twin_bssid") or "").lower()
        expected = {twin} if twin else set()
        ok = flagged == expected
        ok_count += ok
        print("%s %s: flagged=%s expected=%s" % ("PASS" if ok else "FAIL", r["filename"],
                                                  sorted(flagged) or "none",
                                                  sorted(expected) or "none"))
        for a in alerts:
            print("    sev=%.2f t=%.3f %s" % (a.severity, a.timestamp, a.reason))

    print("\n%d/%d captures matched" % (ok_count, ran))


if __name__ == "__main__":
    main()
