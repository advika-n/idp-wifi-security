#!/usr/bin/env python3
"""
Run every detector on every capture in captures/labels.csv and check the
result against the label.

    python run_pipeline.py              # summary + alerts
    python run_pipeline.py --sequences  # also print per-client state sequences

Writes results/pipeline_results.json (all alerts per capture).

Per scenario, the detectors that MUST fire and the ones that MAY fire.
A capture passes if  required <= fired <= allowed.
    evil_twin         must: fingerprinting          may: + sequence, fusion
    deauth            must: deauth                  may: + sequence
    evil_twin_deauth  must: fingerprinting, deauth, fusion   may: + sequence
    benign            must: nothing                 may: sequence (review them,
                      sequence alerts on benign data are false-positive candidates)
"""
import csv
import json
import os
import sys
import time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from shared.pcap_parser import parse_pcap                                    # noqa: E402
from fingerprinting.detector import build_trusted, detect_evil_twin          # noqa: E402
from deauth_fusion.deauth_detector import detect_deauth                      # noqa: E402
from deauth_fusion.fusion import fuse                                        # noqa: E402
from deauth_fusion.state_sequence_tracker import track, print_sequences      # noqa: E402

EXPECTED = {
    "evil_twin": ({"fingerprinting"}, {"fingerprinting", "sequence", "fusion"}),
    "deauth": ({"deauth"}, {"deauth", "sequence"}),
    "evil_twin_deauth": ({"fingerprinting", "deauth", "fusion"},
                         {"fingerprinting", "deauth", "sequence", "fusion"}),
    "benign": (set(), {"sequence"}),
}


def analyse(path, real_bssid):
    frames = list(parse_pcap(path))
    trusted = build_trusted(frames, real_bssid)
    fp = detect_evil_twin(frames, trusted) if trusted else []
    de = detect_deauth(frames)
    clients, sq = track(frames)
    fused = fuse(fp + de + sq)
    return frames, trusted, clients, sorted(fp + de + sq + fused, key=lambda a: a.timestamp)


def main():
    show_seq = "--sequences" in sys.argv
    with open(os.path.join(ROOT, "captures", "labels.csv"), newline="") as fh:
        rows = list(csv.DictReader(fh))

    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    results = {}
    matched = ran = 0

    for r in rows:
        path = os.path.join(ROOT, "captures", r["filename"])
        if not os.path.exists(path):
            print("SKIP %s (file not found)" % r["filename"])
            continue
        ran += 1
        t0 = time.time()
        frames, trusted, clients, alerts = analyse(path, r["real_bssid"])
        fired = {a.detector for a in alerts}
        exp = EXPECTED.get(r["scenario"])
        if exp is None:
            verdict = "n/a"
        else:
            verdict = "PASS" if exp[0] <= fired <= exp[1] else "FAIL"
        matched += verdict == "PASS"

        print("%s  %s  [%s/%s]  %d frames, %.1fs"
              % (verdict, r["filename"], r["scenario"], r["label"], len(frames), time.time() - t0))
        if exp is not None:
            print("    fired: %s   must: %s   may also: %s"
                  % (sorted(fired) or "none", sorted(exp[0]) or "none", sorted(exp[1] - exp[0]) or "none"))
        if not trusted:
            print("    WARNING: no named beacon from real_bssid %s, fingerprinting skipped" % r["real_bssid"])
        for a in alerts:
            print("    [%s] t=%.3f sev=%.2f bssid=%s client=%s\n        %s"
                  % (a.detector, a.timestamp, a.severity, a.bssid, a.client_mac, a.reason))
        try:
            start = float(r["attack_start"])
            if alerts:
                print("    first alert: %+.2fs relative to attack_start" % (min(a.timestamp for a in alerts) - start))
        except (ValueError, TypeError):
            pass
        if show_seq:
            print("    client state sequences:")
            print_sequences(clients, limit=5)
        print()
        results[r["filename"]] = [a.to_dict() for a in alerts]

    with open(os.path.join(ROOT, "results", "pipeline_results.json"), "w") as fh:
        json.dump(results, fh, indent=2)
    print("%d/%d captures passed. Alerts saved to results/pipeline_results.json" % (matched, ran))


if __name__ == "__main__":
    main()
