"""
Fusion v2: weighted sum of the three detector severities.

Input : one list of Alert objects from any detectors
Output: list of Alert objects with detector="fusion"

1. Group alerts into incidents: two alerts belong together if they name a
   common BSSID (bssid or related_bssid) and are within `window` seconds.
   Fingerprinting names {twin, real AP}, deauth names {real AP}, sequence
   names {new AP, previous AP}, so one attack links up even though the twin
   and the real AP have different BSSIDs.
2. Per incident, take the strongest alert of each detector and compute
       score = sum(weight[detector] * best_severity[detector])
3. If score >= threshold, emit ONE fusion alert for the incident, timestamped
   when the running score first crossed the threshold (so latency is honest).

Hand-picked weights: fingerprinting 0.4, deauth 0.3, sequence 0.3, threshold 0.5.
No single detector can reach 0.5 alone (max 0.4), so fusion needs at least two
detectors to agree. Example scores with typical severities:
    twin (0.85) + deauth (1.0)                0.34 + 0.30 = 0.64  -> fires
    twin + deauth + client rejoined twin      0.64 + 0.21 = 0.85  -> fires
    twin (0.85) only                          0.34                -> no
    deauth (1.0) only                         0.30                -> no
These weights are a starting point, to be tuned with the evaluation data.
"""
from shared.models import Alert

DEFAULT_WEIGHTS = {"fingerprinting": 0.4, "deauth": 0.3, "sequence": 0.3}


def _norm(mac):
    return mac.lower() if mac else None


def _bssids(a):
    return {_norm(a.bssid), _norm(a.related_bssid)} - {None, ""}


def fuse(alerts, window=120.0, weights=None, threshold=0.5):
    w = weights or DEFAULT_WEIGHTS
    sig = sorted((a for a in alerts if a.detector in w), key=lambda a: a.timestamp)
    n = len(sig)

    parent = list(range(n))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    names = [_bssids(a) for a in sig]
    for i in range(n):
        for j in range(i + 1, n):
            if sig[j].timestamp - sig[i].timestamp > window:
                break
            if names[i] & names[j]:
                parent[find(j)] = find(i)

    clusters = {}
    for i in range(n):
        clusters.setdefault(find(i), []).append(sig[i])

    fused = []
    for members in clusters.values():
        best = {}      # detector -> strongest alert
        cross_ts = None
        for a in members:                      # already in time order
            if a.detector not in best or a.severity > best[a.detector].severity:
                best[a.detector] = a
            running = sum(w[d] * x.severity for d, x in best.items())
            if cross_ts is None and running >= threshold - 1e-9:
                cross_ts = a.timestamp
        if cross_ts is None:
            continue

        contrib = {d: round(w[d] * x.severity, 3) for d, x in best.items()}
        score = round(min(1.0, sum(contrib.values())), 3)

        fp, de, sq = best.get("fingerprinting"), best.get("deauth"), best.get("sequence")
        bssid = (fp or de or sq).bssid
        related = (fp.related_bssid if fp else None) or (de.bssid if de else None) \
            or (sq.related_bssid if sq else None)
        client = next((x.client_mac for x in (de, sq) if x and x.client_mac), None)

        parts = " + ".join("%s %.2f" % (d, c) for d, c in contrib.items())
        fused.append(Alert(
            detector="fusion",
            timestamp=cross_ts,
            client_mac=client,
            bssid=bssid,
            severity=score,
            reason="weighted score %.2f >= %.2f (%s) from %d alerts within %.0fs"
                   % (score, threshold, parts, len(members), window),
            related_bssid=related,
            details={"score": score, "threshold": threshold, "contributions": contrib,
                     "weights": dict(w), "n_alerts": len(members)},
        ))

    fused.sort(key=lambda a: a.timestamp)
    return fused
