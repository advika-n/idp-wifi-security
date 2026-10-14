"""
AP fingerprinting detector v2 (weighted rule scoring).

Input : list of parsed frames + a `trusted` profile
Output: list of Alert objects with detector="fingerprinting"

Looks at beacon / probe_resp frames. A frame that advertises a trusted SSID
from a BSSID that is not trusted is a rogue AP. Its severity is the sum of the
weights of the checks it fails (weights sum to 1.0, so severity is 0..1):

    bssid     0.40   not one of the trusted BSSIDs (always true for a rogue)
    security  0.25   e.g. OPEN vs WPA   (twins are often open or downgraded)
    oui       0.20   vendor prefix differs (twins often use random/virtual MACs)
    channel   0.15   weakest: twins often copy the channel, and APs hop

The weights are hand-picked. One Alert per rogue (ssid, bssid), not per beacon.
Rogues scoring below `min_severity` are dropped (default 0.4 keeps every rogue).

trusted format:
    {"dlink": {"bssid": "c4:e9:0a:50:ef:e6", "channel": 1,
               "security": "WPA", "oui": "C4:E9:0A"}}
("bssids": [..] works too.) build_trusted() learns this from the real AP's own
beacons so nothing is hardcoded.

NEXT STEP (not done yet): multi-environment tuning. A legit second BSSID with
the same SSID (mesh node, 5 GHz radio) currently looks like a twin. Collect
home / hostel / campus captures, see how mesh nodes score (they usually match
on OUI and security, so they land around 0.4-0.55 vs 0.65+ for a real twin),
then tune the weights and min_severity from that data.
"""
from shared.models import Alert

WEIGHTS = {"bssid": 0.40, "security": 0.25, "oui": 0.20, "channel": 0.15}


def _norm(mac):
    return mac.lower() if mac else None


def build_trusted(frames, real_bssid):
    """Learn the trusted profile from the first named beacon of the real AP."""
    real = _norm(real_bssid)
    for f in frames:
        if (f.get("frame_type") == "beacon"
                and _norm(f.get("bssid")) == real
                and f.get("ssid")):
            return {f["ssid"]: {"bssids": [real],
                                "channel": f.get("channel"),
                                "security": f.get("security"),
                                "oui": f.get("vendor_oui")}}
    return {}


def detect_evil_twin(frames, trusted, weights=None, min_severity=0.4):
    w = dict(WEIGHTS)
    w.update(weights or {})

    profiles = {}
    for ssid, p in trusted.items():
        raw = p.get("bssids") or [p.get("bssid")]
        profiles[ssid] = dict(p, bssids={_norm(b) for b in raw if b})

    seen = set()
    alerts = []
    for f in frames:
        if f.get("frame_type") not in ("beacon", "probe_resp"):
            continue
        ssid = f.get("ssid")
        p = profiles.get(ssid)
        if not p:
            continue
        bssid = _norm(f.get("bssid"))
        if not bssid or bssid in p["bssids"] or (ssid, bssid) in seen:
            continue
        seen.add((ssid, bssid))

        expected = ", ".join(sorted(p["bssids"]))
        contrib = {"bssid": w["bssid"]}
        why = ["bssid +%.2f (expected %s got %s)" % (w["bssid"], expected, bssid)]

        sec = f.get("security")
        if p.get("security") and sec and sec != p["security"]:
            contrib["security"] = w["security"]
            why.append("security +%.2f (%s vs %s)" % (w["security"], sec, p["security"]))

        oui = f.get("vendor_oui")
        if p.get("oui") and oui and oui.upper() != p["oui"].upper():
            contrib["oui"] = w["oui"]
            why.append("oui +%.2f (%s vs %s)" % (w["oui"], oui.upper(), p["oui"].upper()))

        ch = f.get("channel")
        if p.get("channel") is not None and ch is not None and ch != p["channel"]:
            contrib["channel"] = w["channel"]
            why.append("channel +%.2f (%s vs %s)" % (w["channel"], ch, p["channel"]))

        severity = round(min(1.0, sum(contrib.values())), 3)
        if severity < min_severity:
            continue

        alerts.append(Alert(
            detector="fingerprinting",
            timestamp=f["timestamp"],
            client_mac=None,
            bssid=bssid,
            severity=severity,
            reason="Rogue AP for SSID '%s' (severity %.2f): %s" % (ssid, severity, "; ".join(why)),
            related_bssid=sorted(p["bssids"])[0],
            details={"contributions": contrib},
        ))

    return alerts
