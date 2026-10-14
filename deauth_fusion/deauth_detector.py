"""
Deauth detector v2: burst detection + broadcast / unicast / multi-victim split.

Input : list of parsed frames (dicts from shared.pcap_parser.parse_pcap)
Output: list of Alert objects with detector="deauth"

How it works
  1. Keep deauth + disassoc frames, grouped per AP (bssid).
  2. Slide a `window`-second window over them. If >= `threshold` frames land in
     one window, that is a burst. Bursts closer than `merge_gap` are merged
     into one episode.
  3. Classify the episode by who the frames are aimed at (both directions,
     AP->client and spoofed client->AP, count towards the client):
       broadcast     >= half the frames go to ff:ff:ff:ff:ff:ff.
                     ONE alert, client_mac=None (every client is hit).
       unicast       one victim. ONE alert.
       multi-target  several victims. ONE alert PER victim, so fusion and the
                     evaluation can see each hit client.
     A victim needs >= victim_min_frames and >= victim_min_share of the episode
     to count, so a stray frame doesn't create a victim.
  4. Severity = 0.5..1.0 from the peak rate, +0.10 for broadcast, +0.05 per
     extra victim (max +0.10).

Alert.timestamp is the moment the detector fired (threshold first crossed),
not the burst start. Burst start/end, kind, victims and rates are in
Alert.details.
"""
from collections import Counter, defaultdict

from shared.models import Alert

BROADCAST = "ff:ff:ff:ff:ff:ff"
DEAUTH_TYPES = ("deauth", "disassoc")


def _norm(mac):
    return mac.lower() if mac else None


def _client_of(frame, ap):
    """The client side of a deauth frame (works for AP->client and client->AP)."""
    src, dst = _norm(frame.get("src_mac")), _norm(frame.get("dst_mac"))
    return dst if src == ap else src


def detect_deauth(frames, window=1.0, threshold=20, merge_gap=2.0,
                  victim_min_frames=5, victim_min_share=0.05):
    per_ap = defaultdict(list)
    for f in frames:
        if f.get("frame_type") in DEAUTH_TYPES:
            ap = _norm(f.get("bssid") or f.get("src_mac"))
            if ap:
                per_ap[ap].append(f)

    alerts = []
    for ap, fl in per_ap.items():
        fl.sort(key=lambda f: f["timestamp"])
        ts = [f["timestamp"] for f in fl]

        episodes = []
        cur = None
        left = 0
        for right in range(len(ts)):
            while ts[right] - ts[left] > window:
                left += 1
            count = right - left + 1
            if count < threshold:
                continue
            if cur is not None and ts[right] - cur["last_ts"] <= merge_gap:
                cur["end"] = right
                cur["last_ts"] = ts[right]
                cur["peak"] = max(cur["peak"], count)
            else:
                if cur is not None:
                    episodes.append(cur)
                cur = {"start": left, "end": right, "fire_ts": ts[right],
                       "last_ts": ts[right], "peak": count}
        if cur is not None:
            episodes.append(cur)

        for ep in episodes:
            seg = fl[ep["start"]: ep["end"] + 1]
            n = len(seg)
            burst_start, burst_end = seg[0]["timestamp"], seg[-1]["timestamp"]
            targets = Counter(c for c in (_client_of(f, ap) for f in seg) if c)
            bcast = targets.get(BROADCAST, 0)
            unicast = {m: c for m, c in targets.items() if m != BROADCAST}

            over = (ep["peak"] - threshold) / (4.0 * threshold)
            base = 0.5 + 0.5 * max(0.0, min(1.0, over))

            common = {"frames": n, "peak_rate": ep["peak"], "window": window,
                      "burst_start": burst_start, "burst_end": burst_end,
                      "broadcast_frames": bcast}

            if bcast >= n / 2 or not unicast:
                details = dict(common, kind="broadcast", victims=[])
                reason = ("deauth burst on %s: %d frames in %.1fs (peak %d per %gs), "
                          "broadcast (all clients)"
                          % (ap, n, burst_end - burst_start, ep["peak"], window))
                alerts.append(Alert("deauth", ep["fire_ts"], None, ap,
                                    round(min(1.0, base + 0.10), 3), reason,
                                    details=details))
                continue

            min_frames = max(victim_min_frames, victim_min_share * n)
            victims = sorted((m for m, c in unicast.items() if c >= min_frames),
                             key=lambda m: -unicast[m])
            if not victims:
                victims = [max(unicast, key=unicast.get)]
            kind = "unicast" if len(victims) == 1 else "multi-target"
            bonus = min(0.10, 0.05 * (len(victims) - 1))

            for v in victims:
                details = dict(common, kind=kind, victims=victims,
                               victim_frames=unicast[v])
                reason = ("deauth burst on %s: %d frames in %.1fs (peak %d per %gs), "
                          "%s, victim %s (%d frames)%s"
                          % (ap, n, burst_end - burst_start, ep["peak"], window, kind,
                             v, unicast[v],
                             ", %d victims total" % len(victims) if len(victims) > 1 else ""))
                alerts.append(Alert("deauth", ep["fire_ts"], v, ap,
                                    round(min(1.0, base + bonus), 3), reason,
                                    details=details))

    alerts.sort(key=lambda a: (a.timestamp, a.client_mac or ""))
    return alerts
