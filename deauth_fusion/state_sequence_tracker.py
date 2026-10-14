"""
State-sequence tracker v2: a finite state machine per client.

States (per client, built from management frames on the air):
    idle -> probing -> authenticating -> associated -> disassociated -> probing ...

Frame -> state:
    probe_req            -> probing
    auth, assoc_req      -> authenticating
    assoc_resp           -> associated
    deauth, disassoc     -> disassociated  (a broadcast deauth from an AP
                            disconnects every client currently associated to it)

TRANSITIONS is the transition table. A move is "ok" or "skip" (a state was
skipped). Two things raise a sequence Alert:

  1. Skipped state: probing -> associated, or disassociated -> associated
     (association without authentication). Severity 0.5.
  2. BSSID change on reconnect: the client was associated to AP A and now
     authenticates/associates with AP B.
       after a disconnect (deauth/disassoc in between)   severity 0.7
       directly (no disconnect, looks like a roam)       severity 0.4
     This is the evil-twin signature: deauth the client, it rejoins the twin.
     Legit roaming between mesh nodes triggers it too, which is why fusion
     only trusts it together with other signals.
     The Alert has bssid=new AP, related_bssid=previous AP.

idle means "nothing observed yet", so a capture that starts mid-session is
never flagged for its first frame.

Two rules keep a deauth flood from creating fake anomalies:
  - A deauth/disassoc only disconnects a client that is associated to the AP
    named in the frame (or one we know nothing about yet). A flood lands in
    the middle of a reconnect, and a spoofed deauth from the real AP must not
    knock down a client that is currently on the twin.
  - Skipped-state alerts are limited to one per client and AP every
    SKIP_COOLDOWN seconds, so a flapping client gives one alert, not dozens.

NOT done yet: "too-fast transition" checks. They need benign timing data to
set thresholds, so ClientState entries keep timestamps for that later.

    python deauth_fusion/state_sequence_tracker.py captures/benign_home.pcap
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared.models import Alert, ClientState  # noqa: E402

IDLE, PROBING, AUTH, ASSOC, DISASSOC = (
    "idle", "probing", "authenticating", "associated", "disassociated")

STATE_BY_TYPE = {
    "probe_req": PROBING,
    "auth": AUTH,
    "assoc_req": AUTH,       # still part of joining; repeats collapse
    "assoc_resp": ASSOC,
    "deauth": DISASSOC,
    "disassoc": DISASSOC,
}

OK, SKIP = "ok", "skip"
TRANSITIONS = {
    IDLE:     {PROBING: OK, AUTH: OK, ASSOC: OK, DISASSOC: OK},
    PROBING:  {PROBING: OK, AUTH: OK, ASSOC: SKIP, DISASSOC: OK},
    AUTH:     {AUTH: OK, ASSOC: OK, PROBING: OK, DISASSOC: OK},
    ASSOC:    {ASSOC: OK, DISASSOC: OK, PROBING: OK, AUTH: OK},
    DISASSOC: {DISASSOC: OK, PROBING: OK, AUTH: OK, ASSOC: SKIP},
}
SKIPPED = {(PROBING, ASSOC): AUTH, (DISASSOC, ASSOC): AUTH}

SKIP_COOLDOWN = 10.0   # seconds between skipped-state alerts per (client, AP)

SEVERITY = {
    "skipped_state": 0.5,
    "bssid_change_after_disconnect": 0.7,
    "bssid_change_roam": 0.4,
}


def _norm(mac):
    return mac.lower() if mac else None


def _is_group(mac):
    """True for broadcast / multicast addresses."""
    try:
        return int(mac.split(":")[0], 16) & 1 == 1
    except (ValueError, AttributeError):
        return True


class SequenceTracker:
    def __init__(self):
        self.clients = {}              # mac -> ClientState
        self.alerts = []
        self._last_assoc_ap = {}       # mac -> BSSID of the last association
        self._disc_since_assoc = {}    # mac -> True if a disconnect happened since
        self._flagged = set()          # (client, old_ap, new_ap) already reported
        self._last_skip = {}           # (client, ap) -> time of last skipped-state alert

    def feed(self, f):
        ftype = f.get("frame_type")
        state = STATE_BY_TYPE.get(ftype)
        if not state:
            return
        src, dst, bssid = _norm(f.get("src_mac")), _norm(f.get("dst_mac")), _norm(f.get("bssid"))

        if ftype == "probe_req":
            client, ap = src, None
        else:
            if not bssid:
                return
            if state == DISASSOC and src == bssid and _is_group(dst):
                self._broadcast_disassoc(bssid, f["timestamp"])
                return
            client = dst if src == bssid else src
            if client == bssid:
                return
            ap = bssid

        if not client or _is_group(client):
            return
        self._move(client, state, ap, f["timestamp"])

    def _broadcast_disassoc(self, ap, ts):
        for client, cs in self.clients.items():
            h = cs.state_history
            if h and h[-1]["state"] == ASSOC and h[-1]["bssid"] == ap:
                self._move(client, DISASSOC, ap, ts)

    def _move(self, client, state, bssid, ts):
        cs = self.clients.setdefault(client, ClientState(client_mac=client))
        hist = cs.state_history
        prev = hist[-1] if hist else None
        prev_state = prev["state"] if prev else IDLE
        if prev and prev["state"] == state and prev["bssid"] == bssid:
            return

        # A deauth only counts if it hits the AP the client is associated to.
        if state == DISASSOC and prev_state not in (IDLE, DISASSOC):
            if not (prev_state == ASSOC and prev["bssid"] == bssid):
                return

        hist.append({"state": state, "timestamp": ts, "bssid": bssid})

        # 1. skipped state (rate limited per client + AP)
        if TRANSITIONS[prev_state].get(state) == SKIP:
            key = (client, bssid)
            if ts - self._last_skip.get(key, -1e18) >= SKIP_COOLDOWN:
                self._last_skip[key] = ts
                skipped = SKIPPED[(prev_state, state)]
                self.alerts.append(Alert(
                    "sequence", ts, client, bssid or "", SEVERITY["skipped_state"],
                    "skipped state: %s -> %s without %s" % (prev_state, state, skipped),
                    details={"anomaly": "skipped_state", "from": prev_state,
                             "to": state, "skipped": skipped}))

        # 2. BSSID change on reconnect
        if state in (AUTH, ASSOC) and bssid:
            last = self._last_assoc_ap.get(client)
            if last and last != bssid and (client, last, bssid) not in self._flagged:
                self._flagged.add((client, last, bssid))
                after = self._disc_since_assoc.get(client, False)
                sev = SEVERITY["bssid_change_after_disconnect" if after else "bssid_change_roam"]
                self.alerts.append(Alert(
                    "sequence", ts, client, bssid, sev,
                    "BSSID changed on reconnect: was associated to %s, now %s with %s%s"
                    % (last, state, bssid,
                       " (after a disconnect)" if after else " (no disconnect seen, roam?)"),
                    related_bssid=last,
                    details={"anomaly": "bssid_change", "from": last, "to": bssid,
                             "after_disconnect": after}))

        if state == ASSOC and bssid:
            self._last_assoc_ap[client] = bssid
            self._disc_since_assoc[client] = False
        elif state == DISASSOC:
            self._disc_since_assoc[client] = True


def track(frames):
    """Run the FSM over frames (in capture order). Returns (clients, alerts)."""
    t = SequenceTracker()
    for f in frames:
        t.feed(f)
    return t.clients, t.alerts


def build_client_states(frames):
    return track(frames)[0]


def print_sequences(states, limit=10, max_len=12):
    ranked = sorted(states.values(), key=lambda s: len(s.state_history), reverse=True)[:limit]
    for s in ranked:
        h = s.state_history
        seq = " -> ".join(x["state"] for x in h[:max_len])
        more = " ... (+%d more)" % (len(h) - max_len) if len(h) > max_len else ""
        print("    %s: %s%s" % (s.client_mac, seq, more))


if __name__ == "__main__":
    from shared.pcap_parser import parse_pcap
    clients, alerts = track(list(parse_pcap(sys.argv[1])))
    print("%d clients with state transitions, %d sequence alerts" % (len(clients), len(alerts)))
    print_sequences(clients)
    for a in alerts:
        print("  [sequence] t=%.3f sev=%.2f client=%s :: %s" % (a.timestamp, a.severity, a.client_mac, a.reason))
