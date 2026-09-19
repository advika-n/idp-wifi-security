"""
shared/pcap_parser.py

Common parsing layer for the IDP Wi-Fi evil-twin / deauth detection project.
Converts raw .pcap files into the parsed-frame dict format defined in the
team's data spec, so fingerprinting (B) and deauth+fusion (C) both consume
the same structure.

Usage:
    python3 pcap_parser.py captures/evil_twin_only.pcap
    python3 pcap_parser.py captures/evil_twin_only.pcap --out parsed_evil_twin.json
    python3 pcap_parser.py captures/*.pcap --out-dir parsed/

Requires: scapy  (pip install scapy)
"""

import argparse
import json
import sys
from pathlib import Path

from scapy.all import rdpcap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Elt, RadioTap


# --- Frame type mapping -----------------------------------------------------
# Dot11.type: 0 = management, 1 = control, 2 = data
# Dot11.subtype meanings below are for management frames (type 0).
MGMT_SUBTYPE_MAP = {
    0: "assoc_req",
    1: "assoc_resp",
    2: "reassoc_req",
    3: "reassoc_resp",
    4: "probe_req",
    5: "probe_resp",
    8: "beacon",
    10: "disassoc",
    11: "auth",
    12: "deauth",
    13: "action",
}


def classify_frame_type(pkt) -> str:
    dot11 = pkt[Dot11]
    if dot11.type == 0:  # management
        return MGMT_SUBTYPE_MAP.get(dot11.subtype, f"mgmt_subtype_{dot11.subtype}")
    elif dot11.type == 1:  # control
        return "control"
    elif dot11.type == 2:  # data
        return "data"
    return "unknown"


def extract_ssid(pkt):
    """Pull SSID from the Dot11Elt chain (ID 0 = SSID) if present."""
    if not pkt.haslayer(Dot11Elt):
        return None
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 0:  # SSID element
            try:
                ssid = elt.info.decode("utf-8", errors="ignore")
            except Exception:
                ssid = None
            return ssid if ssid else None  # empty string -> hidden/broadcast SSID
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def extract_channel(pkt):
    """DS Parameter Set element (ID 3) carries the channel number directly."""
    if not pkt.haslayer(Dot11Elt):
        return None
    elt = pkt.getlayer(Dot11Elt)
    while elt:
        if elt.ID == 3 and len(elt.info) >= 1:  # DSset
            return elt.info[0]
        elt = elt.payload.getlayer(Dot11Elt)
    return None


def extract_security(pkt):
    """
    Only meaningful on beacon/probe-resp frames.
    Looks for RSN (WPA2/WPA3, ID 48) and WPA vendor-specific (ID 221, OUI 00:50:F2 type 1)
    information elements. Falls back to the Privacy bit in capability info for WEP/OPEN.
    """
    if not (pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp)):
        return None

    has_rsn = False
    has_wpa = False

    if pkt.haslayer(Dot11Elt):
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 48:
                has_rsn = True
            elif elt.ID == 221 and elt.info[:4] == b"\x00\x50\xf2\x01":
                has_wpa = True
            elt = elt.payload.getlayer(Dot11Elt)

    if has_rsn:
        # Distinguishing WPA2 vs WPA3 properly requires parsing the AKM suite list
        # inside the RSN element; flagging as WPA2/WPA3 generically for now.
        return "WPA2/WPA3"
    if has_wpa:
        return "WPA"

    # No RSN/WPA element -> check Privacy bit for WEP vs OPEN
    cap = None
    if pkt.haslayer(Dot11Beacon):
        cap = pkt[Dot11Beacon].cap
    elif pkt.haslayer(Dot11ProbeResp):
        cap = pkt[Dot11ProbeResp].cap

    if cap is not None:
        return "WEP" if cap.privacy else "OPEN"
    return None


def extract_vendor_oui(mac):
    if not mac:
        return None
    return mac.upper()[:8]  # first 3 octets, e.g. "AA:BB:CC"


def extract_signal_dbm(pkt):
    if pkt.haslayer(RadioTap):
        radio = pkt[RadioTap]
        if hasattr(radio, "dBm_AntSignal"):
            return radio.dBm_AntSignal
    return None


def parse_frame(pkt):
    """Convert one scapy packet into the team's parsed-frame dict, or None if not 802.11."""
    if not pkt.haslayer(Dot11):
        return None

    dot11 = pkt[Dot11]
    frame_type = classify_frame_type(pkt)

    return {
        "timestamp": float(pkt.time),
        "frame_type": frame_type,
        "src_mac": dot11.addr2,
        "dst_mac": dot11.addr1,
        "bssid": dot11.addr3,
        "ssid": extract_ssid(pkt),
        "channel": extract_channel(pkt),
        "security": extract_security(pkt),
        "vendor_oui": extract_vendor_oui(dot11.addr3 or dot11.addr2),
        "signal_dbm": extract_signal_dbm(pkt),
    }


def parse_pcap(path):
    """Parse a single pcap file, returning a list of frame dicts."""
    packets = rdpcap(str(path))
    frames = []
    for pkt in packets:
        frame = parse_frame(pkt)
        if frame is not None:
            frames.append(frame)
    return frames


def main():
    ap = argparse.ArgumentParser(description="Parse pcap(s) into the team's shared frame format.")
    ap.add_argument("pcaps", nargs="+", help="One or more .pcap/.cap files")
    ap.add_argument("--out", help="Write combined output to this JSON file (single input only)")
    ap.add_argument("--out-dir", help="Write one JSON file per input pcap into this directory")
    args = ap.parse_args()

    if args.out and len(args.pcaps) > 1:
        print("--out only supports a single input pcap; use --out-dir for multiple files.", file=sys.stderr)
        sys.exit(1)

    for pcap_path in args.pcaps:
        path = Path(pcap_path)
        if not path.exists():
            print(f"Skipping {path}: file not found", file=sys.stderr)
            continue

        print(f"Parsing {path} ...")
        frames = parse_pcap(path)
        print(f"  -> {len(frames)} 802.11 frames parsed")

        if args.out_dir:
            out_dir = Path(args.out_dir)
            out_dir.mkdir(parents=True, exist_ok=True)
            out_path = out_dir / f"{path.stem}.json"
        elif args.out:
            out_path = Path(args.out)
        else:
            out_path = path.with_suffix(".json")

        with open(out_path, "w") as f:
            json.dump(frames, f, indent=2)
        print(f"  -> wrote {out_path}")


if __name__ == "__main__":
    main()
