from dataclasses import dataclass, field, asdict
from typing import Optional, List


@dataclass
class Alert:
    detector: str              # "fingerprinting" | "deauth" | "sequence" | "fusion"
    timestamp: float           # when the detector fired
    client_mac: Optional[str]  # None for AP-level alerts
    bssid: str
    severity: float            # 0.0 - 1.0
    reason: str
    # Optional extras (not in the original spec):
    # related_bssid: the legit AP this alert is about. Fingerprinting sets it to
    #   the real AP, sequence sets it to the AP the client was on before, so
    #   fusion can link alerts that name different BSSIDs (twin vs real AP).
    # details: machine-readable breakdown (kind, victims, score parts, ...).
    related_bssid: Optional[str] = None
    details: Optional[dict] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class ClientState:
    client_mac: str
    # each entry: {"state": str, "timestamp": float, "bssid": str}
    state_history: List[dict] = field(default_factory=list)
