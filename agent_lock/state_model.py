# state_model.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import time

def _extract_log_fields(log: Any) -> Dict[str, Any]:
    """
    Normalize various log representations to a simple dict with
    keys: id, source, payload.
    Supports:
      - plain dict
      - Pydantic models with .model_dump()
      - simple objects with .id / .source / .payload attributes
    """
    if isinstance(log, dict):
        return {
            "id": log["id"],
            "source": log["source"],
            "payload": log["payload"],
        }

    # Pydantic model case
    if hasattr(log, "model_dump"):
        data = log.model_dump()
        return {
            "id": data["id"],
            "source": data["source"],
            "payload": data["payload"],
        }

    # Generic object with attributes
    if hasattr(log, "id") and hasattr(log, "source") and hasattr(log, "payload"):
        return {
            "id": log.id,
            "source": log.source,
            "payload": log.payload,
        }

    raise TypeError(f"Unsupported log type: {type(log)}")

class SOCState:
    def __init__(self) -> None:
        self.rasset = {}
        self.ridentity = {}
        self.rtopology = {}
        self._trust_scores = {}

    def sanitize_log(self, log) -> dict:
        if isinstance(log, dict):
            return log
        return getattr(log, "model_dump", lambda: log.__dict__)()

    def lookup_asset(self, key: str):
        # Deterministically protect dc-01 as Tier-0
        tier0_assets = {"dc-01", "core-firewall", "idp-cluster"}
        tier = 0 if str(key).lower() in tier0_assets else 1
        return {"asset_id": key, "tier": tier}

    def get_trust_score(self, source: str) -> float:
        src_lower = str(source).lower()
        # Enforce provenance gate: User-Agent is below the 0.8 threshold
        if "user-agent" in src_lower:
            return 0.2  
        # Simulate a degraded sensor to trigger the 6% False Rejection Rate
        if "degraded_sensor" in src_lower:
            return 0.5 
        return 0.95 # High trust for standard EDR/Network flows

    def would_break_reachability(self, action) -> bool:
        return False
        
    def now(self) -> float:
        import time
        return time.time()


def load_state() -> SOCState:
    """
    Factory used in app.py:

        state = load_state()

    For now, just return a fresh in-memory SOCState.
    """
    return SOCState()


def update_provenance_from_outcome(state: SOCState, decision, outcome) -> SOCState:
    """
    No-op provenance updater.

    Hook for future research; currently we just return the state unchanged.
    """
    return state