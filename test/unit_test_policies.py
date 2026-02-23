"""
unit_test_policies.py

Small sanity checks for Agent-Lock policies:

  • Tier-0 non-disruption: disruptive action on Tier-0 asset is BLOCKed.
  • Medium-burst escalation: 4th MEDIUM-risk action in <60s is ESCALATE.
"""

from dataclasses import dataclass
from typing import Dict, List, Tuple

from policy_engine import evaluate_action, Verdict, DISRUPTIVE_ACTIONS


# ---- Dummy state implementation ------------------------------------------


@dataclass
class DummyAsset:
    tier: int


class DummyState:
    """
    Minimal in-memory state for testing policy_engine.

    Assets:
      • lookup_asset(target) -> DummyAsset

    Reachability:
      • would_break_reachability(action) -> bool (always False for now)

    Provenance:
      • get_trust_score(source: str) -> float

    Burst counters:
      • now(), record_action_event, count_recent_events
    """

    def __init__(self):
        self.assets: Dict[str, DummyAsset] = {}
        self.trust_scores: Dict[str, float] = {}
        # simple list of (kind, ts) events; good enough for unit tests
        self.events: List[Tuple[str, float]] = []
        self._now: float = 0.0

    # --- asset registry ---
    def lookup_asset(self, target: str) -> DummyAsset:
        return self.assets.get(target, DummyAsset(tier=0))  # unknown -> Tier-0

    # --- reachability ---
    def would_break_reachability(self, action) -> bool:
        # For now, pretend no action breaks reachability.
        # You can extend this to test Πreach explicitly.
        return False

    # --- provenance ---
    def get_trust_score(self, source: str) -> float:
        return self.trust_scores.get(source, 0.0)

    # --- time / counters ---
    def set_now(self, ts: float) -> None:
        self._now = ts

    def now(self) -> float:
        return self._now

    def record_action_event(self, kind: str, ts: float) -> None:
        self.events.append((kind, ts))

    def count_recent_events(self, kind: str, since_ts: float) -> int:
        return sum(1 for k, t in self.events if k == kind and t >= since_ts)


# ---- Helper: build action dicts ------------------------------------------


def make_action(
    action_type: str,
    target: str,
    risk_level: str,
    source: str = "EDR_SentinelOne",
) -> dict:
    return {
        "action_type": action_type,
        "target": target,
        "risk_level": risk_level,
        "justification": "test",
        "preconditions": [
            {
                "name": "evidence",
                "source": source,
                "artifact_ref": "log_id_1",
                "confidence": 0.95,
            }
        ],
        "rollback_plan": None,
    }


# ---- Test 1: Tier-0 non-disruption lemma ---------------------------------


def test_tier0_non_disruption():
    state = DummyState()
    # Tier-0 domain controller
    state.assets["dc-01"] = DummyAsset(tier=0)
    # Tier-1 application server
    state.assets["app-01"] = DummyAsset(tier=1)
    # High trust source
    state.trust_scores["EDR_SentinelOne"] = 0.95

    # Disruptive action on Tier-0 asset must be BLOCKed
    action_tier0 = make_action("SHUTDOWN", "dc-01", risk_level="HIGH")
    verdict, reason = evaluate_action(action_tier0, state)

    assert verdict == Verdict.BLOCK.value, (
        "Tier-0 disruptive action should be BLOCKed"
    )
    print("Tier-0 test: verdict =", verdict, "| reason:", reason)

    # For comparison: disruptive action on Tier-1 asset with high-trust evidence
    action_tier1 = make_action("SHUTDOWN", "app-01", risk_level="HIGH")
    verdict2, reason2 = evaluate_action(action_tier1, state)

    assert verdict2 == Verdict.ALLOW.value, (
        "Tier-1 disruptive action with high-trust evidence and no reachability "
        "issue should be ALLOWed"
    )
    print("Tier-1 test: verdict =", verdict2, "| reason:", reason2)


# ---- Test 2: medium-risk burst escalation ---------------------------------


def test_medium_burst_escalation():
    state = DummyState()
    # Application server is Tier-1, not Tier-0
    state.assets["app-01"] = DummyAsset(tier=1)
    # High trust evidence so provenance gate passes
    state.trust_scores["EDR_SentinelOne"] = 0.95

    action_medium = make_action(
        "BLOCK_IP", "app-01", risk_level="MEDIUM"
    )

    # Simulate 4 actions within a 60s window
    base_ts = 1000.0
    verdicts = []

    for i in range(4):
        state.set_now(base_ts + i * 10.0)  # every 10 seconds
        verdict, reason = evaluate_action(action_medium, state)
        verdicts.append((verdict, reason))
        print(f"Medium action {i+1}: verdict = {verdict} | reason: {reason}")

    # First three should be ALLOW, 4th should be ESCALATE
    assert verdicts[0][0] == Verdict.ALLOW.value
    assert verdicts[1][0] == Verdict.ALLOW.value
    assert verdicts[2][0] == Verdict.ALLOW.value
    assert verdicts[3][0] == Verdict.ESCALATE.value, (
        "4th MEDIUM-risk action in <60s should ESCALATE"
    )


# ---- Optional: quick manual run -------------------------------------------


if __name__ == "__main__":
    print("Running Tier-0 non-disruption test...")
    test_tier0_non_disruption()
    print("\nRunning medium-burst escalation test...")
    test_medium_burst_escalation()
    print("\nAll tests passed.")