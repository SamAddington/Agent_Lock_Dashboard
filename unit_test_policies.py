from dataclasses import dataclass
from typing import Dict, List, Tuple, Iterable

from policy_engine import evaluate_action, Verdict, THRESHOLD_HIGH


@dataclass
class DummyAsset:
    tier: int


class DummyState:
    """
    Minimal in-memory state for testing policy_engine, including:

      • assets / tiers
      • reachability
      • provenance trust + learning
      • time + burst counters
    """

    def __init__(self):
        self.assets: Dict[str, DummyAsset] = {}
        self._trust_scores: Dict[str, float] = {}
        self.events: List[Tuple[str, float]] = []
        self._now: float = 0.0

    # --- asset registry ---
    def lookup_asset(self, target: str) -> DummyAsset:
        return self.assets.get(target, DummyAsset(tier=0))  # unknown -> Tier-0

    # --- reachability ---
    def would_break_reachability(self, action) -> bool:
        # For tests we assume nothing breaks reachability.
        return False

    # --- provenance: trust scores + learning ---
    def get_trust_score(self, source: str) -> float:
        return self._trust_scores.get(source, 0.0)

    def set_trust_score(self, source: str, tau: float) -> None:
        self._trust_scores[source] = max(0.0, min(1.0, tau))

    def update_provenance_from_outcome(
        self,
        signatures: Iterable[str],
        outcome: str,
        eta: float = 0.2,
    ) -> None:
        """
        τ_{t+1}(p) = clip((1 − η) τ_t(p) + η · 1[ y_t = GOOD ], 0, 1)
        """
        is_good = (outcome.upper() == "GOOD")
        for p in signatures:
            p = str(p)
            old = self.get_trust_score(p)
            increment = 1.0 if is_good else 0.0
            new = (1.0 - eta) * old + eta * increment
            self.set_trust_score(p, new)

    # --- time / counters ---
    def set_now(self, ts: float) -> None:
        self._now = ts

    def now(self) -> float:
        return self._now

    def record_action_event(self, kind: str, ts: float) -> None:
        self.events.append((kind, ts))

    def count_recent_events(self, kind: str, since_ts: float) -> int:
        return sum(1 for k, t in self.events if k == kind and t >= since_ts)


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


def test_tier0_non_disruption():
    state = DummyState()
    state.assets["dc-01"] = DummyAsset(tier=0)
    state.assets["app-01"] = DummyAsset(tier=1)
    state.set_trust_score("EDR_SentinelOne", 0.95)

    # Tier-0 disruptive action must be BLOCKed
    a0 = make_action("SHUTDOWN", "dc-01", risk_level="HIGH")
    v0, r0 = evaluate_action(a0, state)
    print("Tier-0:", v0, "|", r0)
    assert v0 == Verdict.BLOCK.value

    # Tier-1 disruptive action with good provenance should ALLOW
    a1 = make_action("SHUTDOWN", "app-01", risk_level="HIGH")
    v1, r1 = evaluate_action(a1, state)
    print("Tier-1:", v1, "|", r1)
    assert v1 == Verdict.ALLOW.value


def test_medium_burst_escalation():
    state = DummyState()
    state.assets["app-01"] = DummyAsset(tier=1)
    state.set_trust_score("EDR_SentinelOne", 0.95)

    a = make_action("BLOCK_IP", "app-01", risk_level="MEDIUM")

    base = 1000.0
    verdicts = []
    for i in range(4):
        state.set_now(base + i * 10.0)
        v, r = evaluate_action(a, state)
        verdicts.append(v)
        print(f"Medium action {i+1}:", v, "|", r)

    assert verdicts[0] == Verdict.ALLOW.value
    assert verdicts[1] == Verdict.ALLOW.value
    assert verdicts[2] == Verdict.ALLOW.value
    assert verdicts[3] == Verdict.ESCALATE.value


def test_provenance_bad_shrinks_allowed_set():
    state = DummyState()
    state.assets["app-01"] = DummyAsset(tier=1)
    source = "EDR_SentinelOne"
    initial_tau = THRESHOLD_HIGH + 0.1
    state.set_trust_score(source, initial_tau)

    a = make_action("SHUTDOWN", "app-01", risk_level="HIGH", source=source)

    v1, r1 = evaluate_action(a, state)
    print("Pre-BAD:", v1, "|", r1)
    assert v1 == Verdict.ALLOW.value

    # BAD outcome lowers τ below threshold
    state.update_provenance_from_outcome([source], outcome="BAD", eta=0.5)
    tau = state.get_trust_score(source)
    print("τ after BAD:", tau)
    assert tau < THRESHOLD_HIGH

    v2, r2 = evaluate_action(a, state)
    print("Post-BAD:", v2, "|", r2)
    assert v2 == Verdict.BLOCK.value


def test_provenance_good_grows_allowed_set():
    state = DummyState()
    state.assets["app-01"] = DummyAsset(tier=1)
    source = "EDR_SentinelOne"
    initial_tau = max(0.0, THRESHOLD_HIGH - 0.3)
    state.set_trust_score(source, initial_tau)

    a = make_action("SHUTDOWN", "app-01", risk_level="HIGH", source=source)

    v1, r1 = evaluate_action(a, state)
    print("Initial (low τ):", v1, "|", r1)
    assert v1 == Verdict.BLOCK.value

    # Multiple GOOD outcomes raise τ above threshold
    for i in range(5):
        state.update_provenance_from_outcome([source], outcome="GOOD", eta=0.5)
        print(f"Step {i+1} τ:", state.get_trust_score(source))

    tau = state.get_trust_score(source)
    assert tau >= THRESHOLD_HIGH

    v2, r2 = evaluate_action(a, state)
    print("Post-GOOD:", v2, "|", r2)
    assert v2 == Verdict.ALLOW.value


if __name__ == "__main__":
    test_tier0_non_disruption()
    test_medium_burst_escalation()
    test_provenance_bad_shrinks_allowed_set()
    test_provenance_good_grows_allowed_set()
    print("All tests passed.")