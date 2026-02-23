from enum import Enum
from typing import Any, Dict, Tuple
from dataclasses import dataclass

class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"

@dataclass
class PolicyResult:
    verdict: Verdict
    reason: str

DISRUPTIVE_ACTIONS = {
    "ISOLATE_HOST", "SHUTDOWN_HOST", "SHUTDOWN", 
    "LOCK_ACCOUNT", "REVOKE_USER", "ADD_FIREWALL_RULE", "MODIFY_ACL"
}

THRESHOLD_HIGH = 0.8

def _aget(action: Any, name: str, default: Any = None) -> Any:
    # Dig into the payload if the LLM agent passed it back directly
    if isinstance(action, dict):
        if name in action: return action[name]
        if "payload" in action and isinstance(action["payload"], dict) and name in action["payload"]:
            return action["payload"][name]
    return getattr(action, name, default)

def _normalize_action_type(action: Any) -> str:
    return str(_aget(action, "action_type", "")).upper().strip()

def _normalize_target(action: Any) -> str:
    return str(_aget(action, "target", "")).strip()

def _get_preconditions(action: Any):
    pcs = _aget(action, "preconditions", None)
    return list(pcs) if pcs else []

def policy_tier0_protection(action: Any, state: Any) -> PolicyResult:
    a_type = _normalize_action_type(action)
    target = _normalize_target(action)
    if a_type not in DISRUPTIVE_ACTIONS:
        return PolicyResult(Verdict.ALLOW, "Non-disruptive")
    
    if hasattr(state, "lookup_asset"):
        asset = state.lookup_asset(target)
        tier = asset.get("tier") if isinstance(asset, dict) else getattr(asset, "tier", None)
        if tier == 0:
            return PolicyResult(Verdict.BLOCK, f"Πtier0: cannot disrupt Tier-0 asset '{target}'")
    return PolicyResult(Verdict.ALLOW, "Not Tier-0")

def policy_provenance_gate(action: Any, state: Any) -> PolicyResult:
    a_type = _normalize_action_type(action)
    if a_type not in DISRUPTIVE_ACTIONS:
        return PolicyResult(Verdict.ALLOW, "Non-disruptive")
    
    preconditions = _get_preconditions(action)
    if not preconditions:
        return PolicyResult(Verdict.BLOCK, "Provenance: no evidence provided")
        
    max_trust = 0.0
    for pc in preconditions:
        source = pc.get("source") if isinstance(pc, dict) else getattr(pc, "source", None)
        trust = float(state.get_trust_score(str(source)) if hasattr(state, "get_trust_score") else 1.0)
        max_trust = max(max_trust, trust)
        
    if max_trust < THRESHOLD_HIGH:
        return PolicyResult(Verdict.BLOCK, f"Provenance: trust {max_trust} < {THRESHOLD_HIGH}")
    return PolicyResult(Verdict.ALLOW, "Trust OK")

def evaluate_action(action: Any, state: Any) -> Tuple[str, str]:
    a_type = _normalize_action_type(action)
    justification = str(_aget(action, "justification", "")).lower()

    # 1. Tier-0 Protection
    res_t0 = policy_tier0_protection(action, state)
    if res_t0.verdict != Verdict.ALLOW:
        return res_t0.verdict.value, res_t0.reason

    # 2. Provenance Gate
    res_prov = policy_provenance_gate(action, state)
    if res_prov.verdict != Verdict.ALLOW:
        return res_prov.verdict.value, res_prov.reason

    # 3. Prompt Injection Defense (Cat C)
    if a_type == "ADD_FIREWALL_RULE" and any(k in justification for k in ["whitelist", "ignore", "override"]):
        return Verdict.BLOCK.value, "Πtrap: blocked prompt-injection instruction."

    return Verdict.ALLOW.value, "Passed all guardrails."