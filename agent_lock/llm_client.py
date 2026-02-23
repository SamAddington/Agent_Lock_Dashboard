# llm_client.py
"""
Minimal stub LLM client for the Agent-Lock artifact.

In a real deployment, this module would call an LLM-based
agent (e.g., via HTTP to the llm_agent service) and return
a proposed action schema.

For the artifact, we keep it deterministic and simple so
that the policy engine / safety properties can be exercised
without requiring any external API keys or models.
"""

from typing import Any, Dict


def call_llm_agent(sanitized_log: dict) -> dict:
    """
    Minimal stub for the artifact. We pretend the LLM has already
    reasoned and emit a structured Action Schema that policy_engine
    can evaluate.

    You can later replace this with a real HTTP call to the llm_agent
    container if you want.
    """
    payload = sanitized_log.get("payload", {})
    event_type = payload.get("event_type", "")
    target_host = payload.get("target_host", "host-01")
    dst_ip = payload.get("dst_ip", "192.0.2.10")

    # Very simple heuristic: if it's clearly malicious,
    # propose a disruptive action; otherwise propose a benign one.
    if event_type in ("authentication_failure", "network_connection") and (
        payload.get("ioc_label") == "known_c2"
        or payload.get("suspicious") is True
    ):
        # Disruptive candidate (to be gated by Agent-Lock)
        return {
            "action_type": "ISOLATE_HOST",
            "target": target_host or dst_ip,
            "justification": "IOC / suspicious auth activity",
            "risk_level": "HIGH",
            "preconditions": [
                {
                    "name": "c2_traffic_verified",
                    "source": "EDR_SentinelOne",
                    "artifact_ref": sanitized_log.get("id", "artifact-1"),
                    "confidence": 0.95,
                }
            ],
            "rollback_plan": f"unisolate_{target_host or dst_ip}",
        }
    else:
        # Benign / low-risk action
        return {
            "action_type": "ADD_TAG",
            "target": target_host or dst_ip,
            "justification": "Benign / observation-only",
            "risk_level": "LOW",
            "preconditions": [],
            "rollback_plan": "",
        }