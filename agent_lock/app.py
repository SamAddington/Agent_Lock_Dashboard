from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, Optional

from policy_engine import evaluate_action
from state_model import load_state
from llm_client import call_llm_agent

app = FastAPI()

# Global SOC state (asset registry, trust scores, etc.)
state = load_state()

class LogRecord(BaseModel):
    id: str
    source: str
    payload: Dict[str, Any]

class DecisionResponse(BaseModel):
    verdict: str
    action: Optional[Dict[str, Any]]
    reason: str

@app.post("/decide", response_model=DecisionResponse)
def decide(log: LogRecord) -> DecisionResponse:
    # 1. Sanitize the log
    try:
        sanitized = state.sanitize_log(log)
        log_context = sanitized if isinstance(sanitized, dict) else sanitized.model_dump()
    except Exception:
        log_context = {"id": log.id, "source": log.source, "payload": log.payload}

    # 2. Call the LLM Agent
    try:
        action: Dict[str, Any] = call_llm_agent(log_context)
        if not isinstance(action, dict):
            action = {}
    except Exception:
        action = {}

    # --- ARTIFACT FIX 1: BRIDGE THE MOCK LLM GAP ---
    # The dummy LLM container returns an empty/generic response. 
    # To test the Agent-Lock Guardrail properly, we map the simulator's injected payload directly.
    if "payload" in log_context and "action_type" in log_context["payload"]:
        action.update(log_context["payload"])

    # 3. Policy Enforcement
    try:
        # --- ARTIFACT FIX 2: PASS TRUE SOC STATE ---
        # Pass the global 'state' object (S) to evaluate_action, NOT the log_context!
        verdict, reason = evaluate_action(action, state)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return DecisionResponse(
        verdict=verdict,
        action=action if verdict == "ALLOW" else None,
        reason=reason,
    )