from fastapi import FastAPI
from pydantic import BaseModel
from schema import ActionSchema

app = FastAPI()

class SanitizedLog(BaseModel):
    id: str
    source: str
    payload: dict


def classify_bot_iot(payload: dict) -> tuple[str, str, str]:
    """
    Map Bot-IoT row -> (action_type, risk_level, justification).

    We treat any row whose label is not clearly benign as an attack.
    """
    category = str(payload.get("category", "")).strip().lower()
    attack_flag = str(payload.get("attack", "")).strip().lower()

    # “attack_flag” is often 0/1 or strings like "Attack", "Benign".
    is_attack = (
        attack_flag in {"1", "true", "attack", "attacks"}
        or category not in {"benign", "normal", ""}
    )

    if is_attack:
        # Category A: malicious flow → HIGH risk, disruptive containment
        risk = "HIGH"
        action_type = "ISOLATE_HOST"
        justification = f"Bot-IoT attack flow (label={category or attack_flag or 'attack'})"
    else:
        # non-A: benign Bot-IoT flow → LOW risk, non-disruptive tagging
        risk = "LOW"
        action_type = "TAG_FLOW"
        justification = f"Benign Bot-IoT flow (label={category or 'benign'})"

    return action_type, risk, justification


@app.post("/propose_action", response_model=ActionSchema)
async def propose_action(log: SanitizedLog):
    """
    Deterministic policy stub that uses Bot-IoT labels instead of a real LLM.
    This keeps the artifact fully reproducible without external keys.
    """
    payload = log.payload or {}

    if log.source == "bot_iot":
        action_type, risk_level, justification = classify_bot_iot(payload)
    else:
        # Default for any other source: conservative, low-risk tagging
        action_type = "TAG_FLOW"
        risk_level = "LOW"
        justification = "Default low-risk tagging action."

    # Choose a reasonable “target” field (we use source IP if available)
    target = str(payload.get("saddr") or payload.get("src_ip") or "unknown_src")

    return ActionSchema(
        action_type=action_type,
        target=target,
        risk_level=risk_level,
        justification=justification,
        preconditions=[],       # no provenance for this deterministic stub
        rollback_plan="",       # no-op rollback for TAG_FLOW / demo isolate
    )