# llm_client.py
import os
import httpx
from typing import Any, Dict
from urllib.parse import urlparse

LLM_AGENT_URL = os.getenv("LLM_AGENT_URL", "http://llm_agent:8001/propose_action")


def _extract_log_fields(log: Any) -> Dict[str, Any]:
    if isinstance(log, dict):
        return {
            "id": log["id"],
            "source": log["source"],
            "payload": log["payload"],
        }
    if hasattr(log, "model_dump"):
        data = log.model_dump()
        return {
            "id": data["id"],
            "source": data["source"],
            "payload": data["payload"],
        }
    if hasattr(log, "id") and hasattr(log, "source") and hasattr(log, "payload"):
        return {
            "id": log.id,
            "source": log.source,
            "payload": log.payload,
        }
    raise TypeError(f"Unsupported log type: {type(log)}")


def call_llm_agent(log: Any) -> Dict[str, Any]:
    """
    Call the LLM proposer service with a sanitized log.
    Accepts dict, Pydantic, or simple object, but always sends dict.
    """
    fields = _extract_log_fields(log)

    body = {
        "id": fields["id"],
        "source": fields["source"],
        "payload": fields["payload"],
    }

    resp = httpx.post(LLM_AGENT_URL, json=body, timeout=30)
    resp.raise_for_status()
    return resp.json()