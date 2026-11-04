"""ADONAI Local LLM Analyst Adapter — Supports Ollama / OpenAI-compatible local endpoints with strict JSON-schema validation and deterministic fallback."""
import datetime
import json
import os
import socket
import urllib.request
import uuid
from backend.security import redact_secrets

REQUIRED_EXPLANATION_KEYS = {
    "incident_id",
    "generation_mode",
    "model_name",
    "what_happened",
    "where_implicated",
    "why_flagged",
    "evidence_quality_statement",
    "recommended_next_steps",
    "what_cannot_be_determined",
    "cited_ids",
}

def check_local_llm_health() -> dict:
    base_url = os.environ.get("ADONAI_LLM_BASE_URL", "http://127.0.0.1:11434")
    model_name = os.environ.get("ADONAI_LLM_MODEL", "llama3.2:3b-instruct-local")
    host = "127.0.0.1"
    port = 11434
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.35)
            online = (s.connect_ex((host, port)) == 0)
    except Exception:
        online = False

    return {
        "llm_online": online,
        "configured_endpoint": base_url,
        "configured_model": model_name,
        "active_mode": "LIVE_LOCAL_LLM" if online else "DETERMINISTIC_FALLBACK",
        "policy": "LLM is an explanation layer only. It receives minimized, secret-redacted evidence summaries and cannot invent telemetry or autonomously block traffic.",
    }

def validate_explanation_schema(payload: dict) -> bool:
    if not isinstance(payload, dict):
        return False
    if not REQUIRED_EXPLANATION_KEYS.issubset(set(payload.keys())):
        return False
    if not isinstance(payload.get("cited_ids"), list) or len(payload["cited_ids"]) == 0:
        return False
    if not isinstance(payload.get("recommended_next_steps"), list) or len(payload["recommended_next_steps"]) == 0:
        return False
    return True

def generate_incident_explanation(conn, incident_id: str) -> dict:
    cur = conn.cursor()
    cur.execute("SELECT * FROM Incident WHERE incident_id = ?", (incident_id,))
    inc_row = cur.fetchone()
    if not inc_row:
        raise ValueError(f"Incident {incident_id} not found.")
    inc = dict(inc_row)

    det_ids = json.loads(inc["detection_ids_json"])
    evt_ids = json.loads(inc["event_ids_json"])
    cited_ids = [incident_id] + det_ids + evt_ids
    if inc.get("attack_technique_id"):
        cited_ids.append(inc["attack_technique_id"])

    health = check_local_llm_health()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # Minimized, redacted evidence summary
    what_clean = redact_secrets(inc["what_observed"])
    where_clean = redact_secrets(inc["where_implicated"])
    why_clean = redact_secrets(inc["why_risky"])

    structured = None
    mode = "DETERMINISTIC_FALLBACK"
    model_used = "adonai-deterministic-explainer-v1.0"

    if health["llm_online"]:
        try:
            prompt = (
                "You are the ADONAI Local Security Analyst. Explain the following structured incident "
                "strictly from the provided evidence without inventing facts. Output JSON with keys: "
                f"{sorted(list(REQUIRED_EXPLANATION_KEYS))}.\n"
                f"Incident ID: {incident_id}\nEvidence Class: {inc['evidence_class']}\n"
                f"What: {what_clean}\nWhere: {where_clean}\nWhy: {why_clean}\nCited IDs: {cited_ids}"
            )
            req_data = json.dumps({
                "model": health["configured_model"],
                "prompt": prompt,
                "format": "json",
                "stream": False,
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{health['configured_endpoint'].rstrip('/')}/api/generate",
                data=req_data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                candidate = json.loads(body.get("response", "{}"))
                if validate_explanation_schema(candidate):
                    structured = candidate
                    mode = "LIVE_LOCAL_LLM"
                    model_used = health["configured_model"]
        except Exception:
            structured = None

    if structured is None:
        # Deterministic, schema-validated explanation fallback
        structured = {
            "incident_id": incident_id,
            "generation_mode": "DETERMINISTIC_FALLBACK",
            "model_name": model_used,
            "what_happened": what_clean,
            "where_implicated": where_clean,
            "why_flagged": f"{why_clean} (Severity: {inc['severity']}, Evidence Class: {inc['evidence_class']}).",
            "evidence_quality_statement": (
                f"Evidence is marked [{inc['evidence_class']}]. " + inc["uncertainty_note"]
            ),
            "recommended_next_steps": [
                inc["now_what_action"],
                "Review linked source event timestamps and detection rule provenance in the Evidence panel.",
                "Record analyst disposition (Confirmed Threat or False Positive) to refine local suppression rules.",
            ],
            "what_cannot_be_determined": (
                "ADONAI does not decrypt third-party TLS payloads or read private sandboxed app databases; "
                "conclusions are bounded strictly to the cited telemetry and indicator records."
            ),
            "cited_ids": cited_ids,
        }

    schema_ok = validate_explanation_schema(structured)
    summary_text = (
        f"[{mode}] WHAT: {structured['what_happened']} | "
        f"WHY: {structured['why_flagged']} | "
        f"EVIDENCE QUALITY: {structured['evidence_quality_statement']} | "
        f"NEXT STEP: {structured['recommended_next_steps'][0]} "
        f"(Cited: {', '.join(cited_ids)})"
    )

    exp_id = f"exp-{uuid.uuid4().hex[:12]}"
    conn.execute(
        """INSERT INTO LLMExplanation (
            explanation_id, incident_id, model_name, generation_mode,
            summary_text, structured_json, cited_ids_json, schema_valid,
            redaction_applied, environment, provenance, retention_policy,
            schema_version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 'llm_analyst_adapter', '90d_local', '1.0', ?, ?)""",
        (
            exp_id, incident_id, model_used, mode, summary_text,
            json.dumps(structured), json.dumps(cited_ids),
            1 if schema_ok else 0, inc["environment"], ts, ts
        ),
    )
    conn.commit()
    return {
        "explanation_id": exp_id,
        "incident_id": incident_id,
        "generation_mode": mode,
        "model_name": model_used,
        "schema_valid": schema_ok,
        "redaction_applied": True,
        "summary_text": summary_text,
        "structured": structured,
        "created_at": ts,
    }
