"""ADONAI Mac Intelligence Backend & Cyber-Range Orchestrator (FastAPI)."""
import asyncio
import base64
import datetime
import json
import os
import uuid
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.cyber_range import CyberRangeController
from backend.database import REQUIRED_TABLES, get_connection, init_db
from backend.detection_engine import DeterministicDetectionEngine
from backend.llm_analyst import check_local_llm_health, generate_incident_explanation
from backend.security import (
    check_rate_limit,
    complete_device_pairing,
    create_pairing_challenge,
    log_audit,
    revoke_device_pairing,
)

# Guardian imports (lazy — only fail at request time if modules not yet built)
def _get_guardian_modules():
    try:
        from backend.guardian_watermark import compute_content_hash, build_watermark_payload, verify_watermark_integrity
        from backend.guardian_blockchain import GuardianBlockchain
        from backend.guardian_detector import GuardianDetector
        from backend.guardian_web_intel import WebIntelEngine
        return compute_content_hash, build_watermark_payload, verify_watermark_integrity, GuardianBlockchain, GuardianDetector, WebIntelEngine
    except ImportError as e:
        raise HTTPException(status_code=503, detail=f"Guardian modules not yet installed: {e}")

ROOT_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_DIR = ROOT_DIR / "dashboard"

app = FastAPI(
    title="ADONAI Personal Cyber-Intelligence API",
    description="Local-first personal cyber-intelligence brain, deterministic detection engine, and 1,000-node 3D cyber-range.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8410", "http://localhost:8410"],
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

if (DASHBOARD_DIR / "static").exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR / "static")), name="static")

@app.on_event("startup")
def on_startup():
    init_db()

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    if not check_rate_limit(client_ip):
        return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Try again shortly."})
    return await call_next(request)

# Pydantic request models
class PairCompleteRequest(BaseModel):
    pairing_code: str
    device_id: str = "android-pixel8-real-01"
    device_name: str = "Pixel 8 Pro (ADONAI Agent)"
    os_version: str = "Android 15"
    api_level: int = 35

class ShareAnalyzeRequest(BaseModel):
    device_id: str = "android-pixel8-real-01"
    environment: str = "REAL"
    url: Optional[str] = None
    message_text: str = ""
    sender: Optional[str] = None
    app_context: str = "com.adonai.mobile.share"

class EventIngestRequest(BaseModel):
    device_id: str = "android-pixel8-real-01"
    environment: str = "REAL"
    source_type: str = "ANDROID_AGENT"
    event_type: str
    app_context: str = "com.adonai.mobile"
    evidence_class: str = "OBSERVED"
    summary: Optional[str] = None
    payload: dict = Field(default_factory=dict)

class ScenarioRunRequest(BaseModel):
    scenario_id: str
    target_endpoint_id: str = "sim-ep-0001"
    is_replay: bool = False

class RangeControlRequest(BaseModel):
    action: str  # PAUSE, RESUME, STOP, RESET

class FeedbackRequest(BaseModel):
    target_type: str = "INCIDENT"
    target_id: str
    disposition: str  # CONFIRMED_THREAT, FALSE_POSITIVE, BENIGN_EXPECTED, NEEDS_REVIEW
    comment: Optional[str] = None

class ConsentUpdateRequest(BaseModel):
    device_id: str = "android-pixel8-real-01"
    feature_key: str
    granted: bool

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    index_file = DASHBOARD_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(index_file.read_text())
    return HTMLResponse("<h1>ADONAI Dashboard Loading...</h1>")

@app.get("/mobile", response_class=HTMLResponse)
def serve_mobile_companion():
    mobile_file = DASHBOARD_DIR / "mobile.html"
    if mobile_file.exists():
        return HTMLResponse(mobile_file.read_text())
    return HTMLResponse("<h1>ADONAI Android Companion Simulator Loading...</h1>")

@app.get("/api/health")
def get_health():
    conn = get_connection()
    cur = conn.cursor()
    table_counts = {}
    for t in REQUIRED_TABLES:
        cur.execute(f"SELECT COUNT(*) as c FROM {t}")
        table_counts[t] = cur.fetchone()["c"]
    llm_health = check_local_llm_health()
    conn.close()
    return {
        "status": "HEALTHY",
        "product": "ADONAI",
        "version": "1.0.0-pilot",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "components": {
            "sqlite_database": {"status": "ONLINE", "required_tables_present": len(REQUIRED_TABLES), "table_counts": table_counts},
            "detection_engine": {"status": "ONLINE", "layers_active": 10, "deterministic": True},
            "local_llm_analyst": llm_health,
            "cyber_range": CyberRangeController.STATE,
            "network_exposure": "LOCALHOST_AND_PAIRED_LAN_ONLY",
        },
    }

@app.get("/api/overview")
def get_overview(environment: Optional[str] = None):
    conn = get_connection()
    cur = conn.cursor()
    env_filter = ""
    params = ()
    if environment and environment.upper() in ("REAL", "LAB"):
        env_filter = " WHERE environment = ?"
        params = (environment.upper(),)

    cur.execute(f"SELECT COUNT(*) as c FROM SecurityEvent{env_filter}", params)
    total_events = cur.fetchone()["c"]
    cur.execute(f"SELECT COUNT(*) as c FROM Detection{env_filter}", params)
    total_detections = cur.fetchone()["c"]
    cur.execute(f"SELECT COUNT(*) as c FROM Incident{env_filter}", params)
    total_incidents = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) as c FROM SecurityEvent WHERE environment = 'REAL'")
    real_events = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM SecurityEvent WHERE environment = 'LAB'")
    lab_events = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) as c FROM SimulatedEndpoint")
    sim_endpoints = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM SimulatedEndpoint WHERE status = 'ALERT'")
    alert_endpoints = cur.fetchone()["c"]

    cur.execute("SELECT COUNT(*) as c FROM ThreatSource WHERE status LIKE 'INGESTED%'")
    ingested_sources = cur.fetchone()["c"]
    cur.execute("SELECT COUNT(*) as c FROM ThreatSource")
    total_sources = cur.fetchone()["c"]

    cur.execute("SELECT * FROM EvaluationResult ORDER BY created_at DESC LIMIT 1")
    last_eval = cur.fetchone()

    conn.close()
    return {
        "product": "ADONAI",
        "filter_environment": environment or "ALL",
        "metrics": {
            "total_events": total_events,
            "real_device_events": real_events,
            "lab_simulation_events": lab_events,
            "total_detections": total_detections,
            "open_incidents": total_incidents,
            "registered_simulated_endpoints": sim_endpoints,
            "alerting_simulated_endpoints": alert_endpoints,
            "threat_sources_ingested": ingested_sources,
            "threat_sources_total": total_sources,
        },
        "latest_evaluation": dict(last_eval) if last_eval else None,
        "llm_status": check_local_llm_health(),
        "cyber_range_state": CyberRangeController.STATE,
    }

@app.get("/api/devices")
def list_devices():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM Device ORDER BY created_at DESC")
    devices = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM DevicePairing ORDER BY created_at DESC LIMIT 10")
    pairings = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM AppInventory ORDER BY risk_score DESC")
    apps = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM ConsentRecord ORDER BY consent_id ASC")
    consents = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {
        "devices": devices,
        "pairings": pairings,
        "android_app_inventory": apps,
        "consents": consents,
    }

@app.post("/api/pairing/create")
def api_create_pairing():
    conn = get_connection()
    try:
        res = create_pairing_challenge(conn)
        return res
    finally:
        conn.close()

@app.post("/api/pairing/complete")
def api_complete_pairing(req: PairCompleteRequest):
    conn = get_connection()
    try:
        return complete_device_pairing(conn, req.pairing_code, req.device_id, req.device_name, req.os_version, req.api_level)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()

@app.post("/api/pairing/revoke/{device_id}")
def api_revoke_pairing(device_id: str):
    conn = get_connection()
    try:
        return revoke_device_pairing(conn, device_id)
    finally:
        conn.close()

@app.get("/api/events")
def list_events(environment: Optional[str] = None, limit: int = 100):
    conn = get_connection()
    cur = conn.cursor()
    if environment and environment.upper() in ("REAL", "LAB"):
        cur.execute("SELECT * FROM SecurityEvent WHERE environment = ? ORDER BY created_at DESC LIMIT ?", (environment.upper(), limit))
    else:
        cur.execute("SELECT * FROM SecurityEvent ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {"events": rows, "count": len(rows)}

@app.post("/api/events/ingest")
def ingest_event(req: EventIngestRequest):
    conn = get_connection()
    try:
        engine = DeterministicDetectionEngine(conn)
        return engine.evaluate_event(req.dict())
    finally:
        conn.close()

@app.post("/api/analyze/share")
def analyze_shared_content(req: ShareAnalyzeRequest):
    conn = get_connection()
    try:
        engine = DeterministicDetectionEngine(conn)
        ev = {
            "device_id": req.device_id,
            "environment": req.environment,
            "source_type": "ANDROID_SHARE_SHEET",
            "event_type": "SHARE_SHEET_SUBMISSION" if req.url else "MESSAGE_LINK_ANALYSIS",
            "app_context": req.app_context,
            "evidence_class": "OBSERVED",
            "payload": {
                "url": req.url,
                "message_text": req.message_text,
                "sender": req.sender,
                "allow_test_fixtures": True,
            },
        }
        return engine.evaluate_event(ev)
    finally:
        conn.close()

@app.get("/api/incidents")
def list_incidents(environment: Optional[str] = None):
    conn = get_connection()
    cur = conn.cursor()
    if environment and environment.upper() in ("REAL", "LAB"):
        cur.execute("SELECT * FROM Incident WHERE environment = ? ORDER BY created_at DESC", (environment.upper(),))
    else:
        cur.execute("SELECT * FROM Incident ORDER BY created_at DESC")
    incidents = [dict(r) for r in cur.fetchall()]
    for inc in incidents:
        cur.execute("SELECT * FROM IncidentEvidence WHERE incident_id = ?", (inc["incident_id"],))
        inc["evidence_items"] = [dict(e) for e in cur.fetchall()]
        cur.execute("SELECT * FROM LLMExplanation WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1", (inc["incident_id"],))
        exp = cur.fetchone()
        inc["latest_explanation"] = dict(exp) if exp else None
    conn.close()
    return {"incidents": incidents}

@app.post("/api/incidents/{incident_id}/explain")
def explain_incident_api(incident_id: str):
    conn = get_connection()
    try:
        return generate_incident_explanation(conn, incident_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    finally:
        conn.close()

@app.post("/api/feedback")
def submit_feedback(req: FeedbackRequest):
    conn = get_connection()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    fid = f"fb-{uuid.uuid4().hex[:10]}"
    try:
        conn.execute(
            """INSERT INTO UserFeedback (
                feedback_id, target_type, target_id, disposition, comment,
                environment, provenance, retention_policy, schema_version,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'REAL', 'user_analyst_feedback', '180d_local', '1.0', ?, ?)""",
            (fid, req.target_type, req.target_id, req.disposition, req.comment, ts, ts),
        )
        if req.target_type.upper() == "INCIDENT":
            conn.execute("UPDATE Incident SET status = ?, updated_at = ? WHERE incident_id = ?", (req.disposition, ts, req.target_id))
        conn.commit()
        log_audit(conn, "user_analyst", "SUBMIT_DISPOSITION_FEEDBACK", req.target_type, req.target_id, "SUCCESS", {"disposition": req.disposition})
        return {"feedback_id": fid, "status": "RECORDED", "disposition": req.disposition}
    finally:
        conn.close()

@app.get("/api/threat-intel")
def get_threat_intel():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ThreatSource ORDER BY status ASC, name ASC")
    sources = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM ThreatIndicator WHERE is_test_fixture = 0 ORDER BY created_at DESC")
    prod_iocs = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM ThreatIndicator WHERE is_test_fixture = 1 ORDER BY created_at DESC")
    test_iocs = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM ThreatTechnique ORDER BY technique_id ASC")
    techniques = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM DetectionRule ORDER BY rule_id ASC")
    rules = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {
        "sources": sources,
        "production_iocs": prod_iocs,
        "test_fixtures": test_iocs,
        "attack_techniques": techniques,
        "detection_rules": rules,
    }

@app.get("/api/cyber-range/state")
def get_cyber_range_state():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM SimulatedEndpoint ORDER BY endpoint_id ASC")
    endpoints = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM SimulationScenario ORDER BY scenario_id ASC")
    scenarios = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM SimulationRun ORDER BY created_at DESC LIMIT 25")
    runs = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {
        "controller_state": CyberRangeController.STATE,
        "disclaimer": "1,000 nodes represent registered simulated endpoint identities in SQLite, not 1,000 full OS VMs.",
        "total_simulated_endpoints": len(endpoints),
        "endpoints": endpoints,
        "scenarios": scenarios,
        "recent_runs": runs,
    }

@app.get("/api/cyber-range/endpoints/{endpoint_id}")
def get_simulated_endpoint_detail(endpoint_id: str):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM SimulatedEndpoint WHERE endpoint_id = ?", (endpoint_id,))
    ep = cur.fetchone()
    if not ep:
        conn.close()
        raise HTTPException(status_code=404, detail="Simulated endpoint not found")
    cur.execute("SELECT * FROM SecurityEvent WHERE device_id = ? ORDER BY created_at DESC LIMIT 20", (endpoint_id,))
    events = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM Detection WHERE device_id = ? ORDER BY created_at DESC LIMIT 20", (endpoint_id,))
    detections = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {
        "endpoint": dict(ep),
        "events": events,
        "detections": detections,
    }

@app.post("/api/cyber-range/run")
def run_lab_scenario(req: ScenarioRunRequest):
    conn = get_connection()
    try:
        ctrl = CyberRangeController(conn)
        return ctrl.run_scenario(req.scenario_id, req.target_endpoint_id, req.is_replay)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()

@app.post("/api/cyber-range/control")
def control_lab_range(req: RangeControlRequest):
    conn = get_connection()
    try:
        ctrl = CyberRangeController(conn)
        return ctrl.control_range(req.action)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        conn.close()

@app.post("/api/cyber-range/evaluate")
def run_evaluation():
    conn = get_connection()
    try:
        ctrl = CyberRangeController(conn)
        return ctrl.run_full_evaluation_suite()
    finally:
        conn.close()

@app.get("/api/privacy-audit")
def get_privacy_and_audit():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM ConsentRecord ORDER BY consent_id ASC")
    consents = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM RecipientEntity r LEFT JOIN TrustRelationship t ON r.recipient_id = t.recipient_id")
    contacts = [dict(r) for r in cur.fetchall()]
    cur.execute("SELECT * FROM AuditLog ORDER BY created_at DESC LIMIT 50")
    audits = [dict(r) for r in cur.fetchall()]
    conn.close()
    return {
        "consents": consents,
        "trusted_contacts": contacts,
        "audit_logs": audits,
    }

@app.post("/api/privacy/consent")
def update_consent(req: ConsentUpdateRequest):
    conn = get_connection()
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        conn.execute(
            "UPDATE ConsentRecord SET granted = ?, revoked_at = ?, updated_at = ? WHERE device_id = ? AND feature_key = ?",
            (1 if req.granted else 0, None if req.granted else ts, ts, req.device_id, req.feature_key),
        )
        conn.commit()
        log_audit(conn, req.device_id, "UPDATE_CONSENT", "ConsentRecord", req.feature_key, "SUCCESS", {"granted": req.granted})
        return {"device_id": req.device_id, "feature_key": req.feature_key, "granted": req.granted, "updated_at": ts}
    finally:
        conn.close()

@app.delete("/api/privacy/purge-events")
def purge_local_telemetry(environment: str = "LAB"):
    conn = get_connection()
    env = environment.upper()
    if env not in ("REAL", "LAB"):
        conn.close()
        raise HTTPException(status_code=400, detail="Environment must be REAL or LAB")
    try:
        conn.execute("DELETE FROM SecurityEvent WHERE environment = ?", (env,))
        conn.execute("DELETE FROM NetworkObservation WHERE environment = ?", (env,))
        conn.execute("DELETE FROM DataAccessObservation WHERE environment = ?", (env,))
        conn.execute("DELETE FROM Detection WHERE environment = ?", (env,))
        conn.execute("DELETE FROM Incident WHERE environment = ?", (env,))
        conn.execute("DELETE FROM IncidentEvidence WHERE environment = ?", (env,))
        conn.commit()
        log_audit(conn, "user_privacy_control", "PURGE_TELEMETRY", "EnvironmentData", env, "SUCCESS", {"purged_environment": env})
        return {"status": "PURGED", "environment": env}
    finally:
        conn.close()

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute("SELECT * FROM SecurityEvent ORDER BY created_at DESC LIMIT 5")
            recent = [dict(r) for r in cur.fetchall()]
            conn.close()
            await websocket.send_json({"type": "HEARTBEAT_SYNC", "recent_events": recent})
            await asyncio.sleep(3.0)
    except WebSocketDisconnect:
        pass


# ===========================================================================
# ADONAI GUARDIAN — Media Authenticity & Fraud Detection API
# ===========================================================================

class GuardianRegisterRequest(BaseModel):
    device_id: str = "android-pixel8-real-01"
    media_type: str  # IMAGE, AUDIO, VIDEO, TEXT
    file_name: str = "media_file"
    file_size_bytes: int = 0
    content_b64: Optional[str] = None  # base64-encoded file bytes for watermarking
    capture_timestamp: Optional[str] = None
    context_text: str = ""  # any text context (e.g., WhatsApp message accompanying the media)

class GuardianVerifyRequest(BaseModel):
    device_id: str = "android-pixel8-real-01"
    media_type: str  # IMAGE, AUDIO, VIDEO, TEXT
    content_b64: Optional[str] = None  # base64-encoded file bytes
    content_hash: Optional[str] = None  # pre-computed SHA-256 (if bytes not sent)
    context_text: str = ""  # surrounding message/context for money risk analysis
    run_full_forensics: bool = True  # if False, stop at stage 2

class GuardianTextAnalyzeRequest(BaseModel):
    text: str
    context_text: str = ""
    device_id: str = "android-pixel8-real-01"


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


@app.post("/api/guardian/register-media")
def guardian_register_media(req: GuardianRegisterRequest):
    """Register a newly captured media file: embed watermark and anchor to local blockchain."""
    compute_content_hash, build_watermark_payload, verify_watermark_integrity, GuardianBlockchain, GuardianDetector, WebIntelEngine = _get_guardian_modules()

    import base64
    ts = _now_iso()
    media_id = f"grd-{uuid.uuid4().hex[:12]}"

    # Decode media bytes if provided
    media_bytes = base64.b64decode(req.content_b64) if req.content_b64 else b""
    content_hash = compute_content_hash(media_bytes) if media_bytes else f"hash-{uuid.uuid4().hex}"

    # Build watermark payload
    capture_ts_ms = int(datetime.datetime.now().timestamp() * 1000)
    wm_payload = build_watermark_payload(req.device_id, capture_ts_ms, content_hash)

    # Embed watermark (image/audio/video)
    watermark_embedded = False
    watermarked_b64 = None
    if media_bytes:
        try:
            from backend.guardian_watermark import embed_image_watermark, embed_audio_watermark, embed_video_watermark
            if req.media_type.upper() == "IMAGE":
                out_bytes = embed_image_watermark(media_bytes, wm_payload)
                watermark_embedded = True
                watermarked_b64 = base64.b64encode(out_bytes).decode()
            elif req.media_type.upper() == "AUDIO":
                out_bytes = embed_audio_watermark(media_bytes, wm_payload)
                watermark_embedded = True
                watermarked_b64 = base64.b64encode(out_bytes).decode()
            elif req.media_type.upper() == "VIDEO":
                out_bytes = embed_video_watermark(media_bytes, wm_payload, req.device_id)
                watermark_embedded = True
                watermarked_b64 = base64.b64encode(out_bytes).decode()
        except Exception:
            watermark_embedded = False

    # Register on local blockchain
    conn = get_connection()
    try:
        chain = GuardianBlockchain(conn)
        block_id = chain.register_media(
            media_hash=content_hash,
            device_id=req.device_id,
            media_type=req.media_type.upper(),
            watermark_payload=wm_payload,
            metadata={"file_name": req.file_name, "file_size_bytes": req.file_size_bytes, "context": req.context_text}
        )

        # Persist GuardianMediaRecord
        conn.execute(
            """INSERT OR REPLACE INTO GuardianMediaRecord (
                media_id, device_id, media_type, content_hash, watermark_payload,
                watermark_embedded, file_size_bytes, capture_timestamp, file_name,
                block_id, registration_status, provenance, retention_policy, schema_version,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'REGISTERED', 'guardian_camera_hook', '90d_local', '1.0', ?, ?)""",
            (media_id, req.device_id, req.media_type.upper(), content_hash, wm_payload,
             1 if watermark_embedded else 0, req.file_size_bytes,
             req.capture_timestamp or ts, req.file_name, block_id, ts, ts)
        )
        conn.commit()

        return {
            "media_id": media_id,
            "content_hash": content_hash,
            "block_id": block_id,
            "watermark_embedded": watermark_embedded,
            "watermarked_content_b64": watermarked_b64,
            "watermark_payload_preview": wm_payload[:80] + "..." if len(wm_payload) > 80 else wm_payload,
            "registration_status": "REGISTERED",
            "timestamp": ts,
            "message": "Media registered and anchored to ADONAI Guardian local blockchain."
        }
    finally:
        conn.close()


@app.post("/api/guardian/verify")
def guardian_verify_media(req: GuardianVerifyRequest):
    """
    Run the 3-stage Guardian verification pipeline on a media file.
    Stage 1: Watermark check + blockchain lookup
    Stage 2: Web intelligence cross-reference
    Stage 3: AI forensic deep analysis (if stages 1&2 fail)
    """
    import base64, time
    compute_content_hash, build_watermark_payload, verify_watermark_integrity, GuardianBlockchain, GuardianDetector, WebIntelEngine = _get_guardian_modules()

    t0 = time.time()
    ts = _now_iso()
    ver_id = f"ver-{uuid.uuid4().hex[:12]}"

    media_bytes = base64.b64decode(req.content_b64) if req.content_b64 else b""
    content_hash = req.content_hash or (compute_content_hash(media_bytes) if media_bytes else f"hash-unknown-{uuid.uuid4().hex[:8]}")
    media_type = req.media_type.upper()

    result = {
        "verification_id": ver_id,
        "content_hash": content_hash,
        "media_type": media_type,
        "stage_reached": 0,
        "overall_verdict": "PENDING",
        "stages": {}
    }

    conn = get_connection()
    try:
        # ---- STAGE 1: Watermark + Blockchain ----
        result["stage_reached"] = 1
        stage1 = {"name": "Cryptographic Authenticity", "passed": False, "details": {}}

        # Extract watermark
        wm_result = None
        blockchain_result = None

        if media_bytes:
            try:
                from backend.guardian_watermark import extract_image_watermark, extract_audio_watermark, extract_video_watermark
                if media_type == "IMAGE":
                    extracted = extract_image_watermark(media_bytes)
                elif media_type == "AUDIO":
                    extracted = extract_audio_watermark(media_bytes)
                elif media_type == "VIDEO":
                    extracted = extract_video_watermark(media_bytes)
                else:
                    extracted = None

                if extracted:
                    wm_result = verify_watermark_integrity(extracted, req.device_id, content_hash)
                    stage1["details"]["watermark"] = wm_result
            except Exception as e:
                stage1["details"]["watermark_error"] = str(e)

        # Blockchain lookup
        chain = GuardianBlockchain(conn)
        extracted_hash = (wm_result.get("details") or {}).get("payload_hash") if wm_result else None
        blockchain_result = chain.lookup_media(content_hash)
        if not blockchain_result and extracted_hash:
            blockchain_result = chain.lookup_media(extracted_hash)
        stage1["details"]["blockchain_found"] = bool(blockchain_result)
        if blockchain_result:
            stage1["details"]["blockchain_record"] = {
                "block_id": blockchain_result.get("block_id"),
                "block_index": blockchain_result.get("block_index"),
                "registered_at": blockchain_result.get("block_timestamp"),
                "device_id": blockchain_result.get("device_id"),
            }

        watermark_pass = bool(wm_result and wm_result.get("valid"))
        stage1["passed"] = watermark_pass and bool(blockchain_result)
        stage1["watermark_valid"] = watermark_pass
        result["stages"]["stage1"] = stage1

        if stage1["passed"]:
            result["overall_verdict"] = "VERIFIED_AUTHENTIC"
            result["overall_confidence"] = 0.97
            result["verdict_badge"] = "✅ VERIFIED AUTHENTIC"
            result["explanation"] = (
                "This media carries a valid ADONAI Guardian cryptographic watermark and is anchored "
                "to the local blockchain. It was captured unedited on a registered device. "
                "No AI generation or tampering detected."
            )
            result["money_risk_level"] = "LOW"
            _save_verification(conn, ver_id, content_hash, req.device_id, result, ts)
            return result

        # ---- STAGE 2: Web Intelligence ----
        result["stage_reached"] = 2
        stage2 = {"name": "Web Intelligence Cross-Reference", "passed": False, "details": {}}

        web_engine = WebIntelEngine()
        web_result = web_engine.cross_reference(
            content_hash=content_hash,
            media_type=media_type,
            context_text=req.context_text,
            extracted_text=""
        )
        stage2["corroboration_found"] = web_result.corroboration_found
        stage2["confidence"] = web_result.confidence
        stage2["sources_checked"] = web_result.sources_checked
        stage2["matching_sources"] = web_result.matching_sources
        stage2["scheme_detected"] = web_result.scheme_detected
        stage2["scheme_name"] = web_result.scheme_name
        stage2["money_warning"] = web_result.money_warning
        stage2["reason"] = web_result.reason
        stage2["passed"] = web_result.corroboration_found and not web_result.scheme_detected
        result["stages"]["stage2"] = stage2

        if stage2["passed"] and not stage2["scheme_detected"]:
            result["overall_verdict"] = "LIKELY_AUTHENTIC"
            result["overall_confidence"] = web_result.confidence
            result["verdict_badge"] = "⚠️ LIKELY AUTHENTIC (Web Corroborated)"
            result["explanation"] = web_result.reason
            result["money_risk_level"] = "MEDIUM" if web_result.money_warning else "LOW"
            if not req.run_full_forensics:
                _save_verification(conn, ver_id, content_hash, req.device_id, result, ts)
                return result

        # ---- STAGE 3: AI Forensic Deep Analysis ----
        if req.run_full_forensics:
            result["stage_reached"] = 3
            stage3 = {"name": "AI Forensic Deep Analysis", "passed": False, "details": {}}

            detector = GuardianDetector()
            forensic = detector.analyze_media(
                media_bytes=media_bytes,
                media_type=media_type,
                watermark_result=wm_result or {},
                context_text=req.context_text
            )

            stage3["ai_probability"] = forensic.ai_probability
            stage3["fake_possibility"] = forensic.fake_possibility
            stage3["verdict"] = forensic.verdict
            stage3["confidence"] = forensic.confidence
            stage3["reasons"] = forensic.reasons
            stage3["money_risk_level"] = forensic.money_risk_level
            stage3["money_context"] = forensic.money_context
            stage3["technical_breakdown"] = forensic.technical_breakdown
            stage3["ensemble_weights"] = forensic.ensemble_weights
            stage3["processing_time_ms"] = forensic.processing_time_ms
            result["stages"]["stage3"] = stage3

            # Persist forensic report
            report_id = f"rpt-{uuid.uuid4().hex[:12]}"
            conn.execute(
                """INSERT INTO GuardianForensicReport (
                    report_id, verification_id, media_type, ai_probability, fake_possibility,
                    verdict, confidence, money_risk_level, money_context, reasons_json,
                    technical_breakdown_json, ensemble_weights_json, processing_time_ms,
                    frequency_analysis_score, statistical_forensics_score,
                    watermark_detection_score, provenance_score, anomaly_score,
                    model_fingerprint_score, provenance, retention_policy, schema_version,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                          'guardian_forensic_engine', '90d_local', '1.0', ?, ?)""",
                (
                    report_id, ver_id, media_type,
                    forensic.ai_probability, forensic.fake_possibility,
                    forensic.verdict, forensic.confidence,
                    forensic.money_risk_level, json.dumps(forensic.money_context) if isinstance(forensic.money_context, dict) else (forensic.money_context or ""),
                    json.dumps(forensic.reasons),
                    json.dumps(forensic.technical_breakdown),
                    json.dumps(forensic.ensemble_weights),
                    forensic.processing_time_ms,
                    forensic.technical_breakdown.get("frequency_domain", 0.0) if isinstance(forensic.technical_breakdown.get("frequency_domain"), float) else forensic.technical_breakdown.get("frequency_domain", {}).get("score", 0.0),
                    forensic.technical_breakdown.get("statistical", forensic.technical_breakdown.get("statistical_forensics", 0.0)),
                    forensic.technical_breakdown.get("watermark", forensic.technical_breakdown.get("watermark_detection", 0.0)),
                    forensic.technical_breakdown.get("provenance", 0.0),
                    forensic.technical_breakdown.get("anomaly", forensic.technical_breakdown.get("anomaly_detection", 0.0)),
                    forensic.technical_breakdown.get("fingerprint", forensic.technical_breakdown.get("model_fingerprinting", 0.0)),
                    ts, ts
                )
            )

            # Determine final verdict
            if forensic.fake_possibility >= 0.8:
                result["overall_verdict"] = "ALMOST_CERTAINLY_FAKE"
                result["verdict_badge"] = "🚨 ALMOST CERTAINLY FAKE — HIGH FRAUD RISK"
            elif forensic.fake_possibility >= 0.6:
                result["overall_verdict"] = "LIKELY_AI_GENERATED"
                result["verdict_badge"] = "🔴 LIKELY AI-GENERATED / MANIPULATED"
            elif forensic.fake_possibility >= 0.3:
                result["overall_verdict"] = "UNCERTAIN"
                result["verdict_badge"] = "🟡 UNCERTAIN — Treat with Caution"
            else:
                result["overall_verdict"] = "LIKELY_AUTHENTIC"
                result["verdict_badge"] = "🟢 LIKELY AUTHENTIC (No Watermark)"

            if web_result.scheme_detected:
                result["overall_verdict"] = "FRAUD_SCHEME_DETECTED"
                result["verdict_badge"] = f"🚨 FRAUD SCHEME DETECTED: {web_result.scheme_name}"

            result["overall_confidence"] = forensic.confidence
            result["ai_probability_percent"] = round(forensic.ai_probability * 100, 1)
            result["fake_possibility_percent"] = round(forensic.fake_possibility * 100, 1)
            result["money_risk_level"] = forensic.money_risk_level
            # money_context may be a dict from the detector — convert to a readable summary string
            mc = forensic.money_context
            if isinstance(mc, dict):
                mc_parts = []
                if mc.get("money_detected"):
                    mc_parts.append(f"Financial amounts detected: {', '.join(str(a) for a in mc.get('amounts_found', [])[:3])}")
                if mc.get("urgency_keywords"):
                    mc_parts.append(f"Urgency triggers: {', '.join(mc['urgency_keywords'][:3])}")
                if mc.get("investment_keywords"):
                    mc_parts.append(f"Investment keywords: {', '.join(mc['investment_keywords'][:3])}")
                result["money_context"] = " | ".join(mc_parts) if mc_parts else ""
            else:
                result["money_context"] = mc or ""
            result["explanation"] = _build_explanation(forensic, web_result, stage1)
            result["why_it_could_be_fake"] = forensic.reasons

        result["processing_time_ms"] = round((time.time() - t0) * 1000, 1)
        _save_verification(conn, ver_id, content_hash, req.device_id, result, ts)
        return result
    finally:
        conn.close()


@app.post("/api/guardian/analyze-text")
def guardian_analyze_text(req: GuardianTextAnalyzeRequest):
    """Analyze text for AI generation, perplexity, and fraud patterns."""
    compute_content_hash, build_watermark_payload, verify_watermark_integrity, GuardianBlockchain, GuardianDetector, WebIntelEngine = _get_guardian_modules()

    detector = GuardianDetector()
    forensic = detector.analyze_text(req.text, req.context_text)
    web_engine = WebIntelEngine()
    web_result = web_engine.cross_reference("text", "TEXT", req.context_text, req.text)

    mc = forensic.money_context
    if isinstance(mc, dict):
        mc_parts = []
        if mc.get("money_detected"):
            mc_parts.append(f"Financial amounts detected: {', '.join(str(a) for a in mc.get('amounts_found', [])[:3])}")
        if mc.get("urgency_keywords"):
            mc_parts.append(f"Urgency triggers: {', '.join(mc['urgency_keywords'][:3])}")
        if mc.get("investment_keywords"):
            mc_parts.append(f"Investment keywords: {', '.join(mc['investment_keywords'][:3])}")
        mc_str = " | ".join(mc_parts) if mc_parts else ""
    else:
        mc_str = mc or ""

    return {
        "media_type": "TEXT",
        "ai_probability": forensic.ai_probability,
        "ai_probability_percent": round(forensic.ai_probability * 100, 1),
        "fake_possibility": forensic.fake_possibility,
        "fake_possibility_percent": round(forensic.fake_possibility * 100, 1),
        "verdict": forensic.verdict,
        "confidence": forensic.confidence,
        "money_risk_level": forensic.money_risk_level,
        "money_context": mc_str,
        "reasons": forensic.reasons,
        "technical_breakdown": forensic.technical_breakdown,
        "scheme_detected": web_result.scheme_detected,
        "scheme_name": web_result.scheme_name,
        "money_warning": web_result.money_warning,
    }


@app.get("/api/guardian/blockchain")
def guardian_blockchain_state():
    """Get local blockchain state and recent registrations."""
    compute_content_hash, build_watermark_payload, verify_watermark_integrity, GuardianBlockchain, GuardianDetector, WebIntelEngine = _get_guardian_modules()

    conn = get_connection()
    try:
        chain = GuardianBlockchain(conn)
        integrity = chain.verify_chain_integrity()
        recent = chain.get_recent_registrations(limit=20)
        return {
            "chain_integrity": integrity,
            "recent_registrations": recent,
        }
    finally:
        conn.close()


@app.get("/api/guardian/blockchain/lookup/{content_hash}")
def guardian_blockchain_lookup(content_hash: str):
    """Look up a media hash on the local blockchain."""
    compute_content_hash, build_watermark_payload, verify_watermark_integrity, GuardianBlockchain, GuardianDetector, WebIntelEngine = _get_guardian_modules()

    conn = get_connection()
    try:
        chain = GuardianBlockchain(conn)
        record = chain.lookup_media(content_hash)
        if not record:
            return {"found": False, "content_hash": content_hash}
        return {"found": True, "content_hash": content_hash, "record": record}
    finally:
        conn.close()


@app.get("/api/guardian/verdicts")
def guardian_verdicts(limit: int = 50, device_id: Optional[str] = None):
    """Get verification history."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        if device_id:
            cur.execute(
                "SELECT * FROM GuardianVerification WHERE device_id = ? ORDER BY created_at DESC LIMIT ?",
                (device_id, limit)
            )
        else:
            cur.execute("SELECT * FROM GuardianVerification ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        return {"verdicts": rows, "count": len(rows)}
    finally:
        conn.close()


@app.get("/api/guardian/media")
def guardian_media_registry(device_id: Optional[str] = None, limit: int = 50):
    """List registered media in Guardian vault."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        if device_id:
            cur.execute(
                "SELECT * FROM GuardianMediaRecord WHERE device_id = ? ORDER BY created_at DESC LIMIT ?",
                (device_id, limit)
            )
        else:
            cur.execute("SELECT * FROM GuardianMediaRecord ORDER BY created_at DESC LIMIT ?", (limit,))
        rows = [dict(r) for r in cur.fetchall()]
        return {"media_records": rows, "count": len(rows)}
    finally:
        conn.close()


def _save_verification(conn, ver_id, content_hash, device_id, result, ts):
    """Persist verification result to GuardianVerification table."""
    stages = result.get("stages", {})
    s1 = stages.get("stage1", {})
    s2 = stages.get("stage2", {})
    s3 = stages.get("stage3", {})
    try:
        conn.execute(
            """INSERT OR REPLACE INTO GuardianVerification (
                verification_id, content_hash, device_id, stage_reached,
                stage1_watermark_pass, stage1_blockchain_found, stage1_result,
                stage2_web_checked, stage2_corroboration_found, stage2_scheme_detected, stage2_result,
                stage3_forensic_run, stage3_ai_probability, stage3_fake_possibility, stage3_verdict,
                overall_verdict, overall_confidence, money_risk_level, money_context,
                explanation_summary, full_report_json,
                provenance, retention_policy, schema_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                      'guardian_verification_engine', '90d_local', '1.0', ?, ?)""",
            (
                ver_id, content_hash, device_id, result.get("stage_reached", 0),
                1 if s1.get("watermark_valid") else 0,
                1 if s1.get("details", {}).get("blockchain_found") else 0,
                json.dumps(s1),
                1 if s2 else 0,
                1 if s2.get("corroboration_found") else 0,
                1 if s2.get("scheme_detected") else 0,
                json.dumps(s2),
                1 if s3 else 0,
                s3.get("ai_probability"), s3.get("fake_possibility"), s3.get("verdict"),
                result.get("overall_verdict", "PENDING"),
                result.get("overall_confidence"),
                result.get("money_risk_level"),
                result.get("money_context"),
                result.get("explanation", "")[:500],
                json.dumps(result),
                ts, ts
            )
        )
        conn.commit()
    except Exception:
        pass


def _build_explanation(forensic, web_result, stage1) -> str:
    parts = []
    if not stage1.get("passed"):
        parts.append("⚠️ No valid ADONAI watermark found — this file was NOT captured by a Guardian-registered camera.")
    if web_result.scheme_detected:
        parts.append(f"🚨 FRAUD SCHEME MATCH: This content matches the pattern of '{web_result.scheme_name}' fraud.")
    if web_result.money_warning:
        parts.append(f"💰 MONEY RISK: {web_result.money_warning}")
    parts.append(f"AI Generation Probability: {round(forensic.ai_probability * 100)}%")
    parts.append(f"Fake Possibility: {round(forensic.fake_possibility * 100)}%")
    if forensic.reasons:
        parts.append("Why it could be fake: " + "; ".join(forensic.reasons[:3]))
    return " | ".join(parts)
