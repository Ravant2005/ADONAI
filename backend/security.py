"""ADONAI Security, Pairing, Secret Redaction, Rate Limiting, and Audit Service."""
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import time
import uuid
from collections import defaultdict

SECRET_KEY = os.environ.get("ADONAI_SECRET_KEY", "adonai-local-pilot-hmac-key-do-not-expose-publicly")

# Rate limiter state: ip/token -> list of timestamps
_RATE_BUCKETS = defaultdict(list)
RATE_LIMIT_MAX_REQ = 180
RATE_LIMIT_WINDOW_SEC = 60.0

SECRET_PATTERNS = [
    (re.compile(r"(?i)(bearer\s+)[a-zA-Z0-9_\-\.]{12,}"), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(?i)(password|passwd|secret|api_key|apikey|access_token)\s*[:=]\s*['\"]?([^'\"\s,;]+)"), r"\1=[REDACTED_SECRET]"),
    (re.compile(r"\b(\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})\b"), "[REDACTED_CARD]"),
]

def redact_secrets(text: str) -> str:
    if not text:
        return ""
    out = str(text)
    for pat, repl in SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out

def check_rate_limit(client_key: str) -> bool:
    now = time.time()
    bucket = _RATE_BUCKETS[client_key]
    _RATE_BUCKETS[client_key] = [t for t in bucket if now - t < RATE_LIMIT_WINDOW_SEC]
    if len(_RATE_BUCKETS[client_key]) >= RATE_LIMIT_MAX_REQ:
        return False
    _RATE_BUCKETS[client_key].append(now)
    return True

def pseudonymous_token(indicator_value: str) -> str:
    """Generates a privacy-preserving HMAC-SHA256 pseudonymous correlation token."""
    digest = hmac.new(SECRET_KEY.encode("utf-8"), indicator_value.strip().lower().encode("utf-8"), hashlib.sha256).hexdigest()
    return f"pseudo-{digest[:16]}"

def log_audit(conn, actor: str, action: str, resource_type: str, resource_id: str, status: str, details: dict, environment: str = "REAL"):
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    aid = f"audit-{uuid.uuid4().hex[:12]}"
    conn.execute(
        """INSERT INTO AuditLog (
            audit_id, actor, action, resource_type, resource_id, status,
            details_json, environment, provenance, retention_policy,
            schema_version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'security_audit_service', '365d_audit', '1.0', ?, ?)""",
        (aid, actor, action, resource_type, resource_id, status, json.dumps(details), environment, ts, ts),
    )
    conn.commit()
    return aid

def create_pairing_challenge(conn, ttl_seconds: int = 300) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc)
    expires = now + datetime.timedelta(seconds=ttl_seconds)
    code = f"{secrets.randbelow(900000) + 100000}"
    pairing_id = f"pair-{uuid.uuid4().hex[:10]}"
    qr_payload = json.dumps({
        "product": "ADONAI",
        "pairing_id": pairing_id,
        "code": code,
        "host": "127.0.0.1:8410",
        "expires_at": expires.isoformat(),
    })
    conn.execute(
        """INSERT INTO DevicePairing (
            pairing_id, device_id, pairing_code, qr_payload, token_hash,
            status, expires_at, environment, provenance, retention_policy,
            schema_version, created_at, updated_at
        ) VALUES (?, NULL, ?, ?, NULL, 'PENDING', ?, 'REAL', 'pairing_service', '30d_audit', '1.0', ?, ?)""",
        (pairing_id, code, qr_payload, expires.isoformat(), now.isoformat(), now.isoformat()),
    )
    log_audit(conn, "mac_admin", "CREATE_PAIRING_CODE", "DevicePairing", pairing_id, "SUCCESS", {"expires_at": expires.isoformat()})
    return {
        "pairing_id": pairing_id,
        "pairing_code": code,
        "qr_payload": qr_payload,
        "status": "PENDING",
        "expires_at": expires.isoformat(),
    }

def complete_device_pairing(conn, pairing_code: str, device_id: str, device_name: str, os_version: str = "Android 15", api_level: int = 35) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc)
    cur = conn.cursor()
    cur.execute(
        "SELECT * FROM DevicePairing WHERE pairing_code = ? AND status = 'PENDING'",
        (pairing_code.strip(),),
    )
    row = cur.fetchone()
    if not row:
        log_audit(conn, device_id, "COMPLETE_PAIRING", "DevicePairing", pairing_code, "FAILED_INVALID_CODE", {})
        raise ValueError("Invalid or already used pairing code.")
    expires_at = datetime.datetime.fromisoformat(row["expires_at"])
    if now > expires_at:
        conn.execute("UPDATE DevicePairing SET status = 'EXPIRED', updated_at = ? WHERE pairing_id = ?", (now.isoformat(), row["pairing_id"]))
        conn.commit()
        raise ValueError("Pairing code has expired.")

    raw_token = f"adonai_tok_{secrets.token_urlsafe(24)}"
    tok_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    # Upsert device in REAL environment
    cur.execute("SELECT device_id FROM Device WHERE device_id = ?", (device_id,))
    if cur.fetchone():
        conn.execute(
            "UPDATE Device SET name = ?, os_version = ?, api_level = ?, status = 'PAIRED_ONLINE', last_seen_at = ?, updated_at = ? WHERE device_id = ?",
            (device_name, os_version, api_level, now.isoformat(), now.isoformat(), device_id),
        )
    else:
        conn.execute(
            """INSERT INTO Device (
                device_id, name, platform, os_version, api_level, environment,
                is_physical, status, last_seen_at, provenance, retention_policy,
                schema_version, created_at, updated_at
            ) VALUES (?, ?, 'Android', ?, ?, 'REAL', 1, 'PAIRED_ONLINE', ?, 'authenticated_lan_pairing', '90d_local', '1.0', ?, ?)""",
            (device_id, device_name, os_version, api_level, now.isoformat(), now.isoformat(), now.isoformat()),
        )

    conn.execute(
        """UPDATE DevicePairing
           SET device_id = ?, token_hash = ?, status = 'ACTIVE', updated_at = ?
           WHERE pairing_id = ?""",
        (device_id, tok_hash, now.isoformat(), row["pairing_id"]),
    )
    log_audit(conn, device_id, "COMPLETE_PAIRING", "DevicePairing", row["pairing_id"], "SUCCESS", {"device_name": device_name})
    return {
        "pairing_id": row["pairing_id"],
        "device_id": device_id,
        "device_name": device_name,
        "status": "ACTIVE",
        "auth_token": raw_token,
        "paired_at": now.isoformat(),
    }

def revoke_device_pairing(conn, device_id: str) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn.execute(
        "UPDATE DevicePairing SET status = 'REVOKED', revoked_at = ?, updated_at = ? WHERE device_id = ? AND status = 'ACTIVE'",
        (now, now, device_id),
    )
    conn.execute(
        "UPDATE Device SET status = 'REVOKED_OFFLINE', updated_at = ? WHERE device_id = ?",
        (now, device_id),
    )
    log_audit(conn, "user_or_admin", "REVOKE_DEVICE_PAIRING", "Device", device_id, "SUCCESS", {"revoked_at": now})
    return {"device_id": device_id, "status": "REVOKED_OFFLINE", "revoked_at": now}
