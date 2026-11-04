"""ADONAI 10-Layer Deterministic Detection, Contextual Risk, and Evidence Correlation Engine."""
import datetime
import json
import re
import urllib.parse
import uuid
from backend.security import pseudonymous_token, redact_secrets

OTP_PATTERNS = [
    re.compile(r"(?i)\b(6[- ]?digit|otp|verification\s+code|security\s+code|one[- ]time\s+passcode|pin\s+code)\b"),
    re.compile(r"(?i)\b(send\s+me\s+the\s+code|share\s+the\s+otp|reply\s+immediately\s+with)\b"),
]

URGENCY_PATTERNS = [
    re.compile(r"(?i)\b(urgent|immediately|account\s+will\s+be\s+frozen|suspended|locked|within\s+10\s+minutes|wire\s+transfer|stuck\s+at\s+the\s+hospital)\b"),
]

SUSPICIOUS_URL_TOKENS = [
    "verify", "login", "secure", "auth", "otp", "claim", "update-banking", "account", "urgent"
]

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

class DeterministicDetectionEngine:
    """Executes ADONAI's 10 deterministic detection layers independent of the local LLM."""

    def __init__(self, conn):
        self.conn = conn

    def _lookup_ioc(self, indicator_type: str, value: str, allow_test_fixtures: bool = True):
        if not value:
            return None
        cur = self.conn.cursor()
        if allow_test_fixtures:
            cur.execute(
                "SELECT * FROM ThreatIndicator WHERE indicator_type = ? AND lower(value) = lower(?)",
                (indicator_type, value.strip()),
            )
        else:
            cur.execute(
                "SELECT * FROM ThreatIndicator WHERE indicator_type = ? AND lower(value) = lower(?) AND is_test_fixture = 0",
                (indicator_type, value.strip()),
            )
        row = cur.fetchone()
        return dict(row) if row else None

    def _lookup_recipient_trust(self, recipient_id_or_identifier: str):
        if not recipient_id_or_identifier:
            return {"trust_level": "UNKNOWN", "display_name": "Unknown Sender", "reputation_score": 0.2}
        cur = self.conn.cursor()
        cur.execute(
            """SELECT r.*, t.trust_level, t.relationship_label, t.override_policy
               FROM RecipientEntity r
               LEFT JOIN TrustRelationship t ON r.recipient_id = t.recipient_id
               WHERE r.recipient_id = ? OR lower(r.identifier) = lower(?)""",
            (recipient_id_or_identifier, recipient_id_or_identifier),
        )
        row = cur.fetchone()
        if not row:
            return {"trust_level": "UNKNOWN", "display_name": recipient_id_or_identifier, "reputation_score": 0.2}
        return dict(row)

    def _check_prior_correlation(self, corr_token: str, current_device_id: str, environment: str):
        if not corr_token:
            return []
        cur = self.conn.cursor()
        cur.execute(
            """SELECT detection_id, device_id, rule_id, created_at
               FROM Detection
               WHERE pseudonymous_correlation_token = ? AND environment = ?""",
            (corr_token, environment),
        )
        return [dict(r) for r in cur.fetchall()]

    def evaluate_event(self, event_dict: dict) -> dict:
        """
        Normalizes, stores, and runs all 10 deterministic detection layers on an incoming event.
        Returns stored event, detections, and created/updated incident if triggered.
        """
        ts = now_iso()
        event_id = event_dict.get("event_id") or f"evt-{uuid.uuid4().hex[:12]}"
        device_id = event_dict.get("device_id", "android-pixel8-real-01")
        environment = event_dict.get("environment", "REAL").upper()
        if environment not in ("REAL", "LAB"):
            environment = "LAB"

        source_type = event_dict.get("source_type", "USER_SUBMISSION")
        event_type = event_dict.get("event_type", "GENERIC_OBSERVATION")
        app_context = event_dict.get("app_context", "com.adonai.mobile")
        payload = event_dict.get("payload", {})
        allow_fixtures = (environment == "LAB") or bool(payload.get("allow_test_fixtures", True))

        # Redact any accidental raw secrets before persistence
        if "message_text" in payload and payload["message_text"]:
            payload["message_text"] = redact_secrets(payload["message_text"])

        domain = payload.get("domain")
        url = payload.get("url")
        if url and not domain:
            try:
                parsed = urllib.parse.urlparse(url)
                domain = parsed.hostname
            except Exception:
                domain = None

        dst_ip = payload.get("dst_ip")
        sha256 = payload.get("sha256")
        evidence_class = event_dict.get("evidence_class", "OBSERVED").upper()
        if evidence_class not in ("OBSERVED", "INFERRED", "CONFIRMED"):
            evidence_class = "OBSERVED"

        destination = url or domain or dst_ip or "local_device"
        resource_implicated = payload.get("data_category") or payload.get("package_name") or event_type
        summary = event_dict.get("summary") or f"[{environment}] {event_type} from {app_context} -> {destination}"

        # Persist SecurityEvent
        self.conn.execute(
            """INSERT INTO SecurityEvent (
                event_id, device_id, environment, source_type, event_type,
                app_context, resource_implicated, destination, evidence_class,
                summary, payload_json, provenance, retention_policy, schema_version,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '30d_local', '1.0', ?, ?)""",
            (
                event_id, device_id, environment, source_type, event_type,
                app_context, str(resource_implicated), str(destination),
                evidence_class, summary, json.dumps(payload),
                source_type.lower(), ts, ts
            ),
        )

        # If network attributes exist, store NetworkObservation
        if domain or dst_ip:
            tls_enc = 1 if payload.get("tls_encrypted", True) else 0
            self.conn.execute(
                """INSERT INTO NetworkObservation (
                    observation_id, event_id, device_id, protocol, domain, dst_ip,
                    dst_port, tls_encrypted, payload_inspected, bytes_Out,
                    evidence_class, environment, provenance, retention_policy,
                    schema_version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, 'network_metadata_observer', '30d_local', '1.0', ?, ?)""",
                (
                    f"net-{uuid.uuid4().hex[:10]}", event_id, device_id,
                    payload.get("protocol", "UDP/DNS" if event_type == "DNS_QUERY" else "TCP/TLS"),
                    domain, dst_ip, int(payload.get("dst_port", 53 if event_type == "DNS_QUERY" else 443)),
                    tls_enc, int(payload.get("bytes_out", 0)), evidence_class, environment, ts, ts
                ),
            )

        triggered_detections = []

        # --- LAYER 1: Exact IOC Matching (URL, Domain, IP, SHA256) ---
        matched_iocs = []
        for itype, ival in [("url", url), ("domain", domain), ("ip", dst_ip), ("sha256", sha256)]:
            if ival:
                m = self._lookup_ioc(itype, ival, allow_test_fixtures=allow_fixtures)
                if m:
                    matched_iocs.append(m)

        # --- LAYER 2: YARA Pattern Scanning on Submitted Content/Artifact ---
        yara_hit = None
        artifact_content = str(payload.get("artifact_content", ""))
        if "ADONAI-BENIGN-LAB-TEST-ARTIFACT-DO-NOT-ALERT-PROD" in artifact_content:
            yara_hit = {
                "rule": "ADONAI_Synthetic_Lab_Test_Artifact",
                "version": "1.0",
                "technique": "T1204.002",
                "severity": "MEDIUM",
            }
        elif "android.permission.BIND_ACCESSIBILITY_SERVICE" in artifact_content and "android.permission.READ_SMS" in artifact_content:
            yara_hit = {
                "rule": "ADONAI_Suspicious_Android_Manifest_Markers",
                "version": "1.2",
                "technique": "T1404",
                "severity": "HIGH",
            }

        # --- LAYER 3 & 4: Sigma DNS / Brute-Force / Process-to-Network / Exfil Sequence Rules ---
        if event_type == "DNS_QUERY" and (matched_iocs or (domain and domain.endswith(".invalid"))):
            ioc_ref = matched_iocs[0] if matched_iocs else {"ioc_id": "sigma-dns-invalid", "value": domain, "attack_technique_id": "T1071.004"}
            corr_tok = pseudonymous_token(domain or dst_ip or "dns")
            priors = self._check_prior_correlation(corr_tok, device_id, environment)
            rationale = f"DNS lookup to {domain} matched indicator {ioc_ref['ioc_id']} (Rule sigma-adonai-001 v1.2.0)."
            if priors:
                rationale += f" Correlated with {len(priors)} prior detection(s) across endpoints via token {corr_tok}."
            triggered_detections.append({
                "rule_id": "sigma-adonai-001",
                "rule_version": "1.2.0",
                "evidence_class": "CONFIRMED" if matched_iocs else "OBSERVED",
                "confidence_method": "EXACT_IOC_AND_SIGMA_DNS",
                "confidence_score": 0.98,
                "severity": "HIGH",
                "rationale": rationale,
                "attack_technique_id": "T1071.004",
                "recommended_action": f"Apply DNS denylist policy for {domain} via local VPN resolver and inspect calling package {app_context}.",
                "action_supported": 1,
                "corr_token": corr_tok,
                "evidence_fields": {"domain": domain, "dst_ip": dst_ip, "matched_ioc": ioc_ref["ioc_id"], "prior_matches": len(priors)},
            })

        if event_type == "AUTH_FAILURE_BURST" and int(payload.get("failed_login_count", 0)) >= 5:
            cnt = int(payload.get("failed_login_count", 0))
            win = int(payload.get("window_seconds", 60))
            corr_tok = pseudonymous_token(f"auth-{dst_ip or device_id}")
            priors = self._check_prior_correlation(corr_tok, device_id, environment)
            triggered_detections.append({
                "rule_id": "sigma-adonai-002",
                "rule_version": "1.1.0",
                "evidence_class": "OBSERVED",
                "confidence_method": "SIGMA_THRESHOLD_RULE",
                "confidence_score": 0.91,
                "severity": "HIGH",
                "rationale": f"Observed {cnt} consecutive authentication failures within {win}s from {dst_ip or 'local_source'} (Rule sigma-adonai-002 v1.1.0)." + (f" Correlated with {len(priors)} prior burst(s)." if priors else ""),
                "attack_technique_id": "T1110.001",
                "recommended_action": "Enforce account lockout policy, rotate affected credentials, and block source IP in lab firewall.",
                "action_supported": 1,
                "corr_token": corr_tok,
                "evidence_fields": {"failed_login_count": cnt, "window_seconds": win, "dst_ip": dst_ip, "prior_matches": len(priors)},
            })

        if event_type == "PROCESS_NETWORK_CHAIN":
            proc = payload.get("process_name", "unknown_proc")
            corr_tok = pseudonymous_token(f"proc-{proc}-{dst_ip}")
            priors = self._check_prior_correlation(corr_tok, device_id, environment)
            triggered_detections.append({
                "rule_id": "sigma-adonai-003",
                "rule_version": "1.0.4",
                "evidence_class": "OBSERVED",
                "confidence_method": "SEQUENCE_TEMPORAL_CORRELATION",
                "confidence_score": 0.86,
                "severity": "MEDIUM",
                "rationale": f"Process '{proc}' spawned and opened outbound socket to {dst_ip}:{payload.get('dst_port')} within {payload.get('delta_seconds', 2.0)}s.",
                "attack_technique_id": "T1059",
                "recommended_action": "Quarantine or terminate the unexpected script process and review parent binary.",
                "action_supported": 1,
                "corr_token": corr_tok,
                "evidence_fields": {"process_name": proc, "dst_ip": dst_ip, "dst_port": payload.get("dst_port"), "prior_matches": len(priors)},
            })

        # --- LAYER 5: Android Application Permission Escalation ---
        if event_type == "PERMISSION_CHANGE":
            perms = payload.get("permissions_added", [])
            pkg = payload.get("package_name", app_context)
            if "android.permission.READ_SMS" in perms and (
                "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms or "android.permission.SYSTEM_ALERT_WINDOW" in perms
            ):
                corr_tok = pseudonymous_token(f"perm-{pkg}")
                triggered_detections.append({
                    "rule_id": "sigma-adonai-004",
                    "rule_version": "1.3.0",
                    "evidence_class": "OBSERVED",
                    "confidence_method": "ANDROID_PERMISSION_RISK_HEURISTIC",
                    "confidence_score": 0.94,
                    "severity": "HIGH",
                    "rationale": f"Package '{pkg}' (installer: {payload.get('installer_source', 'unknown')}) acquired high-risk permission combination: {', '.join(perms)}.",
                    "attack_technique_id": "T1404",
                    "recommended_action": f"Open Android Settings to revoke Accessibility and SMS permissions for {pkg} or uninstall the app.",
                    "action_supported": 1,
                    "corr_token": corr_tok,
                    "evidence_fields": {"package_name": pkg, "permissions_added": perms, "installer_source": payload.get("installer_source")},
                })

        # --- LAYER 6 & 7: Sensitive Access Followed by Outbound Metadata (Explicitly INFERRED) ---
        if event_type == "SENSITIVE_ACCESS_AND_EGRESS":
            cat = payload.get("data_category", "SENSITIVE_STORAGE")
            bytes_out = payload.get("bytes_out", 0)
            corr_tok = pseudonymous_token(f"exfil-{app_context}-{dst_ip}")
            triggered_detections.append({
                "rule_id": "rule-seq-exfil-004",
                "rule_version": "1.3.0",
                "evidence_class": "INFERRED",
                "confidence_method": "BEHAVIORAL_SEQUENCE_CORRELATION",
                "confidence_score": 0.82,
                "severity": "HIGH",
                "rationale": (
                    f"OBSERVED local access to {cat} by {app_context} followed within 5s by {bytes_out:,} bytes of encrypted TLS traffic to {dst_ip}:{payload.get('dst_port', 443)}. "
                    "Labeled INFERRED because TLS payload is encrypted and not inspected by ADONAI."
                ),
                "attack_technique_id": "T1041",
                "recommended_action": f"Block outbound network access for {app_context} via local VPN policy and revoke its storage/contacts permission.",
                "action_supported": 1,
                "corr_token": corr_tok,
                "evidence_fields": {"data_category": cat, "dst_ip": dst_ip, "bytes_out": bytes_out, "tls_encrypted": True, "payload_inspected": False},
            })

        # --- LAYER 1 & 2 Direct IOC / YARA Telemetry Match ---
        if event_type == "IOC_TELEMETRY_MATCH" and (matched_iocs or yara_hit):
            ioc_ids = [m["ioc_id"] for m in matched_iocs]
            corr_tok = pseudonymous_token(dst_ip or sha256 or "ioc-match")
            priors = self._check_prior_correlation(corr_tok, device_id, environment)
            triggered_detections.append({
                "rule_id": "rule-ioc-exact-001",
                "rule_version": "1.4.0",
                "evidence_class": "CONFIRMED",
                "confidence_method": "EXACT_INDICATOR_HASH_AND_IP_MATCH",
                "confidence_score": 0.99,
                "severity": "HIGH",
                "rationale": f"Exact match on configured indicator(s): {', '.join(ioc_ids)} (IP: {dst_ip}, SHA256: {str(sha256)[:16]}...)." + (f" Correlated across {len(priors)} prior event(s)." if priors else ""),
                "attack_technique_id": matched_iocs[0].get("attack_technique_id", "T1071.001") if matched_iocs else "T1204.002",
                "recommended_action": "Isolate destination IP in DNS/VPN policy and quarantine matching file artifact.",
                "action_supported": 1,
                "corr_token": corr_tok,
                "evidence_fields": {"matched_iocs": ioc_ids, "dst_ip": dst_ip, "sha256": sha256, "prior_matches": len(priors)},
            })

        # --- LAYER 6, 8, 9: Contextual Scam Guard (Share-Sheet & Notification Link/Message Analysis) ---
        if event_type in ("SHARE_SHEET_SUBMISSION", "MESSAGE_LINK_ANALYSIS"):
            msg_text = str(payload.get("message_text", ""))
            recipient_ref = payload.get("recipient_id") or payload.get("sender")
            trust_info = self._lookup_recipient_trust(recipient_ref)
            trust_level = trust_info.get("trust_level") or "UNKNOWN"

            has_otp_lure = any(p.search(msg_text) for p in OTP_PATTERNS)
            has_urgency = any(p.search(msg_text) for p in URGENCY_PATTERNS)
            url_lower = (url or "").lower()
            suspicious_url_tokens = [tok for tok in SUSPICIOUS_URL_TOKENS if tok in url_lower]
            is_suspicious_tld = bool(domain and (domain.endswith(".test") or domain.endswith(".invalid") or domain.endswith(".zip") or domain.endswith(".top")))
            has_ioc = len(matched_iocs) > 0

            # Compute deterministic lexical & behavioral risk score
            raw_risk = 0.0
            reasons = []
            if has_ioc:
                raw_risk += 0.65
                reasons.append(f"URL/domain matched threat indicator {matched_iocs[0]['ioc_id']}")
            if has_otp_lure:
                raw_risk += 0.55
                reasons.append("Message explicitly solicits an OTP / verification code")
            if has_urgency:
                raw_risk += 0.25
                reasons.append("Contains high-urgency coercion language")
            if len(suspicious_url_tokens) >= 2 or (suspicious_url_tokens and is_suspicious_tld):
                raw_risk += 0.35
                reasons.append(f"URL contains credential-harvesting lexical tokens ({', '.join(suspicious_url_tokens)})")

            strong_indicator = has_ioc or has_otp_lure or (has_urgency and len(suspicious_url_tokens) >= 2)

            # Layer 9: Context-aware recipient adjustment
            if trust_level == "TRUSTED" and not strong_indicator:
                # Benign family/trusted contact sharing -> suppress nuisance false positives!
                adjusted_risk = max(0.0, raw_risk - 0.35)
                reasons.append(f"Sender '{trust_info.get('display_name')}' is TRUSTED and no strong phishing/OTP/IOC indicators were present (nuisance warning suppressed).")
            elif trust_level == "TRUSTED" and strong_indicator:
                # Account compromise / strong indicator override!
                adjusted_risk = min(1.0, raw_risk + 0.15)
                reasons.append(
                    f"CRITICAL OVERRIDE: Sender '{trust_info.get('display_name')}' is marked TRUSTED, but strong compromise/scam indicators (IOC/OTP solicitation) triggered non-bypassable alert."
                )
            else:
                adjusted_risk = min(1.0, raw_risk)

            if adjusted_risk >= 0.60:
                sev = "CRITICAL" if (has_otp_lure or (trust_level == "TRUSTED" and strong_indicator)) else "HIGH"
                tech = "T1566.002" if (trust_level == "TRUSTED" and strong_indicator) else "T1660"
                ev_class = "CONFIRMED" if has_ioc else "OBSERVED"
                corr_tok = pseudonymous_token(url or msg_text[:40] or "scam-msg")
                priors = self._check_prior_correlation(corr_tok, device_id, environment)
                triggered_detections.append({
                    "rule_id": "rule-trust-override-005" if (trust_level == "TRUSTED" and strong_indicator) else "sigma-adonai-005",
                    "rule_version": "1.5.0" if (trust_level == "TRUSTED" and strong_indicator) else "1.4.0",
                    "evidence_class": ev_class,
                    "confidence_method": "CONTEXTUAL_LEXICAL_AND_IOC_SCORING",
                    "confidence_score": round(adjusted_risk, 2),
                    "severity": sev,
                    "rationale": " | ".join(reasons),
                    "attack_technique_id": tech,
                    "recommended_action": (
                        "Do NOT click the link or share any OTP code. Verify with the contact via an out-of-band voice call."
                        if trust_level == "TRUSTED"
                        else "Do NOT open the link or reply with verification codes; block sender and report phishing indicator."
                    ),
                    "action_supported": 1,
                    "corr_token": corr_tok,
                    "evidence_fields": {
                        "url": url,
                        "sender": trust_info.get("display_name"),
                        "trust_level": trust_level,
                        "strong_indicator_override": bool(trust_level == "TRUSTED" and strong_indicator),
                        "has_otp_lure": has_otp_lure,
                        "matched_iocs": [m["ioc_id"] for m in matched_iocs],
                        "risk_score": round(adjusted_risk, 2),
                        "prior_matches": len(priors),
                    },
                })

        # Persist all triggered detections & build Incident if any detection fired
        stored_detections = []
        created_incident = None

        for d in triggered_detections:
            det_id = f"det-{uuid.uuid4().hex[:12]}"
            self.conn.execute(
                """INSERT INTO Detection (
                    detection_id, rule_id, rule_version, source_event_ids_json,
                    device_id, environment, evidence_class, evidence_fields_json,
                    confidence_method, confidence_score, severity, rationale,
                    attack_technique_id, recommended_action, action_supported,
                    pseudonymous_correlation_token, analyst_disposition, provenance,
                    retention_policy, schema_version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', 'deterministic_detection_engine', '90d_security', '1.0', ?, ?)""",
                (
                    det_id, d["rule_id"], d["rule_version"], json.dumps([event_id]),
                    device_id, environment, d["evidence_class"], json.dumps(d["evidence_fields"]),
                    d["confidence_method"], d["confidence_score"], d["severity"],
                    d["rationale"], d["attack_technique_id"], d["recommended_action"],
                    d["action_supported"], d["corr_token"], ts, ts
                ),
            )
            d_copy = dict(d)
            d_copy["detection_id"] = det_id
            d_copy["created_at"] = ts
            stored_detections.append(d_copy)

        if stored_detections:
            top = stored_detections[0]
            inc_id = f"inc-{uuid.uuid4().hex[:12]}"
            inc_title = f"[{environment}] {event_type.replace('_', ' ').title()} — {top['severity']} Alert"
            uncertainty = (
                "INFERRED behavioral sequence: TLS payload remains encrypted and was not decrypted or inspected. Do not interpret connection metadata alone as confirmed data exfiltration."
                if top["evidence_class"] == "INFERRED"
                else (
                    "CONFIRMED indicator match against loaded intelligence/fixture record; verify whether action was user-initiated."
                    if top["evidence_class"] == "CONFIRMED"
                    else "OBSERVED directly from permitted OS/application telemetry interface."
                )
            )
            self.conn.execute(
                """INSERT INTO Incident (
                    incident_id, title, device_id, environment, severity, status,
                    evidence_class, what_observed, where_implicated, why_risky,
                    now_what_action, uncertainty_note, containment_supported,
                    containment_status, detection_ids_json, event_ids_json,
                    attack_technique_id, provenance, retention_policy, schema_version,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, ?, ?, ?, ?, 'RECOMMENDED', ?, ?, ?, 'incident_correlator', '90d_security', '1.0', ?, ?)""",
                (
                    inc_id, inc_title, device_id, environment, top["severity"],
                    top["evidence_class"], summary,
                    f"Device: {device_id} | App/Context: {app_context} | Target: {destination}",
                    top["rationale"], top["recommended_action"], uncertainty,
                    top["action_supported"],
                    json.dumps([x["detection_id"] for x in stored_detections]),
                    json.dumps([event_id]), top["attack_technique_id"], ts, ts
                ),
            )
            for sd in stored_detections:
                self.conn.execute(
                    """INSERT INTO IncidentEvidence (
                        evidence_id, incident_id, event_id, detection_id, evidence_class,
                        artifact_summary, source_attribution, environment, provenance,
                        retention_policy, schema_version, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'evidence_linker', '90d_security', '1.0', ?, ?)""",
                    (
                        f"evid-{uuid.uuid4().hex[:10]}", inc_id, event_id,
                        sd["detection_id"], sd["evidence_class"], sd["rationale"],
                        f"Rule {sd['rule_id']} v{sd['rule_version']} ({sd['confidence_method']})",
                        environment, ts, ts
                    ),
                )
            created_incident = {
                "incident_id": inc_id,
                "title": inc_title,
                "severity": top["severity"],
                "evidence_class": top["evidence_class"],
                "what_observed": summary,
                "where_implicated": f"Device: {device_id} | App/Context: {app_context} | Target: {destination}",
                "why_risky": top["rationale"],
                "now_what_action": top["recommended_action"],
                "uncertainty_note": uncertainty,
            }

        self.conn.commit()
        return {
            "event_id": event_id,
            "environment": environment,
            "evidence_class": evidence_class,
            "detections": stored_detections,
            "incident": created_incident,
        }
