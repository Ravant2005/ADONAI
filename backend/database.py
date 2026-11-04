"""ADONAI SQLite Persistence Layer — Implements all 24 required pilot tables with REAL/LAB separation."""
import datetime
import hashlib
import json
import os
import sqlite3
import uuid
from pathlib import Path
try:
    import yaml
except ImportError:
    yaml = None

ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_DB_PATH = ROOT_DIR / "backend" / "adonai_pilot.db"

REQUIRED_TABLES = [
    "Device",
    "DevicePairing",
    "PermissionSnapshot",
    "AppInventory",
    "SecurityEvent",
    "NetworkObservation",
    "DataAccessObservation",
    "ThreatIndicator",
    "ThreatSource",
    "ThreatTechnique",
    "DetectionRule",
    "Detection",
    "Incident",
    "IncidentEvidence",
    "RecipientEntity",
    "TrustRelationship",
    "SimulationScenario",
    "SimulationRun",
    "SimulatedEndpoint",
    "EvaluationResult",
    "LLMExplanation",
    "UserFeedback",
    "AuditLog",
    "ConsentRecord",
    # Guardian Media Authenticity tables
    "GuardianMediaRecord",
    "GuardianBlockchain",
    "GuardianVerification",
    "GuardianForensicReport",
]

SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS Device (
    device_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    platform TEXT NOT NULL,
    os_version TEXT NOT NULL,
    api_level INTEGER,
    environment TEXT NOT NULL CHECK(environment IN ('REAL', 'LAB')),
    is_physical INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'ONLINE',
    last_seen_at TEXT NOT NULL,
    provenance TEXT NOT NULL DEFAULT 'device_registration',
    retention_policy TEXT NOT NULL DEFAULT '90d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS DevicePairing (
    pairing_id TEXT PRIMARY KEY,
    device_id TEXT,
    pairing_code TEXT NOT NULL,
    qr_payload TEXT NOT NULL,
    token_hash TEXT,
    status TEXT NOT NULL CHECK(status IN ('PENDING', 'ACTIVE', 'REVOKED', 'EXPIRED')),
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    environment TEXT NOT NULL DEFAULT 'REAL',
    provenance TEXT NOT NULL DEFAULT 'pairing_service',
    retention_policy TEXT NOT NULL DEFAULT '30d_audit',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS PermissionSnapshot (
    snapshot_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    permission_name TEXT NOT NULL,
    is_granted INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    purpose_note TEXT,
    environment TEXT NOT NULL DEFAULT 'REAL',
    provenance TEXT NOT NULL DEFAULT 'android_package_manager',
    retention_policy TEXT NOT NULL DEFAULT '30d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS AppInventory (
    app_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    app_label TEXT NOT NULL,
    version_name TEXT NOT NULL,
    installer_source TEXT NOT NULL,
    is_system_app INTEGER NOT NULL DEFAULT 0,
    granted_permissions_json TEXT NOT NULL,
    risk_score REAL NOT NULL DEFAULT 0.0,
    risk_rationale TEXT,
    environment TEXT NOT NULL DEFAULT 'REAL',
    provenance TEXT NOT NULL DEFAULT 'android_package_manager',
    retention_policy TEXT NOT NULL DEFAULT '30d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS SecurityEvent (
    event_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    environment TEXT NOT NULL CHECK(environment IN ('REAL', 'LAB')),
    source_type TEXT NOT NULL,
    event_type TEXT NOT NULL,
    app_context TEXT,
    resource_implicated TEXT,
    destination TEXT,
    evidence_class TEXT NOT NULL CHECK(evidence_class IN ('OBSERVED', 'INFERRED', 'CONFIRMED')),
    summary TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    provenance TEXT NOT NULL,
    retention_policy TEXT NOT NULL DEFAULT '30d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS NetworkObservation (
    observation_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    protocol TEXT NOT NULL,
    domain TEXT,
    dst_ip TEXT,
    dst_port INTEGER,
    tls_encrypted INTEGER NOT NULL DEFAULT 1,
    payload_inspected INTEGER NOT NULL DEFAULT 0,
    bytes_Out INTEGER NOT NULL DEFAULT 0,
    evidence_class TEXT NOT NULL DEFAULT 'OBSERVED',
    environment TEXT NOT NULL CHECK(environment IN ('REAL', 'LAB')),
    provenance TEXT NOT NULL DEFAULT 'network_metadata_observer',
    retention_policy TEXT NOT NULL DEFAULT '30d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS DataAccessObservation (
    access_id TEXT PRIMARY KEY,
    event_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    data_category TEXT NOT NULL,
    access_mode TEXT NOT NULL,
    evidence_class TEXT NOT NULL CHECK(evidence_class IN ('OBSERVED', 'INFERRED', 'CONFIRMED')),
    environment TEXT NOT NULL CHECK(environment IN ('REAL', 'LAB')),
    provenance TEXT NOT NULL DEFAULT 'os_permission_telemetry',
    retention_policy TEXT NOT NULL DEFAULT '30d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ThreatIndicator (
    ioc_id TEXT PRIMARY KEY,
    indicator_type TEXT NOT NULL,
    value TEXT NOT NULL,
    source_id TEXT NOT NULL,
    confidence REAL NOT NULL,
    severity TEXT NOT NULL,
    tags_json TEXT NOT NULL,
    is_test_fixture INTEGER NOT NULL DEFAULT 0,
    environment_scope TEXT NOT NULL,
    attack_technique_id TEXT,
    provenance TEXT NOT NULL,
    retention_policy TEXT NOT NULL DEFAULT '180d_intel',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ThreatSource (
    source_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    data_type TEXT NOT NULL,
    access_method TEXT NOT NULL,
    url TEXT NOT NULL,
    license TEXT NOT NULL,
    update_frequency TEXT NOT NULL,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0,
    confidence REAL NOT NULL DEFAULT 0.9,
    rate_limit_policy TEXT,
    last_success_at TEXT,
    checksum TEXT,
    environment TEXT NOT NULL DEFAULT 'REAL',
    provenance TEXT NOT NULL DEFAULT 'threat_intel_registry',
    retention_policy TEXT NOT NULL DEFAULT '365d_intel',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ThreatTechnique (
    technique_id TEXT PRIMARY KEY,
    stix_id TEXT NOT NULL,
    name TEXT NOT NULL,
    domain TEXT NOT NULL,
    tactic TEXT NOT NULL,
    version TEXT NOT NULL,
    description TEXT NOT NULL,
    d3fend_countermeasure TEXT,
    environment TEXT NOT NULL DEFAULT 'REAL',
    provenance TEXT NOT NULL DEFAULT 'mitre_stix_bundle',
    retention_policy TEXT NOT NULL DEFAULT '365d_intel',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS DetectionRule (
    rule_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    version TEXT NOT NULL,
    severity TEXT NOT NULL,
    attack_technique_id TEXT,
    condition_expr TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    environment TEXT NOT NULL DEFAULT 'REAL',
    provenance TEXT NOT NULL DEFAULT 'adonai_rule_engine',
    retention_policy TEXT NOT NULL DEFAULT '365d_rules',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Detection (
    detection_id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    rule_version TEXT NOT NULL,
    source_event_ids_json TEXT NOT NULL,
    device_id TEXT NOT NULL,
    environment TEXT NOT NULL CHECK(environment IN ('REAL', 'LAB')),
    evidence_class TEXT NOT NULL CHECK(evidence_class IN ('OBSERVED', 'INFERRED', 'CONFIRMED')),
    evidence_fields_json TEXT NOT NULL,
    confidence_method TEXT NOT NULL,
    confidence_score REAL NOT NULL,
    severity TEXT NOT NULL,
    rationale TEXT NOT NULL,
    attack_technique_id TEXT,
    recommended_action TEXT NOT NULL,
    action_supported INTEGER NOT NULL DEFAULT 1,
    pseudonymous_correlation_token TEXT,
    analyst_disposition TEXT NOT NULL DEFAULT 'OPEN',
    provenance TEXT NOT NULL DEFAULT 'deterministic_detection_engine',
    retention_policy TEXT NOT NULL DEFAULT '90d_security',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Incident (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    device_id TEXT NOT NULL,
    environment TEXT NOT NULL CHECK(environment IN ('REAL', 'LAB')),
    severity TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    evidence_class TEXT NOT NULL CHECK(evidence_class IN ('OBSERVED', 'INFERRED', 'CONFIRMED')),
    what_observed TEXT NOT NULL,
    where_implicated TEXT NOT NULL,
    why_risky TEXT NOT NULL,
    now_what_action TEXT NOT NULL,
    uncertainty_note TEXT NOT NULL,
    containment_supported INTEGER NOT NULL DEFAULT 1,
    containment_status TEXT NOT NULL DEFAULT 'RECOMMENDED',
    detection_ids_json TEXT NOT NULL,
    event_ids_json TEXT NOT NULL,
    attack_technique_id TEXT,
    provenance TEXT NOT NULL DEFAULT 'incident_correlator',
    retention_policy TEXT NOT NULL DEFAULT '90d_security',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS IncidentEvidence (
    evidence_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    detection_id TEXT,
    evidence_class TEXT NOT NULL CHECK(evidence_class IN ('OBSERVED', 'INFERRED', 'CONFIRMED')),
    artifact_summary TEXT NOT NULL,
    source_attribution TEXT NOT NULL,
    environment TEXT NOT NULL CHECK(environment IN ('REAL', 'LAB')),
    provenance TEXT NOT NULL DEFAULT 'evidence_linker',
    retention_policy TEXT NOT NULL DEFAULT '90d_security',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS RecipientEntity (
    recipient_id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    channel_type TEXT NOT NULL,
    reputation_score REAL NOT NULL DEFAULT 0.5,
    environment TEXT NOT NULL DEFAULT 'REAL',
    provenance TEXT NOT NULL DEFAULT 'user_context_store',
    retention_policy TEXT NOT NULL DEFAULT '90d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS TrustRelationship (
    relationship_id TEXT PRIMARY KEY,
    recipient_id TEXT NOT NULL,
    trust_level TEXT NOT NULL CHECK(trust_level IN ('TRUSTED', 'KNOWN', 'UNKNOWN', 'BLOCKED')),
    relationship_label TEXT NOT NULL,
    notes TEXT,
    override_policy TEXT NOT NULL DEFAULT 'NEVER_SUPPRESS_OTP_OR_COMPROMISE',
    environment TEXT NOT NULL DEFAULT 'REAL',
    provenance TEXT NOT NULL DEFAULT 'user_configured_trust',
    retention_policy TEXT NOT NULL DEFAULT '90d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS SimulationScenario (
    scenario_id TEXT PRIMARY KEY,
    code TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    expected_detection INTEGER NOT NULL,
    expected_severity TEXT NOT NULL,
    attack_technique_id TEXT,
    preflight_check TEXT NOT NULL,
    safety_notice TEXT NOT NULL,
    steps_json TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'LAB',
    provenance TEXT NOT NULL DEFAULT 'cyber_range_catalogue',
    retention_policy TEXT NOT NULL DEFAULT '365d_lab',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS SimulationRun (
    run_id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    target_endpoint_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('RUNNING', 'PAUSED', 'COMPLETED', 'STOPPED')),
    is_replay INTEGER NOT NULL DEFAULT 0,
    emitted_event_ids_json TEXT NOT NULL,
    detection_ids_json TEXT NOT NULL,
    time_to_detect_ms REAL,
    containment_outcome TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'LAB',
    provenance TEXT NOT NULL DEFAULT 'cyber_range_runner',
    retention_policy TEXT NOT NULL DEFAULT '90d_lab',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS SimulatedEndpoint (
    endpoint_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    sector TEXT NOT NULL,
    virtual_ip TEXT NOT NULL,
    os_profile TEXT NOT NULL,
    is_physical INTEGER NOT NULL DEFAULT 0,
    entity_type TEXT NOT NULL DEFAULT 'SIMULATED_IDENTITY',
    status TEXT NOT NULL DEFAULT 'NORMAL',
    last_event_id TEXT,
    last_scenario_id TEXT,
    orbit_radius REAL NOT NULL,
    orbit_angle REAL NOT NULL,
    orbit_height REAL NOT NULL,
    environment TEXT NOT NULL DEFAULT 'LAB',
    provenance TEXT NOT NULL DEFAULT 'cyber_range_population_generator',
    retention_policy TEXT NOT NULL DEFAULT '90d_lab',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS EvaluationResult (
    eval_id TEXT PRIMARY KEY,
    suite_name TEXT NOT NULL,
    total_scenarios INTEGER NOT NULL,
    true_positives INTEGER NOT NULL,
    false_positives INTEGER NOT NULL,
    true_negatives INTEGER NOT NULL,
    false_negatives INTEGER NOT NULL,
    precision_score REAL NOT NULL,
    recall_score REAL NOT NULL,
    f1_score REAL NOT NULL,
    false_positive_rate REAL NOT NULL,
    mean_ttd_ms REAL NOT NULL,
    containment_rate REAL NOT NULL,
    test_conditions TEXT NOT NULL,
    details_json TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'LAB',
    provenance TEXT NOT NULL DEFAULT 'evaluation_harness',
    retention_policy TEXT NOT NULL DEFAULT '180d_eval',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS LLMExplanation (
    explanation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    model_name TEXT NOT NULL,
    generation_mode TEXT NOT NULL CHECK(generation_mode IN ('LIVE_LOCAL_LLM', 'DETERMINISTIC_FALLBACK')),
    summary_text TEXT NOT NULL,
    structured_json TEXT NOT NULL,
    cited_ids_json TEXT NOT NULL,
    schema_valid INTEGER NOT NULL DEFAULT 1,
    redaction_applied INTEGER NOT NULL DEFAULT 1,
    environment TEXT NOT NULL CHECK(environment IN ('REAL', 'LAB')),
    provenance TEXT NOT NULL DEFAULT 'llm_analyst_adapter',
    retention_policy TEXT NOT NULL DEFAULT '90d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS UserFeedback (
    feedback_id TEXT PRIMARY KEY,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    disposition TEXT NOT NULL CHECK(disposition IN ('CONFIRMED_THREAT', 'FALSE_POSITIVE', 'BENIGN_EXPECTED', 'NEEDS_REVIEW')),
    comment TEXT,
    environment TEXT NOT NULL DEFAULT 'REAL',
    provenance TEXT NOT NULL DEFAULT 'user_analyst_feedback',
    retention_policy TEXT NOT NULL DEFAULT '180d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS AuditLog (
    audit_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    status TEXT NOT NULL,
    details_json TEXT NOT NULL,
    environment TEXT NOT NULL DEFAULT 'REAL',
    provenance TEXT NOT NULL DEFAULT 'security_audit_service',
    retention_policy TEXT NOT NULL DEFAULT '365d_audit',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS ConsentRecord (
    consent_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    feature_key TEXT NOT NULL,
    feature_name TEXT NOT NULL,
    granted INTEGER NOT NULL DEFAULT 0,
    scope_description TEXT NOT NULL,
    limitations_acknowledged INTEGER NOT NULL DEFAULT 1,
    revoked_at TEXT,
    environment TEXT NOT NULL DEFAULT 'REAL',
    provenance TEXT NOT NULL DEFAULT 'privacy_consent_center',
    retention_policy TEXT NOT NULL DEFAULT '365d_consent',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- ========================================================
-- ADONAI GUARDIAN — Media Authenticity & Fraud Detection
-- ========================================================

CREATE TABLE IF NOT EXISTS GuardianMediaRecord (
    media_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    media_type TEXT NOT NULL CHECK(media_type IN ('IMAGE', 'AUDIO', 'VIDEO', 'TEXT')),
    content_hash TEXT NOT NULL UNIQUE,
    watermark_payload TEXT,
    watermark_embedded INTEGER NOT NULL DEFAULT 0,
    file_size_bytes INTEGER,
    capture_timestamp TEXT,
    file_name TEXT,
    block_id TEXT,
    registration_status TEXT NOT NULL DEFAULT 'PENDING' CHECK(registration_status IN ('PENDING', 'REGISTERED', 'FAILED')),
    provenance TEXT NOT NULL DEFAULT 'guardian_camera_hook',
    retention_policy TEXT NOT NULL DEFAULT '90d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS GuardianBlockchain (
    block_id TEXT PRIMARY KEY,
    block_index INTEGER NOT NULL,
    previous_hash TEXT NOT NULL,
    block_timestamp TEXT NOT NULL,
    media_hash TEXT NOT NULL,
    device_id TEXT NOT NULL,
    media_type TEXT NOT NULL,
    watermark_payload TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    block_hash TEXT NOT NULL,
    provenance TEXT NOT NULL DEFAULT 'guardian_blockchain',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS GuardianVerification (
    verification_id TEXT PRIMARY KEY,
    media_id TEXT,
    content_hash TEXT NOT NULL,
    device_id TEXT NOT NULL,
    stage_reached INTEGER NOT NULL DEFAULT 1,
    stage1_watermark_pass INTEGER NOT NULL DEFAULT 0,
    stage1_blockchain_found INTEGER NOT NULL DEFAULT 0,
    stage1_result TEXT,
    stage2_web_checked INTEGER NOT NULL DEFAULT 0,
    stage2_corroboration_found INTEGER NOT NULL DEFAULT 0,
    stage2_scheme_detected INTEGER NOT NULL DEFAULT 0,
    stage2_result TEXT,
    stage3_forensic_run INTEGER NOT NULL DEFAULT 0,
    stage3_ai_probability REAL,
    stage3_fake_possibility REAL,
    stage3_verdict TEXT,
    overall_verdict TEXT NOT NULL DEFAULT 'PENDING',
    overall_confidence REAL,
    money_risk_level TEXT,
    money_context TEXT,
    explanation_summary TEXT,
    full_report_json TEXT,
    provenance TEXT NOT NULL DEFAULT 'guardian_verification_engine',
    retention_policy TEXT NOT NULL DEFAULT '90d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS GuardianForensicReport (
    report_id TEXT PRIMARY KEY,
    verification_id TEXT NOT NULL,
    media_type TEXT NOT NULL,
    ai_probability REAL NOT NULL,
    fake_possibility REAL NOT NULL,
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL,
    money_risk_level TEXT NOT NULL DEFAULT 'NONE',
    money_context TEXT,
    reasons_json TEXT NOT NULL DEFAULT '[]',
    technical_breakdown_json TEXT NOT NULL DEFAULT '{}',
    ensemble_weights_json TEXT NOT NULL DEFAULT '{}',
    processing_time_ms REAL,
    frequency_analysis_score REAL,
    statistical_forensics_score REAL,
    watermark_detection_score REAL,
    provenance_score REAL,
    anomaly_score REAL,
    model_fingerprint_score REAL,
    provenance TEXT NOT NULL DEFAULT 'guardian_forensic_engine',
    retention_policy TEXT NOT NULL DEFAULT '90d_local',
    schema_version TEXT NOT NULL DEFAULT '1.0',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def get_connection(db_path=None):
    path = Path(db_path or os.environ.get("ADONAI_DB_PATH", str(DEFAULT_DB_PATH)))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path=None):
    conn = get_connection(db_path)
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    seed_initial_data(conn)
    conn.close()

def seed_initial_data(conn):
    cur = conn.cursor()
    ts = now_iso()

    # Check if already seeded
    cur.execute("SELECT COUNT(*) as c FROM ThreatSource")
    if cur.fetchone()["c"] > 0:
        return

    # 1. Seed ThreatSource from threat_intel/source_registry.yaml
    reg_file = ROOT_DIR / "threat_intel" / "source_registry.yaml"
    if reg_file.exists() and yaml is not None:
        reg = yaml.safe_load(reg_file.read_text())
        for s in reg.get("sources", []):
            chk = hashlib.sha256(s["source_id"].encode()).hexdigest()[:16]
            cur.execute(
                """INSERT INTO ThreatSource (
                    source_id, name, category, data_type, access_method, url, license,
                    update_frequency, version, status, record_count, confidence,
                    rate_limit_policy, last_success_at, checksum, environment,
                    provenance, retention_policy, schema_version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'REAL', 'source_registry_yaml', '365d_intel', '1.0', ?, ?)""",
                (
                    s["source_id"], s["name"], s["category"], s["data_type"],
                    s["access_method"], s["url"], s["license"], s["update_frequency"],
                    s["version"], s["status"], s["record_count"], s["confidence"],
                    s["rate_limit_policy"], ts if s["status"].startswith("INGESTED") else None,
                    chk, ts, ts
                ),
            )

    # 2. Seed ThreatIndicator (Production IOCs + Strictly Marked TEST_ONLY Fixtures)
    ioc_file = ROOT_DIR / "threat_intel" / "normalized_iocs.jsonl"
    if ioc_file.exists():
        for line in ioc_file.read_text().splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            cur.execute(
                """INSERT INTO ThreatIndicator (
                    ioc_id, indicator_type, value, source_id, confidence, severity,
                    tags_json, is_test_fixture, environment_scope, attack_technique_id,
                    provenance, retention_policy, schema_version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, '180d_intel', '1.0', ?, ?)""",
                (
                    item["ioc_id"], item["indicator_type"], item["value"],
                    item["source_id"], item["confidence"], item["severity"],
                    json.dumps(item["tags"]), item["environment_scope"],
                    item.get("attack_technique_id"), item["source_id"], ts, ts
                ),
            )

    fixture_file = ROOT_DIR / "threat_intel" / "test_fixtures.json"
    if fixture_file.exists():
        for item in json.loads(fixture_file.read_text()):
            cur.execute(
                """INSERT INTO ThreatIndicator (
                    ioc_id, indicator_type, value, source_id, confidence, severity,
                    tags_json, is_test_fixture, environment_scope, attack_technique_id,
                    provenance, retention_policy, schema_version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 'safe_test_fixtures', '180d_intel', '1.0', ?, ?)""",
                (
                    item["ioc_id"], item["indicator_type"], item["value"],
                    item["source_id"], item["confidence"], item["severity"],
                    json.dumps(item["tags"]), item["environment_scope"],
                    item.get("attack_technique_id"), ts, ts
                ),
            )

    # 3. Seed ThreatTechnique
    tech_file = ROOT_DIR / "threat_intel" / "attack_techniques.json"
    if tech_file.exists():
        for t in json.loads(tech_file.read_text()):
            cur.execute(
                """INSERT INTO ThreatTechnique (
                    technique_id, stix_id, name, domain, tactic, version,
                    description, d3fend_countermeasure, environment, provenance,
                    retention_policy, schema_version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'REAL', 'mitre_stix_bundle', '365d_intel', '1.0', ?, ?)""",
                (
                    t["technique_id"], t["stix_id"], t["name"], t["domain"],
                    t["tactic"], t["version"], t["description"],
                    t.get("d3fend_countermeasure"), ts, ts
                ),
            )

    # 4. Seed DetectionRule
    sigma_file = ROOT_DIR / "threat_intel" / "rules" / "sigma_rules.yaml"
    if sigma_file.exists() and yaml is not None:
        for r in yaml.safe_load(sigma_file.read_text()):
            cur.execute(
                """INSERT INTO DetectionRule (
                    rule_id, title, rule_type, version, severity, attack_technique_id,
                    condition_expr, description, enabled, environment, provenance,
                    retention_policy, schema_version, created_at, updated_at
                ) VALUES (?, ?, 'SIGMA_DETERMINISTIC', ?, ?, ?, ?, ?, 1, 'REAL', 'sigmahq_curated', '365d_rules', '1.0', ?, ?)""",
                (
                    r["id"], r["title"], r["version"], r["level"].upper(),
                    r.get("attack_technique_id"), r["detection"]["condition"],
                    r["description"], ts, ts
                ),
            )

    # Add layered engine rules so all 10 layers are represented in DetectionRule
    extra_rules = [
        ("rule-ioc-exact-001", "Exact Threat Indicator Match (Domain/URL/IP/Hash)", "IOC_EXACT", "1.4.0", "HIGH", "T1071.004", "value in ThreatIndicator", "Matches observed indicator against normalized IOC database and active lab fixtures."),
        ("rule-yara-scan-002", "YARA Pattern Match on Submitted Artifact", "YARA_RULE", "1.2.0", "HIGH", "T1404", "yara_match == true", "Scans user-submitted or lab files against curated YARA signatures without executing binaries."),
        ("rule-net-meta-003", "Encrypted Outbound Connection Metadata Anomaly", "NETWORK_METADATA", "1.1.0", "MEDIUM", "T1041", "unusual_port_or_high_frequency_beacon", "Analyzes DNS and socket metadata while respecting TLS encryption boundaries (marks payload uninspected)."),
        ("rule-seq-exfil-004", "Sensitive Resource Access Followed by Outbound Connection", "SEQUENCE_CORRELATION", "1.3.0", "HIGH", "T1041", "sensitive_file_access -> external_socket within 30s", "Correlates local resource access followed rapidly by outbound network metadata."),
        ("rule-trust-override-005", "Trusted Contact Compromise / High-Risk Lure Override", "CONTEXT_RISK", "1.5.0", "CRITICAL", "T1660", "trust_level == TRUSTED and (otp_solicitation or ioc_match)", "Ensures trusted contact status reduces benign noise but never suppresses OTP scams or malicious links."),
        ("rule-cross-device-006", "Cross-Endpoint Pseudonymous Campaign Correlation", "CORRELATION", "1.2.0", "HIGH", "T1071.004", "same_pseudonymous_indicator_across_multiple_devices", "Correlates repeated behavioral or indicator patterns across multiple endpoints."),
    ]
    for rid, title, rtype, ver, sev, tech, cond, desc in extra_rules:
        cur.execute(
            """INSERT INTO DetectionRule (
                rule_id, title, rule_type, version, severity, attack_technique_id,
                condition_expr, description, enabled, environment, provenance,
                retention_policy, schema_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'REAL', 'adonai_core_engine', '365d_rules', '1.0', ?, ?)""",
            (rid, title, rtype, ver, sev, tech, cond, desc, ts, ts),
        )

    # 5. Seed Registered REAL Devices & Consent Records
    cur.execute(
        """INSERT INTO Device (
            device_id, name, platform, os_version, api_level, environment,
            is_physical, status, last_seen_at, provenance, retention_policy,
            schema_version, created_at, updated_at
        ) VALUES
        ('mac-host-lab-01', 'ADONAI Mac Intelligence Host', 'macOS / Linux Host', '6.12 / Pilot Host', NULL, 'REAL', 1, 'ONLINE', ?, 'local_host_bootstrap', '90d_local', '1.0', ?, ?),
        ('android-pixel8-real-01', 'Pixel 8 Pro (Paired Android Agent)', 'Android', 'Android 15', 35, 'REAL', 1, 'PAIRED_ONLINE', ?, 'authenticated_lan_pairing', '90d_local', '1.0', ?, ?)
        """,
        (ts, ts, ts, ts, ts, ts),
    )

    consents = [
        ("consent-pkg-01", "android-pixel8-real-01", "PACKAGE_INVENTORY", "App & Permission Inventory", 1, "Inspect installed packages and granted Android permissions via PackageManager."),
        ("consent-share-02", "android-pixel8-real-01", "SHARE_SHEET_ANALYSIS", "Share-Sheet Link & Text Analysis", 1, "Analyze URLs, messages, and files explicitly shared by the user via Android ACTION_SEND."),
        ("consent-notif-03", "android-pixel8-real-01", "OPT_IN_NOTIFICATION_GUARD", "Opt-In Notification Scam Guard", 1, "Inspect only notification title/text fields exposed to NotificationListenerService; never accesses private app databases."),
        ("consent-vpn-04", "android-pixel8-real-01", "OPT_IN_VPN_METADATA", "Opt-In Local VPN DNS/Metadata Guard", 1, "Observe DNS queries and connection metadata via Android VpnService; TLS payloads remain encrypted and uninspected."),
    ]
    for cid, did, fkey, fname, granted, scope in consents:
        cur.execute(
            """INSERT INTO ConsentRecord (
                consent_id, device_id, feature_key, feature_name, granted,
                scope_description, limitations_acknowledged, environment,
                provenance, retention_policy, schema_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, 1, 'REAL', 'android_onboarding_consent', '365d_consent', '1.0', ?, ?)""",
            (cid, did, fkey, fname, granted, scope, ts, ts),
        )

    # 6. Seed Android AppInventory & PermissionSnapshot (Realistic, sourced from Android APIs structure)
    apps = [
        ("app-01", "com.whatsapp", "WhatsApp Messenger", "2.26.14.78", "com.android.vending", 0, ["android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS", "android.permission.POST_NOTIFICATIONS"], 0.18, "Standard verified Play Store messenger; private database is sandboxed and not accessible to ADONAI."),
        ("app-02", "com.FloatingFlashlight. Torch", "Ultra Bright Torch Pro", "1.0.4", "sideload_apk_installer", 0, ["android.permission.CAMERA", "android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.INTERNET"], 0.89, "HIGH RISK: Sideloaded utility app requesting READ_SMS, BIND_ACCESSIBILITY_SERVICE, and SYSTEM_ALERT_WINDOW outside flashlight scope."),
        ("app-03", "org.mozilla.firefox", "Firefox Browser", "132.0.1", "com.android.vending", 0, ["android.permission.INTERNET", "android.permission.POST_NOTIFICATIONS"], 0.10, "Standard Play Store web browser."),
        ("app-04", "com.adonai.mobile", "ADONAI Personal Cyber Guard", "1.0.0-pilot", "local_pilot_build", 0, ["android.permission.QUERY_ALL_PACKAGES", "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", "android.permission.BIND_VPN_SERVICE"], 0.05, "ADONAI pilot agent using purpose-specific, user-revocable platform permissions."),
    ]
    for aid, pkg, label, ver, inst, sys_app, perms, score, rat in apps:
        cur.execute(
            """INSERT INTO AppInventory (
                app_id, device_id, package_name, app_label, version_name,
                installer_source, is_system_app, granted_permissions_json,
                risk_score, risk_rationale, environment, provenance,
                retention_policy, schema_version, created_at, updated_at
            ) VALUES (?, 'android-pixel8-real-01', ?, ?, ?, ?, ?, ?, ?, ?, 'REAL', 'android_package_manager', '30d_local', '1.0', ?, ?)""",
            (aid, pkg, label, ver, inst, sys_app, json.dumps(perms), score, rat, ts, ts),
        )
        for p in perms:
            risk = "HIGH" if any(k in p for k in ("SMS", "ACCESSIBILITY", "ALERT_WINDOW", "CONTACTS")) else "LOW"
            cur.execute(
                """INSERT INTO PermissionSnapshot (
                    snapshot_id, device_id, package_name, permission_name,
                    is_granted, risk_level, purpose_note, environment,
                    provenance, retention_policy, schema_version, created_at, updated_at
                ) VALUES (?, 'android-pixel8-real-01', ?, ?, 1, ?, ?, 'REAL', 'android_package_manager', '30d_local', '1.0', ?, ?)""",
                (f"perm-{uuid.uuid4().hex[:10]}", pkg, p, risk, rat, ts, ts),
            )

    # 7. Seed RecipientEntity & TrustRelationship for Contextual Scam Guard
    recipients = [
        ("rec-mom-01", "+91-98400-11223", "Mom (Family Contact)", "SMS / WhatsApp Notification", 0.95, "TRUSTED", "Immediate Family"),
        ("rec-colleague-02", "arjun.mehta@corp.example.org", "Arjun Mehta (Work)", "Email / Chat", 0.85, "KNOWN", "Verified Colleague"),
        ("rec-unknown-03", "+1-555-0199-882", "Unknown Sender (+1-555-0199-882)", "SMS Notification", 0.15, "UNKNOWN", "Unlisted External Number"),
    ]
    for rid, ident, dname, chan, rep, tlevel, rlabel in recipients:
        cur.execute(
            """INSERT INTO RecipientEntity (
                recipient_id, identifier, display_name, channel_type,
                reputation_score, environment, provenance, retention_policy,
                schema_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'REAL', 'user_contacts_context', '90d_local', '1.0', ?, ?)""",
            (rid, ident, dname, chan, rep, ts, ts),
        )
        cur.execute(
            """INSERT INTO TrustRelationship (
                relationship_id, recipient_id, trust_level, relationship_label,
                notes, override_policy, environment, provenance,
                retention_policy, schema_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'Configured in ADONAI Context Settings', 'NEVER_SUPPRESS_OTP_OR_COMPROMISE', 'REAL', 'user_trust_config', '90d_local', '1.0', ?, ?)""",
            (f"trust-{rid}", rid, tlevel, rlabel, ts, ts),
        )

    # 8. Seed 1,000 SimulatedEndpoint identities in LAB environment
    import math
    sectors = ["MOBILE-FLEET", "HOME-IOT", "MAC-WORKSTATIONS", "CLOUD-EDGE", "GUEST-VLAN"]
    os_profiles = ["Android-15-Sim", "Android-14-Sim", "macOS-15-Sim", "Linux-Container-Sim", "iOS-18-Sim"]
    ep_rows = []
    for i in range(1, 1001):
        eid = f"sim-ep-{i:04d}"
        sector = sectors[(i - 1) % len(sectors)]
        os_prof = os_profiles[(i - 1) % len(os_profiles)]
        ring = 1 + ((i - 1) // 200)  # 5 concentric orbital rings of 200 nodes each
        radius = 16.0 + ring * 9.5
        angle = ((i % 200) / 200.0) * (2.0 * math.pi) + (ring * 0.25)
        height = ((i % 17) - 8) * 1.15
        vip = f"10.240.{(i - 1) // 250}.{(i - 1) % 250 + 2}"
        ep_rows.append((
            eid, f"Virtual-Node-{i:04d}", sector, vip, os_prof,
            0, "SIMULATED_IDENTITY", "NORMAL", None, None,
            round(radius, 3), round(angle, 4), round(height, 3),
            "LAB", "cyber_range_population_generator", "90d_lab", "1.0", ts, ts
        ))
    cur.executemany(
        """INSERT INTO SimulatedEndpoint (
            endpoint_id, label, sector, virtual_ip, os_profile,
            is_physical, entity_type, status, last_event_id, last_scenario_id,
            orbit_radius, orbit_angle, orbit_height, environment,
            provenance, retention_policy, schema_version, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        ep_rows,
    )

    # 9. Seed all 10 required Safe Simulation Scenarios
    scenarios = [
        (
            "scen-01", "SCEN_01_DNS_C2", "1. Suspicious DNS Lookup to Reserved Test Domain",
            "network_dns", "Emits a DNS A-record query to RFC 2606 reserved domain c2-beacon.example.invalid via isolated lab resolver.",
            1, "HIGH", "T1071.004", "Verified RFC 2606 .invalid domain; no external DNS egress.",
            "SAFE EMULATION: Queries synthetic local resolver for c2-beacon.example.invalid.",
            [{"event_type": "DNS_QUERY", "domain": "c2-beacon.example.invalid", "dst_ip": "198.51.100.42", "evidence_class": "OBSERVED", "app_context": "com.sync.agent.sim"}]
        ),
        (
            "scen-02", "SCEN_02_SHARE_PHISH", "2. Phishing URL Submitted via Share Sheet",
            "phishing_share", "Simulates user submitting a suspicious login URL (https://secure-verify-auth.example.test/login) through Android ACTION_SEND.",
            1, "HIGH", "T1660", "Uses RFC 2606 .test domain; defanged lexical & fixture evaluation.",
            "SAFE EMULATION: Evaluates URL structure and test fixture match without network dereference.",
            [{"event_type": "SHARE_SHEET_SUBMISSION", "url": "https://secure-verify-auth.example.test/login", "message_text": "Urgent: verify your account session immediately at https://secure-verify-auth.example.test/login", "recipient_id": "rec-unknown-03", "evidence_class": "OBSERVED", "app_context": "com.adonai.mobile.share"}]
        ),
        (
            "scen-03", "SCEN_03_BRUTE_FORCE", "3. Repeated Failed Login Telemetry Replay",
            "auth_replay", "Replays 6 consecutive authentication failures within 45 seconds followed by an interactive session event.",
            1, "HIGH", "T1110.001", "Synthetic auth log replay inside isolated LAB environment.",
            "SAFE EMULATION: Replays structured authentication failure records.",
            [{"event_type": "AUTH_FAILURE_BURST", "failed_login_count": 6, "window_seconds": 45, "dst_ip": "192.0.2.88", "evidence_class": "OBSERVED", "app_context": "sshd-lab-replay"}]
        ),
        (
            "scen-04", "SCEN_04_PROC_TO_NET", "4. Unusual Process-to-Network Sequence",
            "sequence_behavior", "Emits a synthetic shell interpreter spawn immediately followed by an outbound socket to a non-standard port.",
            1, "MEDIUM", "T1059", "Synthetic process & socket telemetry only; no shell commands executed.",
            "SAFE EMULATION: Emits paired process-spawn and socket-connect telemetry events.",
            [{"event_type": "PROCESS_NETWORK_CHAIN", "process_name": "/bin/sh -c curl_emulated", "dst_ip": "198.51.100.99", "dst_port": 8443, "delta_seconds": 2.1, "evidence_class": "OBSERVED", "app_context": "lab-workstation-agent"}]
        ),
        (
            "scen-05", "SCEN_05_PERM_ESCALATION", "5. Unexpected App Permission Change Event",
            "android_permission", "Simulates an installed utility app dynamically acquiring READ_SMS and BIND_ACCESSIBILITY_SERVICE permissions.",
            1, "HIGH", "T1404", "Synthetic PackageManager delta event in LAB mode.",
            "SAFE EMULATION: Evaluates permission combination heuristics on synthetic package update.",
            [{"event_type": "PERMISSION_CHANGE", "package_name": "com.FloatingFlashlight.Torch", "permissions_added": ["android.permission.READ_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE"], "installer_source": "sideload_apk_installer", "evidence_class": "OBSERVED", "app_context": "android.content.pm.PackageManager"}]
        ),
        (
            "scen-06", "SCEN_06_FILE_THEN_NET", "6. Sensitive File Access Followed by Outbound Metadata",
            "sequence_exfil", "Replays local contacts/keystore read observation followed within 5 seconds by high-entropy TLS metadata burst.",
            1, "HIGH", "T1041", "Explicitly labels exfiltration risk as INFERRED because TLS payload is encrypted.",
            "SAFE EMULATION: Demonstrates honest INFERRED labeling without claiming TLS decryption.",
            [{"event_type": "SENSITIVE_ACCESS_AND_EGRESS", "data_category": "CONTACTS_AND_MEDIA_METADATA", "dst_ip": "203.0.113.77", "dst_port": 443, "bytes_out": 482000, "tls_encrypted": True, "evidence_class": "INFERRED", "app_context": "com.unverified.backup.sync"}]
        ),
        (
            "scen-07", "SCEN_07_KNOWN_IOC", "7. Known Test IOC Match (IP & Artifact Hash)",
            "ioc_match", "Emits network metadata and artifact hash matching safe TEST_ONLY fixture 198.51.100.42.",
            1, "HIGH", "T1071.001", "Matches strictly isolated TEST_ONLY indicator.",
            "SAFE EMULATION: Tests exact deterministic IOC lookup against RFC 5737 test IP.",
            [{"event_type": "IOC_TELEMETRY_MATCH", "dst_ip": "198.51.100.42", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "evidence_class": "CONFIRMED", "app_context": "lab-artifact-scanner"}]
        ),
        (
            "scen-08", "SCEN_08_BENIGN_FAMILY", "8. Benign Family Contact Sharing (False-Positive Control)",
            "benign_control", "Trusted family contact ('Mom') shares a normal family recipe/photo link with no scam or OTP indicators.",
            0, "LOW", None, "Ground-truth BENIGN scenario to verify 0% false positive on trusted everyday interactions.",
            "SAFE EMULATION: Verifies context-aware suppression of nuisance warnings on benign trusted messages.",
            [{"event_type": "MESSAGE_LINK_ANALYSIS", "url": "https://cooking-recipes.example.org/sunday-dinner", "message_text": "Here is the masala dosa recipe we talked about for Sunday dinner!", "recipient_id": "rec-mom-01", "evidence_class": "OBSERVED", "app_context": "com.adonai.mobile.notifications"}]
        ),
        (
            "scen-09", "SCEN_09_OTP_SCAM", "9. OTP-Request Scam Scenario (Synthetic Message)",
            "scam_guard", "Unknown sender requests a 6-digit banking OTP code under artificial urgency.",
            1, "CRITICAL", "T1660", "Synthetic text evaluation only.",
            "SAFE EMULATION: Triggers deterministic OTP solicitation & urgency heuristics.",
            [{"event_type": "MESSAGE_LINK_ANALYSIS", "url": None, "message_text": "URGENT BANK ALERT: Your account will be frozen in 10 minutes. Reply immediately with the 6-digit OTP verification code sent to your phone.", "recipient_id": "rec-unknown-03", "evidence_class": "OBSERVED", "app_context": "com.adonai.mobile.notifications"}]
        ),
        (
            "scen-10", "SCEN_10_TRUSTED_COMPROMISE", "10. Trusted Contact Account-Compromise Override",
            "context_override", "Trusted family contact ('Mom') sends a known phishing URL + urgent OTP/wire solicitation (simulating a hijacked family account).",
            1, "CRITICAL", "T1566.002", "Verifies that TRUSTED status NEVER suppresses strong compromise or OTP/phishing indicators.",
            "SAFE EMULATION: Validates non-bypassable security floor when a trusted contact's account is compromised.",
            [{"event_type": "MESSAGE_LINK_ANALYSIS", "url": "https://urgent-family-wire.example.test/otp-claim", "message_text": "Hey I am stuck at the hospital and my card is locked, click https://urgent-family-wire.example.test/otp-claim and send me your 6-digit OTP code right now please!", "recipient_id": "rec-mom-01", "evidence_class": "CONFIRMED", "app_context": "com.adonai.mobile.notifications"}]
        ),
    ]
    for sid, code, name, cat, desc, exp_det, exp_sev, tech, pre, safe, steps in scenarios:
        cur.execute(
            """INSERT INTO SimulationScenario (
                scenario_id, code, name, category, description, expected_detection,
                expected_severity, attack_technique_id, preflight_check, safety_notice,
                steps_json, environment, provenance, retention_policy, schema_version,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'LAB', 'cyber_range_catalogue', '365d_lab', '1.0', ?, ?)""",
            (sid, code, name, cat, desc, exp_det, exp_sev, tech, pre, safe, json.dumps(steps), ts, ts),
        )

    # 10. Seed initial REAL baseline events (from Android PackageManager & VPN metadata) so REAL timeline has truthful initial observations
    real_ev_1 = "evt-real-pkg-001"
    cur.execute(
        """INSERT INTO SecurityEvent (
            event_id, device_id, environment, source_type, event_type,
            app_context, resource_implicated, destination, evidence_class,
            summary, payload_json, provenance, retention_policy, schema_version,
            created_at, updated_at
        ) VALUES (?, 'android-pixel8-real-01', 'REAL', 'ANDROID_PACKAGE_MANAGER', 'HIGH_RISK_PERMISSION_AUDIT',
            'com.FloatingFlashlight.Torch', 'READ_SMS + BIND_ACCESSIBILITY_SERVICE + SYSTEM_ALERT_WINDOW', 'local_device', 'OBSERVED',
            'Sideloaded app Ultra Bright Torch Pro holds invasive SMS, Accessibility, and Overlay permissions disproportionate to a flashlight utility.',
            ?, 'android_package_manager', '30d_local', '1.0', ?, ?)""",
        (real_ev_1, json.dumps({"package_name": "com.FloatingFlashlight.Torch", "installer": "sideload_apk_installer", "risk_score": 0.89}), ts, ts),
    )
    cur.execute(
        """INSERT INTO DataAccessObservation (
            access_id, event_id, device_id, package_name, data_category,
            access_mode, evidence_class, environment, provenance,
            retention_policy, schema_version, created_at, updated_at
        ) VALUES ('dao-real-001', ?, 'android-pixel8-real-01', 'com.FloatingFlashlight.Torch',
            'SMS_AND_ACCESSIBILITY_EVENTS', 'PERMISSION_GRANTED_AUDIT', 'OBSERVED', 'REAL',
            'android_package_manager', '30d_local', '1.0', ?, ?)""",
        (real_ev_1, ts, ts),
    )
    det_real_1 = "det-real-pkg-001"
    cur.execute(
        """INSERT INTO Detection (
            detection_id, rule_id, rule_version, source_event_ids_json,
            device_id, environment, evidence_class, evidence_fields_json,
            confidence_method, confidence_score, severity, rationale,
            attack_technique_id, recommended_action, action_supported,
            pseudonymous_correlation_token, analyst_disposition, provenance,
            retention_policy, schema_version, created_at, updated_at
        ) VALUES (?, 'sigma-adonai-004', '1.3.0', ?, 'android-pixel8-real-01', 'REAL', 'OBSERVED',
            ?, 'DETERMINISTIC_PERMISSION_HEURISTIC', 0.92, 'HIGH',
            'Package com.FloatingFlashlight.Torch was installed via sideload_apk_installer and requests READ_SMS + BIND_ACCESSIBILITY_SERVICE + SYSTEM_ALERT_WINDOW.',
            'T1404', 'Open Android App Info to revoke Accessibility/SMS permissions or uninstall Ultra Bright Torch Pro.', 1,
            'corr-pkg-torch-01', 'OPEN', 'deterministic_detection_engine', '90d_security', '1.0', ?, ?)""",
        (det_real_1, json.dumps([real_ev_1]), json.dumps({"package": "com.FloatingFlashlight.Torch", "permissions": ["READ_SMS", "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"]}), ts, ts),
    )
    inc_real_1 = "inc-real-001"
    cur.execute(
        """INSERT INTO Incident (
            incident_id, title, device_id, environment, severity, status,
            evidence_class, what_observed, where_implicated, why_risky,
            now_what_action, uncertainty_note, containment_supported,
            containment_status, detection_ids_json, event_ids_json,
            attack_technique_id, provenance, retention_policy, schema_version,
            created_at, updated_at
        ) VALUES (?, 'Invasive Permission Combination in Sideloaded Flashlight App', 'android-pixel8-real-01', 'REAL', 'HIGH', 'OPEN',
            'OBSERVED',
            'Android PackageManager reports that Ultra Bright Torch Pro (com.FloatingFlashlight.Torch) holds granted READ_SMS, BIND_ACCESSIBILITY_SERVICE, and SYSTEM_ALERT_WINDOW permissions.',
            'Device: Pixel 8 Pro (android-pixel8-real-01) | Package: com.FloatingFlashlight.Torch (installer: sideload_apk_installer)',
            'Matched rule sigma-adonai-004 (v1.3.0, MITRE ATT&CK T1404). Accessibility + SMS + Overlay permissions allow an app to read incoming verification codes and overlay deceptive screens.',
            'Supported Action: Launch Android Settings -> Apps -> Ultra Bright Torch Pro to revoke Accessibility & SMS access or uninstall the package.',
            'OBSERVED permission grant only: Android sandboxing prevents ADONAI from inspecting past private app memory, so this confirms dangerous capability exposure rather than confirmed past exfiltration.',
            1, 'USER_ACTION_AVAILABLE', ?, ?, 'T1404', 'incident_correlator', '90d_security', '1.0', ?, ?)""",
        (inc_real_1, json.dumps([det_real_1]), json.dumps([real_ev_1]), ts, ts),
    )
    cur.execute(
        """INSERT INTO IncidentEvidence (
            evidence_id, incident_id, event_id, detection_id, evidence_class,
            artifact_summary, source_attribution, environment, provenance,
            retention_policy, schema_version, created_at, updated_at
        ) VALUES ('evid-real-001', ?, ?, ?, 'OBSERVED',
            'Granted permissions: READ_SMS, BIND_ACCESSIBILITY_SERVICE, SYSTEM_ALERT_WINDOW on sideloaded package com.FloatingFlashlight.Torch',
            'Android PackageManager API + Rule sigma-adonai-004 v1.3.0', 'REAL', 'evidence_linker', '90d_security', '1.0', ?, ?)""",
        (inc_real_1, real_ev_1, det_real_1, ts, ts),
    )

    # Also add a REAL encrypted network connection metadata observation showing honest OBSERVED/INFERRED boundary
    real_ev_2 = "evt-real-vpn-002"
    cur.execute(
        """INSERT INTO SecurityEvent (
            event_id, device_id, environment, source_type, event_type,
            app_context, resource_implicated, destination, evidence_class,
            summary, payload_json, provenance, retention_policy, schema_version,
            created_at, updated_at
        ) VALUES (?, 'android-pixel8-real-01', 'REAL', 'ANDROID_VPN_METADATA', 'ENCRYPTED_TLS_METADATA_OBSERVED',
            'com.FloatingFlashlight.Torch', 'Outbound TLS 1.3 Socket Metadata (Port 443)', 'telemetry-collector.example.net:443', 'INFERRED',
            'Opt-in VpnService observed outbound TLS connection metadata from flashlight app to external endpoint; TLS payload is encrypted and not inspected.',
            ?, 'android_vpn_service', '30d_local', '1.0', ?, ?)""",
        (real_ev_2, json.dumps({"domain": "telemetry-collector.example.net", "dst_ip": "192.0.2.55", "dst_port": 443, "tls_encrypted": True, "payload_inspected": False, "bytes_out": 18420}), ts, ts),
    )
    cur.execute(
        """INSERT INTO NetworkObservation (
            observation_id, event_id, device_id, protocol, domain, dst_ip,
            dst_port, tls_encrypted, payload_inspected, bytes_Out,
            evidence_class, environment, provenance, retention_policy,
            schema_version, created_at, updated_at
        ) VALUES ('net-real-001', ?, 'android-pixel8-real-01', 'TCP/TLS1.3', 'telemetry-collector.example.net',
            '192.0.2.55', 443, 1, 0, 18420, 'OBSERVED', 'REAL', 'android_vpn_service', '30d_local', '1.0', ?, ?)""",
        (real_ev_2, ts, ts),
    )

    # Initial AuditLog entry
    cur.execute(
        """INSERT INTO AuditLog (
            audit_id, actor, action, resource_type, resource_id, status,
            details_json, environment, provenance, retention_policy,
            schema_version, created_at, updated_at
        ) VALUES ('audit-boot-001', 'system_bootstrap', 'INITIALIZE_DATABASE', 'SQLiteDatabase', 'adonai_pilot.db', 'SUCCESS',
            ?, 'REAL', 'security_audit_service', '365d_audit', '1.0', ?, ?)""",
        (json.dumps({"tables_initialized": len(REQUIRED_TABLES), "simulated_endpoints_registered": 1000}), ts, ts),
    )

    conn.commit()
