# ADONAI — End-to-End Data Flow Map

```
[Android Agent / Share Sheet / Opt-in Notification / Opt-in VPN Metadata]
       │
       ├──► 1. Secret Redaction (`redact_secrets`)
       ├──► 2. Local Room Cache (`LocalEventEntity`, Offline-Capable)
       │
       ▼ (Authenticated LAN Sync / `/api/events/ingest` or `/api/analyze/share`)
[Mac FastAPI Orchestrator (`127.0.0.1:8410`)]
       │
       ├──► 3. Event Normalization (`SecurityEvent` + `OBSERVED`/`INFERRED`/`CONFIRMED` class)
       ├──► 4. 10-Layer Deterministic Detection Engine (`DetectionRule`, `ThreatIndicator`, `TrustRelationship`)
       ├──► 5. Pseudonymous Cross-Device Correlation (`HMAC-SHA256` token)
       ├──► 6. Incident & 5-Question Evidence Linking (`Incident`, `IncidentEvidence`)
       └──► 7. Local LLM Analyst / Deterministic Fallback (`LLMExplanation` — JSON Schema Validated)
```
