# ADONAI — REST & WebSocket API Reference

Base URL: `http://127.0.0.1:8410`

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Component health check across all 24 SQLite tables, 10 detection layers, local LLM, and cyber range. |
| `GET` | `/api/overview?environment=REAL\|LAB` | Computed dashboard counters, latest benchmark result, and LLM status. |
| `GET` | `/api/devices` | Paired devices, pairing history, Android `AppInventory`, and `ConsentRecord` list. |
| `POST` | `/api/pairing/create` | Generates a short-lived 6-digit pairing code and QR JSON payload. |
| `POST` | `/api/pairing/complete` | Completes Android-to-Mac pairing and returns an authenticated bearer token. |
| `POST` | `/api/pairing/revoke/{device_id}` | Revokes an active device pairing immediately. |
| `GET` | `/api/events?environment=REAL\|LAB` | Normalized `SecurityEvent` timeline with `OBSERVED`/`INFERRED`/`CONFIRMED` labels. |
| `POST` | `/api/events/ingest` | Ingests and evaluates a security event through the 10-layer detection engine. |
| `POST` | `/api/analyze/share` | Evaluates user-shared URLs and message text with recipient trust context. |
| `GET` | `/api/incidents?environment=REAL\|LAB` | Returns incidents with 5-question guidance, evidence items, and LLM explanations. |
| `POST` | `/api/incidents/{incident_id}/explain` | Generates a schema-validated Local LLM or deterministic fallback explanation. |
| `POST` | `/api/feedback` | Records user disposition (`CONFIRMED_THREAT`, `FALSE_POSITIVE`, `BENIGN_EXPECTED`). |
| `GET` | `/api/threat-intel` | Returns all 18 threat sources, production IOCs, isolated test fixtures, ATT&CK techniques, and rules. |
| `GET` | `/api/cyber-range/state` | Returns all 1,000 registered `SimulatedEndpoint` identities and 10 safe scenarios. |
| `POST` | `/api/cyber-range/run` | Executes or replays a safe lab scenario against a target simulated endpoint. |
| `POST` | `/api/cyber-range/control` | Controls cyber range state (`PAUSE`, `RESUME`, `STOP`, `RESET`). |
| `POST` | `/api/cyber-range/evaluate` | Runs the 10-scenario ground-truth benchmark and persists `EvaluationResult`. |
| `GET` | `/api/privacy-audit` | Returns consent records, trusted contacts, and `AuditLog` entries. |
| `POST` | `/api/privacy/consent` | Grants or revokes a specific device telemetry feature consent. |
| `DELETE` | `/api/privacy/purge-events?environment=REAL\|LAB` | Purges stored events, detections, and incidents for the chosen environment. |
| `WS` | `/ws/events` | Live WebSocket event stream. |
