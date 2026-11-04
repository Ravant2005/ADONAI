# ADONAI — Security Threat Model (STRIDE)

| Threat Category | Vector Considered | ADONAI Mitigation Implemented |
|---|---|---|
| **Spoofing** | Rogue device attempting to push fake telemetry to Mac API | Short-lived 6-digit pairing challenge (5-min TTL) + SHA-256 hashed bearer tokens + one-click revocation (`/api/pairing/revoke/{device_id}`). |
| **Tampering** | Cross-contamination between lab simulations and personal phone telemetry | Mandatory `environment CHECK(environment IN ('REAL', 'LAB'))` column on events, detections, incidents, and evidence + separate purge controls. |
| **Repudiation** | Unaudited administrative or scenario actions | Immutable `AuditLog` table recording actor, action, resource ID, status, and UTC timestamp for pairing, revocation, scenario runs, and data purges. |
| **Information Disclosure** | Leakage of passwords, bearer tokens, or card numbers into logs or LLM prompts | `redact_secrets()` regex scrubber strips tokens, credentials, and card numbers before SQLite storage and before LLM prompt assembly. |
| **Denial of Service** | Flood of API requests or unbounded event queues | Per-IP sliding-window rate limiter (`check_rate_limit`) + bounded SQLite query pagination. |
| **Elevation of Privilege / LLM Hallucination** | Prompt injection in a phishing message attempting to make the LLM execute commands or suppress alerts | LLM has zero shell/tool execution access and cannot alter detection verdicts. Deterministic rules fire independently before the LLM is ever consulted, and LLM output must pass `validate_explanation_schema()`. |
