# ADONAI Pilot Acceptance Checklist

## Android
- [x] Complete Kotlin + Jetpack Compose project (`android-agent/`) + interactive 12-screen Web Companion (`/mobile`).
- [x] Onboarding accurately describes what is and is not visible (`m-01` & `AdonaiScreens.kt`).
- [x] Permission center explains each permission's purpose and revocation (`m-02` & `ConsentRecord`).
- [x] Pairing to Mac uses authenticated short-lived 6-digit pairing code & QR payload (`/api/pairing/create`, `/api/pairing/complete`).
- [x] User can revoke paired Mac (`/api/pairing/revoke/{device_id}`).
- [x] App inventory/permission display is sourced from Android `PackageManager` APIs (`AppInventoryCollector.kt` & `AppInventory` table).
- [x] Share-sheet submission (`ACTION_SEND`) works for text and URLs (`ShareSheetAnalyzerActivity.kt` & `/api/analyze/share`).
- [x] URL analysis uses actual configured reputation/rule sources and isolated test fixtures.
- [x] Notification analysis is opt-in and only handles accessible notification fields (`AdonaiNotificationService.kt`).
- [x] Optional VPN mode starts/stops correctly and explains metadata-only / encrypted TLS limitations (`AdonaiVpnService.kt`).
- [x] Local event timeline persists (`AdonaiDatabase.kt` Room entities & `SecurityEvent`).
- [x] App handles Mac offline gracefully (`ShareSheetAnalyzerActivity.evaluateLocallyDeterministic` & `MacSyncWorker.kt`).
- [x] Battery/CPU/network overhead measured and documented (`docs/TEST_AND_PERFORMANCE_REPORT.md`).
- [x] No unsupported universal monitoring claims.

## Mac
- [x] Backend starts with one documented command (`./scripts/start_mac_lab.sh`).
- [x] Health endpoint (`/api/health`) reports component status across all 24 tables.
- [x] Local LLM health check and deterministic schema-validated fallback work (`backend/llm_analyst.py`).
- [x] Threat source registry shows actual connection/ingestion status across 18 sources (`threat_intel/source_registry.yaml`).
- [x] IOC/rule engine matches imported records and strictly separated `TEST_ONLY` fixtures (`backend/detection_engine.py`).
- [x] 3D lab nodes correspond to actual 1,000 registered `SimulatedEndpoint` entities (`sim-ep-0001`..`sim-ep-1000`).
- [x] Scenario runner creates auditable `LAB` events across all 10 safe scenarios.
- [x] Replay yields deterministic detection and cross-endpoint pseudonymous correlation.
- [x] Evaluation metrics derive from labeled ground truth (`EvaluationResult`).
- [x] `LAB` and `REAL` data are strictly separated across database, API, and UI filters.

## Security/privacy
- [x] API authentication, sliding-window rate limits, immutable `AuditLog`, and pairing revocation implemented.
- [x] No secrets in source control; `redact_secrets()` scrubs tokens, passwords, and card numbers.
- [x] Local API bound to `127.0.0.1:8410` by default.
- [x] User can delete local data (`DELETE /api/privacy/purge-events`) and revoke consent (`POST /api/privacy/consent`).
- [x] Data retention is documented (`docs/PRIVACY_AND_RETENTION_POLICY.md`).
- [x] CycloneDX `SBOM.json` and `DEPENDENCY_LICENSE_INVENTORY.md` generated.
- [x] No malware execution on host or phone.
- [x] Lab network isolation verified (`internal: true` in `cyber-range/docker-compose.yml`).

## Evidence and reporting
- [x] Real screenshots captured from running app (`docs/screenshots/01..05_*.png`).
- [x] Actual test and performance report generated (`docs/TEST_AND_PERFORMANCE_REPORT.md`).
- [x] Known limitations listed (`KNOWN_LIMITATIONS.md`).
- [x] Demo script distinguishes real and simulated events (`JUDGE_DEMO_SCRIPT.md`).
