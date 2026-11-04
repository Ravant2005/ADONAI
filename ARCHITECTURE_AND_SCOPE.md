# ADONAI — Architecture and Build Notes

## System topology

Android phone
  ├─ Kotlin/Compose app (`android-agent/`) + Interactive Web Companion (`/mobile`)
  ├─ PackageManager app/permission inventory
  ├─ Share-sheet submission (`ACTION_SEND`) for URLs/text/files
  ├─ Optional `NotificationListenerService` (explicit opt-in; notification content only)
  ├─ Optional `VpnService` (explicit opt-in; network metadata and DNS policy; TLS payload remains encrypted)
  └─ Local Room event store
          │ authenticated short-lived pairing over trusted LAN
          ▼
MacBook / Local Intelligence Host
  ├─ FastAPI API + WebSocket (`backend/main.py`)
  ├─ SQLite pilot database (`24` typed tables with `REAL` vs `LAB` separation)
  ├─ Threat intelligence importers (`threat_intel/`)
  ├─ 10-layer deterministic IOC / rule / sequence / context detection engine (`backend/detection_engine.py`)
  ├─ Local LLM adapter (`backend/llm_analyst.py` — Ollama/OpenAI compatible + deterministic schema-validated fallback)
  ├─ Safe simulation controller (`backend/cyber_range.py` — 10 safe scenarios, pause/resume/stop/reset, replay)
  ├─ Ground-truth evaluation harness (`EvaluationResult`)
  └─ Red/Black 12-view web dashboard & 1,000-node 3D cyber range (`dashboard/`)

## Important boundaries
- Android cannot freely inspect another app's private database or all screen contents.
- Notification access is not equivalent to full WhatsApp/email access.
- A local VPN can observe connection metadata and DNS, but cannot automatically read arbitrary HTTPS payloads.
- macOS endpoint telemetry may require specific entitlements, permissions, and APIs.
- A 3D view of 1,000 simulated endpoints is a visualization of registered simulated identities (`SimulatedEndpoint`), not 1,000 full operating systems.
- A local LLM is an analyst/explainer, not a security authority.
- No security product can guarantee detection of every attack or identify every leak.

## Red/black design tokens
- Background: `#050505`
- Surface: `#101010`
- Elevated: `#171111`
- Primary: `#E50914`
- Deep red: `#8B0000`
- Alert: `#FF3030`
- Text: `#F5F5F5`
- Muted: `#A7A7A7`
- Border: `#352020`

No blue, green, purple, orange, cyan, or multicolor gradients.
