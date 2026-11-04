# ADONAI Judge Demonstration Script (8–10 minutes)

## Before judges arrive
- Start Mac backend and dashboard.
- Confirm local LLM health (or deterministic fallback status).
- Confirm threat source ingestion status.
- Pair the Android phone.
- Verify lab network isolation.
- Load only safe, labeled simulation scenarios.
- Confirm no production or personal data is in the demo.

## 1. Product overview (1 minute)
Explain: ADONAI correlates Android-visible security signals, user-submitted suspicious content, threat intelligence, and controlled lab telemetry. It does not claim unrestricted access to private app data.

## 2. Android experience (2 minutes)
- Show app inventory and permissions sourced from Android.
- Submit a synthetic phishing URL via Android share sheet.
- Show evidence, source, timestamp, confidence rationale, and safe recommendation.
- Show trusted-contact context scenario: benign family message should not trigger a scam warning.
- Show OTP/credential solicitation scenario: high-risk content should be flagged despite a trusted label if strong indicators exist.

## 3. Live Mac intelligence (2 minutes)
- Show event arriving from the paired phone or lab runner.
- Open incident evidence.
- Show observed vs inferred vs confirmed labels.
- Ask local LLM to explain the structured evidence.
- Show that the deterministic detection still works if LLM is offline.

## 4. 3D cyber range (2 minutes)
- Show registered simulated endpoints.
- Run a benign attack-emulation scenario in the isolated lab.
- Show real event stream and detection.
- Replay the same scenario against a second simulated endpoint.
- Show correlation with prior pattern and the rule/version responsible.
- Explain that 1,000 nodes are simulated endpoint identities, not 1,000 full OS installations.

## 5. Evaluation (1 minute)
Show measured recall, precision, false positives, detection latency, and test conditions. If results are preliminary, say so.

## 6. Close (1 minute)
ADONAI's novelty is the integrated user-facing exposure timeline, context-aware communication risk, evidence-grounded explanation, local intelligence, and privacy-preserving learning loop validated in a controlled cyber range.
