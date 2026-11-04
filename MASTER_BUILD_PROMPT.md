# ADONAI — Master Build Prompt for Gemini/Argon
## Build a real, pilot-ready personal cyber-intelligence product

You are the principal product architect, Android engineer, macOS/security engineer, backend engineer, ML engineer, 3D visualization engineer, QA lead, privacy engineer, and technical writer for ADONAI.

Your task is to inspect the target development environment, plan, implement, test, document, and package a working pilot product. Do not merely generate a UI prototype. Do not claim that a feature works unless it is connected to a real permitted data source, a real detection engine, and a verifiable action. Do not fabricate threat detections, device counts, attack success, data leakage, model confidence, or benchmark results.

## 0. Product mission

ADONAI is a privacy-first personal cyber-intelligence system with:
1. An Android protection application.
2. A macOS-hosted local intelligence laboratory.
3. A local LLM running on the Mac for evidence explanation and analyst assistance.
4. A real threat-intelligence ingestion and normalization pipeline.
5. A controlled cyber-range simulator for repeatable defensive testing.
6. A shared event, detection, evidence, and incident model.

The product should help users understand:
- Which application or browser context generated an observed event.
- What permission, resource, destination, or data category is implicated.
- When it happened.
- Whether evidence is observed, inferred, or externally confirmed.
- Why the event is suspicious.
- Whether the system could prevent or contain it.
- What the user can safely do next.

The product must not say that data was exfiltrated merely because an app made an encrypted network connection. Use evidence labels:
- OBSERVED: directly observed OS, browser, VPN, or application event.
- INFERRED: likely interpretation from metadata or behaviour; payload not inspected.
- CONFIRMED: supported by direct evidence or a trusted external breach/intelligence source.
Never overstate attribution.

## 1. Non-negotiable delivery rules

- Build a functioning pilot, not a deceptive mockup.
- No fake device telemetry, fake live attack feed, fake threat counters, fake data-leak claims, fake map/3D events, or hard-coded “96% similarity”.
- Every dashboard number must be computed from stored events or explicitly marked as a static system limit.
- If an integration is unavailable, show “Not connected” or “Permission required”; never substitute fabricated data.
- Add a visible DEMO/LAB label to generated simulation events.
- Separate LAB events from REAL DEVICE events in the database, API, UI, and exports.
- Never run real malware or destructive exploits on the host Mac or personal phone.
- Never scan, attack, or probe public IPs, third-party services, or networks without explicit authorization.
- Use benign emulation, synthetic telemetry, replayable PCAPs, test domains in an isolated network, and dedicated disposable VMs.
- No root, jailbreak, private API, stealth persistence, credential harvesting, keylogging, covert recording, or bypass of OS permission boundaries.
- Do not request Android Accessibility permission unless a clearly documented, user-facing feature genuinely needs it. Do not use it to scrape other apps.
- Do not attempt to read WhatsApp's private database or messages. Use Android-supported notification access only with informed opt-in, and only for content actually exposed by Android notifications. Respect notification privacy settings.
- No interception/decryption of third-party TLS traffic. Explain metadata limitations.
- All sensitive actions require explicit user consent or a clearly configured policy. Provide undo/recovery where feasible.
- Secure the Mac API with device pairing, authentication, TLS when used beyond localhost, rate limits, audit logs, and revocation.
- Do not expose the Mac local LLM endpoint or admin APIs to the public internet.
- Do not train models on user data by default. Minimize, redact, and locally process telemetry.
- Add threat model, privacy policy, data-flow map, SBOM, dependency/license inventory, setup guide, and known-limitations document.

## 2. Required target environment

Primary development host: macOS laptop (Apple Silicon likely; detect architecture and available RAM/storage rather than assuming).
Mobile target: Android phone (detect Android version and API level).
Local LLM: user-selected model served locally on the Mac (for example through Ollama or another OpenAI-compatible local inference server). Detect endpoint/model availability. Never assume a model is installed. Provide setup instructions and health check.
The Android app connects to the Mac only when on the same trusted LAN or through a user-configured secure tunnel. It must continue to provide on-device features when the Mac is offline.

At startup, run environment discovery:
- macOS version, CPU architecture, memory, disk space.
- Android SDK/JDK/Gradle/ADB availability.
- Docker/Podman availability.
- Python and Node versions.
- Local LLM runtime and model availability.
- Available ports.
Generate `ENVIRONMENT_REPORT.md` and adapt resource settings to actual hardware.

## 3. Product architecture

Use a modular architecture with explicit interfaces:

A. Android application
- Kotlin + Jetpack Compose.
- Material design foundations, but custom red/black visual system.
- Room for local event cache.
- WorkManager for deferrable sync.
- Android Keystore for secrets.
- NotificationListenerService only for an opt-in notification-risk feature; explain exactly which notification fields are accessible.
- VpnService only for an opt-in local VPN/DNS/network metadata protection feature; document battery, compatibility, and TLS visibility limits.
- PackageManager permission/app inventory using supported APIs.
- ACTION_SEND/share target for user-submitted suspicious text, URLs, screenshots, or files.
- Supported browser protection via a browser extension or safe-browsing integration where feasible.
- Use Android APIs appropriate to the detected OS level. No hidden background execution or overlay tricks.
- Foreground service only for a feature that legally and technically qualifies; show persistent notification and controls.
- Never promise automatic inspection of all WhatsApp/SMS/email content. Provide user-authorized notification/link/share analysis instead.
- Do not interfere with normal phone operation. Include battery, CPU, network, and crash monitoring.

B. macOS laboratory and backend
- Python + FastAPI for API and orchestration.
- SQLite for the simplest single-user pilot; PostgreSQL may be added when justified. Avoid needless infrastructure.
- WebSocket/SSE for live event updates.
- Docker Compose for isolated lab services, if Docker is installed.
- A local event bus or bounded asyncio queue for the pilot; add Kafka only if measured throughput requires it.
- A dedicated lab network; never bridge attack containers to the host LAN or public internet by default.
- Optional Zeek/Suricata integration for lab PCAP/network telemetry.
- Optional osquery or macOS Endpoint Security integration only if supported, correctly entitled, and documented. Do not claim deep endpoint visibility without the required privileges/entitlements.
- Local LLM adapter supports Ollama or OpenAI-compatible local endpoint, configurable by environment variables.
- The LLM receives minimized, redacted evidence summaries, not raw secrets. It cannot make final block decisions.
- Threat intelligence importers and rule engine work independently of the LLM.

C. Detection engine
Implement a layered deterministic engine:
1. Exact IOC matching (domain, URL, IP, file hash where applicable).
2. YARA scanning for user-selected files and lab artifacts; no automatic execution.
3. Sigma-compatible event rules where event schema permits.
4. DNS and network metadata analysis.
5. Application permission and package-risk heuristics.
6. Phishing URL and message analysis.
7. Behaviour/sequence rules for suspicious chains.
8. Anomaly scoring only after a labeled dataset and evaluation are available.
9. Context-aware recipient risk; trusted contacts lower nuisance alerts but never bypass strong indicators, OTP/credential requests, impersonation, or account-compromise signals.
10. Correlation across devices using privacy-preserving, pseudonymous indicators.

Every detection must store:
- Detection ID and rule/model version.
- Source event IDs.
- Detection timestamp.
- Device ID and environment (REAL/LAB).
- Evidence fields.
- Confidence method and score, if calibrated.
- Severity and rationale.
- ATT&CK technique mapping where defensible.
- Recommended action and whether action is supported.
- False-positive feedback and analyst disposition.

D. Local LLM analyst
Use local LLM only for:
- Plain-language explanation of structured evidence.
- Incident summaries and user guidance.
- Querying the local threat knowledge base using retrieval.
- Drafting remediation steps from approved playbooks.
Do not let it:
- Invent evidence, claim a leak without evidence, execute shell commands, autonomously block traffic, or make unsupported attribution.
Require JSON-schema output, cite internal event/rule/IOC IDs, and validate output. If the LLM is offline, the product remains functional with deterministic explanations.

## 4. Threat intelligence: data to acquire and maintain

Do not claim “all cybersecurity data” is included. No finite database contains every attack. Build a versioned, source-attributed, updateable intelligence corpus.

Create an ingestion registry with source, data type, access method, terms/license, update frequency, last-success time, record count, hash/checksum, and parsing status. Respect rate limits, API keys, terms of service, and redistribution restrictions. Do not scrape sites in violation of terms.

Priority sources:
1. MITRE ATT&CK Enterprise/Mobile/ICS STIX data — tactics, techniques, sub-techniques, mitigations, groups, software, campaigns. Map only relevant techniques; keep version and STIX IDs.
2. CISA Known Exploited Vulnerabilities catalog — CVEs known to be exploited; do not treat every CVE as active exploitation.
3. NIST National Vulnerability Database feeds/API — CVE metadata, CVSS, CWE, CPE; respect API requirements.
4. CISA advisories and alerts — advisory metadata and references.
5. MISP feeds / community threat sharing — IOC ingestion only after source trust and confidence checks.
6. URLhaus — malicious URL intelligence; use API/feeds under its terms.
7. PhishTank — phishing URL reports; validate feed access and terms.
8. Spamhaus — IP/domain reputation according to applicable access terms.
9. AbuseIPDB — IP reputation via API; key and rate limits required.
10. MalwareBazaar — malware metadata/hashes; never download or execute samples by default.
11. Have I Been Pwned — breach/account checks only through authorized API workflows; never upload passwords. Use k-anonymity or approved breach-check patterns where available.
12. OpenCTI/MISP — optional local knowledge management connectors.
13. SigmaHQ rules — detection rule source; validate log-source compatibility and license.
14. YARA rules — use curated rules with provenance, license and false-positive tests.
15. Zeek/Suricata rules — only compatible, maintained rulesets with license tracking.
16. OWASP Top 10 and OWASP ASVS — web application security taxonomy and control guidance.
17. MITRE D3FEND — defensive countermeasure mapping.
18. Android security bulletins and Apple/macOS security releases — platform vulnerability context.

Dataset/research sources for model development and lab replay:
- CIC-IDS2017 and CSE-CIC-IDS2018.
- CTU-13.
- UNSW-NB15.
- Bot-IoT, where license and research use terms permit.
- Stratosphere IPS datasets.
- Public phishing URL datasets with documented license, date, label quality, and safe handling.
Do not combine datasets blindly. Record schema, collection period, class imbalance, leakage risk, and train/test split methodology. Use time-based and source-separated splits to avoid data leakage. Never include malware binaries in the default pilot.

Create:
- `threat_intel/source_registry.yaml`
- `threat_intel/ingestion_status.json`
- `threat_intel/normalized_iocs.jsonl` or database tables
- `threat_intel/attack_techniques.json`
- `threat_intel/rules/`
- `threat_intel/DATA_PROVENANCE.md`
- `threat_intel/LICENSES.md`

If network access or API credentials are unavailable, implement the importer and show a truthful source status. Do not fill the database with invented indicators. Provide a clearly labeled small set of safe test IOCs in a separate test fixture that cannot trigger production alerts.

## 5. Attack simulation laboratory

Build a polished 3D cyber-range visualization in the web dashboard, but make it a visualization of real lab state, not a fake animation.

- Use Three.js or React Three Fiber.
- Display the Mac host, isolated lab network, real disposable VMs/containers where available, simulated endpoint agents, event streams, attack scenario nodes, detection engine and response outcomes.
- Every rendered endpoint must correspond to a registered lab device record.
- Distinguish REAL devices from LAB devices.
- Simulated endpoints can represent thousands of virtual identities, but label them “simulated endpoints”; do not imply they are physical devices or actually running full OS instances.
- Only show an attack animation when the scenario runner emits a real event.
- Clicking a node shows its event history, scenario, telemetry source, detection result and status.
- Support pause/resume/stop and reset.
- Provide a safe scenario catalogue with preflight checks and clear authorization notice.
- Default to benign telemetry scenarios and replay datasets.
- Atomic Red Team / CALDERA integration may be added only for selected, documented tests in disposable VMs. Require explicit confirmation and preflight isolation checks.
- Never implement exploit payloads, persistence, credential theft, ransomware execution, or destructive actions.
- A “repeat attack” demo should replay a benign, deterministic event sequence and demonstrate matching/correlation. Label it as emulation, not a live exploit.
- Evaluate recall, precision, false-positive rate, time-to-detect, and containment outcome using known ground truth.

Scenario examples:
1. Suspicious DNS lookup to a reserved test domain.
2. Phishing URL submitted through share sheet.
3. Repeated failed login telemetry replay.
4. Unusual process-to-network sequence from synthetic events.
5. Unexpected app permission change event.
6. Sensitive file access followed by unusual outbound metadata (synthetic/replay only).
7. Known test IOC match.
8. Benign family contact sharing scenario to test low false positives.
9. OTP-request scam scenario using synthetic message content.
10. Trusted contact account-compromise scenario to ensure trusted status does not suppress strong indicators.

## 6. Red-and-black UI/UX system

Strict visual palette: black and red only, plus neutral opacity/texture derived from black and red. No blue, green, purple, orange, cyan, or multicolor gradients. Status must be communicated through text/icons/patterns as well as red intensity; do not rely on color alone.

Suggested tokens:
- Background: #050505
- Surface: #101010
- Elevated surface: #171111
- Primary red: #E50914
- Deep red: #8B0000
- Alert red: #FF3030
- Text: #F5F5F5
- Muted text: #A7A7A7
- Border: #352020

Use restrained red accents, high contrast, readable typography, generous spacing, subtle motion, and accessible contrast. Avoid excessive glow, clutter, fake hacker terminal effects, and unreadable tiny text.

Mobile screens:
1. Onboarding and honest capability explanation.
2. Permission center with per-permission purpose and revoke instructions.
3. Device protection home.
4. Live activity timeline.
5. Data exposure details.
6. Scam/message/link analysis.
7. Threat incident detail with evidence and action.
8. Trusted contacts and context settings.
9. Device/network protection settings.
10. Local Mac connection and pairing.
11. Privacy/data retention controls.
12. Lab mode clearly separated from personal protection mode.

Mac dashboard:
1. Overview.
2. 3D cyber range.
3. Endpoint/device registry.
4. Live event stream.
5. Threat intelligence inventory and freshness.
6. Detection rules and ATT&CK explorer.
7. Incidents and evidence.
8. Simulation scenarios and replay.
9. Evaluation metrics.
10. LLM analyst and local model status.
11. Data sources and ingestion health.
12. Privacy, audit and system health.

All controls must work. Disabled controls must say why. No decorative buttons that imply nonexistent actions.

## 7. Required data model

Design migrations and typed schemas for:
- Device
- DevicePairing
- PermissionSnapshot
- AppInventory
- SecurityEvent
- NetworkObservation
- DataAccessObservation
- ThreatIndicator
- ThreatSource
- ThreatTechnique
- DetectionRule
- Detection
- Incident
- IncidentEvidence
- RecipientEntity
- TrustRelationship
- SimulationScenario
- SimulationRun
- SimulatedEndpoint
- EvaluationResult
- LLMExplanation
- UserFeedback
- AuditLog
- ConsentRecord
Include created_at, updated_at, provenance, environment, retention policy and schema version where applicable.

## 8. Functional acceptance criteria

A feature is DONE only if its acceptance test passes.

Android:
- App installs on the actual target phone.
- Onboarding explains limitations and permissions.
- User can pair with Mac using QR or short-lived pairing code.
- Pairing is authenticated and revocable.
- App inventory/permission view uses real Android APIs.
- User can submit a URL/text through Android share sheet and receive an evidence-based analysis.
- Optional notification analysis only processes notifications actually exposed to the service and explicitly opted into.
- Optional VPN mode has a clear persistent notification, start/stop controls, battery test and documented traffic visibility.
- Events are timestamped and stored locally.
- App works when Mac is offline; cloud/local backend features show offline status.
- No fake universal scanning or “all apps monitored” claim.

Mac:
- Backend starts from one documented command.
- Health endpoint reports each component.
- Local LLM connectivity is tested; offline fallback works.
- Threat sources have honest ingestion status.
- IOC/rule matching works on real imported records and safe test fixtures.
- Event stream updates live from real backend events.
- 3D nodes map to actual registered lab entities.
- Lab scenario runner produces auditable events.
- Repeat scenario produces deterministic detection/correlation.
- Evaluation metrics are computed from labeled ground truth.
- Logs and exports separate LAB and REAL events.

Security:
- No secrets committed to repository.
- API authentication and device revocation work.
- Input validation, rate limiting and audit logs are present.
- Local API is not publicly exposed by default.
- Dependency scanning and SBOM generated.
- No malware executed on host.
- No cross-contamination between lab and personal device data.

Performance:
- Measure Android battery impact over at least a representative test window.
- Measure memory, CPU and network overhead.
- Provide graceful degradation.
- Do not claim “zero impact”; publish measured results and test conditions.

## 9. Implementation workflow

Work in this order and do not skip validation:

1. Inspect environment and create `ENVIRONMENT_REPORT.md`.
2. Write product requirements, threat model, data-flow diagram and architecture.
3. Create repository structure, schemas and API contracts.
4. Implement Mac backend, persistence, health checks and local LLM adapter.
5. Implement threat intelligence registry/importers and source status.
6. Implement deterministic detection engine and tests.
7. Implement safe simulation controller, event generator and evaluation harness.
8. Implement 3D visualization connected to real lab records/events.
9. Implement Android app, pairing, app inventory, share analysis and optional integrations.
10. Implement incident detail, evidence explanation and supported response controls.
11. Run end-to-end tests on the actual Android phone and Mac.
12. Run security, privacy, performance and accessibility checks.
13. Generate documentation, SBOM, licenses, pilot guide and demo script.
14. Package release artifacts and report known limitations.

Use incremental commits and keep the project runnable after each milestone. Do not silently replace failing functionality with a mock.

## 10. Required final deliverables

- Complete source repository.
- Android installable APK (and build instructions).
- Mac backend and dashboard launch scripts.
- Docker Compose or alternative lab setup.
- Local LLM setup/configuration guide.
- Threat intelligence source registry and import status.
- Safe scenario catalogue.
- 3D lab dashboard.
- API documentation.
- Database schema/migrations.
- Threat model.
- Privacy policy and data retention policy.
- Data provenance and licenses.
- Test report with actual results.
- Performance report with actual measurements.
- SBOM.
- Known limitations.
- Pilot installation guide.
- Judge demonstration script.
- Architecture diagrams.
- Screenshots captured from the real running build.
- `BUILD_STATUS.md` clearly separating implemented, tested, partially implemented, unavailable, and future capabilities.

## 11. How to behave as the build agent

First inspect the repository and environment. Then present a concise execution plan and immediately begin implementation. Do not ask the user to re-approve every small engineering decision. Ask only when a required credential, device permission, destructive action, or ambiguous product decision blocks safe progress.

Never state that the product is “complete”, “pilot-ready”, “real-time”, or “protects all data” unless the corresponding acceptance tests pass. If a platform restriction prevents a requested capability, implement the strongest supported alternative, explain the limitation in the UI, and record it in `KNOWN_LIMITATIONS.md`.

The objective is an honest, secure, visually excellent, working pilot — not a fictional universal security product.
