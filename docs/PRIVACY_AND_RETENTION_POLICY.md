# ADONAI — Privacy Policy & Data Retention Controls

1. **Local-First Processing**: All device observations, app inventories, and incident analyses are stored locally on the user's Android device (Room) and paired Mac host (`adonai_pilot.db`). No telemetry is uploaded to external cloud servers.
2. **Zero Model Training on User Data**: User messages, shared URLs, and notification fields are never used to train or fine-tune any machine learning model.
3. **Automatic Secret Redaction**: Any credential, `Bearer` token, API key, or 16-digit card number present in submitted text is automatically replaced with `[REDACTED_*]` prior to persistence.
4. **Explicit Opt-In & Instant Revocation**: Each telemetry source (`PACKAGE_INVENTORY`, `SHARE_SHEET_ANALYSIS`, `OPT_IN_NOTIFICATION_GUARD`, `OPT_IN_VPN_METADATA`) is governed by a `ConsentRecord` that can be toggled off at any time, plus one-click `DELETE /api/privacy/purge-events` to erase stored records.
5. **Retention Schedule**:
   - `SecurityEvent`, `NetworkObservation`, `DataAccessObservation`: `30d_local`
   - `Detection`, `Incident`, `IncidentEvidence`, `LLMExplanation`: `90d_security`
   - `AuditLog`, `ConsentRecord`: `365d_audit`
