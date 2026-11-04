# ADONAI — Local LLM Setup & Offline Fallback Guide

## 1. Supported Local Runtimes
ADONAI connects to a user-controlled local inference server on `127.0.0.1:11434` (Ollama or any OpenAI-compatible local server) and never sends telemetry to cloud LLM APIs by default.

```bash
# Optional: Start Ollama locally on macOS/Linux
ollama serve
ollama pull llama3.2:3b-instruct-local

# Configure ADONAI (optional environment variables)
export ADONAI_LLM_BASE_URL="http://127.0.0.1:11434"
export ADONAI_LLM_MODEL="llama3.2:3b-instruct-local"
```

## 2. Deterministic Fallback Guarantee
If Ollama is not installed or is offline, `backend/llm_analyst.py` automatically detects that `127.0.0.1:11434` is unreachable and switches to `DETERMINISTIC_FALLBACK`. It constructs a complete, JSON-schema-validated explanation citing exact `incident_id`, `detection_id`, `event_id`, and MITRE ATT&CK IDs so the product never fails or hallucinates when offline.
