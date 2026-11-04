# ADONAI — Environment Discovery Report

Generated automatically by `scripts/discover_environment.py` at `2026-11-04T17:51:17.548613+00:00`.

## 1. Host Hardware & OS
| Property | Detected Value |
|---|---|
| Operating System | `Darwin 25.5.0` |
| CPU Architecture | `arm64` (10 logical cores) |
| System Memory (RAM) | `8.0 GB` |
| Available Disk Space | `46.31 GB free / 460.38 GB total` |

## 2. Runtime & Toolchain Availability
| Component | Available | Version / Details |
|---|---|---|
| Python | `True` | `3.14.7` (`/opt/homebrew/opt/python@3.14/bin/python3.14`) |
| Node.js | `True` | `v20.20.2` |
| npm | `True` | `10.8.2` |
| Java / JDK | `True` | `installed` |
| Android ADB | `False` | `Not connected in current host` |
| Docker | `True` | `WARNING: Error loading config file: open /Users/benny/.docker/config.json: operation not permitted` |
| Local LLM Server | `False` | Endpoint `http://127.0.0.1:11434` — Mode: `DETERMINISTIC_SCHEMA_VALIDATED` |

## 3. Adaptive Resource Configuration
- **Database Engine**: SQLite (`WAL` mode enabled, zero external daemon overhead).
- **Cyber-Range Capacity**: `1,000` registered virtual endpoint identities (`SimulatedEndpoint` records).
- **Bounded Event Queue**: `5000` max in-memory events.
- **Analyst Explanation Mode**: `DETERMINISTIC_SCHEMA_VALIDATED` (automatically promotes to live Ollama/OpenAI local inference when endpoint `127.0.0.1:11434` responds, and guarantees 100% deterministic schema-validated explanations when offline).
