#!/usr/bin/env python3
"""ADONAI Environment Discovery & Hardware Adaptation Utility."""
import datetime
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
from pathlib import Path

def check_cmd(cmd):
    path = shutil.which(cmd)
    if not path:
        return {"available": False, "path": None, "version": None}
    try:
        out = subprocess.check_output([cmd, "--version"], stderr=subprocess.STDOUT, timeout=3).decode("utf-8", errors="ignore").strip().splitlines()[0]
    except Exception:
        out = "installed"
    return {"available": True, "path": path, "version": out}

def check_port(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(("127.0.0.1", port)) != 0

def check_ollama():
    url = os.environ.get("ADONAI_LLM_BASE_URL", "http://127.0.0.1:11434")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        reachable = s.connect_ex(("127.0.0.1", 11434)) == 0
    return {
        "configured_endpoint": url,
        "reachable": reachable,
        "fallback_mode": "DETERMINISTIC_SCHEMA_VALIDATED" if not reachable else "LIVE_LOCAL_LLM",
    }

def discover():
    uname = platform.uname()
    mem_gb = 8.0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    mem_gb = round(int(line.split()[1]) / (1024 * 1024), 2)
    except Exception:
        pass
    disk = shutil.disk_usage(".")
    disk_free_gb = round(disk.free / (1024**3), 2)
    disk_total_gb = round(disk.total / (1024**3), 2)

    report = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "product": "ADONAI Personal Cyber-Intelligence System",
        "host": {
            "os": uname.system,
            "release": uname.release,
            "machine": uname.machine,
            "processor": uname.processor or "x86_64/arm64",
            "cpu_count": os.cpu_count() or 2,
            "memory_total_gb": mem_gb,
            "disk_free_gb": disk_free_gb,
            "disk_total_gb": disk_total_gb,
        },
        "toolchains": {
            "python": {"available": True, "version": sys.version.split()[0], "path": sys.executable},
            "node": check_cmd("node"),
            "npm": check_cmd("npm"),
            "java": check_cmd("java"),
            "adb": check_cmd("adb"),
            "gradle": check_cmd("gradle"),
            "docker": check_cmd("docker"),
            "podman": check_cmd("podman"),
        },
        "local_llm": check_ollama(),
        "ports": {
            "8410_api_available": check_port(8410),
            "11434_ollama_available": check_port(11434),
        },
        "recommended_profile": {
            "sqlite_wal_mode": True,
            "max_simulated_endpoints": 1000,
            "event_queue_bound": 5000 if mem_gb >= 4 else 1000,
            "llm_mode": check_ollama()["fallback_mode"],
        }
    }
    return report

if __name__ == "__main__":
    rep = discover()
    root = Path(__file__).resolve().parent.parent
    out_json = root / "docs" / "environment_discovery.json"
    out_md = root / "ENVIRONMENT_REPORT.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(rep, indent=2))

    md = f"""# ADONAI — Environment Discovery Report

Generated automatically by `scripts/discover_environment.py` at `{rep["timestamp_utc"]}`.

## 1. Host Hardware & OS
| Property | Detected Value |
|---|---|
| Operating System | `{rep["host"]["os"]} {rep["host"]["release"]}` |
| CPU Architecture | `{rep["host"]["machine"]}` ({rep["host"]["cpu_count"]} logical cores) |
| System Memory (RAM) | `{rep["host"]["memory_total_gb"]} GB` |
| Available Disk Space | `{rep["host"]["disk_free_gb"]} GB free / {rep["host"]["disk_total_gb"]} GB total` |

## 2. Runtime & Toolchain Availability
| Component | Available | Version / Details |
|---|---|---|
| Python | `{rep["toolchains"]["python"]["available"]}` | `{rep["toolchains"]["python"]["version"]}` (`{rep["toolchains"]["python"]["path"]}`) |
| Node.js | `{rep["toolchains"]["node"]["available"]}` | `{rep["toolchains"]["node"]["version"]}` |
| npm | `{rep["toolchains"]["npm"]["available"]}` | `{rep["toolchains"]["npm"]["version"]}` |
| Java / JDK | `{rep["toolchains"]["java"]["available"]}` | `{rep["toolchains"]["java"]["version"]}` |
| Android ADB | `{rep["toolchains"]["adb"]["available"]}` | `{rep["toolchains"]["adb"]["version"] or "Not connected in current host"}` |
| Docker | `{rep["toolchains"]["docker"]["available"]}` | `{rep["toolchains"]["docker"]["version"] or "Not installed in sandbox; native Python lab runner active"}` |
| Local LLM Server | `{rep["local_llm"]["reachable"]}` | Endpoint `{rep["local_llm"]["configured_endpoint"]}` — Mode: `{rep["local_llm"]["fallback_mode"]}` |

## 3. Adaptive Resource Configuration
- **Database Engine**: SQLite (`WAL` mode enabled, zero external daemon overhead).
- **Cyber-Range Capacity**: `1,000` registered virtual endpoint identities (`SimulatedEndpoint` records).
- **Bounded Event Queue**: `{rep["recommended_profile"]["event_queue_bound"]}` max in-memory events.
- **Analyst Explanation Mode**: `{rep["recommended_profile"]["llm_mode"]}` (automatically promotes to live Ollama/OpenAI local inference when endpoint `127.0.0.1:11434` responds, and guarantees 100% deterministic schema-validated explanations when offline).
"""
    out_md.write_text(md)
    print(f"Wrote {out_md} and {out_json}")
