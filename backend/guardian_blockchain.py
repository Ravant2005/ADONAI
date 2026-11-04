"""ADONAI Guardian — Local Blockchain Hash Registry.

Implements a local append-only blockchain for media authenticity anchoring.
Each block contains: block_index, previous_hash, timestamp, media_hash,
device_id, metadata_json, block_hash.
Also provides stub interface for external chain (Ethereum/Polygon) lookup.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import random
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = Path(__file__).parent / "adonai_pilot.db"
GENESIS_PREV_HASH = "0" * 64  # genesis block previous hash


# ---------------------------------------------------------------------------
# GuardianBlockchain
# ---------------------------------------------------------------------------

class GuardianBlockchain:
    """SQLite-backed append-only blockchain for media authenticity records.

    Thread-safe via per-instance lock + SQLite WAL mode.
    """

    TABLE_DDL = """
    CREATE TABLE IF NOT EXISTS GuardianBlockchain (
        block_id TEXT PRIMARY KEY,
        block_index INTEGER NOT NULL,
        previous_hash TEXT NOT NULL,
        block_timestamp TEXT NOT NULL,
        media_hash TEXT NOT NULL,
        device_id TEXT NOT NULL,
        media_type TEXT NOT NULL DEFAULT 'unknown',
        watermark_payload TEXT NOT NULL DEFAULT '',
        metadata_json TEXT NOT NULL DEFAULT '{}',
        block_hash TEXT NOT NULL UNIQUE,
        provenance TEXT NOT NULL DEFAULT 'guardian_blockchain',
        created_at TEXT NOT NULL
    );
    """

    INDEX_DDL = """
    CREATE INDEX IF NOT EXISTS idx_guardian_media_hash
        ON GuardianBlockchain (media_hash);
    """

    def __init__(self, db_path_or_conn=None) -> None:
        """Accept either a file path string/Path, or an existing sqlite3.Connection.
        When a connection is passed (from main.py), use it directly — this ensures
        all operations share the same transaction as the caller."""
        import sqlite3 as _sqlite3
        if isinstance(db_path_or_conn, _sqlite3.Connection):
            self._conn = db_path_or_conn
            self._db_path = None
            self._external_conn = True
            # Ensure table exists on the passed connection
            self._conn.execute(self.TABLE_DDL)
            self._conn.execute(self.INDEX_DDL)
        else:
            self._db_path = str(db_path_or_conn) if db_path_or_conn else str(DEFAULT_DB_PATH)
            self._conn = None
            self._external_conn = False
            self._init_db()
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        if self._external_conn and self._conn is not None:
            return self._conn
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _release(self, conn: sqlite3.Connection) -> None:
        """Only close the connection if we opened it ourselves."""
        if not self._external_conn:
            conn.close()

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.execute(self.TABLE_DDL)
            conn.execute(self.INDEX_DDL)
            conn.commit()
            self._release(conn)

    def _compute_block_hash(
        self,
        block_index: int,
        previous_hash: str,
        timestamp: str | float,
        media_hash: str,
        device_id: str,
        media_type: str,
        watermark_payload: str,
        metadata_json: str,
    ) -> str:
        """Deterministic SHA-256 of all block fields."""
        raw = "|".join([
            str(block_index),
            previous_hash,
            str(timestamp),
            media_hash,
            device_id,
            media_type,
            watermark_payload,
            metadata_json,
        ])
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _get_last_block(self, conn: sqlite3.Connection) -> Optional[sqlite3.Row]:
        return conn.execute(
            "SELECT * FROM GuardianBlockchain ORDER BY block_index DESC LIMIT 1"
        ).fetchone()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_media(
        self,
        media_hash: str,
        device_id: str,
        media_type: str = "unknown",
        watermark_payload: str = "",
        metadata: dict | None = None,
    ) -> str:
        """Append a new block for a media file. Returns the new block_id."""
        metadata_json = json.dumps(metadata or {}, separators=(",", ":"))
        timestamp_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self._lock:
            conn = self._connect()
            last = self._get_last_block(conn)
            if last is None:
                previous_hash = GENESIS_PREV_HASH
                next_index = 1
            else:
                previous_hash = last["block_hash"]
                next_index = int(last["block_index"]) + 1

            block_hash = self._compute_block_hash(
                next_index, previous_hash, timestamp_str,
                media_hash, device_id, media_type,
                watermark_payload, metadata_json,
            )
            block_id = f"blk-{uuid.uuid4().hex[:10]}"

            conn.execute(
                """
                INSERT INTO GuardianBlockchain
                    (block_id, block_index, previous_hash, block_timestamp, media_hash, device_id,
                     media_type, watermark_payload, metadata_json, block_hash, provenance, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'guardian_blockchain', ?)
                """,
                (block_id, next_index, previous_hash, timestamp_str, media_hash, device_id,
                 media_type, watermark_payload, metadata_json, block_hash, timestamp_str),
            )
            conn.commit()
            self._release(conn)
            return block_id

    def lookup_media(self, media_hash: str) -> Optional[dict]:
        """Return the earliest block for the given media_hash, or None."""
        conn = self._connect()
        row = conn.execute(
            "SELECT * FROM GuardianBlockchain WHERE media_hash = ? ORDER BY block_index ASC LIMIT 1",
            (media_hash,),
        ).fetchone()
        self._release(conn)
        if row is None:
            return None
        return dict(row)

    def verify_chain_integrity(self) -> dict:
        """Walk the full chain and verify every block's hash and linkage.

        Returns:
            {valid: bool, block_count: int, broken_at: Optional[int]}
        """
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM GuardianBlockchain ORDER BY block_index ASC"
        ).fetchall()
        self._release(conn)

        if not rows:
            return {"valid": True, "block_count": 0, "broken_at": None}

        prev_hash = GENESIS_PREV_HASH
        for row in rows:
            t_val = row["block_timestamp"] if "block_timestamp" in row.keys() else row["timestamp"]
            expected_hash = self._compute_block_hash(
                row["block_index"], row["previous_hash"], t_val,
                row["media_hash"], row["device_id"], row["media_type"],
                row["watermark_payload"], row["metadata_json"],
            )
            if row["block_hash"] != expected_hash:
                return {"valid": False, "block_count": len(rows), "broken_at": row["block_index"]}
            if row["previous_hash"] != prev_hash:
                return {"valid": False, "block_count": len(rows), "broken_at": row["block_index"]}
            prev_hash = row["block_hash"]

        return {"valid": True, "block_count": len(rows), "broken_at": None}

    def get_recent_registrations(self, limit: int = 20) -> list:
        """Return the most recent *limit* blocks (newest first)."""
        conn = self._connect()
        rows = conn.execute(
            "SELECT * FROM GuardianBlockchain ORDER BY block_index DESC LIMIT ?",
            (limit,),
        ).fetchall()
        self._release(conn)
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# MockExternalChain
# ---------------------------------------------------------------------------

class MockExternalChain:
    """Simulates an Ethereum/Polygon blockchain lookup for media hash anchoring.

    No actual network calls are made. Provides realistic latency simulation
    and deterministic confidence scores based on hash characteristics.
    """

    # Simulated known-good hashes (in a real system these would come from on-chain data)
    _SIMULATED_REGISTRY: dict[str, dict] = {}

    def __init__(self, network: str = "polygon-mumbai") -> None:
        self.network = network

    def _simulate_tx_hash(self, media_hash: str) -> str:
        """Deterministically generate a fake transaction hash."""
        return "0x" + hashlib.sha256(f"mock_tx:{media_hash}".encode()).hexdigest()

    def _simulate_latency(self) -> None:
        """Simulate realistic RPC call latency (50–350ms)."""
        # We use a no-op sleep simulation — in prototype mode we just delay slightly
        # time.sleep(random.uniform(0.05, 0.35))  # commented out to keep tests fast
        pass

    def register_on_chain(self, media_hash: str, metadata: dict | None = None) -> dict:
        """Simulate submitting a transaction to register a media hash on-chain.

        Returns:
            {success: bool, tx_hash: str, block_number: int, gas_used: int}
        """
        self._simulate_latency()
        tx_hash = self._simulate_tx_hash(media_hash)
        block_number = random.randint(40_000_000, 50_000_000)
        gas_used = random.randint(21_000, 65_000)
        # Store in local simulation registry
        self._SIMULATED_REGISTRY[media_hash] = {
            "tx_hash": tx_hash,
            "block_number": block_number,
            "gas_used": gas_used,
            "metadata": metadata or {},
            "network": self.network,
        }
        return {
            "success": True,
            "tx_hash": tx_hash,
            "block_number": block_number,
            "gas_used": gas_used,
            "network": self.network,
        }

    def lookup_on_chain(self, media_hash: str) -> dict:
        """Look up a media hash on the simulated external chain.

        Returns:
            {found: bool, tx_hash: Optional[str], confidence: float,
             block_number: Optional[int], network: str}
        """
        self._simulate_latency()

        # Check simulated local registry first
        if media_hash in self._SIMULATED_REGISTRY:
            entry = self._SIMULATED_REGISTRY[media_hash]
            return {
                "found": True,
                "tx_hash": entry["tx_hash"],
                "confidence": 0.97,
                "block_number": entry["block_number"],
                "network": self.network,
            }

        # Deterministic pseudo-random result based on hash prefix
        # (simulates ~15% chance of finding old entries in a demo dataset)
        seed_val = int(media_hash[:8], 16)
        rng = random.Random(seed_val)
        found = rng.random() < 0.15
        if found:
            return {
                "found": True,
                "tx_hash": self._simulate_tx_hash(media_hash),
                "confidence": round(rng.uniform(0.70, 0.90), 3),
                "block_number": rng.randint(38_000_000, 42_000_000),
                "network": self.network,
            }
        return {
            "found": False,
            "tx_hash": None,
            "confidence": 0.0,
            "block_number": None,
            "network": self.network,
        }
