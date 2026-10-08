"""
Leviathan OSINT v4.0 — Microkernel 3: Storage
SQLite WAL + FTS5 + JSON1 · Escritura en batch · Audit log inmutable
"""
from __future__ import annotations
import asyncio
import json
import logging
import sqlite3
import time
from pathlib import Path
from core.models import EntityRecord, Correlation, ModuleResult, Target, ScanState

log = logging.getLogger("leviathan.k3")

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS targets (
    id          TEXT PRIMARY KEY,
    raw         TEXT NOT NULL,
    normalized  TEXT NOT NULL,
    type        TEXT NOT NULL,
    started_at  REAL NOT NULL,
    finished_at REAL,
    risk_score  INTEGER DEFAULT 0,
    risk_level  TEXT DEFAULT 'NINGUNO',
    metadata    TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS entities (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES targets(id),
    type        TEXT NOT NULL,
    value       TEXT NOT NULL,
    confidence  REAL NOT NULL,
    verdict     TEXT NOT NULL,
    sources     TEXT DEFAULT '[]',
    flags       TEXT DEFAULT '[]',
    metadata    TEXT DEFAULT '{}',
    module_id   TEXT NOT NULL,
    emitted_at  REAL NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS entities_fts USING fts5(
    value, type, verdict, module_id,
    content='entities', content_rowid='rowid'
);

CREATE TABLE IF NOT EXISTS correlations (
    id          TEXT PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES targets(id),
    entity_a    TEXT NOT NULL,
    entity_b    TEXT NOT NULL,
    rel_type    TEXT NOT NULL,
    confidence  REAL NOT NULL,
    evidence    TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS module_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT NOT NULL REFERENCES targets(id),
    module_id   TEXT NOT NULL,
    module_name TEXT NOT NULL,
    status      TEXT NOT NULL,
    entities_out INTEGER DEFAULT 0,
    duration_ms REAL DEFAULT 0,
    error       TEXT,
    ts          REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS module_health (
    module_id       TEXT PRIMARY KEY,
    module_name     TEXT NOT NULL,
    status          TEXT DEFAULT 'OK',
    last_checked    REAL,
    consecutive_failures INTEGER DEFAULT 0,
    last_entities   INTEGER DEFAULT 0,
    last_duration_ms REAL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS learned_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type   TEXT NOT NULL,
    target_type TEXT NOT NULL,
    module_id   TEXT,
    region      TEXT,
    confidence  REAL DEFAULT 0.5,
    sample_count INTEGER DEFAULT 1,
    created_at  REAL NOT NULL,
    updated_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    scan_id     TEXT,
    action      TEXT NOT NULL,
    detail      TEXT,
    operator    TEXT DEFAULT 'leviathan'
);
"""

class K3Storage:
    """
    Microkernel 3 — Persistencia SQLite.
    Escritura en batch (hasta 50 ops/flush).
    Audit log inmutable.
    """

    def __init__(self, db_path: str = "database/leviathan.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._buffer_entities:      list[EntityRecord] = []
        self._buffer_correlations:  list[Correlation]  = []
        self._buffer_module_results: list[ModuleResult] = []
        self._batch_size = 50
        self._lock       = asyncio.Lock()
        self._conn:      sqlite3.Connection | None = None

    def init(self):
        """Inicializar base de datos y schema."""
        self._conn = sqlite3.connect(
            str(self.db_path),
            check_same_thread=False,
            isolation_level=None,  # autocommit
        )
        self._conn.executescript(SCHEMA)
        self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        log.info(f"K3 Storage initialized: {self.db_path}")

    def _conn_safe(self) -> sqlite3.Connection:
        if self._conn is None:
            self.init()
        return self._conn  # type: ignore

    # ─── Targets ──────────────────────────────────────────────────────────────

    def save_target(self, target: Target):
        conn = self._conn_safe()
        conn.execute("""
            INSERT OR REPLACE INTO targets (id, raw, normalized, type, started_at, metadata)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (target.scan_id, target.raw, target.normalized,
              target.type.value, target.started_at, json.dumps(target.metadata)))
        self._audit("TARGET_STARTED", target.scan_id, target.normalized)

    def finish_target(self, scan_id: str, risk_score: int, risk_level: str):
        conn = self._conn_safe()
        conn.execute("""
            UPDATE targets SET finished_at=?, risk_score=?, risk_level=? WHERE id=?
        """, (time.time(), risk_score, risk_level, scan_id))
        self._audit("SCAN_COMPLETE", scan_id, f"risk={risk_score}")

    # ─── Entities (batched) ───────────────────────────────────────────────────

    def buffer_entity(self, record: EntityRecord):
        self._buffer_entities.append(record)
        if len(self._buffer_entities) >= self._batch_size:
            self._flush_entities()

    def _flush_entities(self):
        if not self._buffer_entities:
            return
        conn = self._conn_safe()
        batch = self._buffer_entities[:]
        self._buffer_entities.clear()
        with conn:
            for r in batch:
                conn.execute("""
                    INSERT OR IGNORE INTO entities
                    (id, scan_id, type, value, confidence, verdict, sources, flags, metadata, module_id, emitted_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (r.id, r.scan_id, r.type.value, r.value, r.confidence,
                      r.verdict.value, json.dumps(r.sources), json.dumps(r.flags),
                      json.dumps(r.metadata), r.module_id, r.emitted_at))
            conn.executemany("""
                INSERT INTO entities_fts(rowid, value, type, verdict, module_id)
                SELECT rowid, value, type, verdict, module_id FROM entities
                WHERE id IN ({})
            """.format(",".join("?" * len(batch))),
                [r.id for r in batch]
            )
        log.debug(f"Flushed {len(batch)} entities to SQLite")

    # ─── Correlations (batched) ───────────────────────────────────────────────

    def buffer_correlation(self, corr: Correlation):
        self._buffer_correlations.append(corr)
        if len(self._buffer_correlations) >= self._batch_size:
            self._flush_correlations()

    def _flush_correlations(self):
        if not self._buffer_correlations:
            return
        conn = self._conn_safe()
        batch = self._buffer_correlations[:]
        self._buffer_correlations.clear()
        with conn:
            for c in batch:
                conn.execute("""
                    INSERT OR IGNORE INTO correlations
                    (id, scan_id, entity_a, entity_b, rel_type, confidence, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (c.id, c.scan_id, c.entity_a, c.entity_b,
                      c.rel_type, c.confidence, json.dumps(c.evidence)))

    # ─── Module results ───────────────────────────────────────────────────────

    def save_module_result(self, result: ModuleResult):
        conn = self._conn_safe()
        conn.execute("""
            INSERT INTO module_results
            (scan_id, module_id, module_name, status, entities_out, duration_ms, error, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (result.scan_id, result.module_id, result.module_name, result.status.value,
              result.entities_out, result.duration_ms, result.error, time.time()))

    # ─── Health ───────────────────────────────────────────────────────────────

    def update_module_health(self, module_id: str, module_name: str,
                             status: str, entities: int, duration_ms: float):
        conn = self._conn_safe()
        failures = 0
        if status == "FAILED":
            row = conn.execute(
                "SELECT consecutive_failures FROM module_health WHERE module_id=?",
                (module_id,)
            ).fetchone()
            failures = (row[0] + 1) if row else 1

        conn.execute("""
            INSERT OR REPLACE INTO module_health
            (module_id, module_name, status, last_checked, consecutive_failures, last_entities, last_duration_ms)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (module_id, module_name, status, time.time(), failures, entities, duration_ms))

    def get_deprecated_modules(self) -> list[str]:
        conn = self._conn_safe()
        rows = conn.execute(
            "SELECT module_id FROM module_health WHERE consecutive_failures >= 3"
        ).fetchall()
        return [r[0] for r in rows]

    def reset_module_health(self, module_id: str):
        conn = self._conn_safe()
        conn.execute(
            "UPDATE module_health SET consecutive_failures=0, status='OK' WHERE module_id=?",
            (module_id,)
        )

    # ─── FTS5 search ──────────────────────────────────────────────────────────

    def search_entities(self, query: str, scan_id: str = "") -> list[dict]:
        conn = self._conn_safe()
        sql  = """
            SELECT e.id, e.type, e.value, e.confidence, e.verdict, e.flags
            FROM entities e
            JOIN entities_fts f ON e.rowid = f.rowid
            WHERE entities_fts MATCH ?
        """
        params: list = [query]
        if scan_id:
            sql += " AND e.scan_id = ?"
            params.append(scan_id)
        rows = conn.execute(sql, params).fetchall()
        return [
            {"id": r[0], "type": r[1], "value": r[2],
             "confidence": r[3], "verdict": r[4], "flags": json.loads(r[5])}
            for r in rows
        ]

    def get_entities(self, scan_id: str, verdict: str = "", entity_type: str = "",
                     min_confidence: float = 0.0) -> list[dict]:
        conn = self._conn_safe()
        sql  = "SELECT * FROM entities WHERE scan_id=?"
        params: list = [scan_id]
        if verdict:
            sql += " AND verdict=?"; params.append(verdict)
        if entity_type:
            sql += " AND type=?"; params.append(entity_type)
        if min_confidence > 0:
            sql += " AND confidence>=?"; params.append(min_confidence)
        rows = conn.execute(sql, params).fetchall()
        cols = ["id","scan_id","type","value","confidence","verdict",
                "sources","flags","metadata","module_id","emitted_at"]
        return [dict(zip(cols, r)) for r in rows]

    # ─── Learned rules ────────────────────────────────────────────────────────

    def save_learned_rule(self, rule_type: str, target_type: str,
                          module_id: str, region: str, confidence: float):
        conn = self._conn_safe()
        now  = time.time()
        existing = conn.execute(
            "SELECT id, sample_count FROM learned_rules WHERE rule_type=? AND target_type=? AND module_id=?",
            (rule_type, target_type, module_id)
        ).fetchone()
        if existing:
            new_conf = (existing[1] * confidence + confidence) / (existing[1] + 1)
            conn.execute(
                "UPDATE learned_rules SET confidence=?, sample_count=sample_count+1, updated_at=? WHERE id=?",
                (new_conf, now, existing[0])
            )
        else:
            conn.execute(
                "INSERT INTO learned_rules (rule_type,target_type,module_id,region,confidence,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
                (rule_type, target_type, module_id, region, confidence, now, now)
            )

    # ─── Audit ────────────────────────────────────────────────────────────────

    def _audit(self, action: str, scan_id: str = "", detail: str = ""):
        try:
            conn = self._conn_safe()
            conn.execute(
                "INSERT INTO audit_log (ts, scan_id, action, detail) VALUES (?,?,?,?)",
                (time.time(), scan_id, action, detail)
            )
        except Exception as e:
            log.error(f"Audit log error: {e}")

    # ─── Flush all buffers ────────────────────────────────────────────────────

    def flush_all(self):
        self._flush_entities()
        self._flush_correlations()

    def close(self):
        self.flush_all()
        if self._conn:
            self._conn.close()
