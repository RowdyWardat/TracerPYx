"""Durable, single-node storage for GitHub sessions and PR analysis jobs."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any


def db_path() -> Path:
    configured = os.getenv("TRACERPYX_DB_PATH")
    if configured:
        return Path(configured).expanduser().resolve()
    return Path(__file__).resolve().parents[1] / ".tracerpyx" / "state.sqlite3"


def _connect() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=20)
    try:
        os.chmod(path, 0o600)
    except OSError:
        # Windows ACLs govern access on Windows; POSIX deployments use a private file mode.
        pass
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


def init_db() -> None:
    with _connect() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS github_sessions (
                session_hash TEXT PRIMARY KEY,
                token_ciphertext TEXT NOT NULL,
                login TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pr_jobs (
                job_id TEXT PRIMARY KEY,
                session_hash TEXT NOT NULL,
                cache_key TEXT NOT NULL,
                repo_id INTEGER NOT NULL,
                full_name TEXT NOT NULL,
                pr_number INTEGER NOT NULL,
                base_sha TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                status TEXT NOT NULL,
                stage TEXT NOT NULL,
                result_json TEXT,
                error TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS pr_jobs_cache_idx ON pr_jobs(cache_key, status);
            CREATE INDEX IF NOT EXISTS pr_jobs_owner_idx ON pr_jobs(session_hash, job_id);
            CREATE TABLE IF NOT EXISTS pr_job_access (
                job_id TEXT NOT NULL REFERENCES pr_jobs(job_id) ON DELETE CASCADE,
                session_hash TEXT NOT NULL,
                PRIMARY KEY(job_id, session_hash)
            );
            CREATE TABLE IF NOT EXISTS pr_result_cache (
                cache_key TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                created_at REAL NOT NULL
            );
        """)


def hash_session(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def put_session(session_hash: str, token_ciphertext: str, login: str) -> None:
    with _connect() as db:
        db.execute("INSERT OR REPLACE INTO github_sessions VALUES (?, ?, ?, ?)",
                   (session_hash, token_ciphertext, login, time.time()))


def get_session(session_hash: str) -> dict[str, Any] | None:
    with _connect() as db:
        row = db.execute("SELECT * FROM github_sessions WHERE session_hash=?", (session_hash,)).fetchone()
    return dict(row) if row else None


def delete_session(session_hash: str) -> None:
    with _connect() as db:
        db.execute("DELETE FROM github_sessions WHERE session_hash=?", (session_hash,))


def create_job(*, session_hash: str, cache_key: str, repo_id: int, full_name: str,
               pr_number: int, base_sha: str, head_sha: str,
               force_refresh: bool = False) -> tuple[dict[str, Any], bool]:
    now = time.time()
    with _connect() as db:
        active = None if force_refresh else db.execute("""SELECT * FROM pr_jobs WHERE cache_key=?
            AND status IN ('queued','running') ORDER BY created_at DESC LIMIT 1""", (cache_key,)).fetchone()
        if active:
            db.execute("INSERT OR IGNORE INTO pr_job_access VALUES (?, ?)", (active["job_id"], session_hash))
            return dict(active), True
        completed = None if force_refresh else db.execute("""SELECT j.* FROM pr_jobs j JOIN pr_job_access a ON a.job_id=j.job_id
            WHERE j.cache_key=? AND j.status='complete' AND a.session_hash=? ORDER BY j.created_at DESC LIMIT 1""",
            (cache_key, session_hash)).fetchone()
        if completed:
            return dict(completed), True
        cached = None if force_refresh else db.execute("SELECT result_json FROM pr_result_cache WHERE cache_key=?", (cache_key,)).fetchone()
        job_id = str(uuid.uuid4())
        status = "complete" if cached else "queued"
        stage = "complete" if cached else "queued"
        result_json = cached["result_json"] if cached else None
        db.execute("""INSERT INTO pr_jobs
            (job_id,session_hash,cache_key,repo_id,full_name,pr_number,base_sha,head_sha,status,stage,result_json,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (job_id,session_hash,cache_key,repo_id,full_name,pr_number,base_sha,head_sha,status,stage,result_json,now,now))
        db.execute("INSERT OR IGNORE INTO pr_job_access VALUES (?, ?)", (job_id, session_hash))
        row = db.execute("SELECT * FROM pr_jobs WHERE job_id=?", (job_id,)).fetchone()
        return dict(row), bool(cached)


def update_job(job_id: str, *, status: str | None = None, stage: str | None = None,
               result: dict[str, Any] | None = None, error: str | None = None,
               cache_key: str | None = None) -> None:
    fields: list[str] = ["updated_at=?"]
    values: list[Any] = [time.time()]
    if status is not None:
        fields.append("status=?"); values.append(status)
    if stage is not None:
        fields.append("stage=?"); values.append(stage)
    if result is not None:
        serialized = json.dumps(result, ensure_ascii=False, separators=(",", ":"))
        fields.append("result_json=?"); values.append(serialized)
        if cache_key:
            with _connect() as db:
                db.execute("INSERT OR REPLACE INTO pr_result_cache VALUES (?, ?, ?)", (cache_key, serialized, time.time()))
    if error is not None:
        fields.append("error=?"); values.append(error)
    values.append(job_id)
    with _connect() as db:
        db.execute(f"UPDATE pr_jobs SET {', '.join(fields)} WHERE job_id=?", values)


def get_job(job_id: str, session_hash: str) -> dict[str, Any] | None:
    with _connect() as db:
        row = db.execute("SELECT j.* FROM pr_jobs j JOIN pr_job_access a ON a.job_id=j.job_id WHERE j.job_id=? AND a.session_hash=?", (job_id, session_hash)).fetchone()
    return dict(row) if row else None


def request_cancel(job_id: str, session_hash: str) -> bool:
    with _connect() as db:
        cursor = db.execute("UPDATE pr_jobs SET cancel_requested=1, updated_at=? WHERE job_id=? AND status IN ('queued','running') AND EXISTS (SELECT 1 FROM pr_job_access a WHERE a.job_id=pr_jobs.job_id AND a.session_hash=?)",
                            (time.time(), job_id, session_hash))
        return cursor.rowcount > 0


def cancelled(job_id: str) -> bool:
    with _connect() as db:
        row = db.execute("SELECT cancel_requested FROM pr_jobs WHERE job_id=?", (job_id,)).fetchone()
    return bool(row and row[0])


def mark_orphaned_jobs() -> None:
    with _connect() as db:
        db.execute("UPDATE pr_jobs SET status='failed', stage='interrupted', error='Analysis worker stopped before completion', updated_at=? WHERE status IN ('queued','running')",
                   (time.time(),))


init_db()
