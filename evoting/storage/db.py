"""Persistencia SQLite. Las restricciones UNIQUE hacen atómicos el consumo de token y el anti-replay."""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from evoting.crypto.group import Scalar
from evoting.protocol.models import PublicParams

_SCHEMA = """
CREATE TABLE IF NOT EXISTS elections(
    election_id TEXT PRIMARY KEY, state TEXT NOT NULL,
    params_json TEXT NOT NULL, expediente_json TEXT);
CREATE TABLE IF NOT EXISTS authority_secrets(
    election_id TEXT PRIMARY KEY REFERENCES elections(election_id),
    x_hex TEXT NOT NULL, token_key_hex TEXT NOT NULL, signing_seed_hex TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tokens(
    token_id TEXT PRIMARY KEY, election_id TEXT NOT NULL REFERENCES elections(election_id),
    consumed INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS ballots(
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    election_id TEXT NOT NULL REFERENCES elections(election_id),
    token_id TEXT NOT NULL UNIQUE, ct_hash TEXT NOT NULL UNIQUE, ballot_json TEXT NOT NULL);
"""


class DuplicateError(Exception):
    """Token ya consumido o ciphertext ya registrado."""


class ElectionClosedError(Exception):
    """La elección no está abierta (cerrada o inexistente) al intentar registrar la papeleta."""


class Store:
    def __init__(self, path: str | Path):
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.RLock()
        self._conn.execute("PRAGMA foreign_keys=ON")
        with self._conn:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def _one(self, sql: str, args: tuple = ()):
        with self._lock:
            return self._conn.execute(sql, args).fetchone()

    def save_election(self, params: PublicParams, x: Scalar, token_key: bytes,
                      signing_seed: bytes) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO elections(election_id, state, params_json) VALUES (?, 'open', ?)",
                (params.election_id, json.dumps(params.to_dict())))
            self._conn.execute(
                "INSERT INTO authority_secrets VALUES (?, ?, ?, ?)",
                (params.election_id, x.to_hex(), token_key.hex(), signing_seed.hex()))

    def load_params(self, eid: str) -> PublicParams | None:
        row = self._one("SELECT params_json FROM elections WHERE election_id=?", (eid,))
        return None if row is None else PublicParams.from_dict(json.loads(row[0]))

    def load_authority_secrets(self, eid: str) -> tuple[Scalar, bytes]:
        row = self._one("SELECT x_hex, signing_seed_hex FROM authority_secrets WHERE election_id=?",
                        (eid,))
        if row is None:
            raise KeyError(eid)
        return Scalar.from_hex(row[0]), bytes.fromhex(row[1])

    def load_token_key(self, eid: str) -> bytes:
        row = self._one("SELECT token_key_hex FROM authority_secrets WHERE election_id=?", (eid,))
        if row is None:
            raise KeyError(eid)
        return bytes.fromhex(row[0])

    def get_state(self, eid: str) -> str | None:
        row = self._one("SELECT state FROM elections WHERE election_id=?", (eid,))
        return None if row is None else row[0]

    def set_state(self, eid: str, state: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE elections SET state=? WHERE election_id=?", (state, eid))

    def add_issued_token(self, eid: str, token_id: str) -> None:
        with self._lock, self._conn:
            self._conn.execute("INSERT INTO tokens(token_id, election_id) VALUES (?, ?)",
                               (token_id, eid))

    def count_issued(self, eid: str) -> int:
        return self._one("SELECT COUNT(*) FROM tokens WHERE election_id=?", (eid,))[0]

    def is_consumed(self, token_id: str) -> bool:
        return self._one(
            "SELECT 1 FROM ballots WHERE token_id=? "
            "UNION SELECT 1 FROM tokens WHERE token_id=? AND consumed=1",
            (token_id, token_id)) is not None

    def has_ct_hash(self, h: str) -> bool:
        return self._one("SELECT 1 FROM ballots WHERE ct_hash=?", (h,)) is not None

    def commit_ballot(self, eid: str, token_id: str, ct_hash: str, ballot_json: str) -> None:
        with self._lock:
            try:
                with self._conn:  # una sola transacción: commit o rollback completo
                    row = self._conn.execute(
                        "SELECT state FROM elections WHERE election_id=?", (eid,)).fetchone()
                    if row is None or row[0] != "open":
                        raise ElectionClosedError("La elección no está abierta")
                    self._conn.execute(
                        "INSERT INTO ballots(election_id, token_id, ct_hash, ballot_json) "
                        "VALUES (?, ?, ?, ?)", (eid, token_id, ct_hash, ballot_json))
                    cur = self._conn.execute(
                        "INSERT INTO tokens(token_id, election_id, consumed) VALUES (?, ?, 1) "
                        "ON CONFLICT(token_id) DO UPDATE SET consumed=1 WHERE consumed=0",
                        (token_id, eid))
                    if cur.rowcount != 1:
                        raise DuplicateError("Token ya consumido")
            except sqlite3.IntegrityError as e:
                raise DuplicateError(str(e)) from e

    def accepted_ballots(self, eid: str) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT ballot_json FROM ballots WHERE election_id=? ORDER BY seq", (eid,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def save_expediente(self, eid: str, d: dict) -> None:
        with self._lock, self._conn:
            self._conn.execute("UPDATE elections SET expediente_json=? WHERE election_id=?",
                               (json.dumps(d), eid))

    def load_expediente(self, eid: str) -> dict | None:
        row = self._one("SELECT expediente_json FROM elections WHERE election_id=?", (eid,))
        return None if row is None or row[0] is None else json.loads(row[0])
