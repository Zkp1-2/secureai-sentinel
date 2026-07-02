from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from app.schemas.analysis import AnalysisResponse

DB_PATH = Path(__file__).resolve().parents[2] / "data" / "secureai_sentinel.db"


class StorageService:
    def __init__(self, db_path: Path = DB_PATH) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT DEFAULT '',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(project_id) REFERENCES projects(id)
                );
                CREATE TABLE IF NOT EXISTS finding_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER NOT NULL,
                    finding_index INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    owner TEXT DEFAULT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(analysis_id, finding_index),
                    FOREIGN KEY(analysis_id) REFERENCES analyses(id)
                );
                """
            )

    def create_project(self, name: str, description: str = "") -> Dict[str, Any]:
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO projects(name, description, created_at) VALUES (?, ?, ?)",
                (name, description, created_at),
            )
            project_id = int(cur.lastrowid)
        return {"id": project_id, "name": name, "description": description, "created_at": created_at}

    def list_projects(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute("SELECT id, name, description, created_at FROM projects ORDER BY id DESC").fetchall()
        return [dict(row) for row in rows]

    def save_analysis(self, project_id: int, analysis: AnalysisResponse) -> Dict[str, Any]:
        created_at = datetime.now(timezone.utc).isoformat()
        payload = analysis.model_dump()
        with self._connect() as conn:
            if not conn.execute("SELECT id FROM projects WHERE id=?", (project_id,)).fetchone():
                raise ValueError(f"Project {project_id} does not exist")
            cur = conn.execute(
                "INSERT INTO analyses(project_id, title, severity, score, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (project_id, analysis.title, analysis.risk.severity, analysis.risk.score, json.dumps(payload, ensure_ascii=False), created_at),
            )
            analysis_id = int(cur.lastrowid)
        return {"id": analysis_id, "project_id": project_id, "title": analysis.title, "severity": analysis.risk.severity, "score": analysis.risk.score, "created_at": created_at}

    def list_analyses(self, project_id: int | None = None) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            if project_id is None:
                rows = conn.execute("SELECT id, project_id, title, severity, score, created_at FROM analyses ORDER BY id DESC LIMIT 200").fetchall()
            else:
                rows = conn.execute("SELECT id, project_id, title, severity, score, created_at FROM analyses WHERE project_id=? ORDER BY id DESC LIMIT 200", (project_id,)).fetchall()
        return [dict(row) for row in rows]

    def get_analysis_payload(self, analysis_id: int) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT payload_json FROM analyses WHERE id=?", (analysis_id,)).fetchone()
        if not row:
            raise ValueError(f"Analysis {analysis_id} does not exist")
        return json.loads(row["payload_json"])

    def update_finding_status(self, analysis_id: int, finding_index: int, status: str, owner: str | None = None) -> Dict[str, Any]:
        updated_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            if not conn.execute("SELECT id FROM analyses WHERE id=?", (analysis_id,)).fetchone():
                raise ValueError(f"Analysis {analysis_id} does not exist")
            conn.execute(
                """
                INSERT INTO finding_status(analysis_id, finding_index, status, owner, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(analysis_id, finding_index)
                DO UPDATE SET status=excluded.status, owner=excluded.owner, updated_at=excluded.updated_at
                """,
                (analysis_id, finding_index, status, owner, updated_at),
            )
        return {"analysis_id": analysis_id, "finding_index": finding_index, "status": status, "owner": owner, "updated_at": updated_at}
