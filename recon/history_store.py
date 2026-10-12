"""Local SQLite persistence for Recon-GUI projects and scan history."""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


def default_database_path() -> Path:
    """Return a per-user path suitable for Windows, macOS, and Linux."""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("XDG_DATA_HOME")
    root = Path(base) / "Recon-GUI" if base else Path.home() / ".recon-gui"
    return root / "history.sqlite3"


def project_key(target: str) -> str:
    """Group scans by origin so different start paths on one site share a history."""
    parsed = urlsplit((target or "").strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("target must be a valid HTTP(S) URL")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    port = parsed.port
    default = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    netloc = f"[{host}]" if ":" in host else host
    if port and not default:
        netloc += f":{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "/", "", ""))


def _json(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


def _page_fingerprint(page: dict) -> tuple:
    return (
        page.get("status"), page.get("final_url") or page.get("url"),
        page.get("title") or "", page.get("content_hash") or "",
        page.get("text_hash") or "", page.get("content_length") or 0,
    )


class HistoryStore:
    """SQLite-backed project and scan history; stored reports exclude response bodies."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path) if db_path else default_database_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self):
        con = sqlite3.connect(str(self.db_path), timeout=10)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON")
        con.execute("PRAGMA busy_timeout = 10000")
        return con

    def _initialize(self):
        with self._connect() as con:
            con.executescript("""
                CREATE TABLE IF NOT EXISTS projects (
                    id INTEGER PRIMARY KEY,
                    origin TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY,
                    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    page_count INTEGER NOT NULL DEFAULT 0,
                    report_json TEXT NOT NULL,
                    summary_json TEXT NOT NULL DEFAULT '{}'
                );
                CREATE INDEX IF NOT EXISTS idx_scans_project_date
                    ON scans(project_id, id DESC);
                CREATE TABLE IF NOT EXISTS pages (
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    url TEXT NOT NULL,
                    status INTEGER,
                    title TEXT NOT NULL DEFAULT '',
                    final_url TEXT NOT NULL DEFAULT '',
                    word_count INTEGER NOT NULL DEFAULT 0,
                    content_length INTEGER NOT NULL DEFAULT 0,
                    content_hash TEXT NOT NULL DEFAULT '',
                    text_hash TEXT NOT NULL DEFAULT '',
                    content_type TEXT NOT NULL DEFAULT '',
                    depth INTEGER NOT NULL DEFAULT 0,
                    error TEXT NOT NULL DEFAULT '',
                    PRIMARY KEY(scan_id, url)
                );
                CREATE TABLE IF NOT EXISTS findings (
                    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    value TEXT NOT NULL,
                    details_json TEXT NOT NULL DEFAULT '{}',
                    UNIQUE(scan_id, kind, value)
                );
            """)

    @staticmethod
    def _findings(report: dict):
        for key in (
            "emails", "subdomains", "endpoints", "discovered_routes",
            "js_files", "source_maps", "sensitive_findings", "forms",
            "json_ld", "passive_subdomains", "historical_urls",
        ):
            values = report.get(key) or []
            for item in values:
                if isinstance(item, dict):
                    value = str(item.get("value") or item.get("url") or item.get("name") or _json(item))
                    yield key, value, item
                else:
                    yield key, str(item), {}

    @staticmethod
    def _diff(current_pages: list[dict], previous_pages: list[dict]) -> dict:
        current = {str(p.get("url", "")): p for p in current_pages if p.get("url")}
        previous = {str(p.get("url", "")): p for p in previous_pages if p.get("url")}
        added = sorted(current.keys() - previous.keys())
        removed = sorted(previous.keys() - current.keys())
        changed = sorted(
            url for url in current.keys() & previous.keys()
            if _page_fingerprint(current[url]) != _page_fingerprint(previous[url])
        )
        return {
            "previous_scan_id": None,
            "added_urls": added,
            "removed_urls": removed,
            "changed_urls": changed,
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
        }

    def save_report(self, report: dict) -> dict:
        """Atomically persist one completed/partial scan and attach a diff to its report."""
        report = dict(report or {})
        target = str(report.get("target") or "")
        origin = project_key(target)
        now = datetime.now(timezone.utc).isoformat(timespec="seconds")
        pages = report.get("pages") or []
        status = (
            "stopped" if report.get("stopped_by_user") else
            "rate-limited" if report.get("crawler_rate_limited_stop") or report.get("wordlist_rate_limited_stop") else
            "completed"
        )
        stored_report = dict(report)
        # This is a local history, not a raw response archive: never persist response bodies.
        stored_report.pop("page_html", None)
        with self._connect() as con:
            con.execute(
                "INSERT INTO projects(origin, created_at, updated_at) VALUES(?,?,?) "
                "ON CONFLICT(origin) DO UPDATE SET updated_at=excluded.updated_at",
                (origin, now, now),
            )
            project_id = con.execute(
                "SELECT id FROM projects WHERE origin=?", (origin,)
            ).fetchone()["id"]
            prior = con.execute(
                "SELECT id, report_json FROM scans WHERE project_id=? ORDER BY id DESC LIMIT 1",
                (project_id,),
            ).fetchone()
            previous_pages = []
            diff = self._diff(pages, [])
            if prior:
                try:
                    previous = json.loads(prior["report_json"])
                except (TypeError, json.JSONDecodeError):
                    previous = {}
                previous_pages = previous.get("pages") or []
                diff = self._diff(pages, previous_pages)
                diff["previous_scan_id"] = int(prior["id"])
            report["history_diff"] = diff
            report["previous_scan_id"] = diff.get("previous_scan_id")
            stored_report["history_diff"] = diff
            stored_report["previous_scan_id"] = diff.get("previous_scan_id")
            serialized = _json(stored_report)
            cursor = con.execute(
                """INSERT INTO scans(project_id,target,started_at,completed_at,status,
                   page_count,report_json,summary_json) VALUES(?,?,?,?,?,?,?,?)""",
                (
                    project_id, target, str(report.get("started_at") or now), now,
                    status, len(pages), serialized, _json({
                        "added_count": diff["added_count"],
                        "removed_count": diff["removed_count"],
                        "changed_count": diff["changed_count"],
                    }),
                ),
            )
            scan_id = int(cursor.lastrowid)
            for page in pages:
                if not page.get("url"):
                    continue
                con.execute(
                    """INSERT OR REPLACE INTO pages
                    (scan_id,url,status,title,final_url,word_count,content_length,
                     content_hash,text_hash,content_type,depth,error)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        scan_id, str(page.get("url")), page.get("status"),
                        str(page.get("title") or ""), str(page.get("final_url") or ""),
                        int(page.get("word_count") or 0), int(page.get("content_length") or 0),
                        str(page.get("content_hash") or ""), str(page.get("text_hash") or ""),
                        str(page.get("content_type") or ""), int(page.get("depth") or 0),
                        str(page.get("error") or ""),
                    ),
                )
            for kind, value, details in self._findings(report):
                con.execute(
                    "INSERT OR IGNORE INTO findings(scan_id,kind,value,details_json) VALUES(?,?,?,?)",
                    (scan_id, kind, value, _json(details)),
                )
        report["scan_id"] = scan_id
        report["history_database"] = str(self.db_path)
        report["history_status"] = status
        report["recent_scans"] = self.recent_scans(target)
        return report

    def recent_scans(self, target: str, limit: int = 20) -> list[dict]:
        origin = project_key(target)
        limit = max(1, min(int(limit), 100))
        with self._connect() as con:
            rows = con.execute(
                """SELECT s.id,s.target,s.started_at,s.completed_at,s.status,s.page_count,
                          s.summary_json
                   FROM scans s JOIN projects p ON p.id=s.project_id
                   WHERE p.origin=? ORDER BY s.id DESC LIMIT ?""",
                (origin, limit),
            ).fetchall()
        results = []
        for row in rows:
            try:
                summary = json.loads(row["summary_json"] or "{}")
            except json.JSONDecodeError:
                summary = {}
            results.append({
                "scan_id": row["id"], "target": row["target"],
                "started_at": row["started_at"], "completed_at": row["completed_at"],
                "status": row["status"], "page_count": row["page_count"],
                **summary,
            })
        return results

    def get_scan(self, scan_id: int) -> dict | None:
        with self._connect() as con:
            row = con.execute("SELECT report_json FROM scans WHERE id=?", (int(scan_id),)).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["report_json"])
        except json.JSONDecodeError:
            return None
