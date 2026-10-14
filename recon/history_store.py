"""Local SQLite persistence for Recon-GUI projects and scan history."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
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

    @contextmanager
    def _connection(self):
        con = self._connect()
        try:
            with con:
                yield con
        finally:
            con.close()

    def _initialize(self):
        with self._connection() as con:
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
            "endpoint_inventory", "parameters", "related_findings",
        ):
            values = report.get(key) or []
            for item in values:
                if isinstance(item, dict):
                    value = str(item.get("value") or item.get("url") or item.get("name") or _json(item))
                    yield key, value, item
                else:
                    yield key, str(item), {}

    @staticmethod
    def _diff(current_pages: list[dict], previous_pages: list[dict], complete: bool = True) -> dict:
        current = {str(p.get("url", "")): p for p in current_pages if p.get("url")}
        previous = {str(p.get("url", "")): p for p in previous_pages if p.get("url")}
        added = sorted(current.keys() - previous.keys())
        # A partial crawl cannot prove pages disappeared; removals are inferred only
        # when the scan completed without a user stop or rate-limit stop.
        removed = sorted(previous.keys() - current.keys()) if complete else []
        changed = sorted(
            url for url in current.keys() & previous.keys()
            if _page_fingerprint(current[url]) != _page_fingerprint(previous[url])
        )
        return {
            "previous_scan_id": None,
            "comparison_status": "complete" if complete else "partial; removals not inferred",
            "added_urls": added,
            "removed_urls": removed,
            "changed_urls": changed,
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
        }

    @staticmethod
    def _entity_map(report: dict, key: str, identity: str):
        result = {}
        for item in report.get(key, []) or []:
            if isinstance(item, dict):
                name = str(item.get(identity) or "")
                # Keep comparable metadata while excluding raw values and unstable ordering.
                metadata = {
                    "sources": sorted(item.get("sources", []) or []),
                    "locations": sorted(item.get("locations", []) or []),
                    "methods": sorted(item.get("methods", []) or []),
                    "classification": item.get("classification", ""),
                    "parameter_count": item.get("parameter_count", 0),
                    "occurrences": item.get("occurrences", 0),
                }
            else:
                name = str(item)
                metadata = {}
            if name:
                result[name] = metadata
        return result

    @classmethod
    def _entity_diff(cls, current: dict, previous: dict, key: str, identity: str, complete: bool):
        current_map = cls._entity_map(current, key, identity)
        previous_map = cls._entity_map(previous, key, identity)
        added = sorted(current_map.keys() - previous_map.keys())
        removed = sorted(previous_map.keys() - current_map.keys()) if complete else []
        changed = sorted(
            name for name in current_map.keys() & previous_map.keys()
            if current_map[name] != previous_map[name]
        )
        return {"added": added, "removed": removed, "changed": changed}

    @staticmethod
    def _finding_keys(report: dict) -> set[str]:
        keys = set()
        for key in ("sensitive_findings", "related_findings"):
            for item in report.get(key, []) or []:
                if isinstance(item, dict):
                    fields = (item.get("type"), item.get("title"), item.get("page"),
                              item.get("source"), item.get("category"), item.get("evidence"))
                    keys.add("|".join(str(value or "") for value in fields))
        return keys

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
            "partial" if (
                report.get("page_limit_reached")
                or report.get("depth_limit_reached")
                or report.get("wordlist_candidate_limit_reached")
                or report.get("wordlist_recursion_depth_limit_reached")
                or report.get("content_limit_reached")
            ) else
            "completed"
        )
        complete = status == "completed"
        stored_report = dict(report)
        # This is a local history, not a raw response archive: never persist response bodies.
        stored_report.pop("page_html", None)
        with self._connection() as con:
            con.execute(
                "INSERT INTO projects(origin, created_at, updated_at) VALUES(?,?,?) "
                "ON CONFLICT(origin) DO UPDATE SET updated_at=excluded.updated_at",
                (origin, now, now),
            )
            project_id = con.execute(
                "SELECT id FROM projects WHERE origin=?", (origin,)
            ).fetchone()["id"]
            prior = con.execute(
                "SELECT id, report_json, status FROM scans WHERE project_id=? AND status='completed' ORDER BY id DESC LIMIT 1",
                (project_id,),
            ).fetchone()
            previous_pages = []
            diff = self._diff(pages, [], complete=complete)
            if prior:
                try:
                    previous = json.loads(prior["report_json"])
                except (TypeError, json.JSONDecodeError):
                    previous = {}
                previous_pages = previous.get("pages") or []
                diff = self._diff(pages, previous_pages, complete=complete)
                diff["previous_scan_id"] = int(prior["id"])
                endpoint_diff = self._entity_diff(report, previous, "endpoint_inventory", "endpoint", complete)
                parameter_diff = self._entity_diff(report, previous, "parameters", "name", complete)
                diff.update({
                    "added_endpoints": endpoint_diff["added"],
                    "removed_endpoints": endpoint_diff["removed"],
                    "changed_endpoints": endpoint_diff["changed"],
                    "added_parameters": parameter_diff["added"],
                    "removed_parameters": parameter_diff["removed"],
                    "changed_parameters": parameter_diff["changed"],
                    "added_endpoint_count": len(endpoint_diff["added"]),
                    "removed_endpoint_count": len(endpoint_diff["removed"]),
                    "changed_endpoint_count": len(endpoint_diff["changed"]),
                    "added_parameter_count": len(parameter_diff["added"]),
                    "removed_parameter_count": len(parameter_diff["removed"]),
                    "changed_parameter_count": len(parameter_diff["changed"]),
                })
                current_findings = self._finding_keys(report)
                previous_findings = self._finding_keys(previous)
                diff["added_findings"] = sorted(current_findings - previous_findings)
                diff["removed_findings"] = sorted(previous_findings - current_findings) if complete else []
                diff["added_finding_count"] = len(diff["added_findings"])
                diff["removed_finding_count"] = len(diff["removed_findings"])
            if not prior:
                diff["comparison_status"] = "first scan; baseline created"
                endpoint_diff = self._entity_diff(report, {}, "endpoint_inventory", "endpoint", complete)
                parameter_diff = self._entity_diff(report, {}, "parameters", "name", complete)
                diff.update({
                    "added_endpoints": endpoint_diff["added"], "removed_endpoints": [],
                    "changed_endpoints": [], "added_parameters": parameter_diff["added"],
                    "removed_parameters": [], "changed_parameters": [],
                    "added_endpoint_count": len(endpoint_diff["added"]),
                    "removed_endpoint_count": 0, "changed_endpoint_count": 0,
                    "added_parameter_count": len(parameter_diff["added"]),
                    "removed_parameter_count": 0, "changed_parameter_count": 0,
                })
            report["history_diff"] = diff
            report["previous_scan_id"] = diff.get("previous_scan_id")
            # Correlate after the previous-scan comparison exists, so newly discovered
            # endpoints/parameters can become transparent review leads.
            from recon.finding_correlator import correlate_findings
            report["related_findings"] = correlate_findings(report)
            if prior:
                current_findings = self._finding_keys(report)
                previous_findings = self._finding_keys(previous)
                diff["added_findings"] = sorted(current_findings - previous_findings)
                diff["removed_findings"] = sorted(previous_findings - current_findings) if complete else []
                diff["added_finding_count"] = len(diff["added_findings"])
                diff["removed_finding_count"] = len(diff["removed_findings"])
            else:
                diff["added_findings"] = [
                    f"{item.get('category', '')}|{item.get('title', '')}"
                    for item in report["related_findings"]
                ]
                diff["added_finding_count"] = len(diff["added_findings"])
                diff["removed_findings"] = []
                diff["removed_finding_count"] = 0
            report["history_diff"] = diff
            stored_report["history_diff"] = diff
            stored_report["previous_scan_id"] = diff.get("previous_scan_id")
            stored_report["related_findings"] = report["related_findings"]
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
                        "added_endpoint_count": diff.get("added_endpoint_count", 0),
                        "added_parameter_count": diff.get("added_parameter_count", 0),
                        "added_finding_count": diff.get("added_finding_count", 0),
                    }),
                ),
            )
            scan_id = int(cursor.lastrowid)
            report["scan_id"] = scan_id
            report["history_database"] = str(self.db_path)
            report["history_status"] = status
            stored_report["scan_id"] = scan_id
            stored_report["history_database"] = str(self.db_path)
            stored_report["history_status"] = status
            con.execute(
                "UPDATE scans SET report_json=? WHERE id=?",
                (_json(stored_report), scan_id),
            )
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
        with self._connection() as con:
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
        with self._connection() as con:
            row = con.execute("SELECT report_json FROM scans WHERE id=?", (int(scan_id),)).fetchone()
        if not row:
            return None
        try:
            return json.loads(row["report_json"])
        except json.JSONDecodeError:
            return None
