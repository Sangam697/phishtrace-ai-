import json
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional
from app.models import DomainAnalysisResponse

DB_PATH = Path(__file__).resolve().parent.parent / "phishguard_scans.db"


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                input_target TEXT NOT NULL,
                normalized_domain TEXT NOT NULL,
                overall_risk_score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                verdict TEXT NOT NULL,
                threat_category TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_scan(result: DomainAnalysisResponse) -> int:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (
                timestamp, input_target, normalized_domain,
                overall_risk_score, risk_level, verdict,
                threat_category, payload_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.timestamp,
                result.input_target,
                result.normalized_domain,
                result.overall_risk_score,
                result.risk_level,
                result.verdict,
                result.ai_report.threat_category,
                result.model_dump_json(),
            ),
        )
        scan_id = cursor.lastrowid
        conn.commit()
        return int(scan_id or 0)


def get_recent_scans(limit: int = 20) -> List[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, timestamp, input_target, normalized_domain,
                   overall_risk_score, risk_level, verdict, threat_category
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, payload_json FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
        if not row:
            return None
        data = json.loads(row["payload_json"])
        data["scan_id"] = row["id"]
        return data


def get_stats() -> Dict[str, Any]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute("SELECT COUNT(*) as cnt FROM scans").fetchone()["cnt"]
        malicious = conn.execute(
            "SELECT COUNT(*) as cnt FROM scans WHERE overall_risk_score >= 70"
        ).fetchone()["cnt"]
        suspicious = conn.execute(
            "SELECT COUNT(*) as cnt FROM scans WHERE overall_risk_score >= 40 AND overall_risk_score < 70"
        ).fetchone()["cnt"]
        safe = conn.execute(
            "SELECT COUNT(*) as cnt FROM scans WHERE overall_risk_score < 40"
        ).fetchone()["cnt"]
        avg_row = conn.execute(
            "SELECT AVG(overall_risk_score) as avg_score FROM scans"
        ).fetchone()
        avg_score = round(float(avg_row["avg_score"] or 0.0), 1)

        return {
            "total_scans": total,
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "safe_count": safe,
            "average_risk_score": avg_score,
        }


def clear_history() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()


# Ensure database table exists on import
init_db()

