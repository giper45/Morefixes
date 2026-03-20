from __future__ import annotations

from sqlalchemy import bindparam, func, inspect, text

from app.extensions import db
from app.models import Fix


def _table_exists(table_name: str) -> bool:
    return table_name in inspect(db.engine).get_table_names()


def get_cve_fix_availability(cve_ids: list[str]) -> dict[str, dict[str, int | str | None]]:
    if not cve_ids:
        return {}

    availability = {
        cve_id: {
            "label": "No fixes",
            "badge": "text-bg-secondary",
            "fix_count": 0,
        }
        for cve_id in cve_ids
    }

    fix_counts = dict(
        db.session.query(Fix.cve_id, func.count().label("fix_count"))
        .filter(Fix.cve_id.in_(cve_ids))
        .group_by(Fix.cve_id)
        .all()
    )

    for cve_id, fix_count in fix_counts.items():
        availability[cve_id] = {
            "label": "Fix refs",
            "badge": "text-bg-warning",
            "fix_count": int(fix_count),
        }

    if _table_exists("commits"):
        stmt = text(
            """
            SELECT DISTINCT f.cve_id
            FROM fixes f
            JOIN commits c ON c.hash = f.hash AND c.repo_url = f.repo_url
            WHERE f.cve_id IN :cve_ids
            """
        ).bindparams(bindparam("cve_ids", expanding=True))
        commit_cve_ids = {row[0] for row in db.session.execute(stmt, {"cve_ids": cve_ids}).all()}
        for cve_id in commit_cve_ids:
            availability[cve_id]["label"] = "Commit data"
            availability[cve_id]["badge"] = "text-bg-info"

    if _table_exists("file_change"):
        stmt = text(
            """
            SELECT DISTINCT f.cve_id
            FROM fixes f
            JOIN file_change fc ON fc.hash = f.hash
            WHERE f.cve_id IN :cve_ids
            """
        ).bindparams(bindparam("cve_ids", expanding=True))
        code_cve_ids = {row[0] for row in db.session.execute(stmt, {"cve_ids": cve_ids}).all()}
        for cve_id in code_cve_ids:
            availability[cve_id]["label"] = "Code data"
            availability[cve_id]["badge"] = "text-bg-success"

    return availability


def get_cve_ids_with_commit_changes() -> set[str]:
    if not _table_exists("commits"):
        return set()

    rows = db.session.execute(
        text(
            """
            SELECT DISTINCT f.cve_id
            FROM fixes f
            JOIN commits c ON c.hash = f.hash AND c.repo_url = f.repo_url
            """
        )
    ).all()
    return {row[0] for row in rows if row and row[0]}