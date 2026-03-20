from __future__ import annotations

import ast
from collections import defaultdict

from sqlalchemy import bindparam, inspect, text

from app.extensions import db


def _table_exists(table_name: str) -> bool:
    return table_name in inspect(db.engine).get_table_names()


def _fetch_all(query_text: str, params: dict | None = None):
    return db.session.execute(text(query_text), params or {}).mappings().all()


def _fetch_one(query_text: str, params: dict | None = None):
    return db.session.execute(text(query_text), params or {}).mappings().first()


def _fetch_all_in(query_text: str, key: str, values: list):
    if not values:
        return []
    stmt = text(query_text).bindparams(bindparam(key, expanding=True))
    return db.session.execute(stmt, {key: values}).mappings().all()


def _to_bool(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "t", "yes", "y"}


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_literal_list(value):
    if value in (None, "", "None"):
        return []
    if isinstance(value, list):
        return value
    try:
        parsed = ast.literal_eval(value)
    except (ValueError, SyntaxError, TypeError):
        return [str(value)]
    return parsed if isinstance(parsed, list) else [parsed]


def _get_fix_rows(repo_url: str, commit_hash: str, cve_id: str | None = None):
    query = """
        SELECT cve_id, hash, repo_url, rel_type, score, extraction_status
        FROM fixes
        WHERE repo_url = :repo_url AND hash = :commit_hash
    """
    params = {"repo_url": repo_url, "commit_hash": commit_hash}
    if cve_id:
        query += " AND cve_id = :cve_id"
        params["cve_id"] = cve_id
    query += " ORDER BY score DESC NULLS LAST, cve_id"
    return _fetch_all(query, params)


def _get_commit_row(repo_url: str, commit_hash: str):
    if not _table_exists("commits"):
        return None

    return _fetch_one(
        """
        SELECT hash, repo_url, parents, author, committer, msg, author_date, committer_date,
               num_lines_added, num_lines_deleted, dmm_unit_complexity, dmm_unit_interfacing, dmm_unit_size
        FROM commits
        WHERE repo_url = :repo_url AND hash = :commit_hash
        """,
        {"repo_url": repo_url, "commit_hash": commit_hash},
    )


def get_fix_files(repo_url: str, commit_hash: str):
    if not _table_exists("file_change"):
        return []

    rows = _fetch_all(
        """
        SELECT file_change_id, hash, filename, old_path, new_path, change_type, diff,
               num_lines_added, num_lines_deleted, code_before, code_after,
               programming_language, complexity, token_count, nloc
        FROM file_change
        WHERE hash = :commit_hash
        ORDER BY file_change_id
        """,
        {"commit_hash": commit_hash},
    )

    return [
        {
            "file_change_id": row.get("file_change_id"),
            "hash": row.get("hash"),
            "filename": row.get("filename"),
            "old_path": row.get("old_path"),
            "new_path": row.get("new_path"),
            "change_type": row.get("change_type"),
            "diff": row.get("diff"),
            "num_lines_added": _safe_int(row.get("num_lines_added")),
            "num_lines_deleted": _safe_int(row.get("num_lines_deleted")),
            "code_before": row.get("code_before"),
            "code_after": row.get("code_after"),
            "programming_language": row.get("programming_language"),
            "complexity": row.get("complexity"),
            "token_count": row.get("token_count"),
            "nloc": row.get("nloc"),
        }
        for row in rows
    ]


def get_file_methods(file_change_id: int):
    if not _table_exists("method_change"):
        return []

    rows = _fetch_all(
        """
        SELECT method_change_id, file_change_id, name, signature, parameters,
               start_line, end_line, code, nloc, complexity, token_count,
               top_nesting_level, before_change
        FROM method_change
        WHERE file_change_id = :file_change_id
        ORDER BY start_line, method_change_id
        """,
        {"file_change_id": file_change_id},
    )

    return [
        {
            "method_change_id": row.get("method_change_id"),
            "file_change_id": row.get("file_change_id"),
            "name": row.get("name"),
            "signature": row.get("signature"),
            "parameters": _parse_literal_list(row.get("parameters")),
            "start_line": _safe_int(row.get("start_line")),
            "end_line": _safe_int(row.get("end_line")),
            "code": row.get("code"),
            "nloc": _safe_int(row.get("nloc")),
            "complexity": row.get("complexity"),
            "token_count": row.get("token_count"),
            "top_nesting_level": _safe_int(row.get("top_nesting_level")),
            "before_change": _to_bool(row.get("before_change")),
        }
        for row in rows
    ]


def get_fix_detail(repo_url: str, commit_hash: str, cve_id: str | None = None):
    fix_rows = _get_fix_rows(repo_url, commit_hash, cve_id=cve_id)
    if not fix_rows:
        return None

    primary_fix = fix_rows[0]
    commit_row = _get_commit_row(repo_url, commit_hash) or {}
    files = get_fix_files(repo_url, commit_hash)
    file_change_ids = [row["file_change_id"] for row in files if row.get("file_change_id") is not None]

    methods_by_file = defaultdict(list)
    if file_change_ids and _table_exists("method_change"):
        method_rows = _fetch_all_in(
            """
            SELECT method_change_id, file_change_id, name, signature, parameters,
                   start_line, end_line, code, nloc, complexity, token_count,
                   top_nesting_level, before_change
            FROM method_change
            WHERE file_change_id IN :file_change_ids
            ORDER BY file_change_id, start_line, method_change_id
            """,
            "file_change_ids",
            file_change_ids,
        )
        for row in method_rows:
            methods_by_file[row.get("file_change_id")].append(
                {
                    "method_change_id": row.get("method_change_id"),
                    "file_change_id": row.get("file_change_id"),
                    "name": row.get("name"),
                    "signature": row.get("signature"),
                    "parameters": _parse_literal_list(row.get("parameters")),
                    "start_line": _safe_int(row.get("start_line")),
                    "end_line": _safe_int(row.get("end_line")),
                    "code": row.get("code"),
                    "nloc": _safe_int(row.get("nloc")),
                    "complexity": row.get("complexity"),
                    "token_count": row.get("token_count"),
                    "top_nesting_level": _safe_int(row.get("top_nesting_level")),
                    "before_change": _to_bool(row.get("before_change")),
                }
            )

    files_changed = []
    for file_row in files:
        file_row["methods"] = methods_by_file.get(file_row.get("file_change_id"), [])
        files_changed.append(file_row)

    repo_url_value = primary_fix.get("repo_url")
    commit_hash_value = primary_fix.get("hash")
    commit_url = None
    if repo_url_value and commit_hash_value:
        commit_url = f"{str(repo_url_value).rstrip('/')}/commit/{commit_hash_value}"

    return {
        "cve_id": primary_fix.get("cve_id"),
        "related_cve_ids": [row.get("cve_id") for row in fix_rows],
        "hash": commit_hash_value,
        "repo_url": repo_url_value,
        "commit_url": commit_url,
        "parents": _parse_literal_list(commit_row.get("parents")),
        "author": commit_row.get("author"),
        "committer": commit_row.get("committer"),
        "author_date": commit_row.get("author_date"),
        "committer_date": commit_row.get("committer_date"),
        "msg": commit_row.get("msg"),
        "num_lines_added": _safe_int(commit_row.get("num_lines_added")),
        "num_lines_deleted": _safe_int(commit_row.get("num_lines_deleted")),
        "score": primary_fix.get("score"),
        "rel_type": primary_fix.get("rel_type"),
        "extraction_status": primary_fix.get("extraction_status"),
        "files_changed": files_changed,
    }


def get_cve_fix_summaries(cve_id: str):
    rows = _fetch_all(
        """
        SELECT f.cve_id, f.hash, f.repo_url, f.rel_type, f.score, f.extraction_status,
               c.author, c.author_date, c.msg, c.num_lines_added, c.num_lines_deleted
        FROM fixes f
        LEFT JOIN commits c ON c.hash = f.hash AND c.repo_url = f.repo_url
        WHERE f.cve_id = :cve_id
        ORDER BY f.score DESC NULLS LAST, f.repo_url, f.hash
        """,
        {"cve_id": cve_id},
    )

    result = []
    for row in rows:
        repo_url = row.get("repo_url")
        commit_hash = row.get("hash")
        result.append(
            {
                "cve_id": row.get("cve_id"),
                "hash": commit_hash,
                "repo_url": repo_url,
                "commit_url": None if not (repo_url and commit_hash) else f"{str(repo_url).rstrip('/')}/commit/{commit_hash}",
                "rel_type": row.get("rel_type"),
                "score": row.get("score"),
                "extraction_status": row.get("extraction_status"),
                "author": row.get("author"),
                "author_date": row.get("author_date"),
                "msg": row.get("msg"),
                "num_lines_added": _safe_int(row.get("num_lines_added")),
                "num_lines_deleted": _safe_int(row.get("num_lines_deleted")),
            }
        )
    return result