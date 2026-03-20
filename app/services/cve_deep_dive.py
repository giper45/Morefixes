from __future__ import annotations

from collections import defaultdict

from sqlalchemy import bindparam, inspect, text

from app.extensions import db


def _table_exists(table_name: str) -> bool:
    return table_name in inspect(db.engine).get_table_names()


def _fetch_all(query_text: str, params: dict | None = None):
    return db.session.execute(text(query_text), params or {}).mappings().all()


def _fetch_all_in(query_text: str, key: str, values: list[str]):
    if not values:
        return []
    stmt = text(query_text).bindparams(bindparam(key, expanding=True))
    return db.session.execute(stmt, {key: values}).mappings().all()


def _to_bool(value) -> bool:
    return str(value).strip().lower() in {"1", "true", "t", "yes", "y"}


def _safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _safe_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def get_cwe_deep_dive(cve_id: str, problem_types: list[str]):
    if not (_table_exists("cwe") and _table_exists("cwe_classification")):
        return []

    rows = _fetch_all(
        """
        SELECT c.cwe_id, c.cwe_name, c.description, c.extended_description, c.url, c.is_category
        FROM cwe_classification cc
        JOIN cwe c ON c.cwe_id = cc.cwe_id
        WHERE cc.cve_id = :cve_id
        ORDER BY c.cwe_id
        """,
        {"cve_id": cve_id},
    )

    if not rows and problem_types:
        cwe_tokens = sorted({token for token in problem_types if token.upper().startswith("CWE-")})
        rows = _fetch_all_in(
            """
            SELECT cwe_id, cwe_name, description, extended_description, url, is_category
            FROM cwe
            WHERE cwe_id IN :cwe_ids
            ORDER BY cwe_id
            """,
            "cwe_ids",
            cwe_tokens,
        )

    result = []
    for row in rows:
        result.append(
            {
                "cwe_id": row.get("cwe_id"),
                "cwe_name": row.get("cwe_name"),
                "description": row.get("description"),
                "extended_description": row.get("extended_description"),
                "url": row.get("url"),
                "is_category": _to_bool(row.get("is_category")),
            }
        )
    return result


def get_fix_reliability(cve_id: str):
    if not _table_exists("fixes"):
        return []

    rows = _fetch_all(
        """
        SELECT cve_id, hash, repo_url, rel_type, score, extraction_status
        FROM fixes
        WHERE cve_id = :cve_id
        ORDER BY score DESC
        """,
        {"cve_id": cve_id},
    )

    result = []
    for row in rows:
        repo_url = row.get("repo_url")
        commit_hash = row.get("hash")
        commit_url = None
        if repo_url and commit_hash:
            commit_url = f"{str(repo_url).rstrip('/')}/commit/{commit_hash}"

        result.append(
            {
                "cve_id": row.get("cve_id"),
                "hash": commit_hash,
                "repo_url": repo_url,
                "rel_type": row.get("rel_type"),
                "score": row.get("score"),
                "extraction_status": row.get("extraction_status"),
                "commit_url": commit_url,
            }
        )
    return result


def get_project_context(cve_id: str, fix_rows: list[dict]):
    project_links = []
    if _table_exists("cve_project"):
        project_links = _fetch_all(
            """
            SELECT cve, project_url, rel_type, checked
            FROM cve_project
            WHERE cve = :cve_id
            ORDER BY project_url
            """,
            {"cve_id": cve_id},
        )

    repo_candidates = {
        row.get("repo_url") for row in fix_rows if row.get("repo_url")
    } | {
        row.get("project_url") for row in project_links if row.get("project_url")
    }
    repo_urls = sorted(repo_candidates)

    repositories = []
    if repo_urls and _table_exists("repository"):
        repositories = _fetch_all_in(
            """
            SELECT repo_url, repo_name, repo_language, owner, stars_count, forks_count, date_last_push
            FROM repository
            WHERE repo_url IN :repo_urls
            """,
            "repo_urls",
            repo_urls,
        )

    repo_map = {row.get("repo_url"): row for row in repositories}
    result_repos = []
    for repo_url in repo_urls:
        row = repo_map.get(repo_url, {})
        result_repos.append(
            {
                "repo_url": repo_url,
                "repo_name": row.get("repo_name"),
                "repo_language": row.get("repo_language"),
                "owner": row.get("owner"),
                "stars_count": _safe_int(row.get("stars_count")),
                "forks_count": _safe_int(row.get("forks_count")),
                "date_last_push": row.get("date_last_push"),
            }
        )

    result_links = [
        {
            "project_url": row.get("project_url"),
            "rel_type": row.get("rel_type"),
            "checked": _to_bool(row.get("checked")),
        }
        for row in project_links
    ]

    return {"repositories": result_repos, "project_links": result_links}


def get_code_forensics(fix_rows: list[dict]):
    hashes = sorted({row.get("hash") for row in fix_rows if row.get("hash")})
    if not hashes:
        return {
            "file_changes": [],
            "method_changes": [],
            "metrics": {
                "avg_complexity_before": None,
                "avg_complexity_after": None,
                "avg_token_before": None,
                "avg_token_after": None,
                "complexity_delta": None,
                "token_delta": None,
            },
        }

    file_changes = []
    if _table_exists("file_change"):
        file_changes = _fetch_all_in(
            """
            SELECT file_change_id, hash, filename, old_path, new_path, change_type, diff,
                   num_lines_added, num_lines_deleted, code_before, code_after,
                   complexity, token_count, programming_language
            FROM file_change
            WHERE hash IN :hashes
                 ORDER BY num_lines_added DESC, num_lines_deleted DESC
            LIMIT 50
            """,
            "hashes",
            hashes,
        )

    file_change_ids = [row.get("file_change_id") for row in file_changes if row.get("file_change_id") is not None]
    method_changes = []
    if file_change_ids and _table_exists("method_change"):
        method_changes = _fetch_all_in(
            """
            SELECT method_change_id, file_change_id, name, signature, parameters,
                   complexity, token_count, before_change
            FROM method_change
            WHERE file_change_id IN :file_change_ids
            ORDER BY file_change_id, before_change DESC
            """,
            "file_change_ids",
            file_change_ids,
        )

    before_complexity = []
    after_complexity = []
    before_tokens = []
    after_tokens = []

    for row in method_changes:
        complexity = _safe_float(row.get("complexity"))
        tokens = _safe_float(row.get("token_count"))
        is_before = _to_bool(row.get("before_change"))
        if is_before:
            if complexity is not None:
                before_complexity.append(complexity)
            if tokens is not None:
                before_tokens.append(tokens)
        else:
            if complexity is not None:
                after_complexity.append(complexity)
            if tokens is not None:
                after_tokens.append(tokens)

    def avg(values):
        if not values:
            return None
        return round(sum(values) / len(values), 2)

    avg_complexity_before = avg(before_complexity)
    avg_complexity_after = avg(after_complexity)
    avg_token_before = avg(before_tokens)
    avg_token_after = avg(after_tokens)

    return {
        "file_changes": [dict(row) for row in file_changes],
        "method_changes": [dict(row) for row in method_changes],
        "metrics": {
            "avg_complexity_before": avg_complexity_before,
            "avg_complexity_after": avg_complexity_after,
            "avg_token_before": avg_token_before,
            "avg_token_after": avg_token_after,
            "complexity_delta": None if (avg_complexity_before is None or avg_complexity_after is None) else round(avg_complexity_after - avg_complexity_before, 2),
            "token_delta": None if (avg_token_before is None or avg_token_after is None) else round(avg_token_after - avg_token_before, 2),
        },
    }


def get_commit_timeline(fix_rows: list[dict]):
    hashes = sorted({row.get("hash") for row in fix_rows if row.get("hash")})
    if not hashes or not _table_exists("commits"):
        return {"commits": [], "lines_added": 0, "lines_deleted": 0}

    rows = _fetch_all_in(
        """
        SELECT hash, repo_url, author, author_date, msg, num_lines_added, num_lines_deleted,
               dmm_unit_complexity, dmm_unit_interfacing, dmm_unit_size
        FROM commits
        WHERE hash IN :hashes
         ORDER BY author_date DESC
        """,
        "hashes",
        hashes,
    )

    total_added = sum(_safe_int(row.get("num_lines_added")) for row in rows)
    total_deleted = sum(_safe_int(row.get("num_lines_deleted")) for row in rows)

    return {
        "commits": [dict(row) for row in rows],
        "lines_added": total_added,
        "lines_deleted": total_deleted,
    }


def build_cve_deep_dive(cve_id: str, presentable_cve: dict):
    cwe_deep_dive = get_cwe_deep_dive(cve_id, presentable_cve.get("problem_types") or [])
    fix_reliability = get_fix_reliability(cve_id)
    code_forensics = get_code_forensics(fix_reliability)
    project_context = get_project_context(cve_id, fix_reliability)
    commit_timeline = get_commit_timeline(fix_reliability)

    method_map = defaultdict(list)
    for method in code_forensics["method_changes"]:
        method_map[method.get("file_change_id")].append(method)

    for file_change in code_forensics["file_changes"]:
        file_change["methods"] = method_map.get(file_change.get("file_change_id"), [])

    return {
        "cwe_deep_dive": cwe_deep_dive,
        "fix_reliability": fix_reliability,
        "code_forensics": code_forensics,
        "project_context": project_context,
        "commit_timeline": commit_timeline,
    }
