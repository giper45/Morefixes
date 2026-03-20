from flask import jsonify, render_template, request, url_for
from sqlalchemy import func
from sqlalchemy import or_

from app.api import api_bp
from app.auth import auth_required
from app.extensions import db
from app.models import CVE, Fix
from app.services.categorization import infer_category
from app.services.cve_presenter import present_cve
from app.services.database_overview import get_database_summary, get_recent_cves, get_table_overview
from app.services.fix_details import get_cve_fix_summaries, get_file_methods, get_fix_detail, get_fix_files
from app.services.openapi import build_openapi_spec


def cve_to_dict(cve: CVE):
    return present_cve(cve)


def fix_to_dict(fix: Fix):
    return {
        "cve_id": fix.cve_id,
        "hash": fix.hash,
        "repo_url": fix.repo_url,
        "rel_type": fix.rel_type,
        "score": fix.score,
        "extraction_status": fix.extraction_status,
        "commit_url": fix.commit_url,
    }


@api_bp.get("/health")
def health():
    return jsonify({"status": "ok"})


@api_bp.get("/openapi.json")
def openapi_spec():
    return jsonify(build_openapi_spec(spec_url=url_for("api.openapi_spec", _external=True)))


@api_bp.get("/docs")
def swagger_ui():
    return render_template("swagger.html", spec_url=url_for("api.openapi_spec"))


@api_bp.get("/database/summary")
@auth_required
def database_summary():
    summary = get_database_summary()
    summary["recent_cves"] = [present_cve(row) for row in get_recent_cves(limit=10)]
    return jsonify(summary)


@api_bp.get("/database/tables")
@auth_required
def database_tables():
    return jsonify(get_table_overview())


@api_bp.route("/cve", methods=["GET", "POST", "DELETE"])
@auth_required
def cve_collection():
    if request.method == "GET":
        q = request.args.get("q", "").strip()
        severities = [value.strip().upper() for value in request.args.getlist("severity") if value.strip()]
        cwe_values = [value.strip() for value in request.args.getlist("cwe") if value.strip()]
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)

        query = CVE.query
        if q:
            ilike_term = f"%{q}%"
            query = query.filter((CVE.cve_id.ilike(ilike_term)) | (CVE.description.ilike(ilike_term)))
        if severities:
            query = query.filter(
                (func.upper(CVE.severity).in_(severities)) | (func.upper(CVE.cvss3_base_severity).in_(severities))
            )
        if cwe_values:
            query = query.filter(or_(*[CVE.problemtype_json.ilike(f"%{cwe}%") for cwe in cwe_values]))

        data = query.order_by(CVE.cve_id).offset(offset).limit(limit).all()
        return jsonify([cve_to_dict(row) for row in data])

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        cve_id = payload.get("cve_id")
        if not cve_id:
            return jsonify({"error": "'cve_id' is required"}), 400

        row = CVE.query.get(cve_id)
        if row is None:
            row = CVE(cve_id=cve_id)
            db.session.add(row)

        updatable = [
            "published_date", "last_modified_date", "description", "nodes", "severity",
            "obtain_all_privilege", "obtain_user_privilege", "obtain_other_privilege",
            "user_interaction_required", "cvss2_vector_string", "cvss2_access_vector",
            "cvss2_access_complexity", "cvss2_authentication", "cvss2_confidentiality_impact",
            "cvss2_integrity_impact", "cvss2_availability_impact", "cvss2_base_score",
            "cvss3_vector_string", "cvss3_attack_vector", "cvss3_attack_complexity",
            "cvss3_privileges_required", "cvss3_user_interaction", "cvss3_scope",
            "cvss3_confidentiality_impact", "cvss3_integrity_impact", "cvss3_availability_impact",
            "cvss3_base_score", "cvss3_base_severity", "exploitability_score", "impact_score",
            "ac_insuf_info", "reference_json", "problemtype_json",
        ]

        for field in updatable:
            if field in payload:
                setattr(row, field, payload[field])

        db.session.commit()
        return jsonify(cve_to_dict(row)), 201

    payload = request.get_json(silent=True) or {}
    cve_id = payload.get("cve_id") or request.args.get("cve_id")
    if not cve_id:
        return jsonify({"error": "'cve_id' is required"}), 400

    row = CVE.query.get(cve_id)
    if not row:
        return jsonify({"error": "CVE not found"}), 404

    db.session.delete(row)
    db.session.commit()
    return jsonify({"deleted": cve_id})


@api_bp.get("/cve/<string:cve_id>")
@auth_required
def cve_detail(cve_id: str):
    row = CVE.query.get_or_404(cve_id)
    return jsonify(cve_to_dict(row))


@api_bp.get("/cve/<string:cve_id>/fixes")
@auth_required
def cve_fix_details(cve_id: str):
    if CVE.query.get(cve_id) is None:
        return jsonify({"error": "CVE not found"}), 404
    return jsonify(get_cve_fix_summaries(cve_id))


@api_bp.route("/fixes", methods=["GET", "POST", "DELETE"])
@auth_required
def fixes_collection():
    if request.method == "GET":
        q = request.args.get("q", "").strip()
        limit = min(int(request.args.get("limit", 50)), 200)
        offset = max(int(request.args.get("offset", 0)), 0)

        query = Fix.query
        if q:
            ilike_term = f"%{q}%"
            query = query.filter((Fix.cve_id.ilike(ilike_term)) | (Fix.repo_url.ilike(ilike_term)) | (Fix.hash.ilike(ilike_term)))

        rows = query.order_by(Fix.cve_id.desc()).offset(offset).limit(limit).all()
        return jsonify([fix_to_dict(row) for row in rows])

    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        required = ["cve_id", "hash", "repo_url"]
        if not all(payload.get(k) for k in required):
            return jsonify({"error": "'cve_id', 'hash', and 'repo_url' are required"}), 400

        row = Fix.by_identity(payload["cve_id"], payload["hash"], payload["repo_url"])
        if row is None:
            row = Fix(cve_id=payload["cve_id"], hash=payload["hash"], repo_url=payload["repo_url"])
            db.session.add(row)

        if "rel_type" in payload:
            row.rel_type = payload["rel_type"]
        if "score" in payload:
            row.score = payload["score"]
        if "extraction_status" in payload:
            row.extraction_status = payload["extraction_status"]

        db.session.commit()
        return jsonify(fix_to_dict(row)), 201

    payload = request.get_json(silent=True) or {}
    cve_id = payload.get("cve_id") or request.args.get("cve_id")
    commit_hash = payload.get("hash") or request.args.get("hash")
    repo_url = payload.get("repo_url") or request.args.get("repo_url")

    if not (cve_id and commit_hash and repo_url):
        return jsonify({"error": "'cve_id', 'hash', and 'repo_url' are required"}), 400

    row = Fix.by_identity(cve_id, commit_hash, repo_url)
    if not row:
        return jsonify({"error": "Fix not found"}), 404

    db.session.delete(row)
    db.session.commit()
    return jsonify({"deleted": {"cve_id": cve_id, "hash": commit_hash, "repo_url": repo_url}})


@api_bp.get("/fixes/categories")
@auth_required
def fixes_categories():
    rows = (
        db.session.query(Fix.repo_url, CVE.description, func.count().label("count"))
        .outerjoin(CVE, CVE.cve_id == Fix.cve_id)
        .group_by(Fix.repo_url, CVE.description)
        .all()
    )

    buckets = {}
    for repo_url, description, count in rows:
        category = infer_category(repo_url, description)
        buckets[category] = buckets.get(category, 0) + int(count)

    return jsonify([
        {"category": category, "fixes": total}
        for category, total in sorted(buckets.items(), key=lambda x: x[1], reverse=True)
    ])


@api_bp.get("/fixes/<path:repo_url>/<string:commit_hash>")
@auth_required
def fix_detail(repo_url: str, commit_hash: str):
    detail = get_fix_detail(repo_url, commit_hash, cve_id=request.args.get("cve_id"))
    if detail is None:
        return jsonify({"error": "Fix not found"}), 404
    return jsonify(detail)


@api_bp.get("/fixes/<path:repo_url>/<string:commit_hash>/files")
@auth_required
def fix_files(repo_url: str, commit_hash: str):
    detail = get_fix_detail(repo_url, commit_hash, cve_id=request.args.get("cve_id"))
    if detail is None:
        return jsonify({"error": "Fix not found"}), 404
    return jsonify({
        "cve_id": detail.get("cve_id"),
        "repo_url": repo_url,
        "hash": commit_hash,
        "files_changed": get_fix_files(repo_url, commit_hash),
    })


@api_bp.get("/fixes/<path:repo_url>/<string:commit_hash>/files/<int:file_change_id>/methods")
@auth_required
def fix_file_methods(repo_url: str, commit_hash: str, file_change_id: int):
    detail = get_fix_detail(repo_url, commit_hash, cve_id=request.args.get("cve_id"))
    if detail is None:
        return jsonify({"error": "Fix not found"}), 404

    files = get_fix_files(repo_url, commit_hash)
    file_row = next((row for row in files if row.get("file_change_id") == file_change_id), None)
    if file_row is None:
        return jsonify({"error": "File change not found"}), 404

    return jsonify({
        "cve_id": detail.get("cve_id"),
        "repo_url": repo_url,
        "hash": commit_hash,
        "file_change_id": file_change_id,
        "filename": file_row.get("filename"),
        "methods": get_file_methods(file_change_id),
    })
