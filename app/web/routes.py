from flask import flash, redirect, render_template, request, session, url_for
from sqlalchemy import func
from sqlalchemy import or_
from urllib.parse import urlencode

from app.auth import credentials_are_valid, web_login_required
from app.extensions import db
from app.models import CVE, Fix
from app.services.categorization import infer_category
from app.services.cve_deep_dive import build_cve_deep_dive
from app.services.cve_presenter import present_cve
from app.services.database_overview import get_database_summary, get_recent_cves, get_table_overview
from app.web import web_bp


@web_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("authenticated"):
        return redirect(url_for("web.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next") or url_for("web.dashboard")

        if credentials_are_valid(username, password):
            session["authenticated"] = True
            session["username"] = username
            return redirect(next_url)

        flash("Invalid username or password.", "danger")

    return render_template("login.html", next=request.args.get("next", url_for("web.dashboard")))


@web_bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("web.login"))


@web_bp.get("/")
@web_login_required
def dashboard():
    summary = get_database_summary()

    category_rows = (
        db.session.query(Fix.repo_url, CVE.description, func.count().label("count"))
        .outerjoin(CVE, CVE.cve_id == Fix.cve_id)
        .group_by(Fix.repo_url, CVE.description)
        .all()
    )

    categories = {}
    for repo_url, description, count in category_rows:
        category = infer_category(repo_url, description)
        categories[category] = categories.get(category, 0) + int(count)

    sorted_categories = sorted(categories.items(), key=lambda item: item[1], reverse=True)

    return render_template(
        "dashboard.html",
        total_cve=summary["total_cve"],
        total_fixes=summary["total_fixes"],
        average_score=summary["average_cvss3"],
        categories=sorted_categories,
        recent_cves=[present_cve(row) for row in get_recent_cves(limit=10)],
    )


@web_bp.get("/cves")
@web_login_required
def cve_table():
    q = request.args.get("q", "").strip()
    selected_severities = [value.strip().upper() for value in request.args.getlist("severity") if value.strip()]
    selected_cwes = [value.strip() for value in request.args.getlist("cwe") if value.strip()]
    page = max(int(request.args.get("page", 1)), 1)
    per_page = min(int(request.args.get("per_page", 50)), 100)

    query = CVE.query
    if q:
        ilike_term = f"%{q}%"
        query = query.filter((CVE.cve_id.ilike(ilike_term)) | (CVE.description.ilike(ilike_term)))
    if selected_severities:
        query = query.filter(
            (func.upper(CVE.severity).in_(selected_severities)) | (func.upper(CVE.cvss3_base_severity).in_(selected_severities))
        )
    if selected_cwes:
        query = query.filter(or_(*[CVE.problemtype_json.ilike(f"%{cwe}%") for cwe in selected_cwes]))

    pagination = query.order_by(CVE.cve_id.desc()).paginate(page=page, per_page=per_page, error_out=False)
    rows = [present_cve(row) for row in pagination.items]

    def build_page_url(page_number: int) -> str:
        params = []
        if q:
            params.append(("q", q))
        for severity in selected_severities:
            params.append(("severity", severity))
        for cwe in selected_cwes:
            params.append(("cwe", cwe))
        params.append(("page", page_number))
        return f"{url_for('web.cve_table')}?{urlencode(params, doseq=True)}"

    prev_url = build_page_url(pagination.prev_num) if pagination.has_prev else None
    next_url = build_page_url(pagination.next_num) if pagination.has_next else None

    return render_template(
        "cves.html",
        pagination=pagination,
        rows=rows,
        q=q,
        selected_severities=selected_severities,
        selected_cwes=selected_cwes,
        prev_url=prev_url,
        next_url=next_url,
    )


@web_bp.get("/database")
@web_login_required
def database_overview():
    return render_template(
        "database.html",
        summary=get_database_summary(),
        tables=get_table_overview(),
        recent_cves=[present_cve(row) for row in get_recent_cves(limit=15)],
    )


@web_bp.get("/fixes")
@web_login_required
def fixes_table():
    q = request.args.get("q", "").strip()
    limit = min(int(request.args.get("limit", 100)), 500)

    query = db.session.query(Fix, CVE.description).outerjoin(CVE, CVE.cve_id == Fix.cve_id)
    if q:
        ilike_term = f"%{q}%"
        query = query.filter((Fix.cve_id.ilike(ilike_term)) | (Fix.repo_url.ilike(ilike_term)) | (Fix.hash.ilike(ilike_term)) | (CVE.description.ilike(ilike_term)))

    rows = query.order_by(Fix.cve_id.desc()).limit(limit).all()
    return render_template("fixes.html", rows=rows, q=q)


@web_bp.get("/cve/<string:cve_id>")
@web_login_required
def cve_detail(cve_id: str):
    row = CVE.query.get_or_404(cve_id)
    cve = present_cve(row)
    deep_dive = build_cve_deep_dive(cve_id, cve)
    return render_template("cve_detail.html", cve=cve, deep_dive=deep_dive)
