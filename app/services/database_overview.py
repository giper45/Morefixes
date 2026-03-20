import math

from sqlalchemy import func, inspect, text

from app.extensions import db
from app.models import CVE, Fix


def get_average_cvss_score():
    values = []
    rows = db.session.query(CVE.cvss3_base_score).filter(CVE.cvss3_base_score.isnot(None)).all()
    for (score,) in rows:
        try:
            numeric_value = float(score)
        except (TypeError, ValueError):
            continue
        if math.isnan(numeric_value):
            continue
        values.append(numeric_value)

    if not values:
        return None
    return round(sum(values) / len(values), 2)


def get_table_overview():
    inspector = inspect(db.engine)
    if db.engine.dialect.name == "postgresql":
        table_names = inspector.get_table_names(schema="public")
    else:
        table_names = []
    if not table_names:
        table_names = inspector.get_table_names()
    table_names = sorted(table_names)
    overview = []
    for table_name in table_names:
        row_count = db.session.execute(text(f'SELECT COUNT(*) FROM "{table_name}"')).scalar() or 0
        overview.append({"table_name": table_name, "row_count": int(row_count)})
    return overview


def get_database_summary():
    total_cve = db.session.query(func.count(CVE.cve_id)).scalar() or 0
    total_fixes = db.session.query(func.count()).select_from(Fix).scalar() or 0
    return {
        "total_cve": int(total_cve),
        "total_fixes": int(total_fixes),
        "average_cvss3": get_average_cvss_score(),
    }


def get_recent_cves(limit=10):
    return CVE.query.order_by(CVE.cve_id.desc()).limit(limit).all()
