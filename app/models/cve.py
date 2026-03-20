from sqlalchemy import cast, func
from sqlalchemy.dialects.postgresql import DOUBLE_PRECISION

from app.extensions import db


class CVE(db.Model):
    __tablename__ = "cve"

    cve_id = db.Column(db.Text, primary_key=True)
    published_date = db.Column(db.Text)
    last_modified_date = db.Column(db.Text)
    description = db.Column(db.Text)
    nodes = db.Column(db.Text)
    severity = db.Column(db.Text)
    obtain_all_privilege = db.Column(db.Text)
    obtain_user_privilege = db.Column(db.Text)
    obtain_other_privilege = db.Column(db.Text)
    user_interaction_required = db.Column(db.Text)
    cvss2_vector_string = db.Column(db.Text)
    cvss2_access_vector = db.Column(db.Text)
    cvss2_access_complexity = db.Column(db.Text)
    cvss2_authentication = db.Column(db.Text)
    cvss2_confidentiality_impact = db.Column(db.Text)
    cvss2_integrity_impact = db.Column(db.Text)
    cvss2_availability_impact = db.Column(db.Text)
    cvss2_base_score = db.Column(db.Text)
    cvss3_vector_string = db.Column(db.Text)
    cvss3_attack_vector = db.Column(db.Text)
    cvss3_attack_complexity = db.Column(db.Text)
    cvss3_privileges_required = db.Column(db.Text)
    cvss3_user_interaction = db.Column(db.Text)
    cvss3_scope = db.Column(db.Text)
    cvss3_confidentiality_impact = db.Column(db.Text)
    cvss3_integrity_impact = db.Column(db.Text)
    cvss3_availability_impact = db.Column(db.Text)
    cvss3_base_score = db.Column(db.Text)
    cvss3_base_severity = db.Column(db.Text)
    exploitability_score = db.Column(db.Text)
    impact_score = db.Column(db.Text)
    ac_insuf_info = db.Column(db.Text)
    reference_json = db.Column(db.Text)
    problemtype_json = db.Column(db.Text)

    @classmethod
    def average_score(cls):
        # cvss3_base_score is stored as text in the source schema.
        return db.session.query(func.avg(cast(cls.cvss3_base_score, DOUBLE_PRECISION))).scalar()
