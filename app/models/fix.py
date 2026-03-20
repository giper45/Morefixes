from sqlalchemy import and_

from app.extensions import db


class Fix(db.Model):
    __tablename__ = "fixes"

    cve_id = db.Column(db.Text, primary_key=True)
    hash = db.Column(db.Text, primary_key=True)
    repo_url = db.Column(db.Text, primary_key=True)
    rel_type = db.Column(db.Text)
    score = db.Column(db.BigInteger)
    extraction_status = db.Column(db.Text)

    @property
    def commit_url(self):
        if self.repo_url and self.hash:
            return f"{self.repo_url.rstrip('/')}/commit/{self.hash}"
        return None

    @classmethod
    def by_identity(cls, cve_id: str, commit_hash: str, repo_url: str):
        return cls.query.filter(
            and_(
                cls.cve_id == cve_id,
                cls.hash == commit_hash,
                cls.repo_url == repo_url,
            )
        ).first()
