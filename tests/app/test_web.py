from app.extensions import db
from app.models import CVE, Fix


def _login_web_session(client):
    with client.session_transaction() as session:
        session["authenticated"] = True
        session["username"] = "swadmin"


def test_cves_page_filters_by_inferred_category(client, app_instance):
    _login_web_session(client)

    with app_instance.app_context():
        db.session.add(
            CVE(
                cve_id="CVE-2026-1000",
                description="WordPress privilege escalation",
                severity="HIGH",
            )
        )
        db.session.add(
            CVE(
                cve_id="CVE-2026-1001",
                description="Linux kernel race condition",
                severity="HIGH",
            )
        )
        db.session.add(
            Fix(
                cve_id="CVE-2026-1000",
                hash="abc123",
                repo_url="https://github.com/WordPress/wordpress-develop",
                rel_type="patch",
                score=80,
                extraction_status="COMPLETED",
            )
        )
        db.session.add(
            Fix(
                cve_id="CVE-2026-1001",
                hash="def456",
                repo_url="https://github.com/torvalds/linux",
                rel_type="patch",
                score=90,
                extraction_status="COMPLETED",
            )
        )
        db.session.commit()

    response = client.get("/cves?category=WordPress")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "CVE-2026-1000" in body
    assert "CVE-2026-1001" not in body


def test_fix_detail_page_renders_nested_file_and_method_data(client, app_instance):
    _login_web_session(client)

    with app_instance.app_context():
        db.session.add(CVE(cve_id="CVE-2026-1002", description="Fix detail"))
        db.session.add(
            Fix(
                cve_id="CVE-2026-1002",
                hash="abc123",
                repo_url="https://github.com/WordPress/wordpress-develop",
                rel_type="patch",
                score=88,
                extraction_status="COMPLETED",
            )
        )
        db.session.commit()
        db.session.execute(
            db.text(
                """
                CREATE TABLE commits (
                    hash TEXT,
                    repo_url TEXT,
                    parents TEXT,
                    author TEXT,
                    committer TEXT,
                    msg TEXT,
                    author_date TEXT,
                    committer_date TEXT,
                    num_lines_added INTEGER,
                    num_lines_deleted INTEGER,
                    dmm_unit_complexity TEXT,
                    dmm_unit_interfacing TEXT,
                    dmm_unit_size TEXT
                )
                """
            )
        )
        db.session.execute(
            db.text(
                """
                CREATE TABLE file_change (
                    file_change_id INTEGER PRIMARY KEY,
                    hash TEXT,
                    filename TEXT,
                    old_path TEXT,
                    new_path TEXT,
                    change_type TEXT,
                    diff TEXT,
                    num_lines_added INTEGER,
                    num_lines_deleted INTEGER,
                    code_before TEXT,
                    code_after TEXT,
                    programming_language TEXT,
                    complexity TEXT,
                    token_count TEXT,
                    nloc INTEGER
                )
                """
            )
        )
        db.session.execute(
            db.text(
                """
                CREATE TABLE method_change (
                    method_change_id INTEGER PRIMARY KEY,
                    file_change_id INTEGER,
                    name TEXT,
                    signature TEXT,
                    parameters TEXT,
                    start_line INTEGER,
                    end_line INTEGER,
                    code TEXT,
                    nloc INTEGER,
                    complexity TEXT,
                    token_count TEXT,
                    top_nesting_level INTEGER,
                    before_change TEXT
                )
                """
            )
        )
        db.session.execute(
            db.text(
                """
                INSERT INTO commits (hash, repo_url, parents, author, committer, msg, num_lines_added, num_lines_deleted)
                VALUES ('abc123', 'https://github.com/WordPress/wordpress-develop', '["prevhash"]', 'dev', 'dev', 'fix issue', 12, 5)
                """
            )
        )
        db.session.execute(
            db.text(
                """
                INSERT INTO file_change (file_change_id, hash, filename, old_path, new_path, change_type, diff, num_lines_added, num_lines_deleted, code_before, code_after, programming_language)
                VALUES (1, 'abc123', 'src/A.java', 'src/A.java', 'src/A.java', 'MODIFY', '@@ ...', 12, 5, 'old', 'new', 'Java')
                """
            )
        )
        db.session.execute(
            db.text(
                """
                INSERT INTO method_change (method_change_id, file_change_id, name, signature, parameters, start_line, end_line, code, before_change)
                VALUES (10, 1, 'doQuery', 'String doQuery(String x)', '["x"]', 40, 78, 'code', 'false')
                """
            )
        )
        db.session.commit()

    response = client.get("/fix-detail?repo_url=https://github.com/WordPress/wordpress-develop&hash=abc123&cve_id=CVE-2026-1002")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Fix Detail" in body
    assert "src/A.java" in body
    assert "doQuery" in body


def test_cve_detail_links_to_fix_detail_page(client, app_instance):
    _login_web_session(client)

    with app_instance.app_context():
        db.session.add(CVE(cve_id="CVE-2026-1003", description="Link to fix detail"))
        db.session.add(
            Fix(
                cve_id="CVE-2026-1003",
                hash="feedbeef",
                repo_url="https://github.com/WordPress/wordpress-develop",
                rel_type="patch",
                score=91,
                extraction_status="COMPLETED",
            )
        )
        db.session.commit()

    response = client.get("/cve/CVE-2026-1003")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "/fix-detail?repo_url=https://github.com/WordPress/wordpress-develop&amp;hash=feedbeef&amp;cve_id=CVE-2026-1003" in body


def test_cve_explorer_shows_fix_coverage_column(client, app_instance):
    _login_web_session(client)

    with app_instance.app_context():
        db.session.add(CVE(cve_id="CVE-2026-1004", description="No fix coverage yet", severity="LOW"))
        db.session.add(CVE(cve_id="CVE-2026-1005", description="Has code details", severity="HIGH"))
        db.session.add(
            Fix(
                cve_id="CVE-2026-1005",
                hash="code123",
                repo_url="https://github.com/WordPress/wordpress-develop",
                rel_type="patch",
                score=95,
                extraction_status="COMPLETED",
            )
        )
        db.session.commit()
        db.session.execute(
            db.text(
                """
                CREATE TABLE file_change (
                    file_change_id INTEGER PRIMARY KEY,
                    hash TEXT,
                    filename TEXT,
                    old_path TEXT,
                    new_path TEXT,
                    change_type TEXT,
                    diff TEXT,
                    num_lines_added INTEGER,
                    num_lines_deleted INTEGER,
                    code_before TEXT,
                    code_after TEXT,
                    programming_language TEXT,
                    complexity TEXT,
                    token_count TEXT,
                    nloc INTEGER
                )
                """
            )
        )
        db.session.execute(
            db.text(
                """
                INSERT INTO file_change (file_change_id, hash, filename, old_path, new_path, change_type)
                VALUES (1, 'code123', 'src/A.java', 'src/A.java', 'src/A.java', 'MODIFY')
                """
            )
        )
        db.session.commit()

    response = client.get("/cves")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Fix Coverage" in body
    assert "No fixes" in body
    assert "Code data" in body


def test_cve_explorer_filters_only_cves_with_commit_changes(client, app_instance):
    _login_web_session(client)

    with app_instance.app_context():
        db.session.add(CVE(cve_id="CVE-2026-1010", description="Has commit changes", severity="HIGH"))
        db.session.add(CVE(cve_id="CVE-2026-1011", description="Only fix reference", severity="HIGH"))
        db.session.add(
            Fix(
                cve_id="CVE-2026-1010",
                hash="commit1010",
                repo_url="https://github.com/WordPress/wordpress-develop",
                rel_type="patch",
                score=90,
                extraction_status="COMPLETED",
            )
        )
        db.session.add(
            Fix(
                cve_id="CVE-2026-1011",
                hash="commit1011",
                repo_url="https://github.com/WordPress/wordpress-develop",
                rel_type="patch",
                score=85,
                extraction_status="NOT_STARTED",
            )
        )
        db.session.commit()
        db.session.execute(
            db.text(
                """
                CREATE TABLE commits (
                    hash TEXT,
                    repo_url TEXT,
                    parents TEXT,
                    author TEXT,
                    committer TEXT,
                    msg TEXT,
                    author_date TEXT,
                    committer_date TEXT,
                    num_lines_added INTEGER,
                    num_lines_deleted INTEGER,
                    dmm_unit_complexity TEXT,
                    dmm_unit_interfacing TEXT,
                    dmm_unit_size TEXT
                )
                """
            )
        )
        db.session.execute(
            db.text(
                """
                INSERT INTO commits (hash, repo_url, author, msg)
                VALUES ('commit1010', 'https://github.com/WordPress/wordpress-develop', 'dev', 'fix')
                """
            )
        )
        db.session.commit()

    response = client.get("/cves?has_commit_changes=1")

    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "CVE-2026-1010" in body
    assert "CVE-2026-1011" not in body