from app.extensions import db
from app.models import CVE, Fix


def test_health_endpoint_is_public(client):
    response = client.get("/api/health")

    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_cve_requires_authentication(client):
    response = client.get("/api/cve")

    assert response.status_code == 401


def test_cve_crud_flow(client, auth_headers, app_instance):
    create_payload = {
        "cve_id": "CVE-2026-0001",
        "description": "WordPress privilege escalation vulnerability",
        "severity": "HIGH",
        "cvss3_base_score": "8.8",
        "cvss3_base_severity": "HIGH",
    }

    create_response = client.post("/api/cve", json=create_payload, headers=auth_headers)
    assert create_response.status_code == 201
    assert create_response.get_json()["cve_id"] == create_payload["cve_id"]

    list_response = client.get("/api/cve?q=wordpress", headers=auth_headers)
    assert list_response.status_code == 200
    assert len(list_response.get_json()) == 1

    detail_response = client.get(f"/api/cve/{create_payload['cve_id']}", headers=auth_headers)
    assert detail_response.status_code == 200
    assert detail_response.get_json()["severity"] == "HIGH"

    delete_response = client.delete("/api/cve", json={"cve_id": create_payload["cve_id"]}, headers=auth_headers)
    assert delete_response.status_code == 200
    assert delete_response.get_json()["deleted"] == create_payload["cve_id"]

    with app_instance.app_context():
        assert db.session.get(CVE, create_payload["cve_id"]) is None


def test_fixes_crud_flow(client, auth_headers, app_instance):
    with app_instance.app_context():
        db.session.add(CVE(cve_id="CVE-2026-0002", description="Kernel issue"))
        db.session.commit()

    payload = {
        "cve_id": "CVE-2026-0002",
        "hash": "abc123def456",
        "repo_url": "https://github.com/torvalds/linux",
        "rel_type": "patch",
        "score": 93,
        "extraction_status": "ready",
    }

    create_response = client.post("/api/fixes", json=payload, headers=auth_headers)
    assert create_response.status_code == 201
    body = create_response.get_json()
    assert body["commit_url"] == "https://github.com/torvalds/linux/commit/abc123def456"

    list_response = client.get("/api/fixes?q=torvalds", headers=auth_headers)
    assert list_response.status_code == 200
    assert len(list_response.get_json()) == 1

    delete_response = client.delete(
        "/api/fixes",
        json={"cve_id": payload["cve_id"], "hash": payload["hash"], "repo_url": payload["repo_url"]},
        headers=auth_headers,
    )
    assert delete_response.status_code == 200

    with app_instance.app_context():
        assert Fix.by_identity(payload["cve_id"], payload["hash"], payload["repo_url"]) is None


def test_fix_categories_groups_by_inferred_category(client, auth_headers, app_instance):
    with app_instance.app_context():
        db.session.add(
            CVE(
                cve_id="CVE-2026-0003",
                description="WordPress plugin vulnerability",
                cvss3_base_score="7.5",
            )
        )
        db.session.add(
            Fix(
                cve_id="CVE-2026-0003",
                hash="feedbeef",
                repo_url="https://github.com/WordPress/wordpress-develop",
                rel_type="patch",
                score=70,
                extraction_status="ready",
            )
        )
        db.session.commit()

    response = client.get("/api/fixes/categories", headers=auth_headers)

    assert response.status_code == 200
    assert response.get_json() == [{"category": "WordPress", "fixes": 1}]


def test_database_summary_and_tables_expose_visible_data(client, auth_headers, app_instance):
    with app_instance.app_context():
        db.session.add(
            CVE(
                cve_id="CVE-2026-0004",
                description="Visible in database summary",
                cvss3_base_score="9.1",
                severity="CRITICAL",
            )
        )
        db.session.commit()

    summary_response = client.get("/api/database/summary", headers=auth_headers)
    assert summary_response.status_code == 200
    summary_body = summary_response.get_json()
    assert summary_body["total_cve"] >= 1
    assert summary_body["average_cvss3"] == 9.1
    assert summary_body["recent_cves"][0]["cve_id"] == "CVE-2026-0004"

    tables_response = client.get("/api/database/tables", headers=auth_headers)
    assert tables_response.status_code == 200
    tables_body = tables_response.get_json()
    table_names = {row["table_name"] for row in tables_body}
    assert {"cve", "fixes"}.issubset(table_names)


def test_cve_api_normalizes_structured_fields(client, auth_headers, app_instance):
    with app_instance.app_context():
        db.session.add(
            CVE(
                cve_id="CVE-2026-0005",
                description="[{'lang': 'en', 'value': 'Stored XSS in the admin panel.'}]",
                severity="",
                cvss3_base_score="8.1",
                cvss3_base_severity="nan",
                problemtype_json="[{'description': [{'lang': 'en', 'value': 'CWE-79'}]}]",
                reference_json=(
                    "[{'url': 'https://example.test/advisory', 'name': 'Vendor advisory', 'tags': ['Vendor Advisory']}]"
                ),
            )
        )
        db.session.commit()

    response = client.get("/api/cve/CVE-2026-0005", headers=auth_headers)

    assert response.status_code == 200
    body = response.get_json()
    assert body["description"] == "Stored XSS in the admin panel."
    assert body["severity"] == "HIGH"
    assert body["cvss3_base_score"] == 8.1
    assert body["problem_types"] == ["CWE-79"]
    assert body["references"][0]["url"] == "https://example.test/advisory"


def test_cve_api_filters_by_severity_and_cwe(client, auth_headers, app_instance):
    with app_instance.app_context():
        db.session.add(
            CVE(
                cve_id="CVE-2026-0010",
                description="Critical SQL injection",
                severity="CRITICAL",
                problemtype_json="[{'description': [{'lang': 'en', 'value': 'CWE-89'}]}]",
            )
        )
        db.session.add(
            CVE(
                cve_id="CVE-2026-0011",
                description="Medium XSS",
                severity="MEDIUM",
                problemtype_json="[{'description': [{'lang': 'en', 'value': 'CWE-79'}]}]",
            )
        )
        db.session.commit()

    severity_response = client.get("/api/cve?severity=CRITICAL", headers=auth_headers)
    assert severity_response.status_code == 200
    severity_ids = {row["cve_id"] for row in severity_response.get_json()}
    assert "CVE-2026-0010" in severity_ids
    assert "CVE-2026-0011" not in severity_ids

    cwe_response = client.get("/api/cve?cwe=CWE-79", headers=auth_headers)
    assert cwe_response.status_code == 200
    cwe_ids = {row["cve_id"] for row in cwe_response.get_json()}
    assert "CVE-2026-0011" in cwe_ids
    assert "CVE-2026-0010" not in cwe_ids


def test_cve_api_supports_multiselect_filters(client, auth_headers, app_instance):
    with app_instance.app_context():
        db.session.add(
            CVE(
                cve_id="CVE-2026-0020",
                description="High XSS",
                severity="HIGH",
                problemtype_json="[{'description': [{'lang': 'en', 'value': 'CWE-79'}]}]",
            )
        )
        db.session.add(
            CVE(
                cve_id="CVE-2026-0021",
                description="Critical SQLi",
                severity="CRITICAL",
                problemtype_json="[{'description': [{'lang': 'en', 'value': 'CWE-89'}]}]",
            )
        )
        db.session.add(
            CVE(
                cve_id="CVE-2026-0022",
                description="Low path traversal",
                severity="LOW",
                problemtype_json="[{'description': [{'lang': 'en', 'value': 'CWE-22'}]}]",
            )
        )
        db.session.commit()

    response = client.get("/api/cve?severity=HIGH&severity=CRITICAL&cwe=CWE-79&cwe=CWE-89", headers=auth_headers)

    assert response.status_code == 200
    ids = {row["cve_id"] for row in response.get_json()}
    assert "CVE-2026-0020" in ids
    assert "CVE-2026-0021" in ids
    assert "CVE-2026-0022" not in ids


def test_openapi_spec_exposes_current_rest_api(client):
    response = client.get("/api/openapi.json")

    assert response.status_code == 200
    body = response.get_json()
    assert body["openapi"] == "3.0.3"
    assert "/cve" in body["paths"]
    assert "/fixes" in body["paths"]
    assert body["components"]["securitySchemes"]["basicAuth"]["scheme"] == "basic"


def test_swagger_ui_page_is_available(client):
    response = client.get("/api/docs")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "SwaggerUIBundle" in html
    assert "/api/openapi.json" in html


def test_fix_detail_endpoints_expose_nested_commit_file_and_method_data(client, auth_headers, app_instance):
    with app_instance.app_context():
        db.session.add(CVE(cve_id="CVE-2026-3000", description="WordPress detail page"))
        db.session.add(
            Fix(
                cve_id="CVE-2026-3000",
                hash="abc123",
                repo_url="https://github.com/WordPress/wordpress-develop",
                rel_type="patch",
                score=93,
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
                INSERT INTO commits (hash, repo_url, parents, author, committer, msg, author_date, committer_date, num_lines_added, num_lines_deleted)
                VALUES ('abc123', 'https://github.com/WordPress/wordpress-develop', '["prevhash"]', 'dev', 'dev', 'fix issue', '2026-03-20', '2026-03-20', 12, 5)
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

    cve_fixes_response = client.get("/api/cve/CVE-2026-3000/fixes", headers=auth_headers)
    assert cve_fixes_response.status_code == 200
    assert cve_fixes_response.get_json()[0]["hash"] == "abc123"

    fix_detail_response = client.get(
        "/api/fixes/https://github.com/WordPress/wordpress-develop/abc123?cve_id=CVE-2026-3000",
        headers=auth_headers,
    )
    assert fix_detail_response.status_code == 200
    detail_body = fix_detail_response.get_json()
    assert detail_body["cve_id"] == "CVE-2026-3000"
    assert detail_body["files_changed"][0]["filename"] == "src/A.java"
    assert detail_body["files_changed"][0]["methods"][0]["name"] == "doQuery"

    files_response = client.get(
        "/api/fixes/https://github.com/WordPress/wordpress-develop/abc123/files?cve_id=CVE-2026-3000",
        headers=auth_headers,
    )
    assert files_response.status_code == 200
    assert files_response.get_json()["files_changed"][0]["file_change_id"] == 1

    methods_response = client.get(
        "/api/fixes/https://github.com/WordPress/wordpress-develop/abc123/files/1/methods?cve_id=CVE-2026-3000",
        headers=auth_headers,
    )
    assert methods_response.status_code == 200
    assert methods_response.get_json()["methods"][0]["signature"] == "String doQuery(String x)"
