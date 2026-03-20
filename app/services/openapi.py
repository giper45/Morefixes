def build_openapi_spec(spec_url: str):
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "MoreFixes REST API",
            "version": "1.0.0",
            "description": "REST API for browsing CVEs, fixes, and database summaries from MoreFixes.",
        },
        "servers": [{"url": "/api", "description": "Current application"}],
        "components": {
            "securitySchemes": {
                "basicAuth": {
                    "type": "http",
                    "scheme": "basic",
                    "description": "Use the same Basic Auth credentials configured for the API.",
                }
            },
            "schemas": {
                "Health": {
                    "type": "object",
                    "properties": {"status": {"type": "string", "example": "ok"}},
                    "required": ["status"],
                },
                "ProblemReference": {
                    "type": "object",
                    "additionalProperties": True,
                },
                "CVE": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string", "example": "CVE-2026-0001"},
                        "published_date": {"type": "string", "nullable": True},
                        "last_modified_date": {"type": "string", "nullable": True},
                        "description": {"type": "string", "nullable": True},
                        "severity": {"type": "string", "nullable": True, "example": "HIGH"},
                        "cvss3_base_score": {"type": "number", "nullable": True, "example": 8.8},
                        "cvss3_base_severity": {"type": "string", "nullable": True, "example": "HIGH"},
                        "problem_types": {
                            "type": "array",
                            "items": {"type": "string"},
                            "example": ["CWE-79"],
                        },
                        "references": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/ProblemReference"},
                        },
                    },
                    "required": ["cve_id"],
                },
                "Fix": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string", "example": "CVE-2026-0002"},
                        "hash": {"type": "string", "example": "abc123def456"},
                        "repo_url": {"type": "string", "example": "https://github.com/torvalds/linux"},
                        "rel_type": {"type": "string", "nullable": True, "example": "patch"},
                        "score": {"type": "integer", "nullable": True, "example": 93},
                        "extraction_status": {"type": "string", "nullable": True, "example": "ready"},
                        "commit_url": {
                            "type": "string",
                            "nullable": True,
                            "example": "https://github.com/torvalds/linux/commit/abc123def456",
                        },
                    },
                    "required": ["cve_id", "hash", "repo_url"],
                },
                "MethodChange": {
                    "type": "object",
                    "properties": {
                        "method_change_id": {"type": "integer", "example": 10},
                        "file_change_id": {"type": "integer", "example": 1},
                        "name": {"type": "string", "example": "doQuery"},
                        "signature": {"type": "string", "nullable": True, "example": "String doQuery(String x)"},
                        "parameters": {"type": "array", "items": {"type": "string"}},
                        "start_line": {"type": "integer", "nullable": True, "example": 40},
                        "end_line": {"type": "integer", "nullable": True, "example": 78},
                        "code": {"type": "string", "nullable": True},
                        "before_change": {"type": "boolean", "example": False},
                    },
                },
                "FileChange": {
                    "type": "object",
                    "properties": {
                        "file_change_id": {"type": "integer", "example": 1},
                        "filename": {"type": "string", "nullable": True, "example": "src/A.java"},
                        "old_path": {"type": "string", "nullable": True},
                        "new_path": {"type": "string", "nullable": True},
                        "change_type": {"type": "string", "nullable": True, "example": "MODIFY"},
                        "diff": {"type": "string", "nullable": True},
                        "num_lines_added": {"type": "integer", "nullable": True, "example": 12},
                        "num_lines_deleted": {"type": "integer", "nullable": True, "example": 5},
                        "code_before": {"type": "string", "nullable": True},
                        "code_after": {"type": "string", "nullable": True},
                        "programming_language": {"type": "string", "nullable": True, "example": "Java"},
                        "methods": {"type": "array", "items": {"$ref": "#/components/schemas/MethodChange"}},
                    },
                },
                "FixDetail": {
                    "type": "object",
                    "properties": {
                        "cve_id": {"type": "string", "example": "CVE-2024-8162"},
                        "related_cve_ids": {"type": "array", "items": {"type": "string"}},
                        "hash": {"type": "string", "example": "a1b2c3"},
                        "repo_url": {"type": "string", "example": "https://github.com/org/repo"},
                        "parents": {"type": "array", "items": {"type": "string"}},
                        "author": {"type": "string", "nullable": True},
                        "msg": {"type": "string", "nullable": True},
                        "score": {"type": "integer", "nullable": True, "example": 93},
                        "rel_type": {"type": "string", "nullable": True, "example": "patch"},
                        "files_changed": {"type": "array", "items": {"$ref": "#/components/schemas/FileChange"}},
                    },
                    "required": ["cve_id", "hash", "repo_url", "files_changed"],
                },
                "CategoryBucket": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "example": "WordPress"},
                        "fixes": {"type": "integer", "example": 237},
                    },
                    "required": ["category", "fixes"],
                },
                "DatabaseSummary": {
                    "type": "object",
                    "properties": {
                        "total_cve": {"type": "integer"},
                        "total_fixes": {"type": "integer"},
                        "average_cvss3": {"type": "number", "nullable": True},
                        "recent_cves": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/CVE"},
                        },
                    },
                },
                "TableOverview": {
                    "type": "object",
                    "properties": {
                        "table_name": {"type": "string"},
                        "row_count": {"type": "integer"},
                    },
                },
                "Error": {
                    "type": "object",
                    "properties": {
                        "error": {"type": "string"},
                    },
                    "required": ["error"],
                },
            },
        },
        "paths": {
            "/health": {
                "get": {
                    "summary": "Health check",
                    "responses": {
                        "200": {
                            "description": "Service is available",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Health"}}},
                        }
                    },
                }
            },
            "/database/summary": {
                "get": {
                    "summary": "Get database summary",
                    "security": [{"basicAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Database summary",
                            "content": {
                                "application/json": {"schema": {"$ref": "#/components/schemas/DatabaseSummary"}}
                            },
                        },
                        "401": {"description": "Authentication required"},
                    },
                }
            },
            "/database/tables": {
                "get": {
                    "summary": "List database tables and row counts",
                    "security": [{"basicAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Table overview",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/TableOverview"},
                                    }
                                }
                            },
                        },
                        "401": {"description": "Authentication required"},
                    },
                }
            },
            "/cve": {
                "get": {
                    "summary": "List CVEs",
                    "security": [{"basicAuth": []}],
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                        {
                            "name": "severity",
                            "in": "query",
                            "schema": {"type": "array", "items": {"type": "string"}},
                            "style": "form",
                            "explode": True,
                        },
                        {
                            "name": "cwe",
                            "in": "query",
                            "schema": {"type": "array", "items": {"type": "string"}},
                            "style": "form",
                            "explode": True,
                        },
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
                        {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}},
                    ],
                    "responses": {
                        "200": {
                            "description": "Matching CVEs",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "array", "items": {"$ref": "#/components/schemas/CVE"}}
                                }
                            },
                        },
                        "401": {"description": "Authentication required"},
                    },
                },
                "post": {
                    "summary": "Create or update a CVE",
                    "security": [{"basicAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CVE"}}},
                    },
                    "responses": {
                        "201": {
                            "description": "CVE created or updated",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CVE"}}},
                        },
                        "400": {
                            "description": "Invalid request",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                        },
                        "401": {"description": "Authentication required"},
                    },
                },
                "delete": {
                    "summary": "Delete a CVE",
                    "security": [{"basicAuth": []}],
                    "parameters": [
                        {"name": "cve_id", "in": "query", "schema": {"type": "string"}},
                    ],
                    "requestBody": {
                        "required": False,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {"cve_id": {"type": "string"}},
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "CVE deleted"},
                        "400": {
                            "description": "Missing cve_id",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                        },
                        "404": {
                            "description": "CVE not found",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                        },
                        "401": {"description": "Authentication required"},
                    },
                },
            },
            "/cve/{cve_id}": {
                "get": {
                    "summary": "Get one CVE",
                    "security": [{"basicAuth": []}],
                    "parameters": [
                        {"name": "cve_id", "in": "path", "required": True, "schema": {"type": "string"}},
                    ],
                    "responses": {
                        "200": {
                            "description": "CVE details",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/CVE"}}},
                        },
                        "401": {"description": "Authentication required"},
                        "404": {"description": "CVE not found"},
                    },
                }
            },
            "/cve/{cve_id}/fixes": {
                "get": {
                    "summary": "List fixes associated with a CVE",
                    "security": [{"basicAuth": []}],
                    "parameters": [
                        {"name": "cve_id", "in": "path", "required": True, "schema": {"type": "string"}},
                    ],
                    "responses": {
                        "200": {
                            "description": "Fix summaries for the CVE",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "array", "items": {"$ref": "#/components/schemas/Fix"}}
                                }
                            },
                        },
                        "401": {"description": "Authentication required"},
                        "404": {"description": "CVE not found"},
                    },
                }
            },
            "/fixes": {
                "get": {
                    "summary": "List fixes",
                    "security": [{"basicAuth": []}],
                    "parameters": [
                        {"name": "q", "in": "query", "schema": {"type": "string"}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}},
                        {"name": "offset", "in": "query", "schema": {"type": "integer", "default": 0}},
                    ],
                    "responses": {
                        "200": {
                            "description": "Matching fixes",
                            "content": {
                                "application/json": {
                                    "schema": {"type": "array", "items": {"$ref": "#/components/schemas/Fix"}}
                                }
                            },
                        },
                        "/fixes/{repo_url}/{commit_hash}": {
                            "get": {
                                "summary": "Get full fix detail",
                                "security": [{"basicAuth": []}],
                                "parameters": [
                                    {"name": "repo_url", "in": "path", "required": True, "schema": {"type": "string"}},
                                    {"name": "commit_hash", "in": "path", "required": True, "schema": {"type": "string"}},
                                    {"name": "cve_id", "in": "query", "schema": {"type": "string"}},
                                ],
                                "responses": {
                                    "200": {
                                        "description": "Fix detail with nested files and methods",
                                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/FixDetail"}}},
                                    },
                                    "401": {"description": "Authentication required"},
                                    "404": {"description": "Fix not found"},
                                },
                            }
                        },
                        "/fixes/{repo_url}/{commit_hash}/files": {
                            "get": {
                                "summary": "List files changed by a fix",
                                "security": [{"basicAuth": []}],
                                "parameters": [
                                    {"name": "repo_url", "in": "path", "required": True, "schema": {"type": "string"}},
                                    {"name": "commit_hash", "in": "path", "required": True, "schema": {"type": "string"}},
                                    {"name": "cve_id", "in": "query", "schema": {"type": "string"}},
                                ],
                                "responses": {
                                    "200": {"description": "File changes for the fix"},
                                    "401": {"description": "Authentication required"},
                                    "404": {"description": "Fix not found"},
                                },
                            }
                        },
                        "/fixes/{repo_url}/{commit_hash}/files/{file_change_id}/methods": {
                            "get": {
                                "summary": "List method changes for one file in a fix",
                                "security": [{"basicAuth": []}],
                                "parameters": [
                                    {"name": "repo_url", "in": "path", "required": True, "schema": {"type": "string"}},
                                    {"name": "commit_hash", "in": "path", "required": True, "schema": {"type": "string"}},
                                    {"name": "file_change_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                                    {"name": "cve_id", "in": "query", "schema": {"type": "string"}},
                                ],
                                "responses": {
                                    "200": {"description": "Method changes for the file"},
                                    "401": {"description": "Authentication required"},
                                    "404": {"description": "Fix or file change not found"},
                                },
                            }
                        },
                        "401": {"description": "Authentication required"},
                    },
                },
                "post": {
                    "summary": "Create or update a fix",
                    "security": [{"basicAuth": []}],
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Fix"}}},
                    },
                    "responses": {
                        "201": {
                            "description": "Fix created or updated",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Fix"}}},
                        },
                        "400": {
                            "description": "Invalid request",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                        },
                        "401": {"description": "Authentication required"},
                    },
                },
                "delete": {
                    "summary": "Delete a fix",
                    "security": [{"basicAuth": []}],
                    "parameters": [
                        {"name": "cve_id", "in": "query", "schema": {"type": "string"}},
                        {"name": "hash", "in": "query", "schema": {"type": "string"}},
                        {"name": "repo_url", "in": "query", "schema": {"type": "string"}},
                    ],
                    "requestBody": {
                        "required": False,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "cve_id": {"type": "string"},
                                        "hash": {"type": "string"},
                                        "repo_url": {"type": "string"},
                                    },
                                }
                            }
                        },
                    },
                    "responses": {
                        "200": {"description": "Fix deleted"},
                        "400": {
                            "description": "Missing identifier",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                        },
                        "404": {
                            "description": "Fix not found",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}},
                        },
                        "401": {"description": "Authentication required"},
                    },
                },
            },
            "/fixes/categories": {
                "get": {
                    "summary": "Get fixes grouped by inferred category",
                    "security": [{"basicAuth": []}],
                    "responses": {
                        "200": {
                            "description": "Category buckets",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "array",
                                        "items": {"$ref": "#/components/schemas/CategoryBucket"},
                                    }
                                }
                            },
                        },
                        "401": {"description": "Authentication required"},
                    },
                }
            },
        },
        "externalDocs": {
            "description": "OpenAPI JSON",
            "url": spec_url,
        },
    }