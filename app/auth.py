import base64
from functools import wraps

from flask import Response, current_app, redirect, request, session, url_for


def _parse_basic_auth_header(header_value: str):
    if not header_value or not header_value.startswith("Basic "):
        return None, None

    try:
        token = header_value.split(" ", 1)[1].strip()
        decoded = base64.b64decode(token).decode("utf-8")
        username, password = decoded.split(":", 1)
        return username, password
    except Exception:
        return None, None


def credentials_are_valid(username: str | None, password: str | None) -> bool:
    expected_user = current_app.config["AUTH_USER"]
    expected_password = current_app.config["AUTH_PASSWORD"]
    return username == expected_user and password == expected_password


def auth_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        header_user, header_password = _parse_basic_auth_header(request.headers.get("Authorization"))
        fallback_user = request.headers.get("X-USER")
        fallback_password = request.headers.get("X-PWD")

        username = header_user or fallback_user
        password = header_password or fallback_password

        if credentials_are_valid(username, password):
            return view_func(*args, **kwargs)

        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="MoreFixes"'},
        )

    return wrapper


def web_login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if session.get("authenticated"):
            return view_func(*args, **kwargs)

        return redirect(url_for("web.login", next=request.path))

    return wrapper
