"""
View handlers for the demo application.

Each function here contains an INTENTIONAL VULNERABILITY that CodeQL
should detect — but only AFTER the QuickAPI framework has been modeled.

There are 7 intentional vulnerabilities in this file.

Without models, CodeQL does not know that:
  - Request methods return user-controlled data (sources)
  - Database/template/system methods consume data unsafely (sinks)
  - Sanitizer methods propagate taint (summaries)
"""

from quickapi.request import Request
from quickapi.response import Response, JSONResponse, HTMLResponse
from quickapi.database import DatabaseConnection
from quickapi.templating import TemplateEngine
from quickapi.security import SystemHelper, Sanitizer, TokenValidator
from quickapi.utils import CacheManager


# ────────────────────────────────────────────────────────────────────
# 1. SQL Injection via direct string concatenation
# ────────────────────────────────────────────────────────────────────

def search_users(request: Request, db: DatabaseConnection) -> JSONResponse:
    """
    VULNERABILITY: SQL Injection

    The `name` query parameter flows directly into a SQL query string.
    CodeQL needs to know that `request.get_query_param()` is a remote source
    and `db.execute_query()` is a SQL-injection sink.
    """
    name = request.get_query_param("name")
    query = f"SELECT * FROM users WHERE username LIKE '%{name}%'"
    results = db.execute_query(query)
    return JSONResponse({"users": results})


# ────────────────────────────────────────────────────────────────────
# 2. Reflected XSS via template rendering
# ────────────────────────────────────────────────────────────────────

def render_dashboard(request: Request, templates: TemplateEngine, cache: CacheManager) -> HTMLResponse:
    """
    VULNERABILITY: Cross-Site Scripting (XSS)

    The `welcome_msg` query parameter is placed directly into an HTML
    template without escaping.
    CodeQL needs to know that `templates.render_string()` is an
    html-injection sink.
    """
    welcome = request.get_query_param("welcome_msg", "Welcome!")
    html = templates.render_string(
        "<html><body><h1>{{greeting}}</h1></body></html>",
        context={"greeting": welcome},
    )
    return HTMLResponse(html)


# ────────────────────────────────────────────────────────────────────
# 3. Command Injection
# ────────────────────────────────────────────────────────────────────

def admin_diagnostics(request: Request) -> JSONResponse:
    """
    VULNERABILITY: Command Injection

    The `host` query parameter flows into `SystemHelper.ping_host()`,
    which executes a shell command.
    CodeQL needs to know that `ping_host()` is a command-injection sink.
    """
    host = request.get_query_param("host")
    output = SystemHelper.ping_host(host)
    return JSONResponse({"ping_result": output})


# ────────────────────────────────────────────────────────────────────
# 4. Path Traversal
# ────────────────────────────────────────────────────────────────────

def download_report(request: Request) -> Response:
    """
    VULNERABILITY: Path Traversal

    The `filename` query parameter flows into `SystemHelper.read_file()`,
    allowing an attacker to read arbitrary files.
    CodeQL needs to know that `read_file()` is a path-injection sink.
    """
    filename = request.get_query_param("filename")
    content = SystemHelper.read_file(f"reports/{filename}")
    return Response(body=content, content_type="text/plain")


# ────────────────────────────────────────────────────────────────────
# 5. SQL Injection with taint flowing through a summary (Sanitizer)
# ────────────────────────────────────────────────────────────────────

def update_profile(request: Request, db: DatabaseConnection) -> JSONResponse:
    """
    VULNERABILITY: SQL Injection (taint through summary)

    User input passes through `Sanitizer.strip_tags()` (which removes
    HTML tags but does NOT prevent SQL injection), then flows into a
    raw SQL query.

    CodeQL needs a SUMMARY model for `strip_tags()` so it knows taint
    propagates through the sanitizer.
    """
    body = request.get_json_body()
    new_bio = body.get("bio", "")

    # Developer thinks strip_tags makes it safe — it doesn't for SQL!
    cleaned_bio = Sanitizer.strip_tags(new_bio)

    user_id = request.get_query_param("user_id")
    sql = f"UPDATE users SET bio = '{cleaned_bio}' WHERE id = {user_id}"
    db.execute_update(sql)

    return JSONResponse({"status": "updated"})


# ────────────────────────────────────────────────────────────────────
# 6. SQL Injection via token claims (source from TokenValidator)
# ────────────────────────────────────────────────────────────────────

def login(request: Request, db: DatabaseConnection, validator: TokenValidator) -> JSONResponse:
    """
    VULNERABILITY: SQL Injection via token-derived data

    User-controlled claims decoded from a JWT token flow into a SQL query.
    CodeQL needs to know that `TokenValidator.decode_token()` returns
    user-controlled data (source).
    """
    token = request.get_header("Authorization")
    claims = validator.decode_token(token)
    username = claims.get("preferred_username", "")

    sql = f"SELECT * FROM users WHERE username = '{username}'"
    results = db.execute_query(sql)

    if results:
        return JSONResponse({"user": results[0]})
    return JSONResponse({"error": "not found"}, status_code=404)


# ────────────────────────────────────────────────────────────────────
# 7. Log Injection
# ────────────────────────────────────────────────────────────────────

def log_activity(request: Request) -> JSONResponse:
    """
    VULNERABILITY: Log Injection

    User input flows directly into a log message without sanitization.
    CodeQL needs to know that `SystemHelper.write_log()` is a
    log-injection sink.
    """
    action = request.get_query_param("action")
    user_agent = request.get_header("User-Agent")
    message = f"User performed action: {action} from {user_agent}"
    SystemHelper.write_log("/var/log/app.log", message)
    return JSONResponse({"status": "logged"})
