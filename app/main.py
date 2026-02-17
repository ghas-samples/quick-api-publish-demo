"""
Demo application entry point using the QuickAPI framework.

This wires up the routes and starts the server.
"""

from quickapi import QuickAPI
from quickapi.database import DatabaseConnection
from quickapi.templating import TemplateEngine
from quickapi.security import TokenValidator
from quickapi.utils import CacheManager

from app.views import (
    search_users,
    get_user_profile,
    update_profile,
    admin_diagnostics,
    download_report,
    render_dashboard,
    login,
)

# ── Application setup ───────────────────────────────────────────────

app = QuickAPI("demo-app", debug=True)

db = DatabaseConnection("app.db")
db.connect()

templates = TemplateEngine(template_dir="templates")
token_validator = TokenValidator(secret_key="supersecret")
cache = CacheManager()

# ── Route registration ──────────────────────────────────────────────


@app.route("/api/users/search", methods=["GET"])
def handle_search_users(request):
    return search_users(request, db)


@app.route("/api/users/<user_id>", methods=["GET"])
def handle_get_user(request):
    return get_user_profile(request, db, templates)


@app.route("/api/users/<user_id>", methods=["POST"])
def handle_update_profile(request):
    return update_profile(request, db)


@app.route("/admin/diagnostics", methods=["GET"])
def handle_diagnostics(request):
    return admin_diagnostics(request)


@app.route("/reports/download", methods=["GET"])
def handle_download(request):
    return download_report(request)


@app.route("/dashboard", methods=["GET"])
def handle_dashboard(request):
    return render_dashboard(request, templates, cache)


@app.route("/auth/login", methods=["POST"])
def handle_login(request):
    return login(request, db, token_validator)


# ── Start the server ────────────────────────────────────────────────

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
