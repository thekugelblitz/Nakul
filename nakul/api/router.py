"""
API Router
===========

Main FastAPI application setup with all routes, middleware,
template rendering, and static file serving.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, Response, HTTPException, Depends, Form, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("nakul.api")

# Path to templates and static files
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "nakul", "dashboard", "templates")
STATIC_DIR = os.path.join(BASE_DIR, "nakul", "dashboard", "static")


def create_app(db=None, auth_manager=None, config=None, agent=None) -> FastAPI:
    """Create and configure the FastAPI application."""

    app = FastAPI(
        title="Nakul",
        description="Server Intelligence & Protection Platform",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url=None,
    )

    # Store references
    app.state.db = db
    app.state.auth = auth_manager
    app.state.config = config
    app.state.agent = agent

    # Static files
    static_dir = os.path.join(os.path.dirname(__file__), "..", "dashboard", "static")
    if os.path.isdir(static_dir):
        app.mount("/static", StaticFiles(directory=static_dir), name="static")

    # Templates
    template_dir = os.path.join(os.path.dirname(__file__), "..", "dashboard", "templates")
    templates = Jinja2Templates(directory=template_dir) if os.path.isdir(template_dir) else None
    app.state.templates = templates

    # =========================================================================
    # Middleware
    # =========================================================================

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):
        """Check authentication for protected routes."""
        # Public routes
        public_paths = ["/login", "/api/login", "/api/health", "/static", "/favicon.ico"]
        if any(request.url.path.startswith(p) for p in public_paths):
            return await call_next(request)

        # Check token
        token = None

        # Try cookie first
        token = request.cookies.get("nakul_token")

        # Then try Authorization header
        if not token:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]

        if not token:
            if request.url.path.startswith("/api/"):
                return JSONResponse({"error": "Authentication required"}, status_code=401)
            return RedirectResponse(url="/login", status_code=302)

        # Verify token
        auth_mgr = request.app.state.agent.auth if request.app.state.agent else None
        if auth_mgr:
            payload = auth_mgr.verify_token(token)
            if not payload:
                if request.url.path.startswith("/api/"):
                    return JSONResponse({"error": "Invalid or expired token"}, status_code=401)
                return RedirectResponse(url="/login", status_code=302)
            request.state.user = payload.get("sub", "admin")
        else:
            request.state.user = "admin"

        return await call_next(request)

    # =========================================================================
    # Auth Routes
    # =========================================================================

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request):
        """Render login page."""
        if templates:
            return templates.TemplateResponse("login.html", {"request": request})
        return HTMLResponse("<h1>Login</h1><form method='post' action='/api/login'>"
                           "<input name='username' placeholder='Username'>"
                           "<input name='password' type='password' placeholder='Password'>"
                           "<button type='submit'>Login</button></form>")

    @app.post("/api/login")
    async def login(request: Request, username: str = Form(""), password: str = Form("")):
        """Authenticate and return token."""
        client_ip = request.client.host if request.client else "unknown"
        auth_mgr = request.app.state.agent.auth if request.app.state.agent else None
        database = request.app.state.agent.db if request.app.state.agent else None

        if auth_mgr:
            # Rate limit check
            allowed, remaining = auth_mgr.check_rate_limit(client_ip)
            if not allowed:
                raise HTTPException(429, "Too many login attempts. Try again later.")

            # IP allowlist check
            if not auth_mgr.check_ip_allowed(client_ip):
                raise HTTPException(403, "Access denied from this IP")

            # Verify credentials
            admin_user = config.auth.admin_username if config else "admin"
            admin_hash = config.auth.admin_password_hash if config else ""

            if username == admin_user and auth_mgr.verify_password(password, admin_hash):
                token, jti = auth_mgr.create_access_token(username)
                auth_mgr.record_login_attempt(client_ip, True)

                # Log audit
                if database:
                    await database.insert_audit({
                        "id": str(uuid.uuid4()),
                        "user": username,
                        "action": "login",
                        "target_type": "auth",
                        "ip_address": client_ip,
                    })

                # For form submission, redirect with cookie
                content_type = request.headers.get("content-type", "")
                accept = request.headers.get("accept", "")
                if "form" in content_type or "text/html" in accept:
                    response = RedirectResponse(url="/", status_code=302)
                    response.set_cookie(
                        "nakul_token", token,
                        httponly=True, max_age=3600, samesite="lax", path="/"
                    )
                    return response

                return {"access_token": token, "token_type": "bearer"}
            else:
                auth_mgr.record_login_attempt(client_ip, False)
                raise HTTPException(401, "Invalid credentials")
        else:
            return {"access_token": "dev-token", "token_type": "bearer"}

    @app.post("/api/logout")
    async def logout(request: Request):
        """Logout and revoke token."""
        response = RedirectResponse(url="/login", status_code=302)
        response.delete_cookie("nakul_token", path="/")
        return response

    @app.get("/api/me")
    async def get_me(request: Request):
        """Get current user info."""
        return {"username": getattr(request.state, "user", "admin")}

    # =========================================================================
    # Health Check
    # =========================================================================

    @app.get("/api/health")
    async def health_check():
        """Health check endpoint for systemd watchdog."""
        status = {"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "version": "1.0.0"}
        if db:
            try:
                await db.get_setting("schema_version")
                status["database"] = "connected"
            except Exception:
                status["database"] = "error"
                status["status"] = "degraded"

        return status

    # =========================================================================
    # Dashboard Pages (HTML)
    # =========================================================================

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_home(request: Request):
        """Dashboard summary page."""
        if not templates:
            return HTMLResponse("<h1>Nakul Dashboard</h1><p>Templates not found.</p>")

        data = await _get_summary_data()
        return templates.TemplateResponse("summary.html", {
            "request": request,
            "data": data,
            "user": getattr(request.state, "user", "admin"),
        })

    @app.get("/alerts", response_class=HTMLResponse)
    async def alerts_page(request: Request):
        if not templates:
            return HTMLResponse("<h1>Alerts</h1>")
        alerts_data, total = await db.get_alerts(limit=50) if db else ([], 0)
        return templates.TemplateResponse("alerts.html", {
            "request": request, "alerts": alerts_data, "total": total,
            "user": getattr(request.state, "user", "admin"),
        })

    @app.get("/services", response_class=HTMLResponse)
    async def services_page(request: Request):
        if not templates:
            return HTMLResponse("<h1>Services</h1>")
        services = await db.get_services() if db else []
        return templates.TemplateResponse("services.html", {
            "request": request, "services": services,
            "user": getattr(request.state, "user", "admin"),
        })

    @app.get("/resources", response_class=HTMLResponse)
    async def resources_page(request: Request):
        if not templates:
            return HTMLResponse("<h1>Resources</h1>")
        snapshot = await db.get_latest_snapshot() if db else {}
        snapshots = await db.get_snapshots(limit=60) if db else []
        return templates.TemplateResponse("resources.html", {
            "request": request, "snapshot": snapshot or {}, "history": snapshots,
            "user": getattr(request.state, "user", "admin"),
        })

    @app.get("/logs", response_class=HTMLResponse)
    async def logs_page(request: Request):
        if not templates:
            return HTMLResponse("<h1>Logs</h1>")
        return templates.TemplateResponse("logs.html", {
            "request": request,
            "user": getattr(request.state, "user", "admin"),
        })

    @app.get("/database", response_class=HTMLResponse)
    async def database_page(request: Request):
        if not templates:
            return HTMLResponse("<h1>Database</h1>")
        events, _ = await db.get_events(category="database", limit=50) if db else ([], 0)
        return templates.TemplateResponse("database.html", {
            "request": request, "events": events,
            "user": getattr(request.state, "user", "admin"),
        })

    @app.get("/backups", response_class=HTMLResponse)
    async def backups_page(request: Request):
        if not templates:
            return HTMLResponse("<h1>Backups</h1>")
        events, _ = await db.get_events(category="backup", limit=50) if db else ([], 0)
        return templates.TemplateResponse("backups.html", {
            "request": request, "events": events,
            "user": getattr(request.state, "user", "admin"),
        })

    @app.get("/security", response_class=HTMLResponse)
    async def security_page(request: Request):
        if not templates:
            return HTMLResponse("<h1>Security</h1>")
        events, _ = await db.get_events(category="security", limit=50) if db else ([], 0)
        malware_events, _ = await db.get_events(category="malware", limit=20) if db else ([], 0)
        return templates.TemplateResponse("security.html", {
            "request": request, "events": events, "malware_events": malware_events,
            "user": getattr(request.state, "user", "admin"),
        })

    @app.get("/incidents/{incident_id}", response_class=HTMLResponse)
    async def incident_detail_page(request: Request, incident_id: str):
        if not templates:
            return HTMLResponse("<h1>Incident</h1>")
        incident = await db.get_incident_by_id(incident_id) if db else None
        if not incident:
            raise HTTPException(404, "Incident not found")
        return templates.TemplateResponse("incidents.html", {
            "request": request, "incident": incident,
            "user": getattr(request.state, "user", "admin"),
        })

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request):
        if not templates:
            return HTMLResponse("<h1>Settings</h1>")
        from nakul.incidents.rules import get_all_rules
        rules = get_all_rules()
        return templates.TemplateResponse("settings.html", {
            "request": request, "config": config, "rules": rules,
            "user": getattr(request.state, "user", "admin"),
        })

    # =========================================================================
    # JSON API Endpoints
    # =========================================================================

    @app.get("/api/summary")
    async def api_summary():
        """Get dashboard summary data."""
        return await _get_summary_data()

    @app.get("/api/alerts")
    async def api_alerts(
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        limit: int = Query(50, le=200),
        offset: int = Query(0, ge=0),
    ):
        if db:
            alerts, total = await db.get_alerts(severity=severity, acknowledged=acknowledged, limit=limit, offset=offset)
            return {"alerts": alerts, "total": total, "page_size": limit}
        return {"alerts": [], "total": 0}

    @app.put("/api/alerts/{alert_id}/acknowledge")
    async def api_acknowledge_alert(alert_id: str, request: Request):
        user = getattr(request.state, "user", "admin")
        if db:
            success = await db.acknowledge_alert(alert_id, user)
            if success:
                await db.insert_audit({
                    "id": str(uuid.uuid4()), "user": user,
                    "action": "acknowledge_alert", "target_type": "alert",
                    "target_id": alert_id,
                })
                return {"status": "acknowledged"}
        raise HTTPException(404, "Alert not found")

    @app.get("/api/incidents")
    async def api_incidents(
        state: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        limit: int = Query(50, le=200),
        offset: int = Query(0, ge=0),
    ):
        if db:
            incidents, total = await db.get_incidents(state=state, severity=severity, category=category, limit=limit, offset=offset)
            return {"incidents": incidents, "total": total, "page_size": limit}
        return {"incidents": [], "total": 0}

    @app.get("/api/incidents/{incident_id}")
    async def api_incident_detail(incident_id: str):
        if db:
            incident = await db.get_incident_by_id(incident_id)
            if incident:
                return incident
        raise HTTPException(404, "Incident not found")

    @app.put("/api/incidents/{incident_id}/state")
    async def api_update_incident_state(
        incident_id: str,
        request: Request,
        new_state: str = Form(""),
        notes: str = Form(""),
    ):
        user = getattr(request.state, "user", "admin")
        valid_states = ["acknowledged", "investigating", "resolved", "suppressed", "false_positive"]
        if new_state not in valid_states:
            raise HTTPException(400, f"Invalid state. Must be one of: {valid_states}")
        if db:
            success = await db.update_incident_state(incident_id, new_state, notes, user)
            if success:
                await db.insert_audit({
                    "id": str(uuid.uuid4()), "user": user,
                    "action": f"update_incident_{new_state}",
                    "target_type": "incident", "target_id": incident_id,
                    "details": {"notes": notes},
                })
                return {"status": new_state}
        raise HTTPException(404, "Incident not found")

    @app.get("/api/services")
    async def api_services():
        if db:
            services = await db.get_services()
            return {"services": services}
        return {"services": []}

    @app.get("/api/events")
    async def api_events(
        source: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        account: Optional[str] = None,
        ip_address: Optional[str] = None,
        domain: Optional[str] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        limit: int = Query(100, le=500),
        offset: int = Query(0, ge=0),
    ):
        if db:
            events, total = await db.get_events(
                source=source, category=category, severity=severity,
                account=account, ip_address=ip_address, domain=domain,
                since=since, until=until, limit=limit, offset=offset,
            )
            return {"events": events, "total": total, "page_size": limit}
        return {"events": [], "total": 0}

    @app.get("/api/snapshots")
    async def api_snapshots(
        since: Optional[str] = None,
        limit: int = Query(60, le=200),
    ):
        if db:
            snapshots = await db.get_snapshots(since=since, limit=limit)
            return {"snapshots": snapshots}
        return {"snapshots": []}

    @app.get("/api/stats")
    async def api_stats():
        if db:
            return await db.get_stats()
        return {}

    @app.get("/api/summary")
    async def api_summary():
        """Get complete summary data for the dashboard auto-refresh."""
        return await _get_summary_data()

    @app.get("/api/audit")
    async def api_audit(limit: int = Query(100, le=500), offset: int = Query(0, ge=0)):
        if db:
            entries = await db.get_audit_log(limit=limit, offset=offset)
            return {"audit_log": entries}
        return {"audit_log": []}

    # =========================================================================
    # Export
    # =========================================================================

    @app.get("/api/export/incidents")
    async def export_incidents(
        format: str = Query("json", regex="^(json|csv)$"),
        state: Optional[str] = None,
        severity: Optional[str] = None,
    ):
        if not db:
            raise HTTPException(500, "Database not available")

        incidents, _ = await db.get_incidents(state=state, severity=severity, limit=10000)

        if format == "csv":
            import csv
            import io
            output = io.StringIO()
            if incidents:
                writer = csv.DictWriter(output, fieldnames=incidents[0].keys())
                writer.writeheader()
                for inc in incidents:
                    # Flatten lists for CSV
                    row = {}
                    for k, v in inc.items():
                        row[k] = json.dumps(v) if isinstance(v, (list, dict)) else v
                    writer.writerow(row)

            return Response(
                content=output.getvalue(),
                media_type="text/csv",
                headers={"Content-Disposition": "attachment; filename=nakul_incidents.csv"},
            )
        else:
            return Response(
                content=json.dumps(incidents, indent=2, default=str),
                media_type="application/json",
                headers={"Content-Disposition": "attachment; filename=nakul_incidents.json"},
            )

    # =========================================================================
    # SSE (Server-Sent Events) for real-time updates
    # =========================================================================

    @app.get("/api/stream")
    async def event_stream(request: Request):
        """SSE endpoint for real-time dashboard updates."""
        import asyncio

        async def generate():
            while True:
                if await request.is_disconnected():
                    break

                # Send latest data
                try:
                    data = await _get_summary_data()
                    yield f"data: {json.dumps(data, default=str)}\n\n"
                except Exception as e:
                    logger.error(f"SSE error: {e}")
                    yield f"data: {json.dumps({'error': str(e)})}\n\n"

                await asyncio.sleep(10)  # Update every 10 seconds

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # =========================================================================
    # Settings API
    # =========================================================================

    @app.get("/api/settings")
    async def api_get_settings():
        if config:
            return config.model_dump()
        return {}

    @app.get("/api/rules")
    async def api_get_rules():
        from nakul.incidents.rules import get_all_rules
        return get_all_rules()

    # =========================================================================
    # Helpers
    # =========================================================================

    async def _get_summary_data() -> Dict[str, Any]:
        """Gather summary data for the dashboard."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "system": {},
            "services": [],
            "alerts": {"total": 0, "critical": 0, "warning": 0, "unacknowledged": 0},
            "incidents": {"active": 0, "recent": []},
            "events_last_hour": 0,
            "server_health": "unknown",
        }

        if not db:
            return data

        try:
            # Latest snapshot
            snapshot = await db.get_latest_snapshot()
            data["system"] = snapshot or {}

            # Services
            data["services"] = await db.get_services()

            # Stats
            stats = await db.get_stats()
            data["alerts"]["critical"] = stats.get("alerts_critical", 0)
            data["alerts"]["warning"] = stats.get("alerts_warning", 0)
            data["alerts"]["unacknowledged"] = stats.get("unack_alerts", 0)
            data["alerts"]["total"] = stats.get("alerts_critical", 0) + stats.get("alerts_warning", 0) + stats.get("alerts_info", 0)
            data["incidents"]["active"] = stats.get("active_incidents", 0)
            data["events_last_hour"] = stats.get("events_last_hour", 0)

            # Recent incidents
            recent_incidents, _ = await db.get_incidents(limit=5)
            data["incidents"]["recent"] = recent_incidents

            # Overall health
            cpu = (snapshot or {}).get("cpu_percent", 0)
            mem = (snapshot or {}).get("memory_percent", 0)
            disk = (snapshot or {}).get("disk_percent", 0)

            if stats.get("alerts_critical", 0) > 0 or cpu > 95 or mem > 95 or disk > 95:
                data["server_health"] = "critical"
            elif stats.get("alerts_warning", 0) > 0 or cpu > 80 or mem > 85 or disk > 85:
                data["server_health"] = "warning"
            elif snapshot:
                data["server_health"] = "healthy"

        except Exception as e:
            logger.error(f"Error getting summary data: {e}")

        return data

    return app
