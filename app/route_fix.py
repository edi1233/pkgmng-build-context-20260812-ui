from __future__ import annotations

import os

import uvicorn
from fastapi.routing import APIRoute
from fastapi.responses import HTMLResponse

from app import remediation_patch


def patched_index() -> HTMLResponse:
    return HTMLResponse(remediation_patch.dashboard_html())


remediation_patch.main.app.router.routes.insert(
    0,
    APIRoute("/", patched_index, methods=["GET"], response_class=HTMLResponse),
)

app = remediation_patch.app


if __name__ == "__main__":
    uvicorn.run("app.route_fix:app", host=os.getenv("APP_HOST", "0.0.0.0"), port=int(os.getenv("APP_PORT", "8080")))
