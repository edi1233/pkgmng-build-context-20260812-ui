from __future__ import annotations

import json
from contextlib import closing
from typing import Any

from fastapi import Query
from fastapi.routing import APIRoute

from . import main


ORDER_BY = {
    "risk": "security_risk_score DESC, security_status DESC, package, version, architecture",
    "package": "package COLLATE NOCASE, version, architecture",
    "repo": "packages.repo_name COLLATE NOCASE, package COLLATE NOCASE, version, architecture",
    "version": "version COLLATE NOCASE, package COLLATE NOCASE, architecture",
    "status": "security_status DESC, security_severity DESC, security_risk_score DESC, package",
    "severity": "CASE security_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, security_risk_score DESC, package",
    "updated": "refreshed_at DESC, package COLLATE NOCASE, version",
}


def api_packages(
    q: str = "",
    status: str = Query("", pattern="^(|passed|review|failed)$"),
    severity: str = Query("", pattern="^(|none|low|medium|high|critical)$"),
    family: str = "",
    version: str = "",
    repo: str = "",
    package_format: str = Query("", pattern="^(|deb|rpm)$"),
    architecture: str = "",
    checksum_algorithm: str = "",
    sort: str = Query("risk", pattern="^(risk|package|repo|version|status|severity|updated)$"),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    where: list[str] = []
    args: list[Any] = []
    if q:
        where.append("(package LIKE ? OR description LIKE ? OR maintainer LIKE ?)")
        args.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    for column, value in [
        ("security_status", status),
        ("security_severity", severity),
        ("repos.distro_family", family),
        ("repos.release_version", version),
        ("packages.repo_name", repo),
        ("package_format", package_format),
        ("architecture", architecture),
        ("checksum_algorithm", checksum_algorithm),
    ]:
        if value:
            where.append(f"{column} = ?")
            args.append(value)
    base_sql = "SELECT packages.*, repos.distro_family, repos.release_version FROM packages JOIN repos ON repos.name = packages.repo_name"
    count_sql = "SELECT COUNT(*) total FROM packages JOIN repos ON repos.name = packages.repo_name"
    if where:
        where_sql = " WHERE " + " AND ".join(where)
        base_sql += where_sql
        count_sql += where_sql
    sql = f"{base_sql} ORDER BY {ORDER_BY[sort]} LIMIT ? OFFSET ?"
    with closing(main.connect_db()) as conn:
        filtered_total = conn.execute(count_sql, args).fetchone()["total"]
        rows = [dict(row) for row in conn.execute(sql, [*args, limit, offset])]
        for row in rows:
            row["security_findings"] = json.loads(row["security_findings"])
            row["security_checks"] = json.loads(row["security_checks"])
            row["checksum_algorithm"] = row.get("checksum_algorithm") or main.detect_checksum_algorithm(str(row.get("sha256") or ""))
            row.update(main.package_intelligence(row))
        totals = dict(
            conn.execute(
                """
                SELECT COUNT(*) total,
                  COALESCE(SUM(security_status='passed'), 0) passed,
                  COALESCE(SUM(security_status='review'), 0) review,
                  COALESCE(SUM(security_status='failed'), 0) failed
                FROM packages
                """
            ).fetchone()
        )
        filter_options = {
            "architectures": [
                row["architecture"]
                for row in conn.execute("SELECT DISTINCT architecture FROM packages WHERE architecture IS NOT NULL AND architecture != '' ORDER BY architecture COLLATE NOCASE")
            ],
            "checksum_algorithms": [
                row["checksum_algorithm"]
                for row in conn.execute("SELECT DISTINCT checksum_algorithm FROM packages WHERE checksum_algorithm IS NOT NULL AND checksum_algorithm != '' ORDER BY checksum_algorithm COLLATE NOCASE")
            ],
        }
    return {
        "packages": rows,
        "totals": totals,
        "filter_options": filter_options,
        "page": {"total": filtered_total, "returned": len(rows), "limit": limit, "offset": offset, "has_more": offset + len(rows) < filtered_total},
    }


def api_repo_packages(repo_name: str, limit: int = Query(200, ge=1, le=1000), offset: int = Query(0, ge=0)) -> dict[str, Any]:
    return api_packages(q="", status="", severity="", family="", version="", repo=repo_name, package_format="", architecture="", checksum_algorithm="", sort="risk", limit=limit, offset=offset)


def replace_route(path: str, endpoint: Any) -> None:
    main.app.router.routes = [
        route
        for route in main.app.router.routes
        if not (isinstance(route, APIRoute) and route.path == path and "GET" in route.methods)
    ]
    main.app.get(path)(endpoint)


def patch_dashboard() -> None:
    original_dashboard = main.dashboard_html

    def dashboard_html() -> str:
        return original_dashboard()

    main.dashboard_html = dashboard_html
    main.index = dashboard_html


main.init_db()
replace_route("/api/packages", api_packages)
replace_route("/api/repos/{repo_name}/packages", api_repo_packages)
patch_dashboard()
app = main.app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(main.os.getenv("APP_PORT", "8080")))
