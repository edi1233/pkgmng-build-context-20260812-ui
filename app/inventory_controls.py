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
        html = original_dashboard()
        html = html.replace(
            ".toolbar { display:grid; grid-template-columns:minmax(240px,1fr) 160px 190px 160px 210px; gap:12px; align-items:center; margin:16px 0; }",
            ".toolbar-panel { margin:16px 0; padding:12px; border-radius:18px; background:var(--surface); border:1px solid var(--line); box-shadow:var(--shadow-soft); }"
            ".toolbar-panel-head { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:12px; }"
            ".toolbar-panel-head h3 { margin:2px 0 4px; font-size:18px; } .toolbar-panel-head p { margin:0; font-size:13px; }"
            ".toolbar { display:grid; grid-template-columns:minmax(240px,1.4fr) repeat(4,minmax(145px,1fr)); gap:10px; align-items:end; margin:0; }"
            ".filter-field { display:grid; gap:6px; color:var(--muted); font-size:12px; font-weight:720; }"
            ".filter-actions { display:flex; gap:8px; justify-content:flex-end; flex-wrap:wrap; }"
            ".filter-summary { display:flex; flex-wrap:wrap; gap:7px; margin-top:12px; min-height:26px; }"
            ".filter-chip { display:inline-flex; align-items:center; min-height:26px; border-radius:999px; padding:4px 9px; background:var(--neutral-bg); color:var(--ink); border:1px solid var(--line); font-size:12px; font-weight:720; }",
        )
        html = html.replace(
            '<div class="toolbar" role="search">',
            '<div class="toolbar-panel" role="search" aria-label="Package inventory controls"><div class="toolbar-panel-head"><div><div class="eyebrow">Inventory controls</div><h3>Filter every package field</h3><p class="muted">Combine status, severity, source, OS lane, architecture, format, checksum, and sort order.</p></div><div class="filter-actions"><button class="secondary" id="reset-filters" type="button">Reset filters <span class="button-orb" aria-hidden="true"><svg><use href="#icon-refresh"></use></svg></span></button></div></div><div class="toolbar">',
        )
        html = html.replace('<input id="q" aria-label="Search packages" placeholder="Search package, maintainer, description">', '<div class="filter-field"><label for="q">Search</label><input id="q" aria-label="Search packages" placeholder="Package, maintainer, description"></div>')
        html = html.replace('<select id="status" aria-label="Filter by security status">', '<div class="filter-field"><label for="status">Status</label><select id="status" aria-label="Filter by security status">')
        html = html.replace('</select>\n        <select id="family"', '</select></div><div class="filter-field"><label for="severity">Severity</label><select id="severity" aria-label="Filter by security severity"><option value="">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="none">None</option></select></div><div class="filter-field"><label for="family">Distribution</label><select id="family"', 1)
        html = html.replace('</select>\n        <select id="version"', '</select></div><div class="filter-field"><label for="version">OS version</label><select id="version"', 1)
        html = html.replace('</select>\n        <select id="repo-filter"', '</select></div><div class="filter-field"><label for="repo-filter">Repository</label><select id="repo-filter"', 1)
        html = html.replace('        </select>\n      </div>\n      <section class="table-shell"', '        </select></div><div class="filter-field"><label for="format">Format</label><select id="format" aria-label="Filter by package format"><option value="">All formats</option><option value="deb">DEB</option><option value="rpm">RPM</option></select></div><div class="filter-field"><label for="architecture">Architecture</label><select id="architecture" aria-label="Filter by package architecture"><option value="">All architectures</option></select></div><div class="filter-field"><label for="checksum">Checksum</label><select id="checksum" aria-label="Filter by checksum algorithm"><option value="">All checksums</option></select></div><div class="filter-field"><label for="sort">Sort by</label><select id="sort" aria-label="Sort packages"><option value="risk">Risk first</option><option value="severity">Severity</option><option value="status">Status</option><option value="package">Package name</option><option value="repo">Repository</option><option value="version">Version</option><option value="updated">Last refresh</option></select></div></div><div class="filter-summary" id="filter-summary" aria-live="polite"></div></div>\n      <section class="table-shell"', 1)
        html = html.replace(
            "const n = (value) => Number(value || 0).toLocaleString();",
            "const n = (value) => Number(value || 0).toLocaleString(); const filterIds = ['status','severity','family','version','repo-filter','format','architecture','checksum','sort']; const selectedFilters = () => ({ q: $('q').value.trim(), status: $('status').value, severity: $('severity').value, family: $('family').value, version: $('version').value, repo: $('repo-filter').value, package_format: $('format').value, architecture: $('architecture').value, checksum_algorithm: $('checksum').value, sort: $('sort').value }); const setSelectOptions = (id, placeholder, values, current, formatter = (value) => value) => { const options = [...new Set((values || []).filter(Boolean))]; $(id).innerHTML = `<option value=\"\">${placeholder}</option>` + options.map(value => `<option value=\"${esc(value)}\">${esc(formatter(value))}</option>`).join(''); $(id).value = options.includes(current) ? current : ''; }; const renderFilterSummary = (page) => { const filters = selectedFilters(); const labels = [['Search', filters.q], ['Status', filters.status], ['Severity', filters.severity], ['Family', filters.family], ['OS', filters.version], ['Repo', filters.repo], ['Format', filters.package_format ? filters.package_format.toUpperCase() : ''], ['Arch', filters.architecture], ['Checksum', filters.checksum_algorithm ? filters.checksum_algorithm.toUpperCase() : ''], ['Sort', $('sort').selectedOptions[0]?.textContent || 'Risk first']].filter(([, value]) => value); $('filter-summary').innerHTML = labels.map(([key, value]) => `<span class=\"filter-chip\">${esc(key)}: ${esc(value)}</span>`).join('') + `<span class=\"filter-chip\">${n(page.total || 0)} matches</span>`; };",
        )
        html = html.replace(
            "const params = new URLSearchParams({ q: $('q').value, status: $('status').value, family: $('family').value, version: $('version').value, repo: $('repo-filter').value, limit: String(PAGE_LIMIT), offset: String(currentOffset) });",
            "const params = new URLSearchParams({ ...selectedFilters(), limit: String(PAGE_LIMIT), offset: String(currentOffset) });",
        )
        html = html.replace(
            "$('version').value = versionOptions.includes(versionValue) ? versionValue : '';",
            "$('version').value = versionOptions.includes(versionValue) ? versionValue : ''; const filterOptions = packages.filter_options || {}; setSelectOptions('architecture', 'All architectures', filterOptions.architectures || [], $('architecture').value); setSelectOptions('checksum', 'All checksums', filterOptions.checksum_algorithms || [], $('checksum').value, value => value.toUpperCase());",
        )
        html = html.replace("$('page-info').textContent = `Showing ${n(start)}-${n(end)} of ${n(page.total)} matching packages`;", "$('page-info').textContent = `Showing ${n(start)}-${n(end)} of ${n(page.total)} matching packages`; renderFilterSummary(page);")
        html = html.replace(
            "    async function saveSource(event) {",
            "    function resetFilters() { $('q').value = ''; $('status').value = ''; $('severity').value = ''; $('family').value = ''; $('version').value = ''; $('repo-filter').value = ''; $('format').value = ''; $('architecture').value = ''; $('checksum').value = ''; $('sort').value = 'risk'; currentOffset = 0; load(); }\n    async function saveSource(event) {",
        )
        html = html.replace(
            "$('status').addEventListener('change', () => { currentOffset = 0; load(); });\n    $('family').addEventListener('change', () => { currentOffset = 0; load(); });\n    $('version').addEventListener('change', () => { currentOffset = 0; load(); });\n    $('repo-filter').addEventListener('change', () => { currentOffset = 0; load(); });",
            "filterIds.forEach(id => $(id).addEventListener('change', () => { currentOffset = 0; load(); }));\n    $('reset-filters').addEventListener('click', resetFilters);",
        )
        return html

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
