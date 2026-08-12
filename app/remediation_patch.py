from __future__ import annotations

import asyncio
import json
import os
import sqlite3
from contextlib import closing
from typing import Any

import uvicorn
from fastapi import Query
from fastapi.responses import HTMLResponse, JSONResponse

from app import main


def init_scan_runs() -> None:
    main.init_db()
    with closing(main.connect_db()) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              started_at TEXT NOT NULL,
              finished_at TEXT,
              status TEXT NOT NULL,
              trigger TEXT NOT NULL,
              repos_total INTEGER NOT NULL DEFAULT 0,
              repos_ok INTEGER NOT NULL DEFAULT 0,
              repos_error INTEGER NOT NULL DEFAULT 0,
              packages_total INTEGER NOT NULL DEFAULT 0,
              passed INTEGER NOT NULL DEFAULT 0,
              review INTEGER NOT NULL DEFAULT 0,
              failed INTEGER NOT NULL DEFAULT 0,
              highest_severity TEXT NOT NULL DEFAULT 'none',
              notes TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at);
            """
        )
        conn.commit()


def security_totals(conn: sqlite3.Connection) -> dict[str, Any]:
    return dict(
        conn.execute(
            """
            SELECT
              COUNT(*) total,
              COALESCE(SUM(security_status='passed'), 0) passed,
              COALESCE(SUM(security_status='review'), 0) review,
              COALESCE(SUM(security_status='failed'), 0) failed,
              COALESCE(SUM(security_severity='critical'), 0) critical,
              COALESCE(SUM(security_severity='high'), 0) high,
              COALESCE(SUM(security_severity='medium'), 0) medium,
              COALESCE(ROUND(AVG(security_risk_score), 1), 0) avg_risk
            FROM packages
            """
        ).fetchone()
    )


def highest_severity(totals: dict[str, Any]) -> str:
    if totals.get("critical"):
        return "critical"
    if totals.get("high"):
        return "high"
    if totals.get("medium"):
        return "medium"
    return "none"


def remediation_for(check_id: str, status: str, severity: str, detail: str) -> dict[str, Any]:
    if status == "passed":
        return {"action": "No action required", "priority": "none", "owner": "repository operator", "steps": ["Keep package under normal scheduled monitoring."]}
    playbooks = {
        "checksum": ("Quarantine until checksum metadata is corrected", "repository maintainer", ["Do not promote this package into trusted mirrors.", "Re-fetch repository metadata from upstream.", "Compare checksum against signed Release or repomd metadata.", "Escalate if checksum stays missing or malformed."]),
        "artifact_type": ("Block package because artifact extension does not match repository type", "repository maintainer", ["Remove the package from the candidate mirror set.", "Confirm whether the source is a DEB or RPM repository.", "Correct repository configuration and rescan."]),
        "declared_size": ("Verify artifact metadata before promotion", "package reviewer", ["Fetch package headers from upstream.", "Confirm artifact size is non-zero and matches metadata.", "Rescan after metadata refresh."]),
        "transport": ("Move repository metadata fetches to HTTPS", "platform operator", ["Update the repository base URL to HTTPS.", "Validate certificate trust from the cluster runtime.", "Refresh the index and confirm the transport check passes."]),
        "security_channel": ("Review security-channel package before fleet rollout", "security reviewer", ["Read the upstream advisory or changelog.", "Prioritize vulnerable fleets on this OS version.", "Approve rollout after compatibility checks pass."]),
        "priority": ("Stage high-impact package updates", "change manager", ["Test the package in a non-production fleet lane.", "Schedule a maintenance window if required.", "Monitor dependent services after rollout."]),
        "sensitive_section": ("Route sensitive package to manual review", "security reviewer", ["Inspect package purpose, dependencies, and maintainer.", "Check whether it affects kernel, networking, auth, or system services.", "Require approval before production mirroring."]),
        "privileged_behavior": ("Require privileged-code approval", "security reviewer", ["Review package scripts and declared capabilities.", "Confirm setuid, kernel, or root behavior is expected.", "Approve after staging validation."]),
        "advisory_signal": ("Attach advisory context to rollout decision", "security reviewer", ["Map advisory keywords to CVE, errata, or vendor bulletins.", "Record impacted OS and package versions.", "Prefer patched package versions during rollout."]),
    }
    action, owner, steps = playbooks.get(check_id, ("Continue normal monitoring", "repository operator", ["Keep package under scheduled scan cadence."]))
    priority = {"critical": "urgent", "high": "high", "medium": "normal", "low": "low"}.get(severity, "normal")
    return {"action": action, "priority": priority, "owner": owner, "evidence": detail, "steps": steps}


def recommended_action(package: dict[str, Any]) -> str:
    if package.get("security_status") == "passed":
        return "No remediation required. Keep this package under scheduled monitoring."
    if package.get("security_status") == "failed":
        return "Block promotion, quarantine the package from trusted mirrors, and resolve failed metadata checks before rollout."
    return "Route to manual security review, attach advisory context, and approve only after OS-version compatibility checks pass."


original_refresh_all = main.refresh_all


async def tracked_refresh_all(trigger: str = "manual") -> list[dict[str, Any]]:
    init_scan_runs()
    repos = main.configured_repos()
    with closing(main.connect_db()) as conn:
        run_id = conn.execute(
            "INSERT INTO scan_runs(started_at, status, trigger, repos_total, notes) VALUES (?, 'running', ?, ?, ?)",
            (main.now_iso(), trigger, len(repos), "Repository metadata refresh and package security validation started."),
        ).lastrowid
        conn.commit()
    results = await original_refresh_all()
    with closing(main.connect_db()) as conn:
        totals = security_totals(conn)
        repos_ok = sum(1 for result in results if result.get("status") == "ok")
        repos_error = len(results) - repos_ok
        status = "failed" if repos_ok == 0 else "degraded" if repos_error else "succeeded"
        conn.execute(
            """
            UPDATE scan_runs
            SET finished_at = ?, status = ?, repos_ok = ?, repos_error = ?,
                packages_total = ?, passed = ?, review = ?, failed = ?,
                highest_severity = ?, notes = ?
            WHERE id = ?
            """,
            (main.now_iso(), status, repos_ok, repos_error, totals["total"], totals["passed"], totals["review"], totals["failed"], highest_severity(totals), f"Validated {totals['total']} packages across {repos_ok}/{len(results)} healthy repositories.", run_id),
        )
        conn.commit()
    return results


main.refresh_all = tracked_refresh_all


@main.app.post("/api/scans")
async def api_scan() -> JSONResponse:
    return JSONResponse({"results": await tracked_refresh_all("manual-scan")})


@main.app.get("/api/scans")
def api_scans(limit: int = Query(10, ge=1, le=50)) -> dict[str, Any]:
    init_scan_runs()
    with closing(main.connect_db()) as conn:
        runs = [dict(row) for row in conn.execute("SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,))]
    return {"current": runs[0] if runs else None, "runs": runs}


@main.app.get("/api/packages/{package_id}")
def api_package(package_id: int) -> dict[str, Any]:
    with closing(main.connect_db()) as conn:
        row = conn.execute(
            """
            SELECT packages.*, repos.distro_family, repos.release_version, repos.base_url
            FROM packages
            JOIN repos ON repos.name = packages.repo_name
            WHERE packages.id = ?
            """,
            (package_id,),
        ).fetchone()
    if row is None:
        from fastapi import HTTPException

        raise HTTPException(status_code=404, detail="package not found")
    item = dict(row)
    item["security_findings"] = json.loads(item["security_findings"])
    item["security_checks"] = json.loads(item["security_checks"])
    item["remediation"] = [
        check.get("remediation") or remediation_for(check.get("id", "metadata"), check.get("status", "review"), check.get("severity", "medium"), check.get("detail", ""))
        for check in item["security_checks"]
        if check.get("status") != "passed"
    ]
    item["recommended_action"] = recommended_action(item)
    return item


def dashboard_html() -> str:
    html = main.dashboard_html()
    html = html.replace(
        '<button id="refresh">Refresh index <span class="button-orb" aria-hidden="true">+</span></button>',
        '<button id="refresh">Refresh index <span class="button-orb" aria-hidden="true">+</span></button><button id="scan">Run scan <span class="button-orb" aria-hidden="true">!</span></button>',
    )
    html = html.replace(
        '<section class="security-grid" id="security" aria-label="Package validation summary"></section>',
        '<section class="security-grid" id="security" aria-label="Package validation summary"></section><div class="section-head"><div><div class="eyebrow">Scan operations</div><h2>Scan runs and remediation</h2></div><p class="muted">Launch validation, inspect run evidence, and turn package findings into operator action.</p></div><section class="scan-console" aria-label="Security scan operations"><article class="security-panel" id="scan-runs"></article><article class="security-panel" id="remediation"></article></section>',
    )
    html = html.replace(
        ".security-grid { display:grid; grid-template-columns:minmax(280px,.85fr) minmax(360px,1.15fr); gap:14px; margin:0 0 34px; }",
        ".security-grid,.scan-console { display:grid; grid-template-columns:minmax(280px,.85fr) minmax(360px,1.15fr); gap:14px; margin:0 0 34px; } .scan-run{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;padding:10px 0;border-top:1px solid rgba(16,20,24,.08)} .remediation-item{padding:12px;border-radius:16px;background:rgba(16,20,24,.045);border:1px solid rgba(16,20,24,.07);margin-top:10px}.remediation-item strong{display:block;margin-bottom:6px}.remediation-item ol{margin:8px 0 0 18px;padding:0;color:#40505c;font-size:13px;line-height:1.5}.details-button{all:unset;cursor:pointer;color:var(--accent);font-weight:760}.security-grid { display:grid; grid-template-columns:minmax(280px,.85fr) minmax(360px,1.15fr); gap:14px; margin:0 0 34px; }",
    )
    html = html.replace(
        "fetch('/api/security').then(r => r.json()), fetch('/api/packages?' + params).then(r => r.json())]);",
        "fetch('/api/security').then(r => r.json()), fetch('/api/scans').then(r => r.json()), fetch('/api/packages?' + params).then(r => r.json())]);",
    )
    html = html.replace(
        "const [repos, families, versions, security, packages]",
        "const [repos, families, versions, security, scans, packages]",
    )
    html = html.replace(
        "$('security').innerHTML = `<article class=\"security-panel\"><div class=\"eyebrow\">Average risk</div><h3>${avgRisk.toFixed(1)} / 100</h3><div class=\"risk-meter\"><span style=\"width:${avgRisk}%\"></span></div><p class=\"muted\">${n(securityTotals.total)} packages scanned, ${n(securityTotals.critical)} critical metadata failures, ${n(securityTotals.high)} high review signals.</p><div class=\"risk-list\">${lanes || '<div class=\"risk-item\"><strong>No scan data</strong><span>refresh index</span></div>'}</div></article><article class=\"security-panel\"><div class=\"eyebrow\">Highest risk packages</div><h3>Validation queue</h3><div class=\"risk-list\">${topRisk || '<div class=\"risk-item\"><strong>No packages need review</strong><span>clear</span></div>'}</div></article>`;",
        "$('security').innerHTML = `<article class=\"security-panel\"><div class=\"eyebrow\">Average risk</div><h3>${avgRisk.toFixed(1)} / 100</h3><div class=\"risk-meter\"><span style=\"width:${avgRisk}%\"></span></div><p class=\"muted\">${n(securityTotals.total)} packages scanned, ${n(securityTotals.critical)} critical metadata failures, ${n(securityTotals.high)} high review signals.</p><div class=\"risk-list\">${lanes || '<div class=\"risk-item\"><strong>No scan data</strong><span>refresh index</span></div>'}</div></article><article class=\"security-panel\"><div class=\"eyebrow\">Highest risk packages</div><h3>Validation queue</h3><div class=\"risk-list\">${topRisk || '<div class=\"risk-item\"><strong>No packages need review</strong><span>clear</span></div>'}</div></article>`; const currentRun=scans.current||{}; const history=(scans.runs||[]).map(run=>`<div class=\"scan-run\"><span class=\"badge ${run.status==='succeeded'?'passed':run.status==='running'?'pending':run.status==='degraded'?'review':'failed'}\">${esc(run.status)}</span><div><strong>#${esc(run.id)} ${esc(run.trigger)}</strong><br><span class=\"muted\">${esc(run.started_at)}${run.finished_at?' to '+esc(run.finished_at):''}</span></div><span>${n(run.packages_total)} pkgs</span></div>`).join(''); $('scan-runs').innerHTML=`<div class=\"eyebrow\">Current scan</div><h3>${currentRun.id?'#'+esc(currentRun.id):'No scan yet'}</h3><p class=\"muted\">${esc(currentRun.notes||'Run a scan to validate packages and generate remediation guidance.')}</p><div class=\"hero-actions\"><button id=\"run-scan-inline\">Run scan <span class=\"button-orb\" aria-hidden=\"true\">!</span></button><button class=\"ghost\" id=\"failed-inline\">Failed only <span class=\"button-orb\" aria-hidden=\"true\">&gt;</span></button></div>${history||'<div class=\"scan-run\"><span class=\"badge pending\">pending</span><div><strong>No runs recorded</strong><br><span class=\"muted\">Start with Run scan</span></div><span>0 pkgs</span></div>'}`; const remediationRows=(security.top_risk||[]).slice(0,4).map(row=>`<div class=\"remediation-item\"><strong>${esc(row.package)} <span class=\"badge ${esc(row.security_severity)}\">${esc(row.security_severity)}</span></strong><span class=\"muted\">${esc((row.security_findings||[]).join('; ')||'manual review')}</span></div>`).join(''); $('remediation').innerHTML=`<div class=\"eyebrow\">Remediation queue</div><h3>${n(securityTotals.review+securityTotals.failed)} actions</h3><p class=\"muted\">Open a package row to see owner, priority, evidence, and fix steps.</p>${remediationRows||'<div class=\"remediation-item\"><strong>No active remediation</strong><span class=\"muted\">All current package checks passed.</span></div>'}`; $('run-scan-inline').addEventListener('click',runScan); $('failed-inline').addEventListener('click',()=>{$('status').value='failed';load();document.querySelector('#packages-table').scrollIntoView({behavior:'smooth',block:'start'});});",
    )
    html = html.replace(
        "${esc(p.package)}</td>",
        "<button class=\"details-button\" data-package-id=\"${esc(p.id)}\">${esc(p.package)}</button></td>",
    )
    html = html.replace(
        " : '<tr><td colspan=\"5\"><div class=\"state\"><strong>No packages match this filter</strong>Refresh repositories or widen the search criteria.</div></td><td colspan=\"4\"></td></tr>';",
        " : '<tr><td colspan=\"5\"><div class=\"state\"><strong>No packages match this filter</strong>Refresh repositories or widen the search criteria.</div></td><td colspan=\"4\"></td></tr>'; document.querySelectorAll('.details-button').forEach(button=>button.addEventListener('click',()=>showPackage(button.dataset.packageId)));",
    )
    html = html.replace(
        "$('refresh').addEventListener('click', async () =>",
        "async function runScan(){ $('scan').disabled=true; $('scan').innerHTML='Scanning <span class=\"button-orb\" aria-hidden=\"true\">...</span>'; await fetch('/api/scans',{method:'POST'}); $('scan').disabled=false; $('scan').innerHTML='Run scan <span class=\"button-orb\" aria-hidden=\"true\">!</span>'; load(); } async function showPackage(packageId){ const p=await fetch('/api/packages/'+encodeURIComponent(packageId)).then(r=>r.json()); const steps=(p.remediation||[]).map(item=>`<div class=\"remediation-item\"><strong>${esc(item.action)} <span class=\"badge ${esc(item.priority==='urgent'?'critical':item.priority==='high'?'high':'medium')}\">${esc(item.priority)}</span></strong><span class=\"muted\">${esc(item.owner)} - ${esc(item.evidence||'')}</span><ol>${(item.steps||[]).map(step=>`<li>${esc(step)}</li>`).join('')}</ol></div>`).join(''); $('remediation').innerHTML=`<div class=\"eyebrow\">Package remediation</div><h3>${esc(p.package)}</h3><p class=\"muted\">${esc(p.recommended_action)}</p>${steps||'<div class=\"remediation-item\"><strong>No remediation required</strong><span class=\"muted\">This package currently passes validation.</span></div>'}`; document.querySelector('.scan-console').scrollIntoView({behavior:'smooth',block:'start'});} $('scan').addEventListener('click',runScan); $('refresh').addEventListener('click', async () =>",
    )
    return html


def patched_index() -> HTMLResponse:
    return HTMLResponse(dashboard_html())


for route in main.app.router.routes:
    if getattr(route, "path", "") == "/" and "GET" in getattr(route, "methods", set()):
        route.endpoint = patched_index
        route.response_class = HTMLResponse


init_scan_runs()
app = main.app


if __name__ == "__main__":
    uvicorn.run("app.remediation_patch:app", host=os.getenv("APP_HOST", "0.0.0.0"), port=int(os.getenv("APP_PORT", "8080")))
