from __future__ import annotations

import gzip
import json
import lzma
import os
import re
import sqlite3
import time
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager, closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse


APP_VERSION = os.getenv("APP_VERSION", "dev")
DATA_DIR = Path(os.getenv("DATA_DIR", ".data"))
DB_PATH = Path(os.getenv("DB_PATH", str(DATA_DIR / "pkgmng.db")))
REFRESH_INTERVAL_MINUTES = int(os.getenv("REFRESH_INTERVAL_MINUTES", "360"))
APT_REPOS = os.getenv(
    "APT_REPOS",
    "debian-bookworm|https://deb.debian.org/debian|bookworm|main,"
    "debian-security|https://security.debian.org/debian-security|bookworm-security|main",
)
RPM_REPOS = os.getenv(
    "RPM_REPOS",
    "alma-9-baseos|https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/|AlmaLinux 9|BaseOS,"
    "rocky-9-baseos|https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/|Rocky Linux 9|BaseOS,"
    "oracle-9-baseos|https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64/|Oracle Linux 9|BaseOS,"
    "redhat-ubi9-baseos|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/|Red Hat UBI 9|BaseOS",
)
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "30"))
MAX_PACKAGES_PER_REPO = int(os.getenv("MAX_PACKAGES_PER_REPO", "2500"))


@dataclass(frozen=True)
class Repo:
    name: str
    repo_type: str
    base_url: str
    suite: str
    component: str

    @property
    def packages_urls(self) -> list[str]:
        base = self.base_url.rstrip("/")
        rel = f"dists/{self.suite}/{self.component}/binary-amd64/Packages"
        return [f"{base}/{rel}.xz", f"{base}/{rel}.gz", f"{base}/{rel}"]

    @property
    def repomd_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/repodata/repomd.xml"

    @property
    def distro_family(self) -> str:
        value = f"{self.name} {self.suite} {self.base_url}".lower()
        if "alma" in value:
            return "AlmaLinux"
        if "rocky" in value:
            return "Rocky Linux"
        if "oracle" in value or "ol9" in value:
            return "Oracle Linux"
        if "redhat" in value or "ubi" in value:
            return "Red Hat"
        if self.repo_type == "rpm":
            return "RHEL family"
        if "security" in value:
            return "Debian Security"
        return "Debian"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_repos(raw: str = APT_REPOS, repo_type: str = "apt") -> list[Repo]:
    repos: list[Repo] = []
    for item in [part.strip() for part in raw.split(",") if part.strip()]:
        parts = [part.strip() for part in item.split("|")]
        if len(parts) != 4:
            raise ValueError(f"{repo_type.upper()} repo entries must use name|base_url|suite|component")
        repos.append(Repo(parts[0], repo_type, parts[1], parts[2], parts[3]))
    return repos


def configured_repos() -> list[Repo]:
    return [*parse_repos(APT_REPOS, "apt"), *parse_repos(RPM_REPOS, "rpm")]


def connect_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with closing(connect_db()) as conn:
        conn.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS repos (
              name TEXT PRIMARY KEY,
              repo_type TEXT NOT NULL DEFAULT 'apt',
              distro_family TEXT NOT NULL DEFAULT 'Debian',
              base_url TEXT NOT NULL,
              suite TEXT NOT NULL,
              component TEXT NOT NULL,
              last_refresh TEXT,
              package_count INTEGER NOT NULL DEFAULT 0,
              status TEXT NOT NULL DEFAULT 'pending',
              error TEXT
            );
            CREATE TABLE IF NOT EXISTS packages (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              repo_name TEXT NOT NULL,
              package TEXT NOT NULL,
              version TEXT NOT NULL,
              architecture TEXT,
              section TEXT,
              priority TEXT,
              filename TEXT,
              size INTEGER,
              sha256 TEXT,
              maintainer TEXT,
              description TEXT,
              package_format TEXT NOT NULL DEFAULT 'deb',
              security_status TEXT NOT NULL,
              security_findings TEXT NOT NULL,
              refreshed_at TEXT NOT NULL,
              UNIQUE(repo_name, package, version, architecture)
            );
            CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(package);
            CREATE INDEX IF NOT EXISTS idx_packages_status ON packages(security_status);
            """
        )
        ensure_column(conn, "repos", "repo_type", "TEXT NOT NULL DEFAULT 'apt'")
        ensure_column(conn, "repos", "distro_family", "TEXT NOT NULL DEFAULT 'Debian'")
        ensure_column(conn, "packages", "package_format", "TEXT NOT NULL DEFAULT 'deb'")
        for repo in configured_repos():
            conn.execute(
                """
                INSERT INTO repos(name, repo_type, distro_family, base_url, suite, component)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                  repo_type=excluded.repo_type,
                  distro_family=excluded.distro_family,
                  base_url=excluded.base_url,
                  suite=excluded.suite,
                  component=excluded.component
                """,
                (repo.name, repo.repo_type, repo.distro_family, repo.base_url, repo.suite, repo.component),
            )
        conn.commit()


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def parse_packages_index(text: str) -> list[dict[str, Any]]:
    records: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key = ""
    for raw_line in text.splitlines():
        if not raw_line:
            if current:
                records.append(current)
                current = {}
                last_key = ""
            continue
        if raw_line.startswith(" ") and last_key:
            current[last_key] = f"{current[last_key]}\n{raw_line[1:]}"
            continue
        if ":" in raw_line:
            key, value = raw_line.split(":", 1)
            last_key = key
            current[key] = value.strip()
    if current:
        records.append(current)
    return records


def parse_rpm_primary_xml(text: str) -> list[dict[str, Any]]:
    ns = {
        "m": "http://linux.duke.edu/metadata/common",
        "rpm": "http://linux.duke.edu/metadata/rpm",
    }
    root = ET.fromstring(text)
    records: list[dict[str, Any]] = []
    for package in root.findall("m:package", ns):
        version = package.find("m:version", ns)
        checksum = package.find("m:checksum", ns)
        location = package.find("m:location", ns)
        size = package.find("m:size", ns)
        rpm_format = package.find("m:format", ns)
        license_el = rpm_format.find("rpm:license", ns) if rpm_format is not None else None
        group_el = rpm_format.find("rpm:group", ns) if rpm_format is not None else None
        records.append(
            {
                "Package": text_of(package, "m:name", ns),
                "Version": rpm_version(version),
                "Architecture": text_of(package, "m:arch", ns),
                "Section": text_of(group_el) or text_of(license_el),
                "Priority": "",
                "Filename": location.attrib.get("href", "") if location is not None else "",
                "Size": size.attrib.get("package", "0") if size is not None else "0",
                "SHA256": checksum.text.strip() if checksum is not None and checksum.text else "",
                "Maintainer": text_of(package, "m:packager", ns),
                "Description": text_of(package, "m:description", ns) or text_of(package, "m:summary", ns),
                "PackageFormat": "rpm",
            }
        )
    return records


def text_of(element: ET.Element | None, path: str | None = None, ns: dict[str, str] | None = None) -> str:
    target = element.find(path, ns or {}) if element is not None and path else element
    return target.text.strip() if target is not None and target.text else ""


def rpm_version(version: ET.Element | None) -> str:
    if version is None:
        return ""
    epoch = version.attrib.get("epoch", "0")
    ver = version.attrib.get("ver", "")
    rel = version.attrib.get("rel", "")
    prefix = f"{epoch}:" if epoch and epoch != "0" else ""
    suffix = f"-{rel}" if rel else ""
    return f"{prefix}{ver}{suffix}"


def rpm_primary_href(repomd_xml: str) -> str:
    ns = {"repo": "http://linux.duke.edu/metadata/repo"}
    root = ET.fromstring(repomd_xml)
    for data in root.findall("repo:data", ns):
        if data.attrib.get("type") == "primary":
            location = data.find("repo:location", ns)
            if location is not None and location.attrib.get("href"):
                return location.attrib["href"]
    raise RuntimeError("repomd.xml did not include primary metadata")


def assess_package(record: dict[str, Any]) -> tuple[str, list[str]]:
    findings: list[str] = []
    package_format = record.get("PackageFormat", "deb")
    if not record.get("SHA256"):
        findings.append("missing SHA256 checksum")
    expected_suffix = ".rpm" if package_format == "rpm" else ".deb"
    if not record.get("Filename", "").endswith(expected_suffix):
        findings.append(f"package filename is not a {expected_suffix}")
    priority = record.get("Priority", "").lower()
    if priority in {"required", "important"}:
        findings.append(f"high-impact priority: {priority}")
    section = record.get("Section", "").lower()
    if any(word in section for word in ["admin", "kernel", "net", "utils", "system", "security"]):
        findings.append(f"sensitive section: {section}")
    description = record.get("Description", "")
    if re.search(r"\b(setuid|root|privilege|kernel module)\b", description, re.I):
        findings.append("description mentions privileged behavior")
    if not findings:
        return "passed", []
    if any("missing" in item or f"not a {expected_suffix}" in item for item in findings):
        return "failed", findings
    return "review", findings


async def fetch_packages_text(repo: Repo) -> str:
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True) as client:
        last_error = ""
        for url in repo.packages_urls:
            try:
                response = await client.get(url)
                response.raise_for_status()
                data = response.content
                if url.endswith(".xz"):
                    return lzma.decompress(data).decode("utf-8", errors="replace")
                if url.endswith(".gz"):
                    return gzip.decompress(data).decode("utf-8", errors="replace")
                return data.decode("utf-8", errors="replace")
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
        raise RuntimeError(last_error or "no Packages index could be fetched")


async def fetch_rpm_records(repo: Repo) -> list[dict[str, Any]]:
    async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS, follow_redirects=True) as client:
        repomd_response = await client.get(repo.repomd_url)
        repomd_response.raise_for_status()
        primary_url = f"{repo.base_url.rstrip('/')}/{rpm_primary_href(repomd_response.text).lstrip('/')}"
        primary_response = await client.get(primary_url)
        primary_response.raise_for_status()
        data = primary_response.content
        if primary_url.endswith(".gz"):
            text = gzip.decompress(data).decode("utf-8", errors="replace")
        elif primary_url.endswith(".xz"):
            text = lzma.decompress(data).decode("utf-8", errors="replace")
        else:
            text = data.decode("utf-8", errors="replace")
        return parse_rpm_primary_xml(text)


async def repo_records(repo: Repo) -> list[dict[str, Any]]:
    if repo.repo_type == "rpm":
        return (await fetch_rpm_records(repo))[:MAX_PACKAGES_PER_REPO]
    text = await fetch_packages_text(repo)
    return [{**record, "PackageFormat": "deb"} for record in parse_packages_index(text)[:MAX_PACKAGES_PER_REPO]]


async def refresh_repo(repo: Repo) -> dict[str, Any]:
    started = time.time()
    try:
        records = await repo_records(repo)
        refreshed_at = now_iso()
        with closing(connect_db()) as conn:
            conn.execute("DELETE FROM packages WHERE repo_name = ?", (repo.name,))
            for record in records:
                status, findings = assess_package(record)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO packages (
                      repo_name, package, version, architecture, section, priority,
                      filename, size, sha256, maintainer, description,
                      package_format, security_status, security_findings, refreshed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        repo.name,
                        record.get("Package", ""),
                        record.get("Version", ""),
                        record.get("Architecture", ""),
                        record.get("Section", ""),
                        record.get("Priority", ""),
                        record.get("Filename", ""),
                        int(record.get("Size", "0") or "0"),
                        record.get("SHA256", ""),
                        record.get("Maintainer", ""),
                        record.get("Description", ""),
                        record.get("PackageFormat", repo.repo_type),
                        status,
                        json.dumps(findings),
                        refreshed_at,
                    ),
                )
            conn.execute(
                """
                UPDATE repos
                SET last_refresh = ?, package_count = ?, status = 'ok', error = NULL
                WHERE name = ?
                """,
                (refreshed_at, len(records), repo.name),
            )
            conn.commit()
        return {"repo": repo.name, "status": "ok", "packages": len(records), "seconds": round(time.time() - started, 2)}
    except Exception as exc:  # noqa: BLE001
        with closing(connect_db()) as conn:
            conn.execute(
                "UPDATE repos SET status = 'error', error = ?, last_refresh = ? WHERE name = ?",
                (str(exc), now_iso(), repo.name),
            )
            conn.commit()
        return {"repo": repo.name, "status": "error", "error": str(exc)}


async def refresh_all() -> list[dict[str, Any]]:
    return [await refresh_repo(repo) for repo in configured_repos()]


def schedule_refresh() -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(lambda: __import__("asyncio").run(refresh_all()), "interval", minutes=REFRESH_INTERVAL_MINUTES)
    scheduler.start()
    return scheduler


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    scheduler = schedule_refresh()
    try:
        yield
    finally:
        scheduler.shutdown(wait=False)


app = FastAPI(title="pkgmng", version=APP_VERSION, lifespan=lifespan)


@app.get("/healthz")
def healthz() -> dict[str, Any]:
    return {"ok": True, "version": APP_VERSION, "time": now_iso()}


@app.get("/readyz")
def readyz() -> dict[str, Any]:
    with closing(connect_db()) as conn:
        count = conn.execute("SELECT COUNT(*) FROM repos").fetchone()[0]
    return {"ok": count > 0, "repos": count}


@app.post("/api/refresh")
async def api_refresh() -> JSONResponse:
    return JSONResponse({"results": await refresh_all()})


@app.get("/api/repos")
def api_repos() -> list[dict[str, Any]]:
    with closing(connect_db()) as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM repos ORDER BY repo_type, distro_family, name")]


@app.get("/api/families")
def api_families() -> list[dict[str, Any]]:
    with closing(connect_db()) as conn:
        return [
            dict(row)
            for row in conn.execute(
                """
                SELECT
                  distro_family,
                  repo_type,
                  COUNT(*) repos,
                  SUM(package_count) packages,
                  SUM(status='ok') healthy,
                  SUM(status='error') errors
                FROM repos
                GROUP BY distro_family, repo_type
                ORDER BY repo_type, distro_family
                """
            )
        ]


@app.get("/api/packages")
def api_packages(
    q: str = "",
    status: str = Query("", pattern="^(|passed|review|failed)$"),
    family: str = "",
    limit: int = Query(200, ge=1, le=1000),
) -> dict[str, Any]:
    where: list[str] = []
    args: list[Any] = []
    if q:
        where.append("(package LIKE ? OR description LIKE ? OR maintainer LIKE ?)")
        args.extend([f"%{q}%", f"%{q}%", f"%{q}%"])
    if status:
        where.append("security_status = ?")
        args.append(status)
    if family:
        where.append("repos.distro_family = ?")
        args.append(family)
    sql = """
        SELECT packages.*, repos.distro_family
        FROM packages
        JOIN repos ON repos.name = packages.repo_name
    """
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY security_status DESC, package LIMIT ?"
    args.append(limit)
    with closing(connect_db()) as conn:
        rows = [dict(row) for row in conn.execute(sql, args)]
        for row in rows:
            row["security_findings"] = json.loads(row["security_findings"])
        totals = dict(
            conn.execute(
                """
                SELECT
                  COUNT(*) total,
                  SUM(security_status='passed') passed,
                  SUM(security_status='review') review,
                  SUM(security_status='failed') failed
                FROM packages
                """
            ).fetchone()
        )
    return {"packages": rows, "totals": totals}


def dashboard_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="APT and RPM repository index with package metadata and security review status.">
  <title>pkgmng | Linux package control</title>
  <style>
    :root { color-scheme: light; --ink:#101418; --muted:#66727f; --line:#d7dde5; --accent:#0a6f64; --accent-2:#d7f36a; --bad:#a9342c; --warn:#8a641a; --ok:#087443; --rh:#c52032; --oracle:#c74634; --rocky:#10b981; --alma:#2563eb; --shadow:0 22px 70px rgba(32,45,58,.12); --ease:cubic-bezier(.32,.72,0,1); }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body { margin: 0; font-family: "Aptos", "Segoe UI Variable", ui-sans-serif, system-ui, sans-serif; background: radial-gradient(circle at 82% -10%, rgba(215,243,106,.38), transparent 26rem), radial-gradient(circle at 4% 8%, rgba(10,111,100,.14), transparent 24rem), linear-gradient(145deg, #f8faf8 0%, #eef3f1 46%, #f9faf7 100%); color: var(--ink); min-height: 100dvh; }
    body::before { content:""; position: fixed; inset:0; pointer-events:none; z-index:5; opacity:.055; background-image: linear-gradient(90deg, rgba(16,20,24,.12) 1px, transparent 1px), linear-gradient(rgba(16,20,24,.12) 1px, transparent 1px); background-size:42px 42px; mask-image:linear-gradient(to bottom, rgba(0,0,0,.7), transparent 60%); }
    .skip-link { position:absolute; left:-999px; top:10px; padding:10px 14px; background:#fff; color:var(--ink); z-index:10; border-radius:999px; }
    .skip-link:focus { left:16px; }
    .page { position:relative; z-index:1; max-width:1480px; margin:0 auto; padding:24px; }
    header { min-height:62dvh; display:grid; grid-template-columns:minmax(0,1.1fr) minmax(340px,.9fr); gap:28px; align-items:stretch; padding:22px 0 34px; }
    .brandbar { display:flex; align-items:center; justify-content:space-between; gap:14px; margin-bottom:64px; }
    .mark { display:flex; align-items:center; gap:10px; font-weight:750; }
    .mark-dot { width:30px; height:30px; border-radius:10px; background:var(--ink); box-shadow:inset 0 0 0 8px var(--accent-2); }
    .eyebrow { color:var(--accent); font-size:11px; text-transform:uppercase; letter-spacing:.18em; font-weight:760; }
    h1 { margin:18px 0 16px; max-width:850px; font-size:clamp(44px,7vw,108px); line-height:.91; letter-spacing:0; text-wrap:balance; }
    .lede { margin:0; max-width:58ch; color:#40505c; font-size:clamp(17px,2vw,21px); line-height:1.55; }
    .hero-actions { display:flex; align-items:center; flex-wrap:wrap; gap:12px; margin-top:30px; }
    button, select, input { font:inherit; border:1px solid rgba(16,20,24,.13); border-radius:14px; background:rgba(255,255,255,.82); color:var(--ink); height:44px; transition:transform .55s var(--ease), border-color .55s var(--ease), background .55s var(--ease), box-shadow .55s var(--ease); }
    button { display:inline-flex; align-items:center; gap:12px; border:0; border-radius:999px; padding:6px 8px 6px 18px; background:var(--ink); color:#fff; cursor:pointer; box-shadow:0 18px 44px rgba(16,20,24,.18); white-space:nowrap; }
    button:hover { transform:translateY(-2px); box-shadow:0 24px 56px rgba(16,20,24,.22); }
    button:active { transform:translateY(1px) scale(.98); }
    button:focus-visible, input:focus-visible, select:focus-visible { outline:3px solid rgba(10,111,100,.22); outline-offset:3px; }
    button[disabled] { opacity:.68; cursor:progress; }
    .button-orb { display:grid; place-items:center; width:32px; height:32px; border-radius:999px; background:var(--accent-2); color:var(--ink); transition:transform .55s var(--ease); }
    button:hover .button-orb { transform:translateX(2px) translateY(-1px); }
    .ghost { background:rgba(255,255,255,.62); color:var(--ink); border:1px solid rgba(16,20,24,.12); box-shadow:none; }
    .hero-panel { align-self:end; border-radius:28px; padding:8px; background:rgba(16,20,24,.06); box-shadow:var(--shadow); }
    .hero-core { border-radius:22px; background:rgba(255,255,255,.86); padding:22px; min-height:360px; display:grid; align-content:space-between; box-shadow:inset 0 1px 0 rgba(255,255,255,.86); }
    .scanline { display:flex; justify-content:space-between; gap:16px; padding:14px 0; border-bottom:1px solid rgba(16,20,24,.09); }
    .scanline:last-child { border-bottom:0; }
    .scanline strong { display:block; font-size:26px; font-variant-numeric:tabular-nums; }
    .scanline span { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.12em; }
    main { padding:8px 0 64px; }
    .section-head { display:flex; align-items:end; justify-content:space-between; gap:18px; margin:24px 0 16px; }
    h2 { margin:0; font-size:clamp(24px,3vw,42px); line-height:1; letter-spacing:0; }
    .muted { color: var(--muted); }
    .toolbar { display:grid; grid-template-columns:minmax(240px,1fr) 170px 210px; gap:12px; align-items:center; margin:16px 0; }
    input, select { width:100%; padding:0 14px; }
    .metrics { display:grid; grid-template-columns:repeat(4,minmax(140px,1fr)); gap:12px; }
    .metric { border-radius:24px; padding:7px; background:rgba(16,20,24,.055); animation:rise .8s var(--ease) both; }
    .metric-inner { min-height:126px; border-radius:18px; background:rgba(255,255,255,.86); padding:18px; box-shadow:inset 0 1px 0 rgba(255,255,255,.9); }
    .metric strong { display:block; font-size:clamp(30px,4vw,54px); line-height:.9; font-variant-numeric:tabular-nums; }
    .metric span { display:block; margin-top:14px; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.14em; }
    .repos { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:14px; margin-bottom:34px; }
    .repo { border-radius:24px; padding:7px; background:rgba(16,20,24,.055); animation:rise .8s var(--ease) both; }
    .repo-core { min-height:154px; border-radius:18px; background:rgba(255,255,255,.86); padding:18px; box-shadow:inset 0 1px 0 rgba(255,255,255,.9); }
    .repo h3 { display:flex; align-items:center; justify-content:space-between; gap:10px; margin:0 0 14px; font-size:16px; }
    .repo p { margin:8px 0 0; color:var(--muted); font-size:13px; line-height:1.45; overflow-wrap:anywhere; }
    .families { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:12px; margin:0 0 34px; }
    .family { border-radius:22px; padding:16px; background:rgba(255,255,255,.82); border:1px solid rgba(16,20,24,.08); box-shadow:inset 0 1px 0 rgba(255,255,255,.9); }
    .family h3 { display:flex; align-items:center; gap:9px; margin:0 0 10px; font-size:15px; }
    .family-dot { width:10px; height:10px; border-radius:999px; background:var(--accent); }
    .family[data-family*="Alma"] .family-dot { background:var(--alma); }
    .family[data-family*="Rocky"] .family-dot { background:var(--rocky); }
    .family[data-family*="Oracle"] .family-dot { background:var(--oracle); }
    .family[data-family*="Red"] .family-dot { background:var(--rh); }
    .family dl { display:grid; grid-template-columns:1fr 1fr; gap:8px 12px; margin:0; }
    .family dt { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.11em; }
    .family dd { margin:2px 0 0; font-size:22px; font-weight:760; font-variant-numeric:tabular-nums; }
    .badge { display:inline-flex; align-items:center; border-radius:999px; padding:5px 10px; font-size:12px; font-weight:720; text-transform:uppercase; letter-spacing:.08em; }
    .passed { color:#063f27; background:rgba(8,116,67,.13); }
    .review { color:#62440a; background:rgba(138,100,26,.16); }
    .failed { color:#761d18; background:rgba(169,52,44,.14); }
    .pending { color:#404a55; background:rgba(64,74,85,.12); }
    .error { color: var(--bad); }
    .table-shell { border-radius:28px; padding:8px; background:rgba(16,20,24,.06); box-shadow:var(--shadow); }
    .table-wrap { border-radius:22px; overflow:auto; background:rgba(255,255,255,.9); max-height:720px; box-shadow:inset 0 1px 0 rgba(255,255,255,.86); }
    table { width:100%; border-collapse:collapse; table-layout:fixed; min-width:980px; }
    th, td { border-bottom:1px solid rgba(16,20,24,.08); padding:15px 14px; text-align:left; vertical-align:top; font-size:13px; }
    th { position:sticky; top:0; z-index:1; color:#34424e; background:rgba(255,255,255,.96); font-size:11px; text-transform:uppercase; letter-spacing:.13em; }
    td:nth-child(1) { width:16%; font-weight:750; }
    td:nth-child(2) { width:20%; overflow-wrap:anywhere; font-variant-numeric:tabular-nums; }
    td:nth-child(3), td:nth-child(4) { width:9%; }
    td:nth-child(5) { width:12%; }
    tbody tr { transition:background .45s var(--ease); }
    tbody tr:hover { background:rgba(10,111,100,.055); }
    .skeleton { position:relative; overflow:hidden; border-radius:14px; background:rgba(16,20,24,.08); min-height:18px; }
    .skeleton::after { content:""; position:absolute; inset:0; transform:translateX(-100%); background:linear-gradient(90deg, transparent, rgba(255,255,255,.75), transparent); animation:shimmer 1.2s infinite; }
    .state { width:min(420px, calc(100vw - 76px)); padding:34px; text-align:center; color:var(--muted); }
    .state strong { display:block; color:var(--ink); font-size:18px; margin-bottom:8px; }
    footer { display:flex; justify-content:space-between; flex-wrap:wrap; gap:12px; padding:34px 0 0; color:var(--muted); font-size:13px; }
    @keyframes shimmer { to { transform:translateX(100%); } }
    @keyframes rise { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }
    .muted { color: var(--muted); }
    @media (max-width: 760px) {
      .page { padding:16px; }
      header { min-height:auto; grid-template-columns:1fr; padding-top:10px; }
      .brandbar { align-items:flex-start; flex-wrap:wrap; margin-bottom:42px; }
      .brandbar .eyebrow { font-size:9px; }
      h1 { font-size:clamp(40px,14vw,56px); overflow-wrap:anywhere; }
      .hero-core { min-height:260px; }
      .metrics { grid-template-columns:repeat(2,minmax(120px,1fr)); }
      .toolbar { grid-template-columns:1fr; }
      .section-head { align-items:flex-start; flex-direction:column; }
    }
  </style>
</head>
<body>
  <a class="skip-link" href="#packages-table">Skip to packages</a>
  <div class="page">
    <header>
      <section>
        <div class="brandbar">
          <div class="mark"><span class="mark-dot" aria-hidden="true"></span><span>pkgmng</span></div>
          <span class="eyebrow">APT + RHEL-family RPM control plane</span>
        </div>
        <div class="eyebrow">Repository mirror index</div>
        <h1>Package intelligence for Linux fleets.</h1>
        <p class="lede">Track Debian APT plus AlmaLinux, Rocky Linux, Oracle Linux, and Red Hat RPM repositories with security review signals from one production console.</p>
        <div class="hero-actions">
          <button id="refresh">Refresh index <span class="button-orb" aria-hidden="true">+</span></button>
          <button class="ghost" id="show-review">Review queue <span class="button-orb" aria-hidden="true">&gt;</span></button>
        </div>
      </section>
      <aside class="hero-panel" aria-label="Repository scan summary">
        <div class="hero-core" id="hero-summary">
          <div class="scanline"><span>Indexed packages</span><strong>...</strong></div>
          <div class="scanline"><span>Needs review</span><strong>...</strong></div>
          <div class="scanline"><span>Failed checks</span><strong>...</strong></div>
          <div class="scanline"><span>Refresh cadence</span><strong>6h</strong></div>
        </div>
      </aside>
    </header>
    <main id="content">
      <section class="metrics" id="metrics" aria-label="Package security totals"></section>
      <div class="section-head">
        <div>
          <div class="eyebrow">RHEL-family coverage</div>
          <h2>Distribution lanes</h2>
        </div>
        <p class="muted">RPM metadata from AlmaLinux, Rocky Linux, Oracle Linux, and Red Hat UBI sources is indexed alongside Debian APT data.</p>
      </div>
      <section class="families" id="families" aria-label="Distribution family summary"></section>
      <div class="section-head">
        <div>
          <div class="eyebrow">Repository sources</div>
          <h2>Mirror health</h2>
        </div>
        <p class="muted">Status, package counts, and last refresh time for each configured APT or RPM source.</p>
      </div>
      <section class="repos" id="repos"></section>
      <div class="section-head">
        <div>
          <div class="eyebrow">Package inventory</div>
          <h2>Security review table</h2>
        </div>
      </div>
      <div class="toolbar" role="search">
        <input id="q" aria-label="Search packages" placeholder="Search package, maintainer, description">
        <select id="status" aria-label="Filter by security status">
          <option value="">All statuses</option>
          <option value="failed">Failed</option>
          <option value="review">Review</option>
          <option value="passed">Passed</option>
        </select>
        <select id="family" aria-label="Filter by distribution family">
          <option value="">All families</option>
        </select>
      </div>
      <section class="table-shell" id="packages-table">
        <div class="table-wrap">
          <table>
            <thead><tr><th>Package</th><th>Version</th><th>Repo</th><th>Format</th><th>Status</th><th>Section</th><th>Findings</th><th>Description</th></tr></thead>
            <tbody id="packages"></tbody>
          </table>
        </div>
      </section>
    </main>
    <footer>
      <span>pkgmng production console</span>
      <span>Security heuristics are advisory and metadata driven across DEB and RPM packages.</span>
    </footer>
  </div>
  <script>
    const $ = (id) => document.getElementById(id);
    const esc = (v) => String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const skeletonRows = () => Array.from({length: 8}).map(() => '<tr><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td></tr>').join('');
    const statusClass = (value) => ['passed', 'review', 'failed', 'pending'].includes(value) ? value : 'pending';
    const n = (value) => Number(value || 0).toLocaleString();
    async function load() {
      $('packages').innerHTML = skeletonRows();
      try {
        const params = new URLSearchParams({ q: $('q').value, status: $('status').value, family: $('family').value, limit: '300' });
        const [repos, families, packages] = await Promise.all([fetch('/api/repos').then(r => r.json()), fetch('/api/families').then(r => r.json()), fetch('/api/packages?' + params).then(r => r.json())]);
        const totals = packages.totals || {};
        $('hero-summary').innerHTML = [
          ['Indexed packages', n(totals.total)],
          ['Needs review', n(totals.review)],
          ['Failed checks', n(totals.failed)],
          ['Refresh cadence', '6h']
        ].map(([k,v]) => `<div class="scanline"><span>${k}</span><strong>${v}</strong></div>`).join('');
        $('metrics').innerHTML = [['Total', totals.total], ['Passed', totals.passed], ['Review', totals.review], ['Failed', totals.failed]].map(([k,v], i) => `<article class="metric" style="animation-delay:${i * 60}ms"><div class="metric-inner"><strong>${n(v)}</strong><span>${k}</span></div></article>`).join('');
        const familyValue = $('family').value;
        $('family').innerHTML = '<option value="">All families</option>' + families.map(f => `<option value="${esc(f.distro_family)}">${esc(f.distro_family)}</option>`).join('');
        $('family').value = familyValue;
        $('families').innerHTML = families.length ? families.map(f => `<article class="family" data-family="${esc(f.distro_family)}"><h3><span class="family-dot"></span>${esc(f.distro_family)}</h3><dl><div><dt>Repos</dt><dd>${n(f.repos)}</dd></div><div><dt>Packages</dt><dd>${n(f.packages)}</dd></div><div><dt>Healthy</dt><dd>${n(f.healthy)}</dd></div><div><dt>Errors</dt><dd>${n(f.errors)}</dd></div></dl></article>`).join('') : '<article class="family"><h3><span class="family-dot"></span>No family data</h3></article>';
        $('repos').innerHTML = repos.length ? repos.map((r, i) => `<article class="repo" style="animation-delay:${i * 70}ms"><div class="repo-core"><h3>${esc(r.name)} <span class="badge ${r.status === 'ok' ? 'passed' : 'failed'}">${esc(r.status)}</span></h3><p><span class="badge pending">${esc(r.distro_family || (r.repo_type || 'apt').toUpperCase())}</span> <span class="badge pending">${esc((r.repo_type || 'apt').toUpperCase())}</span></p><p>${esc(r.base_url)}</p><p>${esc(r.suite)}/${esc(r.component)} - ${n(r.package_count)} packages</p><p>Refreshed ${esc(r.last_refresh || 'never')}</p>${r.error ? `<p class="error">${esc(r.error)}</p>` : ''}</div></article>`).join('') : '<article class="repo"><div class="repo-core"><h3>No repositories configured</h3><p>Add APT_REPOS or RPM_REPOS entries to begin indexing.</p></div></article>';
        $('packages').innerHTML = packages.packages.length ? packages.packages.map(p => `<tr><td>${esc(p.package)}</td><td>${esc(p.version)}</td><td>${esc(p.repo_name)}</td><td>${esc((p.package_format || 'deb').toUpperCase())}</td><td><span class="badge ${statusClass(p.security_status)}">${esc(p.security_status)}</span></td><td>${esc(p.section || '')}</td><td>${esc((p.security_findings || []).join('; ') || 'none')}</td><td class="muted">${esc((p.description || '').split('\\n')[0])}</td></tr>`).join('') : '<tr><td colspan="4"><div class="state"><strong>No packages match this filter</strong>Refresh repositories or widen the search criteria.</div></td><td colspan="4"></td></tr>';
      } catch (error) {
        $('packages').innerHTML = `<tr><td colspan="7"><div class="state error"><strong>Could not load package data</strong>${esc(error.message || error)}</div></td></tr>`;
      }
    }
    $('refresh').addEventListener('click', async () => { $('refresh').disabled = true; $('refresh').innerHTML = 'Refreshing <span class="button-orb" aria-hidden="true">...</span>'; await fetch('/api/refresh', { method: 'POST' }); $('refresh').disabled = false; $('refresh').innerHTML = 'Refresh index <span class="button-orb" aria-hidden="true">+</span>'; load(); });
    $('show-review').addEventListener('click', () => { $('status').value = 'review'; load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    $('q').addEventListener('input', () => clearTimeout(window.__t) || (window.__t = setTimeout(load, 250)));
    $('status').addEventListener('change', load);
    $('family').addEventListener('change', load);
    load();
  </script>
</body>
</html>"""


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return dashboard_html()


@app.get("/robots.txt", response_class=PlainTextResponse)
def robots() -> str:
    return "User-agent: *\nDisallow:\n"


@app.exception_handler(Exception)
async def error_handler(_, exc: Exception) -> JSONResponse:
    return JSONResponse(status_code=500, content={"error": str(exc)})


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host=os.getenv("APP_HOST", "0.0.0.0"), port=int(os.getenv("APP_PORT", "8080")))
