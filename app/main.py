from __future__ import annotations

import gzip
import io
import json
import lzma
import os
import re
import sqlite3
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from contextlib import asynccontextmanager, closing
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse


APP_VERSION = os.getenv("APP_VERSION", "dev")
DATA_DIR = Path(os.getenv("DATA_DIR", ".data"))
DB_PATH = Path(os.getenv("DB_PATH", str(DATA_DIR / "pkgmng.db")))
REFRESH_INTERVAL_MINUTES = int(os.getenv("REFRESH_INTERVAL_MINUTES", "360"))
APT_REPOS = os.getenv(
    "APT_REPOS",
    "debian-13-main|https://deb.debian.org/debian|trixie|main,"
    "debian-12-main|https://deb.debian.org/debian|bookworm|main,"
    "debian-11-main|https://deb.debian.org/debian|bullseye|main,"
    "debian-13-security|https://security.debian.org/debian-security|trixie-security|main,"
    "debian-12-security|https://security.debian.org/debian-security|bookworm-security|main,"
    "debian-11-security|https://security.debian.org/debian-security|bullseye-security|main",
)
RPM_REPOS = os.getenv(
    "RPM_REPOS",
    "alma-10-baseos|https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/|AlmaLinux 10|BaseOS,"
    "alma-9-baseos|https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/|AlmaLinux 9|BaseOS,"
    "alma-8-baseos|https://repo.almalinux.org/almalinux/8/BaseOS/x86_64/os/|AlmaLinux 8|BaseOS,"
    "rocky-10-baseos|https://dl.rockylinux.org/pub/rocky/10/BaseOS/x86_64/os/|Rocky Linux 10|BaseOS,"
    "rocky-9-baseos|https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/|Rocky Linux 9|BaseOS,"
    "rocky-8-baseos|https://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/|Rocky Linux 8|BaseOS,"
    "oracle-10-baseos|https://yum.oracle.com/repo/OracleLinux/OL10/baseos/latest/x86_64/|Oracle Linux 10|BaseOS,"
    "oracle-9-baseos|https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64/|Oracle Linux 9|BaseOS,"
    "oracle-8-baseos|https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/|Oracle Linux 8|BaseOS,"
    "oracle-7-latest|https://yum.oracle.com/repo/OracleLinux/OL7/latest/x86_64/|Oracle Linux 7|Latest,"
    "redhat-ubi10-baseos|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi10/10/x86_64/baseos/os/|Red Hat UBI 10|BaseOS,"
    "redhat-ubi9-baseos|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/|Red Hat UBI 9|BaseOS,"
    "redhat-ubi8-baseos|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi8/8/x86_64/baseos/os/|Red Hat UBI 8|BaseOS",
)
HTTP_TIMEOUT_SECONDS = float(os.getenv("HTTP_TIMEOUT_SECONDS", "30"))
MAX_PACKAGES_PER_REPO = int(os.getenv("MAX_PACKAGES_PER_REPO", "0"))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
ACTION_RATE_LIMIT_SECONDS = int(os.getenv("ACTION_RATE_LIMIT_SECONDS", "300"))
SCAN_STALE_MINUTES = int(os.getenv("SCAN_STALE_MINUTES", "120"))
DB_BUSY_TIMEOUT_SECONDS = float(os.getenv("DB_BUSY_TIMEOUT_SECONDS", "30"))
ACTION_LAST_RUN: dict[str, float] = {}
SCAN_LAUNCH_LOCK = threading.Lock()


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

    @property
    def release_version(self) -> str:
        value = f"{self.name} {self.suite} {self.base_url}"
        if self.repo_type == "apt":
            debian_versions = {"trixie": "13", "bookworm": "12", "bullseye": "11"}
            for codename, version in debian_versions.items():
                if codename in value.lower():
                    return version
        match = re.search(r"(?:ubi|ol|linux|alma|rocky|debian)[^\d]*(10|9|8|7|13|12|11)\b", value, re.I)
        if match:
            return match.group(1)
        match = re.search(r"/(?:OL|ubi)?(10|9|8|7|13|12|11)(?:/|$)", value, re.I)
        return match.group(1) if match else ""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


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


def repo_from_row(row: sqlite3.Row | dict[str, Any]) -> Repo:
    return Repo(
        str(row["name"]),
        str(row["repo_type"]),
        str(row["base_url"]),
        str(row["suite"]),
        str(row["component"]),
    )


def stored_repos() -> list[Repo]:
    with closing(connect_db()) as conn:
        return [
            repo_from_row(row)
            for row in conn.execute(
                "SELECT name, repo_type, base_url, suite, component FROM repos ORDER BY repo_type, distro_family, name"
            )
        ]


def repo_payload(payload: dict[str, Any], existing_name: str = "") -> Repo:
    name = str(payload.get("name") or existing_name).strip()
    repo_type = str(payload.get("repo_type") or "").strip().lower()
    base_url = str(payload.get("base_url") or "").strip()
    suite = str(payload.get("suite") or "").strip()
    component = str(payload.get("component") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{1,80}", name):
        raise HTTPException(status_code=400, detail="repo name must be 2-81 characters using letters, numbers, dot, underscore, or dash")
    if repo_type not in {"apt", "rpm"}:
        raise HTTPException(status_code=400, detail="repo_type must be apt or rpm")
    if not base_url.startswith(("https://", "http://")):
        raise HTTPException(status_code=400, detail="base_url must start with http:// or https://")
    if not suite or not component:
        raise HTTPException(status_code=400, detail="suite and component are required")
    return Repo(name=name, repo_type=repo_type, base_url=base_url, suite=suite, component=component)


def upsert_repo_source(conn: sqlite3.Connection, repo: Repo, reset_status: bool = False) -> None:
    conn.execute(
        """
        INSERT INTO repos(name, repo_type, distro_family, release_version, base_url, suite, component, status, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', NULL)
        ON CONFLICT(name) DO UPDATE SET
          repo_type=excluded.repo_type,
          distro_family=excluded.distro_family,
          release_version=excluded.release_version,
          base_url=excluded.base_url,
          suite=excluded.suite,
          component=excluded.component,
          status=CASE
            WHEN ? OR repos.repo_type != excluded.repo_type OR repos.base_url != excluded.base_url
                 OR repos.suite != excluded.suite OR repos.component != excluded.component
            THEN 'pending'
            ELSE repos.status
          END,
          error=CASE
            WHEN ? OR repos.repo_type != excluded.repo_type OR repos.base_url != excluded.base_url
                 OR repos.suite != excluded.suite OR repos.component != excluded.component
            THEN NULL
            ELSE repos.error
          END
        """,
        (
            repo.name,
            repo.repo_type,
            repo.distro_family,
            repo.release_version,
            repo.base_url,
            repo.suite,
            repo.component,
            reset_status,
            reset_status,
        ),
    )


def connect_db() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=DB_BUSY_TIMEOUT_SECONDS)
    conn.row_factory = sqlite3.Row
    conn.execute(f"PRAGMA busy_timeout = {int(DB_BUSY_TIMEOUT_SECONDS * 1000)}")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
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
              release_version TEXT NOT NULL DEFAULT '',
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
              checksum_algorithm TEXT,
              maintainer TEXT,
              description TEXT,
              package_format TEXT NOT NULL DEFAULT 'deb',
              security_status TEXT NOT NULL,
              security_findings TEXT NOT NULL,
              security_severity TEXT NOT NULL DEFAULT 'none',
              security_risk_score INTEGER NOT NULL DEFAULT 0,
              security_checks TEXT NOT NULL DEFAULT '[]',
              sandbox_status TEXT NOT NULL DEFAULT 'pending',
              sandbox_verdict TEXT NOT NULL DEFAULT '',
              sandbox_findings TEXT NOT NULL DEFAULT '[]',
              sandbox_evidence TEXT NOT NULL DEFAULT '[]',
              sandbox_next_action TEXT NOT NULL DEFAULT '',
              refreshed_at TEXT NOT NULL,
              UNIQUE(repo_name, package, version, architecture)
            );
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
            CREATE TABLE IF NOT EXISTS scan_events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              scan_run_id INTEGER NOT NULL,
              created_at TEXT NOT NULL,
              level TEXT NOT NULL DEFAULT 'info',
              stage TEXT NOT NULL,
              repo_name TEXT,
              message TEXT NOT NULL,
              details TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS sandbox_runs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              requested_at TEXT NOT NULL,
              started_at TEXT,
              finished_at TEXT,
              status TEXT NOT NULL,
              trigger TEXT NOT NULL,
              target_count INTEGER NOT NULL DEFAULT 0,
              package_ids TEXT NOT NULL DEFAULT '[]',
              passed INTEGER NOT NULL DEFAULT 0,
              review INTEGER NOT NULL DEFAULT 0,
              failed INTEGER NOT NULL DEFAULT 0,
              notes TEXT
            );
            CREATE TABLE IF NOT EXISTS sandbox_package_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              sandbox_run_id INTEGER NOT NULL,
              package_id INTEGER NOT NULL,
              package TEXT NOT NULL,
              version TEXT NOT NULL,
              architecture TEXT,
              repo_name TEXT NOT NULL,
              package_format TEXT NOT NULL,
              status TEXT NOT NULL,
              verdict TEXT NOT NULL,
              next_action TEXT NOT NULL,
              findings TEXT NOT NULL DEFAULT '[]',
              evidence TEXT NOT NULL DEFAULT '[]',
              created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(package);
            CREATE INDEX IF NOT EXISTS idx_packages_status ON packages(security_status);
            CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at);
            CREATE INDEX IF NOT EXISTS idx_scan_events_run ON scan_events(scan_run_id, id);
            CREATE INDEX IF NOT EXISTS idx_sandbox_runs_requested ON sandbox_runs(requested_at);
            CREATE INDEX IF NOT EXISTS idx_sandbox_package_logs_package ON sandbox_package_logs(package_id, id);
            """
        )
        ensure_column(conn, "repos", "repo_type", "TEXT NOT NULL DEFAULT 'apt'")
        ensure_column(conn, "repos", "distro_family", "TEXT NOT NULL DEFAULT 'Debian'")
        ensure_column(conn, "repos", "release_version", "TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "packages", "package_format", "TEXT NOT NULL DEFAULT 'deb'")
        ensure_column(conn, "packages", "checksum_algorithm", "TEXT")
        ensure_column(conn, "packages", "security_severity", "TEXT NOT NULL DEFAULT 'none'")
        ensure_column(conn, "packages", "security_risk_score", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "packages", "security_checks", "TEXT NOT NULL DEFAULT '[]'")
        ensure_column(conn, "packages", "sandbox_status", "TEXT NOT NULL DEFAULT 'pending'")
        ensure_column(conn, "packages", "sandbox_verdict", "TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "packages", "sandbox_findings", "TEXT NOT NULL DEFAULT '[]'")
        ensure_column(conn, "packages", "sandbox_evidence", "TEXT NOT NULL DEFAULT '[]'")
        ensure_column(conn, "packages", "sandbox_next_action", "TEXT NOT NULL DEFAULT ''")
        for repo in configured_repos():
            upsert_repo_source(conn, repo, reset_status=False)
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


def parse_rpm_primary_xml(text: str, limit: int | None = None) -> list[dict[str, Any]]:
    return parse_rpm_primary_stream(io.StringIO(text), limit)


def parse_rpm_primary_stream(stream: Any, limit: int | None = None) -> list[dict[str, Any]]:
    ns = {
        "m": "http://linux.duke.edu/metadata/common",
        "rpm": "http://linux.duke.edu/metadata/rpm",
    }
    records: list[dict[str, Any]] = []
    package_tag = f"{{{ns['m']}}}package"
    for _, package in ET.iterparse(stream, events=("end",)):
        if package.tag != package_tag:
            continue
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
                "ChecksumType": checksum.attrib.get("type", "") if checksum is not None else "",
                "Maintainer": text_of(package, "m:packager", ns),
                "Description": text_of(package, "m:description", ns) or text_of(package, "m:summary", ns),
                "PackageFormat": "rpm",
            }
        )
        package.clear()
        if limit and len(records) >= limit:
            break
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


def package_limit() -> int | None:
    return MAX_PACKAGES_PER_REPO if MAX_PACKAGES_PER_REPO > 0 else None


def add_check(checks: list[dict[str, Any]], check_id: str, label: str, status: str, severity: str, detail: str) -> None:
    checks.append(
        {
            "id": check_id,
            "label": label,
            "status": status,
            "severity": severity,
            "detail": detail,
            "remediation": remediation_for(check_id, status, severity, detail),
        }
    )


KNOWN_DIGEST_LENGTHS = {
    32: "md5",
    40: "sha1",
    64: "sha256",
    96: "sha384",
    128: "sha512",
}


def detect_checksum_algorithm(digest: str, declared: str = "") -> str:
    normalized = (digest or "").strip()
    declared = (declared or "").strip().lower().replace("-", "")
    if declared in {"md5", "sha1", "sha224", "sha256", "sha384", "sha512"} and re.fullmatch(r"[A-Fa-f0-9]+", normalized):
        return declared
    if re.fullmatch(r"[A-Fa-f0-9]+", normalized):
        return KNOWN_DIGEST_LENGTHS.get(len(normalized), "")
    return ""


def remediation_for(check_id: str, status: str, severity: str, detail: str) -> dict[str, Any]:
    if status == "passed":
        return {
            "action": "No action required",
            "priority": "none",
            "owner": "repository operator",
            "steps": ["Keep package under normal scheduled refresh monitoring."],
        }
    playbooks: dict[str, dict[str, Any]] = {
        "checksum": {
            "action": "Quarantine until checksum metadata is corrected",
            "owner": "repository maintainer",
            "steps": [
                "Do not promote this package into trusted mirrors.",
                "Re-fetch repository metadata from the upstream source.",
                "Compare package checksum against signed Release or repomd metadata.",
                "Escalate to the repository owner if the checksum remains missing or malformed.",
            ],
        },
        "artifact_type": {
            "action": "Block package because artifact extension does not match repository type",
            "owner": "repository maintainer",
            "steps": [
                "Remove the package from the candidate mirror set.",
                "Confirm whether the source is a DEB or RPM repository.",
                "Correct the repository configuration before rescanning.",
            ],
        },
        "declared_size": {
            "action": "Verify artifact metadata before promotion",
            "owner": "package reviewer",
            "steps": [
                "Fetch package headers from the upstream repository.",
                "Confirm the artifact size is non-zero and matches repository metadata.",
                "Rescan the repository after metadata refresh.",
            ],
        },
        "transport": {
            "action": "Move repository metadata fetches to HTTPS",
            "owner": "platform operator",
            "steps": [
                "Update the repository base URL to an HTTPS endpoint.",
                "Validate certificate trust from the cluster runtime.",
                "Refresh the index and confirm the transport check passes.",
            ],
        },
        "security_channel": {
            "action": "Prefer official security-channel package during remediation",
            "owner": "repository operator",
            "steps": [
                "Keep the package eligible for normal mirror promotion.",
                "Use the security channel as positive source context during vulnerability remediation.",
                "Continue normal compatibility testing for fleet rollout.",
            ],
        },
        "priority": {
            "action": "Stage high-impact package updates",
            "owner": "change manager",
            "steps": [
                "Test the package in a non-production fleet lane.",
                "Schedule a maintenance window if the package is required or important.",
                "Monitor dependent services after rollout.",
            ],
        },
        "sensitive_section": {
            "action": "Route high-impact package area to manual review",
            "owner": "security reviewer",
            "steps": [
                "Inspect package purpose, dependencies, scripts, and maintainer metadata.",
                "Confirm whether the package affects kernel, auth, cryptography, firewall, or remote access paths.",
                "Require approval before mirroring to production consumers.",
            ],
        },
        "privileged_behavior": {
            "action": "Require privileged-code approval",
            "owner": "security reviewer",
            "steps": [
                "Review package scripts and declared capabilities.",
                "Confirm whether setuid, kernel, or root-level behavior is expected.",
                "Approve only after sandbox or staging validation.",
            ],
        },
        "advisory_signal": {
            "action": "Attach advisory context to rollout decision",
            "owner": "security reviewer",
            "steps": [
                "Map advisory keywords to CVE, errata, or vendor bulletin records.",
                "Record impacted OS versions and package versions.",
                "Prefer patched package versions during remediation rollout.",
            ],
        },
        "metadata": {
            "action": "Continue normal monitoring",
            "owner": "repository operator",
            "steps": ["Keep package under scheduled scan cadence."],
        },
    }
    playbook = playbooks.get(check_id, playbooks["metadata"])
    priority = {"critical": "urgent", "high": "high", "medium": "normal", "low": "low"}.get(severity, "normal")
    return {**playbook, "priority": priority, "evidence": detail}


def validate_package(record: dict[str, Any], repo: Repo | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    package_format = record.get("PackageFormat", "deb")
    filename = record.get("Filename", "")
    checksum = str(record.get("SHA256", "") or "")
    declared_algorithm = str(record.get("ChecksumType", "") or record.get("checksum_algorithm", "") or "")
    size = int(record.get("Size", "0") or "0")
    expected_suffix = ".rpm" if package_format == "rpm" else ".deb"

    checksum_algorithm = detect_checksum_algorithm(checksum, declared_algorithm)
    if checksum_algorithm:
        add_check(
            checks,
            "checksum",
            "Package checksum",
            "passed",
            "none",
            f"valid {checksum_algorithm.upper()} checksum from repository metadata",
        )
    elif checksum:
        add_check(checks, "checksum", "Package checksum", "failed", "critical", "checksum is present but does not match a known digest format")
    else:
        add_check(checks, "checksum", "Package checksum", "failed", "critical", "missing package checksum")

    if filename.endswith(expected_suffix):
        add_check(checks, "artifact_type", "Package artifact type", "passed", "none", f"filename ends with {expected_suffix}")
    else:
        add_check(checks, "artifact_type", "Package artifact type", "failed", "critical", f"package filename is not a {expected_suffix}")

    if size > 0:
        add_check(checks, "declared_size", "Declared package size", "passed", "none", "repository metadata includes package size")
    else:
        add_check(checks, "declared_size", "Declared package size", "review", "medium", "package size is missing or zero")

    repo_family = repo.distro_family if repo else ""
    repo_name = repo.name if repo else str(record.get("RepoName", ""))
    if repo and repo.base_url.startswith("https://"):
        add_check(checks, "transport", "Repository transport", "passed", "none", "repository metadata fetched over HTTPS")
    elif repo:
        add_check(checks, "transport", "Repository transport", "review", "medium", "repository metadata fetched without HTTPS")

    if repo and ("security" in repo_name.lower() or "security" in repo.component.lower()):
        add_check(checks, "security_channel", "Security channel", "passed", "none", "package is published through an official security update channel")
    elif repo:
        add_check(checks, "security_channel", "Security channel", "passed", "none", f"package is indexed from {repo_family or repo.repo_type} repository metadata")

    expected_suffix = ".rpm" if package_format == "rpm" else ".deb"
    priority = record.get("Priority", "").lower()
    if priority in {"required", "important"}:
        add_check(checks, "priority", "High-impact priority", "review", "high", f"high-impact priority: {priority}")
    name = str(record.get("Package", "")).lower()
    section = record.get("Section", "").lower()
    for pattern, meaning in high_impact_patterns():
        evidence = high_impact_evidence(pattern, name, section)
        if evidence:
            add_check(checks, "sensitive_section", "High-impact package area", "review", "medium", f"{meaning}: {evidence}")
            break
    description = record.get("Description", "")
    if re.search(r"\b(setuid|setgid|privileged daemon|kernel module|loads? kernel modules?|grants? root|runs? as root)\b", description, re.I):
        add_check(checks, "privileged_behavior", "Privileged behavior signal", "review", "high", "description mentions privileged behavior")
    if re.search(r"\b(cve|vulnerab|exploit|security update|errata|advisory)\b", description, re.I):
        add_check(checks, "advisory_signal", "Advisory keyword signal", "review", "high", "description contains security advisory language")

    if not checks:
        add_check(checks, "metadata", "Baseline metadata", "passed", "none", "package metadata has no review triggers")

    severity_rank = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    status_rank = {"passed": 0, "review": 1, "failed": 2}
    severity = max((check["severity"] for check in checks), key=lambda value: severity_rank.get(value, 0))
    status = max((check["status"] for check in checks), key=lambda value: status_rank.get(value, 0))
    findings = [check["detail"] for check in checks if check["status"] != "passed"]
    remediation = [check["remediation"] for check in checks if check["status"] != "passed"]
    risk_score = sum({"none": 0, "low": 5, "medium": 15, "high": 30, "critical": 60}.get(check["severity"], 0) for check in checks)
    sandbox = sandbox_assessment(record, checks, repo)
    return {
        "status": status,
        "severity": severity,
        "risk_score": min(risk_score, 100),
        "findings": findings,
        "remediation": remediation,
        "checks": checks,
        "sandbox": sandbox,
    }


def sandbox_assessment(record: dict[str, Any], checks: list[dict[str, Any]], repo: Repo | None = None) -> dict[str, Any]:
    package_format = str(record.get("PackageFormat", repo.repo_type if repo else "deb") or "deb").lower()
    filename = str(record.get("Filename", "") or "")
    name = str(record.get("Package", "") or "")
    description = str(record.get("Description", "") or "")
    section = str(record.get("Section", "") or "")
    failed_checks = [check for check in checks if check.get("status") == "failed"]
    review_checks = [check for check in checks if check.get("status") == "review"]
    evidence = [
        f"artifact format: {package_format.upper()}",
        f"artifact path: {filename or 'not declared'}",
    ]
    if repo:
        evidence.append(f"source repo: {repo.name} ({repo.distro_family} {repo.release_version or repo.component})")
    findings: list[str] = []

    if failed_checks:
        findings.extend(check.get("detail", "") for check in failed_checks if check.get("detail"))
        return {
            "status": "failed",
            "verdict": "sandbox blocked before execution",
            "findings": findings or ["failed metadata checks prevent trusted sandbox execution"],
            "evidence": evidence,
            "next_action": "Quarantine the package until identity, type, checksum, and size metadata are valid. Do not execute it in a sandbox yet because the artifact cannot be trusted.",
        }

    high_impact_ids = {"priority", "sensitive_section", "privileged_behavior", "advisory_signal"}
    high_impact = [check for check in review_checks if check.get("id") in high_impact_ids]
    if high_impact:
        findings.extend(check.get("detail", "") for check in high_impact if check.get("detail"))
        evidence.append("dynamic behavior sandbox required before production promotion")
        return {
            "status": "review",
            "verdict": "dynamic sandbox required",
            "findings": findings,
            "evidence": evidence,
            "next_action": "Run the package in an isolated disposable host lane and inspect install scripts, file writes, service changes, network access, capabilities, and privileged execution before promotion.",
        }

    if re.search(r"\b(postinst|preinst|postrm|preun|scriptlet|systemd|daemon|service|setuid|kernel|module)\b", f"{name} {section} {description}", re.I):
        findings.append("package metadata suggests install-time behavior that should be observed in a sandbox")
        evidence.append("install-time behavior keyword detected in metadata")
        return {
            "status": "review",
            "verdict": "sandbox observation recommended",
            "findings": findings,
            "evidence": evidence,
            "next_action": "Observe install and remove behavior in a sandbox before broad rollout, then attach the result to the package record.",
        }

    return {
        "status": "passed",
        "verdict": "metadata preflight passed",
        "findings": [],
        "evidence": [*evidence, "no sandbox risk trigger detected from repository metadata"],
        "next_action": "Eligible for normal mirror consumption; keep under scheduled scan cadence.",
    }


def high_impact_patterns() -> list[tuple[str, str]]:
    return [
        ("kernel", "kernel or boot path"),
        ("linux-image", "kernel or boot path"),
        ("auth", "authentication path"),
        ("pam", "authentication path"),
        ("sudo", "privilege management path"),
        ("selinux", "mandatory access control path"),
        ("firewall", "network security path"),
        ("iptables", "network security path"),
        ("nftables", "network security path"),
        ("openssl", "cryptography path"),
        ("gnutls", "cryptography path"),
        ("openssh", "remote access path"),
    ]


def high_impact_evidence(term: str, name: str, section: str) -> str:
    generic_sections = {"", "unspecified", "unknown", "misc", "utils", "admin", "system", "applications/system"}
    section = (section or "").strip().lower()
    name = (name or "").strip().lower()
    token = re.escape(term)
    token_pattern = rf"(^|[-_/+.\s]){token}($|[-_/+.\s])"
    if section not in generic_sections and re.search(token_pattern, section):
        return f"package section contains {term} ({section})"
    if re.search(token_pattern, name):
        return f"package name contains {term} ({name})"
    return ""


def package_intelligence(package: dict[str, Any]) -> dict[str, Any]:
    name = str(package.get("package") or package.get("Package") or "").lower()
    section = str(package.get("section") or package.get("Section") or "").lower()
    description = str(package.get("description") or package.get("Description") or "").strip()
    maintainer = str(package.get("maintainer") or package.get("Maintainer") or "").strip()
    checks = package.get("security_checks") or []
    if isinstance(checks, str):
        try:
            checks = json.loads(checks)
        except json.JSONDecodeError:
            checks = []
    findings = package.get("security_findings") or []
    if isinstance(findings, str):
        try:
            findings = json.loads(findings)
        except json.JSONDecodeError:
            findings = []

    category, responsibility = classify_package(name, section, description)
    owner = default_owner_for(category)
    upstream_maintainer = upstream_maintainer_label(maintainer)
    primary_purpose = first_sentence(description) or responsibility
    status = package.get("security_status") or "passed"
    failed_checks = [check for check in checks if check.get("status") == "failed"]
    review_checks = [check for check in checks if check.get("status") == "review"]
    unsafe_reasons = [check.get("detail", "") for check in [*failed_checks, *review_checks] if check.get("detail")]
    why_not_safe = (
        "No unsafe condition detected by current metadata checks."
        if status == "passed"
        else "; ".join(unsafe_reasons or findings or ["Package requires manual security review."])
    )
    impact = impact_for(category, status, package.get("security_severity", "none"))
    safety_summary = (
        "Safe for normal mirror eligibility under scheduled monitoring."
        if status == "passed"
        else f"{status.title()} because {why_not_safe}"
    )
    return {
        "category": category,
        "responsibility": responsibility,
        "primary_purpose": primary_purpose,
        "operational_owner": owner,
        "upstream_maintainer": upstream_maintainer,
        "impact": impact,
        "safety_summary": safety_summary,
        "why_not_safe": why_not_safe,
        "unsafe_check_ids": [check.get("id") for check in [*failed_checks, *review_checks] if check.get("id")],
    }


def upstream_maintainer_label(value: str) -> str:
    maintainer = " ".join((value or "").split())
    if not maintainer:
        return "Not declared in package metadata"
    maintainer = re.sub(r"\s*<[^>]+@[^>]+>\s*", " (email present in package metadata)", maintainer)
    return maintainer


def classify_package(name: str, section: str, description: str) -> tuple[str, str]:
    text = f"{name} {section} {description}".lower()
    rules = [
        ("kernel", "Kernel and boot", "Manages kernel, boot, or low-level host runtime components."),
        ("linux-image", "Kernel and boot", "Provides the Linux kernel image used to boot hosts."),
        ("initramfs", "Kernel and boot", "Builds early boot images required before the root filesystem is mounted."),
        ("systemd", "System services", "Controls service supervision, boot targets, and host lifecycle behavior."),
        ("openssh", "Remote access", "Provides SSH client or server access for remote administration."),
        ("ssh", "Remote access", "Provides SSH client or server access for remote administration."),
        ("openssl", "Cryptography", "Provides TLS and cryptographic primitives used by applications and services."),
        ("gnutls", "Cryptography", "Provides TLS and cryptographic primitives used by applications and services."),
        ("crypto", "Cryptography", "Provides cryptographic libraries or security primitives."),
        ("auth", "Identity and access", "Handles authentication, authorization, or identity integration."),
        ("pam", "Identity and access", "Handles pluggable authentication for logins and privileged actions."),
        ("sudo", "Privilege management", "Controls delegated administrative privilege on hosts."),
        ("selinux", "Mandatory access control", "Enforces host security labels and mandatory access policy."),
        ("firewall", "Network security", "Controls packet filtering or network access policy."),
        ("iptables", "Network security", "Controls packet filtering or network access policy."),
        ("nftables", "Network security", "Controls packet filtering or network access policy."),
        ("network", "Networking", "Provides network configuration, client, daemon, or protocol support."),
        ("dns", "Networking", "Provides name resolution, DNS server, or DNS client behavior."),
        ("http", "Web and API services", "Provides web server, HTTP client, or API transport functionality."),
        ("nginx", "Web and API services", "Provides web serving, reverse proxy, or HTTP routing capability."),
        ("apache", "Web and API services", "Provides web serving, reverse proxy, or HTTP routing capability."),
        ("postgres", "Database", "Provides database client, server, or database integration support."),
        ("mysql", "Database", "Provides database client, server, or database integration support."),
        ("mariadb", "Database", "Provides database client, server, or database integration support."),
        ("sqlite", "Database", "Provides embedded database storage or database client libraries."),
        ("python", "Language runtime", "Provides Python runtime, libraries, packaging, or build support."),
        ("node", "Language runtime", "Provides JavaScript runtime, libraries, packaging, or build support."),
        ("java", "Language runtime", "Provides JVM runtime, libraries, packaging, or build support."),
        ("perl", "Language runtime", "Provides Perl runtime, libraries, packaging, or build support."),
        ("ruby", "Language runtime", "Provides Ruby runtime, libraries, packaging, or build support."),
        ("container", "Container runtime", "Provides container runtime, image, or orchestration support."),
        ("docker", "Container runtime", "Provides container runtime, image, or orchestration support."),
        ("podman", "Container runtime", "Provides container runtime, image, or orchestration support."),
        ("rpm", "Package management", "Provides package installation, repository metadata, or package tooling."),
        ("dnf", "Package management", "Provides package installation, repository metadata, or package tooling."),
        ("apt", "Package management", "Provides package installation, repository metadata, or package tooling."),
        ("devel", "Build tooling", "Provides headers, compilers, or libraries used to build software."),
        ("compiler", "Build tooling", "Provides headers, compilers, or libraries used to build software."),
        ("library", "Shared library", "Provides reusable runtime code consumed by other packages."),
        ("libs", "Shared library", "Provides reusable runtime code consumed by other packages."),
        ("doc", "Documentation", "Provides documentation, examples, or reference material."),
        ("font", "Fonts and assets", "Provides fonts, icons, media, or other user-interface assets."),
    ]
    for needle, category, responsibility in rules:
        if needle in text:
            return category, responsibility
    if "admin" in section or "system" in section:
        return "System administration", "Provides host administration, maintenance, or system utility functionality."
    if "net" in section:
        return "Networking", "Provides network configuration, client, daemon, or protocol support."
    if "lib" in name or section.startswith("lib"):
        return "Shared library", "Provides reusable runtime code consumed by other packages."
    return "Application or utility", "Provides an application, command-line tool, service, or supporting utility."


def first_sentence(text: str) -> str:
    normalized = " ".join(text.split())
    if not normalized:
        return ""
    match = re.search(r"(.{20,220}?[.!?])(?:\s|$)", normalized)
    return match.group(1) if match else normalized[:220]


def default_owner_for(category: str) -> str:
    if category in {"Kernel and boot", "System services", "Privilege management", "Mandatory access control"}:
        return "platform operations"
    if category in {"Cryptography", "Identity and access", "Network security", "Remote access"}:
        return "security team"
    if category in {"Database", "Web and API services", "Language runtime", "Shared library"}:
        return "application owner"
    return "repository operator"


def impact_for(category: str, status: str, severity: str) -> str:
    if status == "passed":
        return f"{category} package is eligible for normal consumption monitoring."
    if severity in {"critical", "high"}:
        return f"{category} package can affect fleet stability or trust boundaries; prioritize review before promotion."
    return f"{category} package needs validation before broad rollout."


def enrich_package(row: dict[str, Any]) -> dict[str, Any]:
    return {**row, **package_intelligence(row)}


def assess_package(record: dict[str, Any]) -> tuple[str, list[str]]:
    profile = validate_package(record)
    return profile["status"], profile["findings"]


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
        with tempfile.NamedTemporaryFile(dir=DATA_DIR, suffix=Path(primary_url).name) as spool:
            async with client.stream("GET", primary_url) as primary_response:
                primary_response.raise_for_status()
                async for chunk in primary_response.aiter_bytes():
                    spool.write(chunk)
            spool.flush()
            spool.seek(0)
            if primary_url.endswith(".gz"):
                with gzip.open(spool.name, "rt", encoding="utf-8", errors="replace") as stream:
                    return parse_rpm_primary_stream(stream, package_limit())
            if primary_url.endswith(".xz"):
                with lzma.open(spool.name, "rt", encoding="utf-8", errors="replace") as stream:
                    return parse_rpm_primary_stream(stream, package_limit())
            with open(spool.name, encoding="utf-8", errors="replace") as stream:
                return parse_rpm_primary_stream(stream, package_limit())


async def repo_records(repo: Repo) -> list[dict[str, Any]]:
    if repo.repo_type == "rpm":
        return await fetch_rpm_records(repo)
    text = await fetch_packages_text(repo)
    records = parse_packages_index(text)
    limit = package_limit()
    if limit:
        records = records[:limit]
    return [{**record, "PackageFormat": "deb"} for record in records]


async def refresh_repo(repo: Repo) -> dict[str, Any]:
    started = time.time()
    try:
        records = await repo_records(repo)
        refreshed_at = now_iso()
        with closing(connect_db()) as conn:
            conn.execute("DELETE FROM packages WHERE repo_name = ?", (repo.name,))
            for record in records:
                profile = validate_package(record, repo)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO packages (
                      repo_name, package, version, architecture, section, priority,
                      filename, size, sha256, checksum_algorithm, maintainer, description,
                      package_format, security_status, security_findings,
                      security_severity, security_risk_score, security_checks,
                      sandbox_status, sandbox_verdict, sandbox_findings, sandbox_evidence, sandbox_next_action,
                      refreshed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        detect_checksum_algorithm(str(record.get("SHA256", "") or ""), str(record.get("ChecksumType", "") or "")),
                        record.get("Maintainer", ""),
                        record.get("Description", ""),
                        record.get("PackageFormat", repo.repo_type),
                        profile["status"],
                        json.dumps(profile["findings"]),
                        profile["severity"],
                        profile["risk_score"],
                        json.dumps(profile["checks"]),
                        profile["sandbox"]["status"],
                        profile["sandbox"]["verdict"],
                        json.dumps(profile["sandbox"]["findings"]),
                        json.dumps(profile["sandbox"]["evidence"]),
                        profile["sandbox"]["next_action"],
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
              COALESCE(SUM(sandbox_status='passed'), 0) sandbox_passed,
              COALESCE(SUM(sandbox_status='review'), 0) sandbox_review,
              COALESCE(SUM(sandbox_status='failed'), 0) sandbox_failed,
              COALESCE(ROUND(AVG(security_risk_score), 1), 0) avg_risk
            FROM packages
            """
        ).fetchone()
    )


def latest_scan_totals(conn: sqlite3.Connection) -> dict[str, Any]:
    row = conn.execute(
        """
        SELECT packages_total, passed, review, failed, highest_severity
        FROM scan_runs
        WHERE status IN ('succeeded', 'degraded')
        ORDER BY id DESC
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        return {
            "total": 0,
            "passed": 0,
            "review": 0,
            "failed": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "sandbox_passed": 0,
            "sandbox_review": 0,
            "sandbox_failed": 0,
            "avg_risk": 0,
        }
    severity = row["highest_severity"] or "none"
    return {
        "total": row["packages_total"] or 0,
        "passed": row["passed"] or 0,
        "review": row["review"] or 0,
        "failed": row["failed"] or 0,
        "critical": 1 if severity == "critical" else 0,
        "high": 1 if severity == "high" else 0,
        "medium": 1 if severity == "medium" else 0,
        "sandbox_passed": 0,
        "sandbox_review": 0,
        "sandbox_failed": 0,
        "avg_risk": 0,
    }


def verify_action_request(request: Request, x_pkgmng_token: str = "") -> None:
    if ADMIN_TOKEN:
        auth_header = request.headers.get("authorization", "")
        bearer = auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else ""
        if x_pkgmng_token != ADMIN_TOKEN and bearer != ADMIN_TOKEN:
            raise HTTPException(status_code=401, detail="admin token required for state-changing package operations")
    key = f"{request.client.host if request.client else 'unknown'}:{request.url.path}"
    now = time.time()
    previous = ACTION_LAST_RUN.get(key, 0)
    if ACTION_RATE_LIMIT_SECONDS > 0 and now - previous < ACTION_RATE_LIMIT_SECONDS:
        retry_after = int(ACTION_RATE_LIMIT_SECONDS - (now - previous))
        raise HTTPException(status_code=429, detail=f"rate limited; retry after {retry_after} seconds")
    ACTION_LAST_RUN[key] = now


def highest_severity(totals: dict[str, Any]) -> str:
    if totals.get("critical"):
        return "critical"
    if totals.get("high"):
        return "high"
    if totals.get("medium"):
        return "medium"
    return "none"


def mark_stale_scan_runs(conn: sqlite3.Connection) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=SCAN_STALE_MINUTES)
    stale_ids: list[int] = []
    for row in conn.execute("SELECT id, started_at FROM scan_runs WHERE status = 'running'"):
        started = parse_iso(row["started_at"])
        if started and started < cutoff:
            stale_ids.append(row["id"])
    if not stale_ids:
        return 0
    placeholders = ",".join("?" for _ in stale_ids)
    conn.execute(
        f"""
        UPDATE scan_runs
        SET status = 'failed',
            finished_at = ?,
            notes = 'Scan run timed out before completion and was marked failed by watchdog.'
        WHERE id IN ({placeholders})
        """,
        [now_iso(), *stale_ids],
    )
    return len(stale_ids)


def mark_interrupted_scan_runs(conn: sqlite3.Connection) -> int:
    cursor = conn.execute(
        """
        UPDATE scan_runs
        SET status = 'failed',
            finished_at = ?,
            notes = 'Scan run was interrupted by application startup before completion.'
        WHERE status = 'running'
        """,
        (now_iso(),),
    )
    return int(cursor.rowcount or 0)


def begin_scan_run(conn: sqlite3.Connection, trigger: str, repos_total: int) -> int:
    conn.execute("BEGIN IMMEDIATE")
    mark_stale_scan_runs(conn)
    active = conn.execute(
        "SELECT id, started_at, trigger FROM scan_runs WHERE status = 'running' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if active:
        conn.rollback()
        raise HTTPException(
            status_code=409,
            detail=f"scan #{active['id']} is already running since {active['started_at']} ({active['trigger']})",
        )
    cursor = conn.execute(
        """
        INSERT INTO scan_runs(started_at, status, trigger, repos_total, notes)
        VALUES (?, 'running', ?, ?, ?)
        """,
        (now_iso(), trigger, repos_total, "Repository metadata refresh and package security validation started."),
    )
    run_id = cursor.lastrowid
    conn.execute(
        """
        INSERT INTO scan_events(scan_run_id, created_at, level, stage, message, details)
        VALUES (?, ?, 'info', 'queued', ?, ?)
        """,
        (
            run_id,
            now_iso(),
            f"Scan #{run_id} queued by {trigger}.",
            json.dumps({"trigger": trigger, "repos_total": repos_total}),
        ),
    )
    conn.commit()
    return int(run_id)


def write_scan_event(
    run_id: int,
    stage: str,
    message: str,
    *,
    level: str = "info",
    repo_name: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    try:
        with closing(connect_db()) as conn:
            conn.execute(
                """
                INSERT INTO scan_events(scan_run_id, created_at, level, stage, repo_name, message, details)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (run_id, now_iso(), level, stage, repo_name, message, json.dumps(details or {})),
            )
            conn.commit()
    except sqlite3.OperationalError as exc:
        print(f"could not write scan event for run #{run_id}: {exc}", flush=True)


def scan_event_rows(conn: sqlite3.Connection, scan_id: int, limit: int = 100) -> list[dict[str, Any]]:
    rows = conn.execute(
        """
        SELECT *
        FROM scan_events
        WHERE scan_run_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (scan_id, limit),
    )
    events: list[dict[str, Any]] = []
    for row in rows:
        event = dict(row)
        event["details"] = json.loads(event.get("details") or "{}")
        events.append(event)
    events.reverse()
    return events


def scan_detail_payload(conn: sqlite3.Connection, scan_id: int, event_limit: int = 100) -> dict[str, Any]:
    run = conn.execute("SELECT * FROM scan_runs WHERE id = ?", (scan_id,)).fetchone()
    if run is None:
        raise HTTPException(status_code=404, detail=f"scan run {scan_id} not found")
    run_dict = dict(run)
    repos_total = int(run_dict.get("repos_total") or 0)
    repos_done = int(run_dict.get("repos_ok") or 0) + int(run_dict.get("repos_error") or 0)
    progress_percent = round((repos_done / repos_total) * 100, 1) if repos_total else 0
    events = scan_event_rows(conn, scan_id, event_limit)
    return {
        "run": run_dict,
        "progress": {
            "repos_done": repos_done,
            "repos_total": repos_total,
            "percent": progress_percent,
            "running": run_dict.get("status") == "running",
        },
        "events": events,
        "logs": scan_log_entries([run_dict]),
    }


async def refresh_all(trigger: str = "manual", run_id: int | None = None) -> list[dict[str, Any]]:
    repos = stored_repos()
    if run_id is None:
        with closing(connect_db()) as conn:
            run_id = begin_scan_run(conn, trigger, len(repos))
    write_scan_event(run_id, "started", f"Scan #{run_id} started; refreshing {len(repos)} repositories.", details={"repos_total": len(repos)})
    results: list[dict[str, Any]] = []
    repos_ok = 0
    repos_error = 0
    for repo in repos:
        write_scan_event(run_id, "repo-started", f"Refreshing repository {repo.name}.", repo_name=repo.name)
        result = await refresh_repo(repo)
        results.append(result)
        if result.get("status") == "ok":
            repos_ok += 1
            write_scan_event(
                run_id,
                "repo-finished",
                f"Repository {repo.name} refreshed with {int(result.get('packages') or 0):,} packages.",
                repo_name=repo.name,
                details=result,
            )
        else:
            repos_error += 1
            write_scan_event(
                run_id,
                "repo-failed",
                f"Repository {repo.name} failed: {result.get('error') or 'unknown error'}",
                level="error",
                repo_name=repo.name,
                details=result,
            )
        with closing(connect_db()) as conn:
            conn.execute(
                """
                UPDATE scan_runs
                SET repos_ok = ?, repos_error = ?,
                    notes = ?
                WHERE id = ?
                """,
                (
                    repos_ok,
                    repos_error,
                    f"Refreshing repositories: {repos_ok + repos_error}/{len(repos)} complete.",
                    run_id,
                ),
            )
            conn.commit()
    with closing(connect_db()) as conn:
        totals = security_totals(conn)
        status = "failed" if repos_ok == 0 else "degraded" if repos_error else "succeeded"
        conn.execute(
            """
            UPDATE scan_runs
            SET finished_at = ?, status = ?, repos_ok = ?, repos_error = ?,
                packages_total = ?, passed = ?, review = ?, failed = ?,
                highest_severity = ?, notes = ?
            WHERE id = ?
            """,
            (
                now_iso(),
                status,
                repos_ok,
                repos_error,
                totals["total"],
                totals["passed"],
                totals["review"],
                totals["failed"],
                highest_severity(totals),
                f"Validated {totals['total']} packages across {repos_ok}/{len(results)} healthy repositories.",
                run_id,
            ),
        )
        conn.commit()
    write_scan_event(
        run_id,
        "finished",
        f"Scan #{run_id} finished with status {status}: {totals['total']:,} packages validated.",
        level="error" if status == "failed" else "info",
        details={"status": status, "packages_total": totals["total"], "repos_ok": repos_ok, "repos_error": repos_error},
    )
    return results


def fail_scan_run(run_id: int, trigger: str, exc: Exception) -> None:
    write_scan_event(
        run_id,
        "failed",
        f"Scan #{run_id} failed while running trigger {trigger}: {exc}",
        level="error",
        details={"trigger": trigger, "error": str(exc)},
    )
    last_error: Exception | None = None
    for _ in range(3):
        try:
            with closing(connect_db()) as conn:
                conn.execute(
                    """
                    UPDATE scan_runs
                    SET status = 'failed',
                        finished_at = ?,
                        notes = ?
                    WHERE id = ?
                    """,
                    (now_iso(), f"Scan worker failed before completion: {exc}", run_id),
                )
                conn.commit()
            return
        except sqlite3.OperationalError as write_exc:
            last_error = write_exc
            time.sleep(1)
    print(f"could not mark scan #{run_id} ({trigger}) failed: {last_error}", flush=True)


def launch_refresh(trigger: str) -> dict[str, Any]:
    repos = stored_repos()
    with SCAN_LAUNCH_LOCK:
        with closing(connect_db()) as conn:
            run_id = begin_scan_run(conn, trigger, len(repos))

    def runner() -> None:
        try:
            __import__("asyncio").run(refresh_all(trigger, run_id=run_id))
        except Exception as exc:  # noqa: BLE001
            print(f"refresh trigger {trigger} failed: {exc}", flush=True)
            fail_scan_run(run_id, trigger, exc)

    threading.Thread(target=runner, name=f"pkgmng-refresh-{trigger}", daemon=True).start()
    return {"run_id": run_id, "repos_total": len(repos)}


def schedule_refresh() -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(lambda: launch_refresh("scheduled"), "interval", minutes=REFRESH_INTERVAL_MINUTES)
    scheduler.start()
    return scheduler


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    with closing(connect_db()) as conn:
        interrupted = mark_interrupted_scan_runs(conn)
        if interrupted:
            conn.commit()
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
async def api_refresh(request: Request, x_pkgmng_token: str = Header(default="")) -> JSONResponse:
    verify_action_request(request, x_pkgmng_token)
    queued = launch_refresh("manual-refresh")
    return JSONResponse({"status": "queued", "trigger": "manual-refresh", **queued}, status_code=202)


@app.post("/api/scans")
async def api_scan(request: Request, x_pkgmng_token: str = Header(default="")) -> JSONResponse:
    verify_action_request(request, x_pkgmng_token)
    queued = launch_refresh("manual")
    return JSONResponse(
        {
            "status": "queued",
            "trigger": "manual",
            **queued,
            "message": "Full repository refresh, security validation, and sandbox preflight queued.",
        },
        status_code=202,
    )


@app.post("/api/sandbox/scans")
async def api_sandbox_scan(request: Request, x_pkgmng_token: str = Header(default="")) -> JSONResponse:
    verify_action_request(request, x_pkgmng_token)
    payload: dict[str, Any] = {}
    try:
        payload = await request.json()
    except Exception:  # noqa: BLE001
        payload = {}
    package_ids = payload.get("package_ids") if isinstance(payload, dict) else None
    if package_ids:
        run = run_targeted_sandbox(package_ids, trigger="manual-sandbox-targeted")
        return JSONResponse(
            {
                "status": run["status"],
                "trigger": run["trigger"],
                "sandbox_run_id": run["id"],
                "target_count": run["target_count"],
                "message": f"Sandbox preflight completed for {run['target_count']} selected packages.",
            },
            status_code=202,
        )
    queued = launch_refresh("manual-sandbox")
    return JSONResponse(
        {
            "status": "queued",
            "trigger": "manual-sandbox",
            **queued,
            "message": "Sandbox metadata preflight queued for every indexed RPM and DEB.",
        },
        status_code=202,
    )


def normalize_package_ids(raw_ids: Any) -> list[int]:
    if not isinstance(raw_ids, list):
        raise HTTPException(status_code=400, detail="package_ids must be a JSON array")
    ids: list[int] = []
    for raw_id in raw_ids:
        try:
            package_id = int(raw_id)
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail="package_ids must contain integer package ids") from exc
        if package_id <= 0:
            raise HTTPException(status_code=400, detail="package_ids must contain positive integers")
        if package_id not in ids:
            ids.append(package_id)
    if not ids:
        raise HTTPException(status_code=400, detail="select at least one package")
    if len(ids) > 20:
        raise HTTPException(status_code=400, detail="targeted sandbox runs are limited to 20 packages")
    return ids


def sandbox_profile_from_package(row: sqlite3.Row) -> dict[str, Any]:
    package = dict(row)
    record = {
        "Package": package.get("package") or "",
        "Version": package.get("version") or "",
        "Architecture": package.get("architecture") or "",
        "Section": package.get("section") or "",
        "Priority": package.get("priority") or "",
        "Filename": package.get("filename") or "",
        "Size": str(package.get("size") or ""),
        "SHA256": package.get("sha256") or "",
        "ChecksumType": package.get("checksum_algorithm") or "",
        "Maintainer": package.get("maintainer") or "",
        "Description": package.get("description") or "",
        "PackageFormat": package.get("package_format") or "",
    }
    repo = Repo(
        str(package["repo_name"]),
        str(package.get("repo_type") or package.get("package_format") or "apt"),
        str(package.get("base_url") or ""),
        str(package.get("suite") or ""),
        str(package.get("component") or ""),
    )
    profile = validate_package(record, repo)
    return profile["sandbox"]


def run_targeted_sandbox(raw_package_ids: Any, trigger: str = "manual-sandbox-targeted") -> dict[str, Any]:
    package_ids = normalize_package_ids(raw_package_ids)
    requested_at = now_iso()
    with closing(connect_db()) as conn:
        placeholders = ",".join("?" for _ in package_ids)
        rows = [
            row
            for row in conn.execute(
                f"""
                SELECT packages.*, repos.repo_type, repos.base_url, repos.suite, repos.component
                FROM packages
                JOIN repos ON repos.name = packages.repo_name
                WHERE packages.id IN ({placeholders})
                ORDER BY packages.package COLLATE NOCASE, packages.version, packages.architecture
                """,
                package_ids,
            )
        ]
        found_ids = {int(row["id"]) for row in rows}
        missing = [package_id for package_id in package_ids if package_id not in found_ids]
        if missing:
            raise HTTPException(status_code=404, detail=f"package ids not found: {missing}")
        cursor = conn.execute(
            """
            INSERT INTO sandbox_runs(requested_at, started_at, status, trigger, target_count, package_ids, notes)
            VALUES (?, ?, 'running', ?, ?, ?, ?)
            """,
            (
                requested_at,
                requested_at,
                trigger,
                len(rows),
                json.dumps(package_ids),
                "Targeted sandbox metadata preflight started for selected packages.",
            ),
        )
        run_id = int(cursor.lastrowid)
        counts = {"passed": 0, "review": 0, "failed": 0}
        for row in rows:
            sandbox = sandbox_profile_from_package(row)
            status = sandbox["status"]
            counts[status] = counts.get(status, 0) + 1
            findings = json.dumps(sandbox["findings"])
            evidence = json.dumps(
                [
                    *sandbox["evidence"],
                    "targeted sandbox preflight was requested by an operator for this package",
                    "dynamic package execution is not performed inside the web pod",
                ]
            )
            conn.execute(
                """
                UPDATE packages
                SET sandbox_status = ?,
                    sandbox_verdict = ?,
                    sandbox_findings = ?,
                    sandbox_evidence = ?,
                    sandbox_next_action = ?
                WHERE id = ?
                """,
                (status, sandbox["verdict"], findings, evidence, sandbox["next_action"], row["id"]),
            )
            conn.execute(
                """
                INSERT INTO sandbox_package_logs(
                  sandbox_run_id, package_id, package, version, architecture, repo_name, package_format,
                  status, verdict, next_action, findings, evidence, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run_id,
                    row["id"],
                    row["package"],
                    row["version"],
                    row["architecture"],
                    row["repo_name"],
                    row["package_format"],
                    status,
                    sandbox["verdict"],
                    sandbox["next_action"],
                    findings,
                    evidence,
                    now_iso(),
                ),
            )
        finished_at = now_iso()
        conn.execute(
            """
            UPDATE sandbox_runs
            SET status = 'succeeded',
                finished_at = ?,
                passed = ?,
                review = ?,
                failed = ?,
                notes = ?
            WHERE id = ?
            """,
            (
                finished_at,
                counts.get("passed", 0),
                counts.get("review", 0),
                counts.get("failed", 0),
                f"Targeted sandbox preflight completed for {len(rows)} selected packages.",
                run_id,
            ),
        )
        conn.commit()
    return {
        "id": run_id,
        "requested_at": requested_at,
        "finished_at": finished_at,
        "status": "succeeded",
        "trigger": trigger,
        "target_count": len(rows),
        **counts,
    }


def sandbox_run_rows(conn: sqlite3.Connection, limit: int) -> list[dict[str, Any]]:
    return [
        dict(row)
        for row in conn.execute(
            """
            SELECT *
            FROM sandbox_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
    ]


def sandbox_package_log_rows(conn: sqlite3.Connection, package_id: int | None = None, limit: int = 25) -> list[dict[str, Any]]:
    if package_id is None:
        rows = conn.execute(
            """
            SELECT *
            FROM sandbox_package_logs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
    else:
        rows = conn.execute(
            """
            SELECT *
            FROM sandbox_package_logs
            WHERE package_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (package_id, limit),
        )
    output: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["findings"] = json.loads(item.get("findings") or "[]")
        item["evidence"] = json.loads(item.get("evidence") or "[]")
        output.append(item)
    return output


def scan_log_entries(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for run in runs:
        status = run.get("status") or "unknown"
        started_at = run.get("started_at") or ""
        finished_at = run.get("finished_at") or ""
        packages_total = int(run.get("packages_total") or 0)
        repos_ok = int(run.get("repos_ok") or 0)
        repos_total = int(run.get("repos_total") or 0)
        notes = run.get("notes") or "No scan note recorded."
        if status == "running":
            message = f"Scan #{run.get('id')} is running from trigger {run.get('trigger')}; repository metadata is being refreshed and sandbox preflight is being recalculated."
        elif status == "succeeded":
            message = f"Scan #{run.get('id')} completed: {packages_total:,} packages validated across {repos_ok}/{repos_total} healthy repositories."
        elif status == "degraded":
            message = f"Scan #{run.get('id')} completed with repository errors: {packages_total:,} packages validated across {repos_ok}/{repos_total} healthy repositories."
        elif status == "failed":
            message = f"Scan #{run.get('id')} failed: {notes}"
        else:
            message = f"Scan #{run.get('id')} status is {status}: {notes}"
        entries.append(
            {
                "run_id": run.get("id"),
                "status": status,
                "trigger": run.get("trigger"),
                "timestamp": finished_at or started_at,
                "message": message,
                "notes": notes,
            }
        )
    return entries


@app.get("/api/scans")
def api_scans(limit: int = Query(10, ge=1, le=50)) -> dict[str, Any]:
    with closing(connect_db()) as conn:
        stale_marked = mark_stale_scan_runs(conn)
        if stale_marked:
            conn.commit()
        runs = [
            dict(row)
            for row in conn.execute(
                """
                SELECT *
                FROM scan_runs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            )
        ]
        current = runs[0] if runs else None
    return {"current": current, "runs": runs, "logs": scan_log_entries(runs)}


@app.get("/api/scans/{scan_id}")
def api_scan_detail(scan_id: int, event_limit: int = Query(100, ge=1, le=250)) -> dict[str, Any]:
    with closing(connect_db()) as conn:
        stale_marked = mark_stale_scan_runs(conn)
        if stale_marked:
            conn.commit()
        return scan_detail_payload(conn, scan_id, event_limit)


@app.get("/api/sandbox/scans")
def api_sandbox_scans(limit: int = Query(10, ge=1, le=50)) -> dict[str, Any]:
    payload = api_scans(limit)
    with closing(connect_db()) as conn:
        targeted_runs = sandbox_run_rows(conn, limit)
        package_logs = sandbox_package_log_rows(conn, limit=limit)
    return {
        **payload,
        "targeted_runs": targeted_runs,
        "package_logs": package_logs,
        "sandbox": {
            "passed": 0,
            "review": 0,
            "failed": 0,
            "pending": 0,
            "next_action": "Start on-demand sandbox preflight after source edits, package refreshes, or remediation changes. Dynamic execution belongs in a disposable worker lane.",
        },
    }


@app.get("/api/packages/{package_id}/sandbox/logs")
def api_package_sandbox_logs(package_id: int, limit: int = Query(25, ge=1, le=100)) -> dict[str, Any]:
    with closing(connect_db()) as conn:
        package = conn.execute(
            """
            SELECT id, package, version, architecture, repo_name, package_format, sandbox_status,
                   sandbox_verdict, sandbox_next_action
            FROM packages
            WHERE id = ?
            """,
            (package_id,),
        ).fetchone()
        if package is None:
            raise HTTPException(status_code=404, detail="package not found")
        logs = sandbox_package_log_rows(conn, package_id=package_id, limit=limit)
    return {"package": dict(package), "logs": logs}


@app.get("/api/repos")
def api_repos() -> list[dict[str, Any]]:
    with closing(connect_db()) as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM repos ORDER BY repo_type, distro_family, name")]


@app.post("/api/repos")
async def api_create_repo(request: Request, x_pkgmng_token: str = Header(default="")) -> JSONResponse:
    verify_action_request(request, x_pkgmng_token)
    repo = repo_payload(await request.json())
    with closing(connect_db()) as conn:
        existing = conn.execute("SELECT name FROM repos WHERE name = ?", (repo.name,)).fetchone()
        if existing:
            raise HTTPException(status_code=409, detail=f"repo {repo.name} already exists")
        upsert_repo_source(conn, repo, reset_status=True)
        conn.commit()
    return JSONResponse({"repo": repo_response(repo), "message": "repository source added"}, status_code=201)


@app.put("/api/repos/{repo_name}")
async def api_update_repo(repo_name: str, request: Request, x_pkgmng_token: str = Header(default="")) -> JSONResponse:
    verify_action_request(request, x_pkgmng_token)
    repo = repo_payload({**await request.json(), "name": repo_name}, existing_name=repo_name)
    with closing(connect_db()) as conn:
        existing = conn.execute("SELECT name FROM repos WHERE name = ?", (repo_name,)).fetchone()
        if existing is None:
            raise HTTPException(status_code=404, detail="repo not found")
        upsert_repo_source(conn, repo, reset_status=True)
        if repo.name != repo_name:
            conn.execute("UPDATE packages SET repo_name = ? WHERE repo_name = ?", (repo.name, repo_name))
            conn.execute("DELETE FROM repos WHERE name = ?", (repo_name,))
        conn.commit()
    return JSONResponse({"repo": repo_response(repo), "message": "repository source updated"})


def repo_response(repo: Repo) -> dict[str, Any]:
    return {
        "name": repo.name,
        "repo_type": repo.repo_type,
        "base_url": repo.base_url,
        "suite": repo.suite,
        "component": repo.component,
        "distro_family": repo.distro_family,
        "release_version": repo.release_version,
    }


@app.get("/api/repos/{repo_name}/packages")
def api_repo_packages(
    repo_name: str,
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> dict[str, Any]:
    return api_packages(
        q="",
        status="",
        severity="",
        sandbox_status="",
        family="",
        version="",
        repo=repo_name,
        package_format="",
        architecture="",
        checksum_algorithm="",
        sort="risk",
        limit=limit,
        offset=offset,
    )


@app.get("/api/families")
def api_families() -> list[dict[str, Any]]:
    with closing(connect_db()) as conn:
        families = [
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
        version_rows = conn.execute(
            """
            SELECT
              distro_family,
              release_version,
              COUNT(*) repos,
              SUM(package_count) packages,
              SUM(status='ok') healthy,
              SUM(status='error') errors
            FROM repos
            WHERE release_version != ''
            GROUP BY distro_family, release_version
            """
        ).fetchall()
    versions_by_family: dict[str, list[dict[str, Any]]] = {}
    for row in version_rows:
        versions_by_family.setdefault(row["distro_family"], []).append(dict(row))
    for family in families:
        versions = versions_by_family.get(family["distro_family"], [])
        family["versions"] = latest_versions(versions)
        family["version_count"] = len(family["versions"])
    return families


@app.get("/api/security")
def api_security() -> dict[str, Any]:
    with closing(connect_db()) as conn:
        totals = latest_scan_totals(conn)
        by_family = [
            dict(row)
            for row in conn.execute(
                """
                SELECT
                  distro_family,
                  release_version,
                  SUM(package_count) total,
                  0 passed,
                  0 review,
                  0 failed,
                  0 critical,
                  0 high,
                  0 avg_risk
                FROM repos
                GROUP BY distro_family, release_version
                ORDER BY distro_family, CAST(release_version AS INTEGER) DESC
                """
            )
        ]
        top_risk = [
            dict(row)
            for row in conn.execute(
                """
                SELECT packages.id, packages.package, packages.version, packages.architecture, packages.repo_name, packages.security_status,
                       packages.security_severity, packages.security_risk_score, packages.security_findings,
                       repos.distro_family, repos.release_version
                FROM packages
                JOIN repos ON repos.name = packages.repo_name
                WHERE packages.security_status != 'passed'
                ORDER BY packages.id ASC
                LIMIT 200
                """
            )
        ]
    seen_packages: set[str] = set()
    deduped_top_risk: list[dict[str, Any]] = []
    for row in top_risk:
        if row["package"] in seen_packages:
            continue
        seen_packages.add(row["package"])
        row["security_findings"] = json.loads(row["security_findings"])
        row["affected_variants"] = 1
        row.update(package_intelligence(row))
        deduped_top_risk.append(row)
        if len(deduped_top_risk) >= 25:
            break
    return {"totals": totals, "by_family": by_family, "top_risk": deduped_top_risk}


@app.get("/api/versions")
def api_versions() -> list[dict[str, Any]]:
    with closing(connect_db()) as conn:
        rows = [
            dict(row)
            for row in conn.execute(
                """
                SELECT
                  distro_family,
                  release_version,
                  repo_type,
                  COUNT(*) repos,
                  SUM(package_count) packages,
                  SUM(status='ok') healthy,
                  SUM(status='error') errors
                FROM repos
                WHERE release_version != ''
                GROUP BY distro_family, release_version, repo_type
                """
            )
        ]
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        family = grouped.setdefault(
            row["distro_family"],
            {"distro_family": row["distro_family"], "repo_type": row["repo_type"], "versions": []},
        )
        family["versions"].append(row)
    return [
        {**family, "versions": latest_versions(family["versions"])}
        for family in sorted(grouped.values(), key=lambda item: (item["repo_type"], item["distro_family"]))
    ]


def latest_versions(rows: list[dict[str, Any]], limit: int = 5) -> list[dict[str, Any]]:
    def sort_key(row: dict[str, Any]) -> tuple[int, str]:
        version = str(row.get("release_version") or "")
        return (int(version) if version.isdigit() else -1, version)

    return sorted(rows, key=sort_key, reverse=True)[:limit]


@app.get("/api/packages")
def api_packages(
    q: str = "",
    status: str = Query("", pattern="^(|passed|review|failed)$"),
    severity: str = Query("", pattern="^(|none|low|medium|high|critical)$"),
    sandbox_status: str = Query("", pattern="^(|passed|review|failed|pending)$"),
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
    if status:
        where.append("security_status = ?")
        args.append(status)
    if severity:
        where.append("security_severity = ?")
        args.append(severity)
    if sandbox_status:
        where.append("sandbox_status = ?")
        args.append(sandbox_status)
    if family:
        where.append("repos.distro_family = ?")
        args.append(family)
    if version:
        where.append("repos.release_version = ?")
        args.append(version)
    if repo:
        where.append("packages.repo_name = ?")
        args.append(repo)
    if package_format:
        where.append("package_format = ?")
        args.append(package_format)
    if architecture:
        where.append("architecture = ?")
        args.append(architecture)
    if checksum_algorithm:
        where.append("checksum_algorithm = ?")
        args.append(checksum_algorithm)
    base_sql = """
        SELECT packages.*, repos.distro_family, repos.release_version
        FROM packages
        JOIN repos ON repos.name = packages.repo_name
    """
    if where:
        where_sql = " WHERE " + " AND ".join(where)
        base_sql += where_sql
    order_options = {
        "risk": "packages.id ASC",
        "package": "package COLLATE NOCASE, version, architecture",
        "repo": "packages.repo_name COLLATE NOCASE, package COLLATE NOCASE, version, architecture",
        "version": "version COLLATE NOCASE, package COLLATE NOCASE, architecture",
        "status": "security_status DESC, security_severity DESC, security_risk_score DESC, package",
        "severity": "CASE security_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END DESC, security_risk_score DESC, package",
        "updated": "refreshed_at DESC, package COLLATE NOCASE, version",
    }
    order_by = order_options[sort]
    sql = base_sql + f" ORDER BY {order_by} LIMIT ? OFFSET ?"
    page_args = [*args, limit + 1, offset]
    with closing(connect_db()) as conn:
        rows = [dict(row) for row in conn.execute(sql, page_args)]
        has_more = len(rows) > limit
        rows = rows[:limit]
        for row in rows:
            row["security_findings"] = json.loads(row["security_findings"])
            row["security_checks"] = json.loads(row["security_checks"])
            row["sandbox_findings"] = json.loads(row.get("sandbox_findings") or "[]")
            row["sandbox_evidence"] = json.loads(row.get("sandbox_evidence") or "[]")
            row["checksum_algorithm"] = row.get("checksum_algorithm") or detect_checksum_algorithm(str(row.get("sha256") or ""))
            row.update(package_intelligence(row))
        page_total = offset + len(rows) + (1 if has_more else 0)
        totals = {
            "total": page_total,
            "passed": sum(1 for row in rows if row.get("security_status") == "passed"),
            "review": sum(1 for row in rows if row.get("security_status") == "review"),
            "failed": sum(1 for row in rows if row.get("security_status") == "failed"),
            "sandbox_passed": sum(1 for row in rows if row.get("sandbox_status") == "passed"),
            "sandbox_review": sum(1 for row in rows if row.get("sandbox_status") == "review"),
            "sandbox_failed": sum(1 for row in rows if row.get("sandbox_status") == "failed"),
        }
        filter_options = {
            "architectures": sorted(
                {value for value in ["amd64", "all", "x86_64", "noarch", *(row.get("architecture") or "" for row in rows)] if value}
            ),
            "checksum_algorithms": sorted(
                {value for value in ["sha1", "sha256", *(row.get("checksum_algorithm") or "" for row in rows)] if value}
            ),
        }
    return {
        "packages": rows,
        "totals": totals,
        "filter_options": filter_options,
        "page": {
            "total": page_total,
            "returned": len(rows),
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
        },
    }


@app.get("/api/packages/{package_id}")
def api_package(package_id: int) -> dict[str, Any]:
    with closing(connect_db()) as conn:
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
        raise HTTPException(status_code=404, detail="package not found")
    item = dict(row)
    item["security_findings"] = json.loads(item["security_findings"])
    item["security_checks"] = json.loads(item["security_checks"])
    item["sandbox_findings"] = json.loads(item.get("sandbox_findings") or "[]")
    item["sandbox_evidence"] = json.loads(item.get("sandbox_evidence") or "[]")
    item["checksum_algorithm"] = item.get("checksum_algorithm") or detect_checksum_algorithm(str(item.get("sha256") or ""))
    item.update(package_intelligence(item))
    item["remediation"] = [
        check.get("remediation", remediation_for(check.get("id", "metadata"), check.get("status", "review"), check.get("severity", "medium"), check.get("detail", "")))
        for check in item["security_checks"]
        if check.get("status") != "passed"
    ]
    item["recommended_action"] = remediation_summary(item)
    return item


def remediation_summary(package: dict[str, Any]) -> str:
    if package.get("security_status") == "passed":
        return "No remediation required. Keep this package under scheduled monitoring."
    if package.get("security_status") == "failed":
        return "Block promotion, quarantine the package from trusted mirrors, and resolve failed metadata checks before rollout."
    return "Route to manual security review, attach advisory context, and approve only after OS-version compatibility checks pass."


def dashboard_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="APT and RPM repository index with package metadata and security review status.">
  <title>pkgmng | Linux package control</title>
  <style>
    :root { color-scheme: light; --bg:#f5f7fb; --surface:#ffffff; --surface-2:#eef3f7; --ink:#101722; --muted:#657386; --soft:#8090a3; --line:#d7e0ea; --primary:#0f4c81; --primary-strong:#09365f; --primary-soft:#dcebf8; --brand:#7ac142; --ok:#087443; --ok-bg:#dff5e8; --low:#2f855a; --low-bg:#e4f7ee; --medium:#946200; --medium-bg:#fff0c2; --high:#b45309; --high-bg:#ffe2c2; --critical:#bd1e2d; --critical-bg:#ffe0e3; --neutral-bg:#e8edf3; --rh:#c52032; --oracle:#c74634; --rocky:#10b981; --alma:#2563eb; --shadow:0 18px 52px rgba(18,33,54,.12); --shadow-soft:0 8px 22px rgba(18,33,54,.08); --ease:cubic-bezier(.32,.72,0,1); }
    [data-theme="dark"] { color-scheme: dark; --bg:#0b1119; --surface:#101824; --surface-2:#172231; --ink:#eef5ff; --muted:#a8b7ca; --soft:#8294aa; --line:#263447; --primary:#5aa7e8; --primary-strong:#8bc6ff; --primary-soft:#122f49; --brand:#8ccf4d; --ok:#61d394; --ok-bg:#103724; --low:#7dd3a7; --low-bg:#113322; --medium:#f0b84b; --medium-bg:#3b2c0b; --high:#fb923c; --high-bg:#44230c; --critical:#fb7185; --critical-bg:#46131c; --neutral-bg:#263447; --shadow:0 18px 58px rgba(0,0,0,.34); --shadow-soft:0 10px 28px rgba(0,0,0,.24); }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body { margin: 0; font-family: "Aptos", "Segoe UI Variable", ui-sans-serif, system-ui, sans-serif; background: radial-gradient(circle at 82% -10%, rgba(15,76,129,.14), transparent 28rem), radial-gradient(circle at 5% 10%, rgba(122,193,66,.11), transparent 20rem), linear-gradient(145deg, var(--bg) 0%, var(--surface-2) 52%, var(--bg) 100%); color: var(--ink); min-height: 100dvh; }
    body::before { content:""; position: fixed; inset:0; pointer-events:none; z-index:5; opacity:.04; background-image: linear-gradient(90deg, currentColor 1px, transparent 1px), linear-gradient(currentColor 1px, transparent 1px); background-size:42px 42px; mask-image:linear-gradient(to bottom, rgba(0,0,0,.7), transparent 60%); }
    .skip-link { position:absolute; left:-999px; top:10px; padding:10px 14px; background:#fff; color:var(--ink); z-index:10; border-radius:999px; }
    .skip-link:focus { left:16px; }
    .page { position:relative; z-index:1; max-width:1480px; margin:0 auto; padding:24px; }
    .console-nav { position:sticky; top:14px; z-index:4; display:flex; align-items:center; justify-content:space-between; gap:12px; margin:0 0 18px; padding:8px; border-radius:18px; background:color-mix(in srgb, var(--surface) 86%, transparent); border:1px solid color-mix(in srgb, var(--line) 82%, transparent); box-shadow:var(--shadow-soft); backdrop-filter:blur(18px); }
    .nav-links { display:flex; align-items:center; gap:4px; overflow:auto; }
    .nav-links a { display:inline-flex; align-items:center; min-height:34px; padding:0 12px; border-radius:12px; color:var(--muted); text-decoration:none; font-size:13px; font-weight:720; white-space:nowrap; transition:background .45s var(--ease), color .45s var(--ease), transform .45s var(--ease); }
    .nav-links a:hover { background:var(--primary-soft); color:var(--primary-strong); transform:translateY(-1px); }
    .theme-toggle { height:34px; padding:4px 6px 4px 11px; color:var(--ink); background:var(--surface-2); border:1px solid var(--line); box-shadow:none; }
    header { min-height:56dvh; display:grid; grid-template-columns:minmax(0,1.08fr) minmax(340px,.92fr); gap:24px; align-items:stretch; padding:20px 0 28px; }
    .brandbar { display:flex; align-items:center; justify-content:space-between; gap:14px; margin-bottom:64px; }
    .mark { display:flex; align-items:center; gap:10px; font-weight:750; }
    .mark-dot { width:30px; height:30px; border-radius:10px; background:var(--primary); box-shadow:inset 0 0 0 8px var(--brand); }
    .eyebrow { color:var(--primary); font-size:11px; text-transform:uppercase; letter-spacing:.18em; font-weight:760; }
    h1 { margin:18px 0 16px; max-width:850px; font-size:clamp(44px,7vw,96px); line-height:.94; letter-spacing:0; text-wrap:balance; }
    .lede { margin:0; max-width:58ch; color:#40505c; font-size:clamp(17px,2vw,21px); line-height:1.55; }
    .hero-actions { display:flex; align-items:center; flex-wrap:wrap; gap:12px; margin-top:30px; }
    button, select, input { font:inherit; border:1px solid color-mix(in srgb, var(--line) 92%, transparent); border-radius:12px; background:color-mix(in srgb, var(--surface) 88%, transparent); color:var(--ink); height:42px; transition:transform .55s var(--ease), border-color .55s var(--ease), background .55s var(--ease), box-shadow .55s var(--ease); }
    button { display:inline-flex; align-items:center; gap:10px; border:0; border-radius:999px; padding:5px 7px 5px 16px; background:var(--primary); color:#fff; cursor:pointer; box-shadow:0 15px 34px color-mix(in srgb, var(--primary) 28%, transparent); white-space:nowrap; font-weight:760; }
    button:hover { transform:translateY(-2px); background:var(--primary-strong); box-shadow:0 20px 46px color-mix(in srgb, var(--primary) 30%, transparent); }
    button:active { transform:translateY(1px) scale(.98); }
    button:focus-visible, input:focus-visible, select:focus-visible { outline:3px solid color-mix(in srgb, var(--primary) 28%, transparent); outline-offset:3px; }
    button[disabled] { opacity:.68; cursor:progress; }
    .button-orb { display:grid; place-items:center; width:30px; height:30px; border-radius:999px; background:color-mix(in srgb, #fff 22%, transparent); color:currentColor; transition:transform .55s var(--ease); }
    .button-orb svg { width:16px; height:16px; stroke:currentColor; stroke-width:2; fill:none; stroke-linecap:round; stroke-linejoin:round; }
    button:hover .button-orb { transform:translateX(2px) translateY(-1px); }
    .secondary { background:var(--surface); color:var(--primary-strong); border:1px solid var(--line); box-shadow:var(--shadow-soft); }
    .ghost { background:transparent; color:var(--ink); border:1px solid var(--line); box-shadow:none; }
    .hero-panel { align-self:end; border-radius:24px; padding:7px; background:color-mix(in srgb, var(--ink) 7%, transparent); box-shadow:var(--shadow); }
    .hero-core { border-radius:18px; background:color-mix(in srgb, var(--surface) 92%, transparent); padding:18px; min-height:330px; display:grid; align-content:space-between; box-shadow:inset 0 1px 0 rgba(255,255,255,.22); }
    .scanline { display:flex; justify-content:space-between; gap:16px; padding:12px 0; border-bottom:1px solid color-mix(in srgb, var(--line) 80%, transparent); }
    .scanline:last-child { border-bottom:0; }
    .scanline strong { display:block; font-size:26px; font-variant-numeric:tabular-nums; }
    .scanline span { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.12em; }
    main { padding:8px 0 64px; }
    .section-head { display:flex; align-items:end; justify-content:space-between; gap:18px; margin:22px 0 12px; scroll-margin-top:84px; }
    h2 { margin:0; font-size:clamp(20px,2vw,28px); line-height:1.12; letter-spacing:0; }
    .muted { color: var(--muted); }
    .toolbar-panel { margin:16px 0; padding:12px; border-radius:18px; background:var(--surface); border:1px solid var(--line); box-shadow:var(--shadow-soft); }
    .toolbar-panel-head { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; margin-bottom:12px; }
    .toolbar-panel-head h3 { margin:2px 0 4px; font-size:18px; }
    .toolbar-panel-head p { margin:0; font-size:13px; }
    .toolbar { display:grid; grid-template-columns:minmax(240px,1.4fr) repeat(4,minmax(145px,1fr)); gap:10px; align-items:end; }
    .filter-field { display:grid; gap:6px; color:var(--muted); font-size:12px; font-weight:720; }
    .filter-field label { color:var(--muted); }
    .filter-actions { display:flex; gap:8px; justify-content:flex-end; flex-wrap:wrap; }
    .filter-summary { display:flex; flex-wrap:wrap; gap:7px; margin-top:12px; min-height:26px; }
    .filter-chip { display:inline-flex; align-items:center; gap:6px; min-height:26px; border-radius:999px; padding:4px 9px; background:var(--neutral-bg); color:var(--ink); border:1px solid var(--line); font-size:12px; font-weight:720; }
    input, select { width:100%; padding:0 14px; }
    .page-controls { display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin:0 0 12px; color:var(--muted); font-size:13px; }
    .page-actions { display:flex; gap:10px; flex-wrap:wrap; }
    .metrics { display:grid; grid-template-columns:repeat(4,minmax(140px,1fr)); gap:12px; }
    .metric { border-radius:18px; padding:0; background:var(--surface); border:1px solid var(--line); box-shadow:var(--shadow-soft); animation:rise .8s var(--ease) both; }
    .metric-inner { min-height:104px; border-radius:18px; background:linear-gradient(180deg, color-mix(in srgb, var(--surface) 92%, transparent), color-mix(in srgb, var(--surface-2) 80%, transparent)); padding:16px; box-shadow:inset 0 1px 0 rgba(255,255,255,.18); }
    .metric strong { display:block; font-size:clamp(30px,4vw,54px); line-height:.9; font-variant-numeric:tabular-nums; }
    .metric span { display:block; margin-top:14px; color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.14em; }
    .repos { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:14px; margin-bottom:34px; }
    .repo { border-radius:14px; padding:0; background:var(--surface); border:1px solid var(--line); box-shadow:none; animation:rise .8s var(--ease) both; transition:transform .45s var(--ease), box-shadow .45s var(--ease); }
    .repo:hover { transform:translateY(-2px); box-shadow:var(--shadow-soft); }
    .repo-core { min-height:132px; border-radius:14px; background:var(--surface); padding:14px; box-shadow:none; }
    .repo h3 { display:flex; align-items:center; justify-content:space-between; gap:10px; margin:0 0 14px; font-size:16px; }
    .repo p { margin:8px 0 0; color:var(--muted); font-size:13px; line-height:1.45; overflow-wrap:anywhere; }
    .source-console { display:grid; grid-template-columns:minmax(300px,.95fr) minmax(360px,1.05fr); gap:14px; margin-bottom:16px; scroll-margin-top:90px; }
    .source-panel { border-radius:18px; padding:16px; background:var(--surface); border:1px solid var(--line); box-shadow:var(--shadow-soft); }
    .source-panel h3 { margin:8px 0 12px; font-size:clamp(22px,2.4vw,30px); line-height:1; }
    .source-form { display:grid; grid-template-columns:1fr 130px; gap:10px; }
    .source-form label { display:grid; gap:6px; color:var(--muted); font-size:12px; font-weight:720; }
    .source-form .wide { grid-column:1 / -1; }
    .source-form-actions { grid-column:1 / -1; display:flex; gap:10px; flex-wrap:wrap; margin-top:4px; }
    .source-list { display:grid; gap:9px; max-height:420px; overflow:auto; padding-right:4px; }
    .source-row { display:grid; grid-template-columns:1fr auto; gap:12px; align-items:center; padding:11px; border-radius:13px; background:color-mix(in srgb, var(--surface-2) 54%, var(--surface)); border:1px solid var(--line); }
    .source-row strong, .source-row span { overflow-wrap:anywhere; }
    .source-row p { margin:5px 0 0; color:var(--muted); font-size:12px; line-height:1.4; overflow-wrap:anywhere; }
    .source-actions { display:flex; gap:6px; flex-wrap:wrap; justify-content:flex-end; }
    .mini-button { height:32px; padding:4px 9px; box-shadow:none; font-size:12px; }
    .source-packages { margin-top:12px; padding:12px; border-radius:14px; background:color-mix(in srgb, var(--primary-soft) 46%, transparent); border:1px solid color-mix(in srgb, var(--primary) 18%, var(--line)); }
    .families { display:grid; grid-template-columns:repeat(auto-fit,minmax(210px,1fr)); gap:12px; margin:0 0 34px; }
    .family { border-radius:16px; padding:14px; background:var(--surface); border:1px solid var(--line); box-shadow:var(--shadow-soft); }
    .family h3 { display:flex; align-items:center; gap:9px; margin:0 0 10px; font-size:15px; }
    .family-dot { width:10px; height:10px; border-radius:999px; background:var(--accent); }
    .family[data-family*="Alma"] .family-dot { background:var(--alma); }
    .family[data-family*="Rocky"] .family-dot { background:var(--rocky); }
    .family[data-family*="Oracle"] .family-dot { background:var(--oracle); }
    .family[data-family*="Red"] .family-dot { background:var(--rh); }
    .family dl { display:grid; grid-template-columns:1fr 1fr; gap:8px 12px; margin:0; }
    .family dt { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.11em; }
    .family dd { margin:2px 0 0; font-size:22px; font-weight:760; font-variant-numeric:tabular-nums; }
    .version-strip { display:flex; flex-wrap:wrap; gap:6px; margin-top:14px; }
    .version-pill { display:inline-flex; align-items:center; min-height:26px; border-radius:999px; padding:4px 9px; background:var(--neutral-bg); color:var(--ink); font-size:12px; font-weight:740; }
    .security-grid { display:grid; grid-template-columns:minmax(280px,.85fr) minmax(360px,1.15fr); gap:14px; margin:0 0 34px; }
    .security-panel { border-radius:18px; padding:16px; background:var(--surface); border:1px solid var(--line); box-shadow:var(--shadow-soft); }
    .security-panel h3 { margin:8px 0 0; font-size:clamp(24px,3vw,38px); line-height:1; font-variant-numeric:tabular-nums; }
    .risk-meter { height:12px; border-radius:999px; overflow:hidden; background:var(--neutral-bg); margin:18px 0 8px; }
    .risk-meter span { display:block; height:100%; width:0; background:linear-gradient(90deg, var(--ok), var(--medium), var(--high), var(--critical)); border-radius:999px; }
    .risk-list { display:grid; gap:8px; margin-top:14px; }
    .risk-item { display:grid; grid-template-columns:1fr auto; gap:10px; align-items:center; padding:9px 0; border-top:1px solid var(--line); }
    .risk-item strong { font-size:13px; overflow-wrap:anywhere; }
    .risk-item span { color:var(--muted); font-size:12px; text-align:right; }
    .scan-console { display:grid; grid-template-columns:minmax(280px,.9fr) minmax(360px,1.1fr); gap:14px; margin:0 0 34px; }
    .scan-card { border-radius:18px; padding:16px; background:var(--surface); border:1px solid var(--line); box-shadow:var(--shadow-soft); }
    .remediation-card { border-radius:18px; padding:16px; background:linear-gradient(180deg, var(--surface), color-mix(in srgb, var(--primary-soft) 42%, var(--surface))); border:1px solid color-mix(in srgb, var(--primary) 18%, var(--line)); box-shadow:var(--shadow-soft); }
    .scan-card h3, .remediation-card h3 { margin:8px 0 12px; font-size:clamp(22px,2.5vw,32px); line-height:1; }
    .scan-actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:16px; }
    .scan-history { display:grid; gap:8px; margin-top:14px; }
    .scan-run { display:grid; grid-template-columns:auto 1fr auto; gap:10px; align-items:center; padding:9px 0; border-top:1px solid var(--line); }
    .scan-run button { appearance:none; border:0; background:transparent; text-align:left; padding:0; color:inherit; cursor:pointer; }
    .scan-run[data-active="true"] { background:color-mix(in srgb, var(--primary-soft) 58%, transparent); margin-inline:-8px; padding-inline:8px; border-radius:12px; }
    .scan-run code { font-family:"SFMono-Regular", Consolas, ui-monospace, monospace; font-size:12px; color:var(--ink); }
    .scan-progress { margin:12px 0; }
    .scan-progress-bar { height:10px; border-radius:999px; background:var(--neutral-bg); overflow:hidden; border:1px solid var(--line); }
    .scan-progress-bar span { display:block; height:100%; width:0; border-radius:999px; background:linear-gradient(90deg, var(--primary), var(--ok)); transition:width .2s ease; }
    .scan-event-list { display:grid; gap:7px; max-height:360px; overflow:auto; padding-right:2px; }
    .scan-event { display:grid; grid-template-columns:auto 1fr; gap:10px; padding:10px; border-radius:12px; border:1px solid var(--line); background:color-mix(in srgb, var(--surface-2) 70%, transparent); }
    .scan-event p { margin:2px 0 0; color:var(--muted); font-size:12px; line-height:1.45; }
    .scan-event strong { font-size:13px; }
    .sandbox-ops { display:grid; grid-template-columns:minmax(300px,.85fr) minmax(380px,1.15fr); gap:14px; margin:0 0 34px; }
    .ops-log { display:grid; gap:8px; margin-top:14px; max-height:280px; overflow:auto; padding-right:4px; }
    .ops-entry { display:grid; grid-template-columns:auto 1fr; gap:10px; align-items:start; padding:10px; border-radius:13px; background:color-mix(in srgb, var(--surface-2) 66%, transparent); border:1px solid var(--line); }
    .ops-entry p { margin:3px 0 0; color:var(--muted); font-size:12px; line-height:1.45; }
    .ops-entry code { font-family:"SFMono-Regular", Consolas, ui-monospace, monospace; font-size:12px; color:var(--ink); }
    .select-cell { text-align:center; }
    .select-cell input { width:18px; height:18px; padding:0; accent-color:var(--primary); }
    .selected-state { display:inline-flex; align-items:center; min-height:32px; padding:4px 10px; border-radius:999px; background:var(--primary-soft); color:var(--primary-strong); font-size:12px; font-weight:760; }
    .remediation-list { display:grid; gap:10px; margin-top:14px; }
    .remediation-item { padding:11px; border-radius:13px; background:color-mix(in srgb, var(--surface-2) 76%, transparent); border:1px solid var(--line); }
    .remediation-item strong { display:block; margin-bottom:6px; }
    .remediation-item ol { margin:8px 0 0 18px; padding:0; color:#40505c; font-size:13px; line-height:1.5; }
    .package-brief { display:grid; gap:10px; margin-top:14px; }
    .brief-row { padding:11px; border-radius:13px; background:color-mix(in srgb, var(--primary-soft) 50%, transparent); border:1px solid color-mix(in srgb, var(--primary) 18%, var(--line)); }
    .brief-row span { display:block; margin-bottom:5px; color:var(--muted); font-size:12px; }
    .brief-row strong { display:block; line-height:1.35; }
    .details-button { all:unset; cursor:pointer; color:var(--primary-strong); font-weight:760; }
    .details-button:focus-visible { outline:3px solid color-mix(in srgb, var(--primary) 28%, transparent); outline-offset:3px; border-radius:8px; }
    .badge { display:inline-flex; align-items:center; border-radius:999px; padding:4px 9px; font-size:11px; font-weight:760; text-transform:uppercase; letter-spacing:.06em; border:1px solid transparent; }
    .passed { color:var(--ok); background:var(--ok-bg); border-color:color-mix(in srgb, var(--ok) 24%, transparent); }
    .review { color:var(--medium); background:var(--medium-bg); border-color:color-mix(in srgb, var(--medium) 24%, transparent); }
    .failed { color:var(--critical); background:var(--critical-bg); border-color:color-mix(in srgb, var(--critical) 24%, transparent); }
    .critical { color:var(--critical); background:var(--critical-bg); border-color:color-mix(in srgb, var(--critical) 28%, transparent); }
    .high { color:var(--high); background:var(--high-bg); border-color:color-mix(in srgb, var(--high) 28%, transparent); }
    .medium { color:var(--medium); background:var(--medium-bg); border-color:color-mix(in srgb, var(--medium) 28%, transparent); }
    .low, .none { color:var(--low); background:var(--low-bg); border-color:color-mix(in srgb, var(--low) 24%, transparent); }
    .pending { color:var(--muted); background:var(--neutral-bg); border-color:var(--line); }
    .error { color: var(--bad); }
    .table-shell { border-radius:20px; padding:10px; background:color-mix(in srgb, var(--ink) 6%, transparent); box-shadow:var(--shadow); scroll-margin-top:90px; }
    .table-wrap { border-radius:14px; overflow:auto; background:var(--surface); max-height:700px; box-shadow:inset 0 1px 0 rgba(255,255,255,.16); }
    table { width:100%; border-collapse:collapse; table-layout:fixed; min-width:1580px; }
    th, td { border-bottom:1px solid var(--line); padding:10px 12px; text-align:left; vertical-align:middle; font-size:13px; height:52px; }
    th { position:sticky; top:0; z-index:2; color:var(--muted); background:var(--surface); font-size:12px; font-weight:760; text-transform:none; letter-spacing:0; }
    th:first-child, td:first-child { position:sticky; left:0; z-index:3; background:var(--surface); box-shadow:8px 0 18px rgba(18,33,54,.06); }
    th:first-child { z-index:4; }
    td .truncate { display:block; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:100%; }
    .insight-cell { display:grid; gap:6px; min-width:0; max-width:100%; }
    .insight-text { display:-webkit-box; -webkit-line-clamp:2; -webkit-box-orient:vertical; overflow:hidden; color:var(--ink); line-height:1.35; }
    .insight-cell[data-expanded="true"] .insight-text { display:block; -webkit-line-clamp:unset; max-height:none; overflow:visible; white-space:normal; }
    .insight-actions { display:flex; align-items:center; flex-wrap:wrap; gap:8px; }
    .insight-toggle { all:unset; width:max-content; cursor:pointer; color:var(--primary-strong); font-size:12px; font-weight:760; line-height:1.2; }
    .insight-toggle:hover { text-decoration:underline; }
    .insight-toggle:focus-visible { outline:3px solid color-mix(in srgb, var(--primary) 28%, transparent); outline-offset:3px; border-radius:8px; }
    .insight-reader { display:none; margin:12px 0; padding:16px; border-radius:16px; background:var(--surface); border:1px solid color-mix(in srgb, var(--primary) 18%, var(--line)); box-shadow:var(--shadow-soft); }
    .insight-reader[data-open="true"] { display:block; }
    .insight-reader-head { display:flex; align-items:flex-start; justify-content:space-between; gap:12px; margin-bottom:10px; }
    .insight-reader h3 { margin:0; font-size:18px; }
    .insight-reader p { margin:0; line-height:1.55; color:var(--ink); white-space:pre-wrap; overflow-wrap:anywhere; }
    td:nth-child(1) { width:4%; }
    td:nth-child(2) { width:13%; font-weight:750; }
    td:nth-child(3) { width:15%; overflow-wrap:anywhere; font-variant-numeric:tabular-nums; }
    td:nth-child(4) { width:10%; }
    td:nth-child(5) { width:6%; }
    td:nth-child(6) { width:13%; }
    td:nth-child(7), td:nth-child(8), td:nth-child(9), td:nth-child(10), td:nth-child(11) { width:7%; }
    td:nth-child(12), td:nth-child(13) { width:14%; }
    tbody tr:nth-child(even) { background:color-mix(in srgb, var(--surface-2) 38%, transparent); }
    tbody tr:nth-child(even) td:first-child { background:color-mix(in srgb, var(--surface-2) 38%, var(--surface)); }
    tbody tr:hover, tbody tr:hover td:first-child { background:color-mix(in srgb, var(--primary-soft) 46%, var(--surface)); }
    .skeleton { position:relative; overflow:hidden; border-radius:10px; background:var(--neutral-bg); min-height:18px; }
    .skeleton::after { content:""; position:absolute; inset:0; transform:translateX(-100%); background:linear-gradient(90deg, transparent, rgba(255,255,255,.75), transparent); animation:shimmer 1.2s infinite; }
    .state { width:min(420px, calc(100vw - 76px)); padding:34px; text-align:center; color:var(--muted); }
    .state strong { display:block; color:var(--ink); font-size:18px; margin-bottom:8px; }
    .package-cards { display:none; gap:12px; }
    .package-card { border-radius:16px; padding:14px; background:var(--surface); border:1px solid var(--line); box-shadow:var(--shadow-soft); }
    .package-card h3 { margin:0 0 8px; font-size:17px; overflow-wrap:anywhere; }
    .package-meta { display:flex; flex-wrap:wrap; gap:6px; margin:8px 0 10px; }
    .package-card dl { display:grid; gap:8px; margin:0; }
    .package-card dt { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.11em; }
    .package-card dd { margin:2px 0 0; line-height:1.35; overflow-wrap:anywhere; }
    footer { display:flex; justify-content:space-between; flex-wrap:wrap; gap:12px; padding:34px 0 0; color:var(--muted); font-size:13px; }
    @keyframes shimmer { to { transform:translateX(100%); } }
    @keyframes rise { from { opacity:0; transform:translateY(20px); } to { opacity:1; transform:translateY(0); } }
    .muted { color: var(--muted); }
    @media (max-width: 760px) {
      .page { padding:16px; }
      header { min-height:auto; grid-template-columns:1fr; padding-top:10px; }
      .console-nav { top:8px; align-items:flex-start; flex-direction:column; }
      .nav-links { width:100%; }
      .brandbar { align-items:flex-start; flex-wrap:wrap; margin-bottom:42px; }
      .brandbar .eyebrow { font-size:9px; }
      h1 { font-size:clamp(40px,14vw,56px); overflow-wrap:anywhere; }
      .hero-core { min-height:260px; }
      .metrics { grid-template-columns:repeat(2,minmax(120px,1fr)); }
      .security-grid { grid-template-columns:1fr; }
      .scan-console { grid-template-columns:1fr; }
      .sandbox-ops { grid-template-columns:1fr; }
      .source-console { grid-template-columns:1fr; }
      .source-form { grid-template-columns:1fr; }
      .toolbar { grid-template-columns:1fr; }
      .toolbar-panel-head { flex-direction:column; }
      .filter-actions { justify-content:flex-start; }
      .section-head { align-items:flex-start; flex-direction:column; }
      .table-wrap { display:none; }
      .package-cards { display:grid; }
    }
  </style>
</head>
<body>
  <a class="skip-link" href="#packages-table">Skip to packages</a>
  <div class="page">
    <svg aria-hidden="true" width="0" height="0" style="position:absolute">
      <symbol id="icon-refresh" viewBox="0 0 24 24"><path d="M20 11a8 8 0 0 0-14.9-4M4 5v5h5"/><path d="M4 13a8 8 0 0 0 14.9 4M20 19v-5h-5"/></symbol>
      <symbol id="icon-play" viewBox="0 0 24 24"><path d="M8 5v14l11-7Z"/></symbol>
      <symbol id="icon-arrow" viewBox="0 0 24 24"><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></symbol>
      <symbol id="icon-moon" viewBox="0 0 24 24"><path d="M20 15.5A8.5 8.5 0 0 1 8.5 4 7 7 0 1 0 20 15.5Z"/></symbol>
      <symbol id="icon-chevron-left" viewBox="0 0 24 24"><path d="m15 18-6-6 6-6"/></symbol>
      <symbol id="icon-chevron-right" viewBox="0 0 24 24"><path d="m9 18 6-6-6-6"/></symbol>
    </svg>
    <nav class="console-nav" aria-label="Dashboard sections">
      <div class="nav-links">
        <a href="#overview">Overview</a>
        <a href="#security-section">Security</a>
        <a href="#scan-section">Scans</a>
        <a href="#sandbox-section">Sandbox</a>
        <a href="#source-section">Sources</a>
        <a href="#repo-section">Repositories</a>
        <a href="#packages-table">Packages</a>
      </div>
      <button class="theme-toggle" id="theme-toggle" type="button">Dark mode <span class="button-orb" aria-hidden="true"><svg><use href="#icon-moon"></use></svg></span></button>
    </nav>
    <header>
      <section id="overview">
        <div class="brandbar">
          <div class="mark"><span class="mark-dot" aria-hidden="true"></span><span>pkgmng</span></div>
          <span class="eyebrow">APT + RHEL-family RPM control plane</span>
        </div>
        <div class="eyebrow">Repository mirror index</div>
        <h1>Package intelligence for Linux fleets.</h1>
        <p class="lede">Track Debian APT plus AlmaLinux, Rocky Linux, Oracle Linux, and Red Hat RPM repositories with security review signals from one production console.</p>
        <div class="hero-actions">
          <button id="scan">Run scan <span class="button-orb" aria-hidden="true"><svg><use href="#icon-play"></use></svg></span></button>
          <button class="secondary" id="refresh">Refresh index <span class="button-orb" aria-hidden="true"><svg><use href="#icon-refresh"></use></svg></span></button>
          <button class="ghost" id="show-review">Review queue <span class="button-orb" aria-hidden="true"><svg><use href="#icon-arrow"></use></svg></span></button>
        </div>
      </section>
      <aside class="hero-panel" aria-label="Repository scan summary">
        <div class="hero-core" id="hero-summary">
          <div class="scanline"><span>Indexed packages</span><strong><span class="skeleton"></span></strong></div>
          <div class="scanline"><span>Needs review</span><strong><span class="skeleton"></span></strong></div>
          <div class="scanline"><span>Failed checks</span><strong><span class="skeleton"></span></strong></div>
          <div class="scanline"><span>Refresh cadence</span><strong>6h</strong></div>
        </div>
      </aside>
    </header>
    <main id="content">
      <section class="metrics" id="metrics" aria-label="Package security totals"></section>
      <div class="section-head" id="security-section">
        <div>
          <div class="eyebrow">Security validation</div>
          <h2>All package checks</h2>
        </div>
        <p class="muted">Every indexed DEB and RPM record is scored for metadata integrity, trusted transport, sandbox preflight, package purpose, and operational impact.</p>
      </div>
      <section class="security-grid" id="security" aria-label="Package validation summary"></section>
      <div class="section-head" id="sandbox-section">
        <div>
          <div class="eyebrow">Sandbox validation</div>
          <h2>Package behavior safety</h2>
        </div>
        <p class="muted">Sandbox status separates packages eligible for normal consumption, packages that need dynamic install observation, and packages blocked before execution because identity metadata is not trustworthy.</p>
      </div>
      <section class="security-grid" id="sandbox-summary" aria-label="Sandbox validation summary"></section>
      <section class="sandbox-ops" aria-label="Sandbox scan operations">
        <article class="scan-card" id="sandbox-queue"></article>
        <article class="scan-card" id="sandbox-logs"></article>
      </section>
      <div class="section-head" id="scan-section">
        <div>
          <div class="eyebrow">Scan operations</div>
          <h2>Scan runs and remediation</h2>
        </div>
        <p class="muted">Launch package validation, inspect current run evidence, and turn findings into operator action.</p>
      </div>
      <section class="scan-console" aria-label="Security scan operations">
        <article class="scan-card" id="scan-runs"></article>
        <article class="scan-card" id="scan-detail"></article>
        <article class="remediation-card" id="remediation"></article>
      </section>
      <div class="section-head" id="version-section">
        <div>
          <div class="eyebrow">RHEL-family coverage</div>
          <h2>Distribution lanes</h2>
        </div>
        <p class="muted">Each distribution lane keeps the latest five configured OS releases, capped to the public versions with reachable repository metadata.</p>
      </div>
      <section class="families" id="families" aria-label="Distribution family summary"></section>
      <div class="section-head" id="repo-section">
        <div>
          <div class="eyebrow">Repository sources</div>
          <h2>Mirror health</h2>
        </div>
        <p class="muted">Status, package counts, and last refresh time for each APT or RPM source.</p>
      </div>
      <section class="source-console" id="source-section" aria-label="Repository source management">
        <article class="source-panel">
          <div class="eyebrow">Source editor</div>
          <h3>Add or edit a repository</h3>
          <form class="source-form" id="source-form">
            <label class="wide">Source name<input id="repo-name" required placeholder="oracle-9-appstream"></label>
            <label>Type<select id="repo-type"><option value="apt">APT / DEB</option><option value="rpm">RPM / RHEL family</option></select></label>
            <label>Suite / distro<input id="repo-suite" required placeholder="bookworm or Oracle Linux 9"></label>
            <label class="wide">Base URL<input id="repo-base-url" required placeholder="https://example.repo/os/"></label>
            <label class="wide">Component / channel<input id="repo-component" required placeholder="main, BaseOS, AppStream, Latest"></label>
            <div class="source-form-actions">
              <button id="save-source" type="submit">Save source <span class="button-orb" aria-hidden="true"><svg><use href="#icon-arrow"></use></svg></span></button>
              <button class="secondary" id="new-source" type="button">New source <span class="button-orb" aria-hidden="true"><svg><use href="#icon-refresh"></use></svg></span></button>
            </div>
          </form>
          <div class="source-packages" id="source-focus">Select a source to edit it or show only its packages.</div>
        </article>
        <article class="source-panel">
          <div class="eyebrow">Configured sources</div>
          <h3>Open source inventory</h3>
          <div class="source-list" id="source-list"></div>
        </article>
      </section>
      <section class="repos" id="repos"></section>
      <div class="section-head">
        <div>
          <div class="eyebrow">Package inventory</div>
          <h2>Package intelligence table</h2>
        </div>
      </div>
      <div class="toolbar-panel" role="search" aria-label="Package inventory controls">
        <div class="toolbar-panel-head">
          <div>
            <div class="eyebrow">Inventory controls</div>
            <h3>Filter every package field</h3>
            <p class="muted">Combine status, severity, source, OS lane, architecture, format, checksum, and sort order.</p>
          </div>
          <div class="filter-actions">
            <button class="secondary" id="reset-filters" type="button">Reset filters <span class="button-orb" aria-hidden="true"><svg><use href="#icon-refresh"></use></svg></span></button>
          </div>
        </div>
        <div class="toolbar">
          <div class="filter-field"><label for="q">Search</label><input id="q" aria-label="Search packages" placeholder="Package, maintainer, description"></div>
          <div class="filter-field"><label for="status">Status</label><select id="status" aria-label="Filter by security status">
            <option value="">All statuses</option>
            <option value="failed">Failed</option>
            <option value="review">Review</option>
            <option value="passed">Passed</option>
          </select></div>
          <div class="filter-field"><label for="severity">Severity</label><select id="severity" aria-label="Filter by security severity">
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="none">None</option>
          </select></div>
          <div class="filter-field"><label for="sandbox-status">Sandbox</label><select id="sandbox-status" aria-label="Filter by sandbox status">
            <option value="">All sandbox states</option>
            <option value="failed">Blocked</option>
            <option value="review">Needs sandbox</option>
            <option value="passed">Passed preflight</option>
            <option value="pending">Pending</option>
          </select></div>
          <div class="filter-field"><label for="family">Distribution</label><select id="family" aria-label="Filter by distribution family">
            <option value="">All families</option>
          </select></div>
          <div class="filter-field"><label for="version">OS version</label><select id="version" aria-label="Filter by operating system version">
            <option value="">All versions</option>
          </select></div>
          <div class="filter-field"><label for="repo-filter">Repository</label><select id="repo-filter" aria-label="Filter by repository source">
            <option value="">All repository sources</option>
          </select></div>
          <div class="filter-field"><label for="format">Format</label><select id="format" aria-label="Filter by package format">
            <option value="">All formats</option>
            <option value="deb">DEB</option>
            <option value="rpm">RPM</option>
          </select></div>
          <div class="filter-field"><label for="architecture">Architecture</label><select id="architecture" aria-label="Filter by package architecture">
            <option value="">All architectures</option>
          </select></div>
          <div class="filter-field"><label for="checksum">Checksum</label><select id="checksum" aria-label="Filter by checksum algorithm">
            <option value="">All checksums</option>
          </select></div>
          <div class="filter-field"><label for="sort">Sort by</label><select id="sort" aria-label="Sort packages">
            <option value="risk">Risk first</option>
            <option value="severity">Severity</option>
            <option value="status">Status</option>
            <option value="package">Package name</option>
            <option value="repo">Repository</option>
            <option value="version">Version</option>
            <option value="updated">Last refresh</option>
          </select></div>
        </div>
        <div class="filter-summary" id="filter-summary" aria-live="polite"></div>
      </div>
      <section class="table-shell" id="packages-table">
        <div class="page-controls">
          <span id="page-info">Loading package results...</span>
          <div class="page-actions">
            <button class="ghost" id="prev-page">Previous <span class="button-orb" aria-hidden="true"><svg><use href="#icon-chevron-left"></use></svg></span></button>
            <button class="ghost" id="next-page">Next <span class="button-orb" aria-hidden="true"><svg><use href="#icon-chevron-right"></use></svg></span></button>
          </div>
        </div>
        <aside class="insight-reader" id="insight-reader" data-open="false" aria-live="polite">
          <div class="insight-reader-head">
            <h3 id="insight-reader-title">Full package insight</h3>
            <button class="ghost mini-button" id="close-insight-reader" type="button">Close</button>
          </div>
          <p id="insight-reader-body"></p>
        </aside>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Select</th><th>Package</th><th>Version</th><th>Repo</th><th>Arch</th><th>Responsible for</th><th>Format</th><th>Status</th><th>Severity</th><th>Risk</th><th>Sandbox</th><th>Why unsafe</th><th>Purpose</th></tr></thead>
            <tbody id="packages"></tbody>
          </table>
        </div>
        <div class="package-cards" id="package-cards"></div>
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
    const PAGE_LIMIT = 100;
    let currentOffset = 0;
    let editingSourceName = '';
    let selectedScanId = null;
    let scanDetailTimer = null;
    const selectedPackageIds = new Set();
    const icon = (name) => `<span class="button-orb" aria-hidden="true"><svg><use href="#icon-${name}"></use></svg></span>`;
    const setTheme = (theme) => {
      document.documentElement.dataset.theme = theme;
      localStorage.setItem('pkgmng-theme', theme);
      $('theme-toggle').innerHTML = `${theme === 'dark' ? 'Light mode' : 'Dark mode'} ${icon('moon')}`;
    };
    const skeletonRows = () => Array.from({length: 8}).map(() => '<tr><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td></tr>').join('');
    const skeletonCards = () => Array.from({length: 4}).map(() => '<article class="package-card"><div class="skeleton"></div><br><div class="skeleton"></div><br><div class="skeleton"></div></article>').join('');
    const statusClass = (value) => ['passed', 'review', 'failed', 'pending'].includes(value) ? value : 'pending';
    const n = (value) => Number(value || 0).toLocaleString();
    const insightCell = (text, label) => {
      const value = String(text || 'none');
      const needsToggle = value.length > 92;
      const readerButton = value && value !== 'none'
        ? `<button class="insight-toggle insight-reader-open" type="button" data-insight-label="${esc(label)}" data-insight-text="${esc(value)}" aria-label="Open full ${esc(label)}">Open full text</button>`
        : '';
      return `<div class="insight-cell" data-expanded="false"><span class="insight-text" title="${esc(value)}">${esc(value)}</span><div class="insight-actions">${needsToggle ? `<button class="insight-toggle insight-expand" type="button" aria-expanded="false" aria-label="Expand ${esc(label)} preview">Show more</button>` : ''}${readerButton}</div></div>`;
    };
    const filterIds = ['q', 'status', 'severity', 'sandbox-status', 'family', 'version', 'repo-filter', 'format', 'architecture', 'checksum', 'sort'];
    const selectedFilters = () => ({
      q: $('q').value.trim(),
      status: $('status').value,
      severity: $('severity').value,
      sandbox_status: $('sandbox-status').value,
      family: $('family').value,
      version: $('version').value,
      repo: $('repo-filter').value,
      package_format: $('format').value,
      architecture: $('architecture').value,
      checksum_algorithm: $('checksum').value,
      sort: $('sort').value
    });
    const setSelectOptions = (id, placeholder, values, current, formatter = (value) => value) => {
      const options = [...new Set(values.filter(Boolean))];
      $(id).innerHTML = `<option value="">${placeholder}</option>` + options.map(value => `<option value="${esc(value)}">${esc(formatter(value))}</option>`).join('');
      $(id).value = options.includes(current) ? current : '';
    };
    const renderFilterSummary = (page) => {
      const filters = selectedFilters();
      const labels = [
        ['Search', filters.q],
        ['Status', filters.status],
        ['Severity', filters.severity],
        ['Sandbox', filters.sandbox_status],
        ['Family', filters.family],
        ['OS', filters.version],
        ['Repo', filters.repo],
        ['Format', filters.package_format ? filters.package_format.toUpperCase() : ''],
        ['Arch', filters.architecture],
        ['Checksum', filters.checksum_algorithm ? filters.checksum_algorithm.toUpperCase() : ''],
        ['Sort', $('sort').selectedOptions[0]?.textContent || 'Risk first']
      ].filter(([, value]) => value);
      $('filter-summary').innerHTML = labels.length
        ? labels.map(([key, value]) => `<span class="filter-chip">${esc(key)}: ${esc(value)}</span>`).join('') + `<span class="filter-chip">${n(page.total || 0)} matches</span>`
        : `<span class="filter-chip">${n(page.total || 0)} packages across all filters</span>`;
    };
    function attachSandboxSummaryFilters() {
      const review = $('sandbox-review-inline');
      const blocked = $('sandbox-blocked-inline');
      if (review) review.addEventListener('click', () => { $('sandbox-status').value = 'review'; currentOffset = 0; load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
      if (blocked) blocked.addEventListener('click', () => { $('sandbox-status').value = 'failed'; currentOffset = 0; load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    }
    function renderSecuritySummary(security) {
      const securityTotals = security.totals || {};
      const avgRisk = Math.max(0, Math.min(100, Number(securityTotals.avg_risk || 0)));
      const lanes = (security.by_family || []).slice(0, 10).map(row => `<div class="risk-item"><strong>${esc(row.distro_family)} v${esc(row.release_version || 'n/a')}</strong><span>${n(row.review)} review / ${n(row.failed)} failed</span></div>`).join('');
      const topRisk = (security.top_risk || []).slice(0, 8).map(row => `<div class="risk-item"><strong>${esc(row.package)}</strong><span>${esc(row.security_severity)} - ${n(row.security_risk_score)} / ${n(row.affected_variants || 1)} variants</span></div>`).join('');
      $('security').innerHTML = `<article class="security-panel"><div class="eyebrow">Average risk</div><h3>${avgRisk.toFixed(1)} / 100</h3><div class="risk-meter"><span style="width:${avgRisk}%"></span></div><p class="muted">${n(securityTotals.total)} packages scanned, ${n(securityTotals.critical)} critical metadata failures, ${n(securityTotals.high)} high review signals.</p><div class="risk-list">${lanes || '<div class="risk-item"><strong>No scan data</strong><span>refresh index</span></div>'}</div></article><article class="security-panel"><div class="eyebrow">Highest risk packages</div><h3>Validation queue</h3><div class="risk-list">${topRisk || '<div class="risk-item"><strong>No packages need review</strong><span>clear</span></div>'}</div></article>`;
      $('sandbox-summary').innerHTML = `<article class="security-panel"><div class="eyebrow">Sandbox preflight</div><h3>${n(securityTotals.sandbox_review + securityTotals.sandbox_failed)} need action</h3><div class="risk-list"><div class="risk-item"><strong>Passed preflight</strong><span>${n(securityTotals.sandbox_passed)}</span></div><div class="risk-item"><strong>Needs dynamic sandbox</strong><span>${n(securityTotals.sandbox_review)}</span></div><div class="risk-item"><strong>Blocked before execution</strong><span>${n(securityTotals.sandbox_failed)}</span></div></div></article><article class="security-panel"><div class="eyebrow">How to proceed</div><h3>Sandbox lane</h3><p class="muted">Passed packages can stay in normal monitoring. Review packages need disposable-host install/remove observation. Blocked packages must first fix checksum, size, or artifact identity before any execution.</p><div class="scan-actions"><button class="ghost" id="sandbox-review-inline">Needs sandbox ${icon('arrow')}</button><button class="ghost" id="sandbox-blocked-inline">Blocked ${icon('arrow')}</button></div></article>`;
      attachSandboxSummaryFilters();
      const remediationRows = (security.top_risk || []).slice(0, 4).map(row => `<div class="remediation-item"><strong>${esc(row.package)} <span class="badge ${esc(row.security_severity)}">${esc(row.security_severity)}</span></strong><span class="muted">${esc(row.responsibility || row.category || 'Package intelligence')}</span><br><span class="muted">${esc(row.why_not_safe || (row.security_findings || []).join('; ') || 'manual review')}</span></div>`).join('');
      $('remediation').innerHTML = `<div class="eyebrow">Remediation queue</div><h3>${n(securityTotals.review + securityTotals.failed)} actions</h3><p class="muted">Open a package row to see the exact owner, priority, evidence, and fix steps for each failed or review check.</p><div class="remediation-list">${remediationRows || '<div class="remediation-item"><strong>No active remediation</strong><span class="muted">All current package checks passed.</span></div>'}</div>`;
    }
    async function showScanDetail(scanId, options = {}) {
      if (!scanId) {
        $('scan-detail').innerHTML = `<div class="eyebrow">Live scan detail</div><h3>Select a scan run</h3><p class="muted">Click any scan run to see live repository progress, notes, and event logs while it executes.</p>`;
        return;
      }
      selectedScanId = Number(scanId);
      if (!options.quiet) {
        $('scan-detail').innerHTML = `<div class="eyebrow">Live scan detail</div><h3>Loading scan #${esc(selectedScanId)}</h3><p class="muted">Fetching current run events...</p>`;
      }
      try {
        const detail = await fetch('/api/scans/' + encodeURIComponent(selectedScanId)).then(r => {
          if (!r.ok) throw new Error(`Scan detail failed with HTTP ${r.status}`);
          return r.json();
        });
        const run = detail.run || {};
        const progress = detail.progress || {};
        const events = detail.events || [];
        const status = run.status || 'unknown';
        const percent = Math.max(0, Math.min(100, Number(progress.percent || 0)));
        const eventRows = events.map(event => `<div class="scan-event"><span class="badge ${event.level === 'error' ? 'failed' : statusClass(event.level === 'warn' ? 'review' : 'passed')}">${esc(event.stage)}</span><div><strong>${esc(event.message)}</strong><p>${esc(event.created_at)}${event.repo_name ? ' · ' + esc(event.repo_name) : ''}</p></div></div>`).join('');
        $('scan-detail').innerHTML = `<div class="eyebrow">Live scan detail</div><h3>Scan #${esc(run.id)} <span class="badge ${statusClass(status === 'succeeded' ? 'passed' : status === 'running' ? 'pending' : status === 'degraded' ? 'review' : status === 'failed' ? 'failed' : 'pending')}">${esc(status)}</span></h3><p class="muted">${esc(run.notes || 'No scan notes recorded yet.')}</p><div class="scan-progress"><div class="risk-item"><strong>Repository progress</strong><span>${n(progress.repos_done)} / ${n(progress.repos_total)} repos</span></div><div class="scan-progress-bar" aria-label="Scan progress"><span style="width:${percent}%"></span></div></div><div class="risk-list"><div class="risk-item"><strong>Trigger</strong><span>${esc(run.trigger || 'unknown')}</span></div><div class="risk-item"><strong>Started</strong><span>${esc(run.started_at || 'n/a')}</span></div><div class="risk-item"><strong>Finished</strong><span>${esc(run.finished_at || 'still running')}</span></div><div class="risk-item"><strong>Packages</strong><span>${n(run.packages_total)}</span></div></div><div class="scan-actions"><button class="ghost" id="scan-detail-refresh" type="button">Refresh detail ${icon('refresh')}</button></div><div class="scan-event-list">${eventRows || '<div class="scan-event"><span class="badge pending">pending</span><div><strong>No events recorded yet</strong><p>The scan worker writes events as it starts and finishes each repository.</p></div></div>'}</div>`;
        $('scan-detail-refresh').addEventListener('click', () => showScanDetail(selectedScanId));
        if (scanDetailTimer) {
          clearTimeout(scanDetailTimer);
          scanDetailTimer = null;
        }
        if (status === 'running') {
          scanDetailTimer = setTimeout(() => showScanDetail(selectedScanId, { quiet: true }), 15000);
        }
      } catch (error) {
        $('scan-detail').innerHTML = `<div class="eyebrow">Live scan detail</div><h3>Could not load scan</h3><p class="muted">${esc(error.message || error)}</p>`;
      }
    }
    async function load() {
      $('packages').innerHTML = skeletonRows();
      $('package-cards').innerHTML = skeletonCards();
      $('page-info').textContent = 'Loading package results...';
      $('security').innerHTML = `<article class="security-panel"><div class="eyebrow">Security posture</div><h3><span class="skeleton"></span></h3><p class="muted">Loading aggregate security totals without blocking package rows.</p></article>`;
      $('sandbox-summary').innerHTML = `<article class="security-panel"><div class="eyebrow">Sandbox preflight</div><h3><span class="skeleton"></span></h3><p class="muted">Loading sandbox aggregate status.</p></article>`;
      $('remediation').innerHTML = `<div class="eyebrow">Remediation queue</div><h3>Loading actions</h3><p class="muted">Package results can be used while this panel updates.</p>`;
      try {
        const filters = selectedFilters();
        const params = new URLSearchParams({ ...filters, limit: String(PAGE_LIMIT), offset: String(currentOffset) });
        const [repos, families, versions, scans, sandboxOps, packages] = await Promise.all([fetch('/api/repos').then(r => r.json()), fetch('/api/families').then(r => r.json()), fetch('/api/versions').then(r => r.json()), fetch('/api/scans').then(r => r.json()), fetch('/api/sandbox/scans').then(r => r.json()), fetch('/api/packages?' + params).then(r => r.json())]);
        const totals = packages.totals || {};
        $('hero-summary').innerHTML = [
          ['Indexed packages', n(totals.total)],
          ['Needs review', n(totals.review)],
          ['Failed checks', n(totals.failed)],
          ['Refresh cadence', '6h']
        ].map(([k,v]) => `<div class="scanline"><span>${k}</span><strong>${v}</strong></div>`).join('');
        $('metrics').innerHTML = [['Total', totals.total], ['Passed', totals.passed], ['Review', totals.review], ['Failed', totals.failed]].map(([k,v], i) => `<article class="metric" style="animation-delay:${i * 60}ms"><div class="metric-inner"><strong>${n(v)}</strong><span>${k}</span></div></article>`).join('');
        fetch('/api/security').then(r => r.json()).then(renderSecuritySummary).catch(error => {
          $('security').innerHTML = `<article class="security-panel"><div class="eyebrow">Security posture</div><h3>Security summary unavailable</h3><p class="muted">${esc(error.message || error)}</p></article>`;
          $('sandbox-summary').innerHTML = `<article class="security-panel"><div class="eyebrow">Sandbox preflight</div><h3>Sandbox summary unavailable</h3><p class="muted">Package-level sandbox filters remain available.</p></article>`;
        });
        const sandboxCurrent = sandboxOps.current || {};
        const sandboxTotals = sandboxOps.sandbox || {};
        const sandboxRunning = sandboxCurrent.status === 'running';
        const sandboxLogRows = (sandboxOps.logs || []).map(entry => `<div class="ops-entry"><span class="badge ${statusClass(entry.status)}">${esc(entry.status)}</span><div><code>#${esc(entry.run_id)} ${esc(entry.trigger || 'unknown')}</code><p>${esc(entry.message)}</p><p>${esc(entry.timestamp || 'no timestamp')}</p></div></div>`).join('');
        const targetedRows = (sandboxOps.targeted_runs || []).map(run => `<div class="ops-entry"><span class="badge ${statusClass(run.status)}">${esc(run.status)}</span><div><code>target #${esc(run.id)} ${esc(run.trigger)}</code><p>${n(run.target_count)} selected packages: ${n(run.passed)} passed, ${n(run.review)} need sandbox, ${n(run.failed)} blocked.</p><p>${esc(run.finished_at || run.started_at || run.requested_at)}</p></div></div>`).join('');
        const packageLogRows = (sandboxOps.package_logs || []).map(log => `<div class="ops-entry"><span class="badge ${statusClass(log.status)}">${esc(log.status)}</span><div><code>${esc(log.package)} ${esc(log.version)} ${esc(log.architecture || '')}</code><p>${esc(log.verdict)} - ${esc(log.next_action)}</p><p>repo ${esc(log.repo_name)} · run #${esc(log.sandbox_run_id)}</p></div></div>`).join('');
        $('sandbox-queue').innerHTML = `<div class="eyebrow">Sandbox run queue</div><h3>${sandboxRunning ? 'Sandbox scan running' : 'Ready for on-demand scan'}</h3><p class="muted">${sandboxRunning ? esc(sandboxCurrent.notes || 'The current sandbox preflight is recalculating package evidence.') : esc(sandboxTotals.next_action || 'Start sandbox preflight after source edits or remediation changes.')}</p><div class="risk-list"><div class="risk-item"><strong>Passed preflight</strong><span>${n(sandboxTotals.passed)}</span></div><div class="risk-item"><strong>Needs sandbox</strong><span>${n(sandboxTotals.review)}</span></div><div class="risk-item"><strong>Blocked</strong><span>${n(sandboxTotals.failed)}</span></div><div class="risk-item"><strong>Pending backfill</strong><span>${n(sandboxTotals.pending)}</span></div></div><div class="scan-actions"><button id="run-sandbox-inline">${sandboxRunning ? 'Scan running' : 'Start sandbox preflight'} ${icon(sandboxRunning ? 'refresh' : 'play')}</button><button class="secondary" id="run-selected-sandbox-inline">Sandbox selected ${icon('play')}</button><button class="ghost" id="clear-selected-inline">Clear selected ${icon('refresh')}</button><button class="ghost" id="sandbox-refresh-inline">Refresh status ${icon('refresh')}</button><span class="selected-state" id="selected-package-count">${n(selectedPackageIds.size)} selected</span></div><p class="muted" id="sandbox-action-state" aria-live="polite">Select up to 20 package rows to sandbox only those RPM/DEB records.</p>`;
        $('sandbox-logs').innerHTML = `<div class="eyebrow">Sandbox operation logs</div><h3>Queue, targeted runs, and package evidence</h3><p class="muted">Logs include full scan-run records plus targeted package sandbox records: status, verdict, evidence, and next action for each selected package.</p><div class="scan-actions"><button class="ghost" id="sandbox-pending-inline">Pending ${icon('arrow')}</button><button class="ghost" id="sandbox-review-log-inline">Needs sandbox ${icon('arrow')}</button><button class="ghost" id="sandbox-failed-log-inline">Blocked ${icon('arrow')}</button></div><div class="ops-log">${targetedRows || packageLogRows || sandboxLogRows || '<div class="ops-entry"><span class="badge pending">pending</span><div><code>No sandbox runs</code><p>Start sandbox preflight or select package rows to create operation logs.</p></div></div>'}</div>`;
        $('run-sandbox-inline').disabled = sandboxRunning;
        $('run-sandbox-inline').addEventListener('click', runSandboxScan);
        $('run-selected-sandbox-inline').addEventListener('click', runSelectedSandboxScan);
        $('clear-selected-inline').addEventListener('click', () => { selectedPackageIds.clear(); load(); });
        $('sandbox-refresh-inline').addEventListener('click', load);
        $('sandbox-pending-inline').addEventListener('click', () => { $('sandbox-status').value = 'pending'; currentOffset = 0; load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
        $('sandbox-review-log-inline').addEventListener('click', () => { $('sandbox-status').value = 'review'; currentOffset = 0; load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
        $('sandbox-failed-log-inline').addEventListener('click', () => { $('sandbox-status').value = 'failed'; currentOffset = 0; load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
        const currentRun = scans.current || {};
        if (!selectedScanId && currentRun.id) selectedScanId = Number(currentRun.id);
        const history = (scans.runs || []).map(run => `<div class="scan-run" data-active="${String(Number(run.id) === Number(selectedScanId))}"><span class="badge ${run.status === 'succeeded' ? 'passed' : run.status === 'running' ? 'pending' : run.status === 'degraded' ? 'review' : 'failed'}">${esc(run.status)}</span><button type="button" class="scan-detail-open" data-scan-id="${esc(run.id)}"><code>#${esc(run.id)} ${esc(run.trigger)}</code><br><span class="muted">${esc(run.started_at)}${run.finished_at ? ' to ' + esc(run.finished_at) : ''}</span></button><span>${n(run.packages_total)} pkgs</span></div>`).join('');
        $('scan-runs').innerHTML = `<div class="eyebrow">Current scan</div><h3>${currentRun.id ? '#' + esc(currentRun.id) : 'No scan yet'}</h3><p class="muted">${esc(currentRun.notes || 'Run a scan to validate package metadata and generate remediation guidance.')}</p><div class="scan-actions"><button id="run-scan-inline">Run scan ${icon('play')}</button><button class="ghost" id="failed-inline">Failed only ${icon('arrow')}</button></div><div class="scan-history">${history || '<div class="scan-run"><span class="badge pending">pending</span><div><code>No runs recorded</code><br><span class="muted">Start with Run scan</span></div><span>0 pkgs</span></div>'}</div>`;
        $('run-scan-inline').addEventListener('click', runScan);
        $('failed-inline').addEventListener('click', () => { $('status').value = 'failed'; currentOffset = 0; load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
        document.querySelectorAll('.scan-detail-open').forEach(button => button.addEventListener('click', () => {
          selectedScanId = Number(button.dataset.scanId);
          document.querySelectorAll('.scan-run').forEach(row => row.dataset.active = String(row.querySelector('.scan-detail-open')?.dataset.scanId === String(selectedScanId)));
          showScanDetail(selectedScanId);
        }));
        showScanDetail(selectedScanId || currentRun.id, { quiet: Boolean(selectedScanId) });
        const familyValue = $('family').value;
        $('family').innerHTML = '<option value="">All families</option>' + families.map(f => `<option value="${esc(f.distro_family)}">${esc(f.distro_family)}</option>`).join('');
        $('family').value = familyValue;
        const repoFilterValue = $('repo-filter').value;
        $('repo-filter').innerHTML = '<option value="">All repository sources</option>' + repos.map(r => `<option value="${esc(r.name)}">${esc(r.name)} · ${esc((r.repo_type || 'apt').toUpperCase())}</option>`).join('');
        $('repo-filter').value = repos.some(r => r.name === repoFilterValue) ? repoFilterValue : '';
        const selectedFamilyVersions = $('family').value ? versions.filter(v => v.distro_family === $('family').value) : versions;
        const versionValue = $('version').value;
        const versionOptions = [...new Set(selectedFamilyVersions.flatMap(v => v.versions.map(item => item.release_version)))].sort((a, b) => Number(b) - Number(a));
        $('version').innerHTML = '<option value="">All versions</option>' + versionOptions.map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join('');
        $('version').value = versionOptions.includes(versionValue) ? versionValue : '';
        const filterOptions = packages.filter_options || {};
        setSelectOptions('architecture', 'All architectures', filterOptions.architectures || [], $('architecture').value);
        setSelectOptions('checksum', 'All checksums', filterOptions.checksum_algorithms || [], $('checksum').value, value => value.toUpperCase());
        $('families').innerHTML = families.length ? families.map(f => {
          const pills = (f.versions || []).map(v => `<span class="version-pill">v${esc(v.release_version)} - ${n(v.packages)} pkgs</span>`).join('');
          return `<article class="family" data-family="${esc(f.distro_family)}"><h3><span class="family-dot"></span>${esc(f.distro_family)}</h3><dl><div><dt>Repos</dt><dd>${n(f.repos)}</dd></div><div><dt>Versions</dt><dd>${n(f.version_count)}</dd></div><div><dt>Healthy mirrors</dt><dd>${n(f.healthy)}</dd></div><div><dt>Mirror sync errors</dt><dd>${n(f.errors)}</dd></div></dl><div class="version-strip">${pills || '<span class="version-pill">No versions</span>'}</div></article>`;
        }).join('') : '<article class="family"><h3><span class="family-dot"></span>No family data</h3></article>';
        const activeRepo = repos.find(r => r.name === $('repo-filter').value);
        $('source-focus').innerHTML = activeRepo ? `<strong>${esc(activeRepo.name)}</strong><br><span class="muted">${n(activeRepo.package_count)} packages from ${esc(activeRepo.distro_family)} ${esc(activeRepo.release_version || '')}. The package table is filtered to this source.</span>` : 'Select a source to edit it or show only its packages.';
        $('source-list').innerHTML = repos.length ? repos.map(r => `<div class="source-row"><div><strong>${esc(r.name)}</strong> <span class="badge ${r.status === 'ok' ? 'passed' : r.status === 'error' ? 'failed' : 'pending'}">${esc(r.status)}</span><p>${esc(r.base_url)}</p><p>${esc(r.suite)}/${esc(r.component)} · ${esc(r.distro_family)} v${esc(r.release_version || 'n/a')} · ${n(r.package_count)} packages</p></div><div class="source-actions"><button class="secondary mini-button" data-source-edit="${esc(r.name)}" type="button">Edit</button><button class="ghost mini-button" data-source-packages="${esc(r.name)}" type="button">Packages</button></div></div>`).join('') : '<div class="source-row"><div><strong>No sources configured</strong><p>Add an APT or RPM source to begin indexing.</p></div></div>';
        document.querySelectorAll('[data-source-edit]').forEach(button => button.addEventListener('click', () => editSource(repos.find(r => r.name === button.dataset.sourceEdit))));
        document.querySelectorAll('[data-source-packages]').forEach(button => button.addEventListener('click', () => showRepoPackages(button.dataset.sourcePackages)));
        $('repos').innerHTML = repos.length ? repos.map((r, i) => `<article class="repo" style="animation-delay:${i * 70}ms"><div class="repo-core"><h3>${esc(r.name)} <span class="badge ${r.status === 'ok' ? 'passed' : r.status === 'error' ? 'failed' : 'pending'}">${esc(r.status)}</span></h3><p><span class="badge pending">${esc(r.distro_family || (r.repo_type || 'apt').toUpperCase())}</span> <span class="badge pending">v${esc(r.release_version || 'n/a')}</span> <span class="badge pending">${esc((r.repo_type || 'apt').toUpperCase())}</span></p><p>${esc(r.base_url)}</p><p>${esc(r.suite)}/${esc(r.component)} - ${n(r.package_count)} packages</p><p>Refreshed ${esc(r.last_refresh || 'never')}</p>${r.error ? `<p class="error">${esc(r.error)}</p>` : ''}</div></article>`).join('') : '<article class="repo"><div class="repo-core"><h3>No repositories configured</h3><p>Add a repository source to begin indexing.</p></div></article>';
        const page = packages.page || { total: packages.packages.length, returned: packages.packages.length, offset: currentOffset, limit: PAGE_LIMIT, has_more: false };
        const start = page.total ? page.offset + 1 : 0;
        const end = page.offset + page.returned;
        $('page-info').textContent = `Showing ${n(start)}-${n(end)} of ${n(page.total)} matching packages`;
        renderFilterSummary(page);
        $('prev-page').disabled = page.offset <= 0;
        $('next-page').disabled = !page.has_more;
        $('packages').innerHTML = packages.packages.length ? packages.packages.map(p => `<tr><td class="select-cell"><input type="checkbox" class="package-select" data-package-id="${esc(p.id)}" aria-label="Select ${esc(p.package)} for targeted sandbox" ${selectedPackageIds.has(String(p.id)) ? 'checked' : ''}></td><td><button class="details-button truncate" title="${esc(p.package)}" data-package-id="${esc(p.id)}">${esc(p.package)}</button><button class="insight-toggle sandbox-one" type="button" data-package-id="${esc(p.id)}">Sandbox this</button></td><td><span class="truncate" title="${esc(p.version)}">${esc(p.version)}</span></td><td><span class="truncate" title="${esc(p.repo_name)}">${esc(p.repo_name)}</span><span class="muted truncate">${esc(p.distro_family)} v${esc(p.release_version || 'n/a')}</span></td><td>${esc(p.architecture || 'n/a')}</td><td><span class="truncate" title="${esc(p.category)}">${esc(p.category)}</span><span class="muted truncate" title="${esc(p.responsibility)}">${esc(p.responsibility)}</span></td><td>${esc((p.package_format || 'deb').toUpperCase())}<br><span class="muted">${esc((p.checksum_algorithm || '').toUpperCase())}</span></td><td><span class="badge ${statusClass(p.security_status)}">${esc(p.security_status)}</span></td><td><span class="badge ${esc(p.security_severity || 'none')}">${esc(p.security_severity || 'none')}</span></td><td>${n(p.security_risk_score)}</td><td><span class="badge ${statusClass(p.sandbox_status)}">${esc(p.sandbox_status || 'pending')}</span><br><span class="muted truncate" title="${esc(p.sandbox_verdict)}">${esc(p.sandbox_verdict || 'not scanned')}</span></td><td>${insightCell(p.why_not_safe || 'none', 'unsafe reason')}</td><td class="muted">${insightCell(p.primary_purpose || (p.description || '').split('\\n')[0], 'package purpose')}</td></tr>`).join('') : '<tr><td colspan="13"><div class="state"><strong>No packages match this filter</strong>Refresh repositories or widen the search criteria.</div></td></tr>';
        $('package-cards').innerHTML = packages.packages.length ? packages.packages.map(p => `<article class="package-card"><h3><button class="details-button" data-package-id="${esc(p.id)}">${esc(p.package)}</button></h3><div class="package-meta"><span class="badge ${statusClass(p.security_status)}">${esc(p.security_status)}</span><span class="badge ${esc(p.security_severity || 'none')}">${esc(p.security_severity || 'none')}</span><span class="badge ${statusClass(p.sandbox_status)}">sandbox ${esc(p.sandbox_status || 'pending')}</span><span class="badge pending">${esc(p.architecture || 'n/a')}</span><span class="badge pending">${esc((p.package_format || 'deb').toUpperCase())}</span></div><dl><div><dt>Version</dt><dd>${esc(p.version)}</dd></div><div><dt>Repo</dt><dd>${esc(p.repo_name)} · ${esc(p.distro_family)} v${esc(p.release_version || 'n/a')}</dd></div><div><dt>Responsible for</dt><dd>${esc(p.responsibility)}</dd></div><div><dt>Sandbox verdict</dt><dd>${esc(p.sandbox_verdict || 'not scanned')}</dd></div><div><dt>Why unsafe</dt><dd>${insightCell(p.why_not_safe || 'none', 'unsafe reason')}</dd></div><div><dt>Purpose</dt><dd>${insightCell(p.primary_purpose || (p.description || '').split('\\n')[0], 'package purpose')}</dd></div></dl></article>`).join('') : '<article class="package-card"><div class="state"><strong>No packages match this filter</strong>Refresh repositories or widen the search criteria.</div></article>';
        document.querySelectorAll('.details-button').forEach(button => button.addEventListener('click', () => showPackage(button.dataset.packageId)));
        document.querySelectorAll('.package-select').forEach(input => input.addEventListener('change', () => {
          if (input.checked) {
            if (selectedPackageIds.size >= 20) {
              input.checked = false;
              $('sandbox-action-state').textContent = 'Targeted sandbox runs are limited to 20 packages.';
              return;
            }
            selectedPackageIds.add(String(input.dataset.packageId));
          } else {
            selectedPackageIds.delete(String(input.dataset.packageId));
          }
          $('selected-package-count').textContent = `${n(selectedPackageIds.size)} selected`;
        }));
        document.querySelectorAll('.sandbox-one').forEach(button => button.addEventListener('click', () => runTargetedSandbox([button.dataset.packageId])));
        document.querySelectorAll('.insight-expand').forEach(button => button.addEventListener('click', () => {
          const cell = button.closest('.insight-cell');
          const expanded = cell.dataset.expanded === 'true';
          cell.dataset.expanded = expanded ? 'false' : 'true';
          button.textContent = expanded ? 'Show more' : 'Show less';
          button.setAttribute('aria-expanded', String(!expanded));
        }));
        document.querySelectorAll('.insight-reader-open').forEach(button => button.addEventListener('click', () => {
          $('insight-reader-title').textContent = button.dataset.insightLabel === 'unsafe reason' ? 'Full Why unsafe reason' : 'Full package purpose';
          $('insight-reader-body').textContent = button.dataset.insightText || 'No detail available.';
          $('insight-reader').dataset.open = 'true';
          $('insight-reader').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }));
      } catch (error) {
        $('packages').innerHTML = `<tr><td colspan="13"><div class="state error"><strong>Could not load package data</strong>${esc(error.message || error)}</div></td></tr>`;
        $('package-cards').innerHTML = `<article class="package-card"><div class="state error"><strong>Could not load package data</strong>${esc(error.message || error)}</div></article>`;
      }
    }
    async function runScan() {
      $('scan').disabled = true;
      $('scan').innerHTML = `Scanning ${icon('refresh')}`;
      try {
        const response = await fetch('/api/scans', { method: 'POST' });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(body.detail || body.error || `Scan request failed with HTTP ${response.status}`);
        }
        if (body.run_id) {
          selectedScanId = Number(body.run_id);
          showScanDetail(selectedScanId);
        }
      } catch (error) {
        $('remediation').innerHTML = `<div class="eyebrow">Scan request</div><h3>Could not queue scan</h3><p class="muted">${esc(error.message || error)}</p>`;
      } finally {
        $('scan').disabled = false;
        $('scan').innerHTML = `Run scan ${icon('play')}`;
        load();
      }
    }
    async function runSandboxScan() {
      const button = $('run-sandbox-inline');
      const state = $('sandbox-action-state');
      button.disabled = true;
      button.innerHTML = `Queueing sandbox preflight ${icon('refresh')}`;
      state.textContent = 'Requesting sandbox preflight queue...';
      try {
        const response = await fetch('/api/sandbox/scans', { method: 'POST' });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(body.detail || body.error || `Sandbox request failed with HTTP ${response.status}`);
        }
        state.textContent = body.message || 'Sandbox preflight queued.';
      } catch (error) {
        state.textContent = error.message || String(error);
      } finally {
        button.disabled = false;
        button.innerHTML = `Start sandbox preflight ${icon('play')}`;
        setTimeout(load, 900);
      }
    }
    async function runTargetedSandbox(packageIds) {
      const ids = [...new Set(packageIds.map(id => String(id)).filter(Boolean))];
      const state = $('sandbox-action-state');
      if (!ids.length) {
        state.textContent = 'Select one to 20 packages before starting a targeted sandbox run.';
        return;
      }
      if (ids.length > 20) {
        state.textContent = 'Targeted sandbox runs are limited to 20 packages.';
        return;
      }
      state.textContent = `Requesting targeted sandbox preflight for ${n(ids.length)} packages...`;
      try {
        const response = await fetch('/api/sandbox/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ package_ids: ids.map(id => Number(id)) })
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
          throw new Error(body.detail || body.error || `Targeted sandbox failed with HTTP ${response.status}`);
        }
        state.textContent = body.message || 'Targeted sandbox preflight completed.';
        ids.forEach(id => selectedPackageIds.delete(id));
      } catch (error) {
        state.textContent = error.message || String(error);
      } finally {
        setTimeout(load, 900);
      }
    }
    async function runSelectedSandboxScan() {
      await runTargetedSandbox([...selectedPackageIds]);
    }
    async function showPackage(packageId) {
      const [p, logPayload] = await Promise.all([
        fetch('/api/packages/' + encodeURIComponent(packageId)).then(r => r.json()),
        fetch('/api/packages/' + encodeURIComponent(packageId) + '/sandbox/logs').then(r => r.json())
      ]);
      const steps = (p.remediation || []).map(item => `<div class="remediation-item"><strong>${esc(item.action)} <span class="badge ${esc(item.priority === 'urgent' ? 'critical' : item.priority === 'high' ? 'high' : 'medium')}">${esc(item.priority)}</span></strong><span class="muted">${esc(item.owner)} - ${esc(item.evidence || '')}</span><ol>${(item.steps || []).map(step => `<li>${esc(step)}</li>`).join('')}</ol></div>`).join('');
      const sandboxEvidence = (p.sandbox_evidence || []).map(item => `<li>${esc(item)}</li>`).join('');
      const sandboxFindings = (p.sandbox_findings || []).map(item => `<li>${esc(item)}</li>`).join('');
      const packageLogs = (logPayload.logs || []).map(log => `<div class="remediation-item"><strong>Run #${esc(log.sandbox_run_id)} <span class="badge ${statusClass(log.status)}">${esc(log.status)}</span></strong><span class="muted">${esc(log.created_at)} - ${esc(log.verdict)}</span><ol>${(log.evidence || []).map(item => `<li>${esc(item)}</li>`).join('')}</ol></div>`).join('');
      $('remediation').innerHTML = `<div class="eyebrow">Package intelligence</div><h3>${esc(p.package)}</h3><div class="scan-actions"><button id="sandbox-package-detail">Sandbox this package ${icon('play')}</button></div><div class="package-brief"><div class="brief-row"><span>Responsible for</span><strong>${esc(p.responsibility)}</strong></div><div class="brief-row"><span>Package purpose</span><strong>${esc(p.primary_purpose)}</strong></div><div class="brief-row"><span>Why it is not safe</span><strong>${esc(p.why_not_safe)}</strong></div><div class="brief-row"><span>Sandbox verdict</span><strong><span class="badge ${statusClass(p.sandbox_status)}">${esc(p.sandbox_status || 'pending')}</span> ${esc(p.sandbox_verdict || 'not scanned')}</strong></div><div class="brief-row"><span>Sandbox next action</span><strong>${esc(p.sandbox_next_action || 'No sandbox action recorded.')}</strong></div><div class="brief-row"><span>Internal owner lane</span><strong>${esc(p.operational_owner)}</strong></div><div class="brief-row"><span>Upstream maintainer from package metadata</span><strong>${esc(p.upstream_maintainer)}</strong></div><div class="brief-row"><span>Architecture</span><strong>${esc(p.architecture || 'n/a')}</strong></div><div class="brief-row"><span>Checksum algorithm</span><strong>${esc((p.checksum_algorithm || 'unknown').toUpperCase())}</strong></div><div class="brief-row"><span>Impact</span><strong>${esc(p.impact)}</strong></div></div><p class="muted">${esc(p.recommended_action)}</p><div class="remediation-list"><div class="remediation-item"><strong>Sandbox evidence</strong><ol>${sandboxEvidence || '<li>No sandbox evidence recorded.</li>'}</ol>${sandboxFindings ? `<strong>Sandbox findings</strong><ol>${sandboxFindings}</ol>` : ''}</div><div class="remediation-item"><strong>Sandbox package logs</strong><span class="muted">Every targeted run for this package is retained here.</span></div>${packageLogs || '<div class="remediation-item"><strong>No targeted package logs yet</strong><span class="muted">Use Sandbox this package to create the first per-package log.</span></div>'}${steps || '<div class="remediation-item"><strong>No remediation required</strong><span class="muted">This package currently passes validation.</span></div>'}</div>`;
      $('sandbox-package-detail').addEventListener('click', () => runTargetedSandbox([packageId]));
      document.querySelector('.scan-console').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    function editSource(repo) {
      if (!repo) return;
      editingSourceName = repo.name;
      $('repo-name').value = repo.name;
      $('repo-type').value = repo.repo_type || 'apt';
      $('repo-base-url').value = repo.base_url || '';
      $('repo-suite').value = repo.suite || '';
      $('repo-component').value = repo.component || '';
      $('source-focus').innerHTML = `<strong>Editing ${esc(repo.name)}</strong><br><span class="muted">Save updates the source definition. Run Refresh index afterward to re-fetch package metadata.</span>`;
      document.querySelector('#source-section').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    function resetSourceForm() {
      editingSourceName = '';
      $('source-form').reset();
      $('repo-type').value = 'apt';
      $('source-focus').textContent = 'Add a new APT or RPM source, then run Refresh index to import its packages.';
    }
    function showRepoPackages(repoName) {
      $('repo-filter').value = repoName;
      currentOffset = 0;
      load();
      document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    function resetFilters() {
      $('q').value = '';
      $('status').value = '';
      $('severity').value = '';
      $('sandbox-status').value = '';
      $('family').value = '';
      $('version').value = '';
      $('repo-filter').value = '';
      $('format').value = '';
      $('architecture').value = '';
      $('checksum').value = '';
      $('sort').value = 'risk';
      currentOffset = 0;
      load();
    }
    async function saveSource(event) {
      event.preventDefault();
      const payload = {
        name: $('repo-name').value.trim(),
        repo_type: $('repo-type').value,
        base_url: $('repo-base-url').value.trim(),
        suite: $('repo-suite').value.trim(),
        component: $('repo-component').value.trim()
      };
      const target = editingSourceName ? '/api/repos/' + encodeURIComponent(editingSourceName) : '/api/repos';
      const method = editingSourceName ? 'PUT' : 'POST';
      $('save-source').disabled = true;
      try {
        const response = await fetch(target, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        if (!response.ok) {
          const body = await response.json().catch(() => ({}));
          throw new Error(body.detail || body.error || `Save failed with HTTP ${response.status}`);
        }
        editingSourceName = payload.name;
        $('repo-filter').value = payload.name;
        await load();
        $('source-focus').innerHTML = `<strong>${esc(payload.name)} saved</strong><br><span class="muted">Run Refresh index to import or update all packages from this source.</span>`;
      } catch (error) {
        $('source-focus').innerHTML = `<strong class="error">Could not save source</strong><br><span class="muted">${esc(error.message || error)}</span>`;
      } finally {
        $('save-source').disabled = false;
      }
    }
    $('refresh').addEventListener('click', async () => { $('refresh').disabled = true; $('refresh').innerHTML = `Refreshing ${icon('refresh')}`; await fetch('/api/refresh', { method: 'POST' }); $('refresh').disabled = false; $('refresh').innerHTML = `Refresh index ${icon('refresh')}`; load(); });
    $('scan').addEventListener('click', runScan);
    $('show-review').addEventListener('click', () => { $('status').value = 'review'; currentOffset = 0; load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    $('prev-page').addEventListener('click', () => { currentOffset = Math.max(0, currentOffset - PAGE_LIMIT); load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    $('next-page').addEventListener('click', () => { currentOffset += PAGE_LIMIT; load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    $('q').addEventListener('input', () => clearTimeout(window.__t) || (window.__t = setTimeout(() => { currentOffset = 0; load(); }, 250)));
    filterIds.filter(id => id !== 'q').forEach(id => $(id).addEventListener('change', () => { currentOffset = 0; load(); }));
    $('reset-filters').addEventListener('click', resetFilters);
    $('source-form').addEventListener('submit', saveSource);
    $('new-source').addEventListener('click', resetSourceForm);
    $('theme-toggle').addEventListener('click', () => setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark'));
    $('close-insight-reader').addEventListener('click', () => {
      $('insight-reader').dataset.open = 'false';
      $('insight-reader-body').textContent = '';
    });
    setTheme(localStorage.getItem('pkgmng-theme') || 'light');
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
