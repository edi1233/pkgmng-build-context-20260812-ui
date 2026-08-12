from __future__ import annotations

import gzip
import io
import json
import lzma
import os
import re
import sqlite3
import tempfile
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
              maintainer TEXT,
              description TEXT,
              package_format TEXT NOT NULL DEFAULT 'deb',
              security_status TEXT NOT NULL,
              security_findings TEXT NOT NULL,
              security_severity TEXT NOT NULL DEFAULT 'none',
              security_risk_score INTEGER NOT NULL DEFAULT 0,
              security_checks TEXT NOT NULL DEFAULT '[]',
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
            CREATE INDEX IF NOT EXISTS idx_packages_name ON packages(package);
            CREATE INDEX IF NOT EXISTS idx_packages_status ON packages(security_status);
            CREATE INDEX IF NOT EXISTS idx_scan_runs_started ON scan_runs(started_at);
            """
        )
        ensure_column(conn, "repos", "repo_type", "TEXT NOT NULL DEFAULT 'apt'")
        ensure_column(conn, "repos", "distro_family", "TEXT NOT NULL DEFAULT 'Debian'")
        ensure_column(conn, "repos", "release_version", "TEXT NOT NULL DEFAULT ''")
        ensure_column(conn, "packages", "package_format", "TEXT NOT NULL DEFAULT 'deb'")
        ensure_column(conn, "packages", "security_severity", "TEXT NOT NULL DEFAULT 'none'")
        ensure_column(conn, "packages", "security_risk_score", "INTEGER NOT NULL DEFAULT 0")
        ensure_column(conn, "packages", "security_checks", "TEXT NOT NULL DEFAULT '[]'")
        repos = configured_repos()
        repo_names = [repo.name for repo in repos]
        if repo_names:
            placeholders = ",".join("?" for _ in repo_names)
            conn.execute(f"DELETE FROM packages WHERE repo_name NOT IN ({placeholders})", repo_names)
            conn.execute(f"DELETE FROM repos WHERE name NOT IN ({placeholders})", repo_names)
        for repo in repos:
            conn.execute(
                """
                INSERT INTO repos(name, repo_type, distro_family, release_version, base_url, suite, component)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                  repo_type=excluded.repo_type,
                  distro_family=excluded.distro_family,
                  release_version=excluded.release_version,
                  base_url=excluded.base_url,
                  suite=excluded.suite,
                  component=excluded.component
                """,
                (
                    repo.name,
                    repo.repo_type,
                    repo.distro_family,
                    repo.release_version,
                    repo.base_url,
                    repo.suite,
                    repo.component,
                ),
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
            "action": "Review security-channel package before fleet rollout",
            "owner": "security reviewer",
            "steps": [
                "Read the upstream advisory or changelog for affected CVEs.",
                "Prioritize vulnerable fleets that run this OS version.",
                "Approve rollout only after compatibility checks pass.",
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
            "action": "Route sensitive package to manual review",
            "owner": "security reviewer",
            "steps": [
                "Inspect package purpose, dependencies, and maintainer.",
                "Check whether the package affects kernel, networking, auth, or system services.",
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
    sha256 = record.get("SHA256", "")
    size = int(record.get("Size", "0") or "0")
    expected_suffix = ".rpm" if package_format == "rpm" else ".deb"

    if sha256 and re.fullmatch(r"[A-Fa-f0-9]{64}", sha256):
        add_check(checks, "checksum", "SHA256 checksum", "passed", "none", "valid 64-character checksum")
    elif sha256:
        add_check(checks, "checksum", "SHA256 checksum", "failed", "critical", "checksum is present but not a valid SHA256 hex digest")
    else:
        add_check(checks, "checksum", "SHA256 checksum", "failed", "critical", "missing SHA256 checksum")

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
        add_check(checks, "security_channel", "Security channel", "review", "high", "package is published through a security update channel")
    elif repo:
        add_check(checks, "security_channel", "Security channel", "passed", "none", f"package is indexed from {repo_family or repo.repo_type} repository metadata")

    expected_suffix = ".rpm" if package_format == "rpm" else ".deb"
    priority = record.get("Priority", "").lower()
    if priority in {"required", "important"}:
        add_check(checks, "priority", "High-impact priority", "review", "high", f"high-impact priority: {priority}")
    section = record.get("Section", "").lower()
    if any(word in section for word in ["admin", "kernel", "net", "utils", "system", "security"]):
        add_check(checks, "sensitive_section", "Sensitive package section", "review", "medium", f"sensitive section: {section}")
    description = record.get("Description", "")
    if re.search(r"\b(setuid|root|privilege|kernel module)\b", description, re.I):
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
    return {
        "status": status,
        "severity": severity,
        "risk_score": min(risk_score, 100),
        "findings": findings,
        "remediation": remediation,
        "checks": checks,
    }


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
    owner = maintainer or default_owner_for(category)
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
        "impact": impact,
        "safety_summary": safety_summary,
        "why_not_safe": why_not_safe,
        "unsafe_check_ids": [check.get("id") for check in [*failed_checks, *review_checks] if check.get("id")],
    }


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
                      filename, size, sha256, maintainer, description,
                      package_format, security_status, security_findings,
                      security_severity, security_risk_score, security_checks, refreshed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        profile["status"],
                        json.dumps(profile["findings"]),
                        profile["severity"],
                        profile["risk_score"],
                        json.dumps(profile["checks"]),
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


async def refresh_all(trigger: str = "manual") -> list[dict[str, Any]]:
    repos = configured_repos()
    started_at = now_iso()
    with closing(connect_db()) as conn:
        cursor = conn.execute(
            """
            INSERT INTO scan_runs(started_at, status, trigger, repos_total, notes)
            VALUES (?, 'running', ?, ?, ?)
            """,
            (started_at, trigger, len(repos), "Repository metadata refresh and package security validation started."),
        )
        run_id = cursor.lastrowid
        conn.commit()
    results = [await refresh_repo(repo) for repo in repos]
    with closing(connect_db()) as conn:
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
    return results


def schedule_refresh() -> BackgroundScheduler:
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(lambda: __import__("asyncio").run(refresh_all("scheduled")), "interval", minutes=REFRESH_INTERVAL_MINUTES)
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
    return JSONResponse({"results": await refresh_all("manual-refresh")})


@app.post("/api/scans")
async def api_scan() -> JSONResponse:
    return JSONResponse({"results": await refresh_all("manual-scan")})


@app.get("/api/scans")
def api_scans(limit: int = Query(10, ge=1, le=50)) -> dict[str, Any]:
    with closing(connect_db()) as conn:
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
    return {"current": current, "runs": runs}


@app.get("/api/repos")
def api_repos() -> list[dict[str, Any]]:
    with closing(connect_db()) as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM repos ORDER BY repo_type, distro_family, name")]


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
        totals = security_totals(conn)
        by_family = [
            dict(row)
            for row in conn.execute(
                """
                SELECT
                  repos.distro_family,
                  repos.release_version,
                  COUNT(*) total,
                  COALESCE(SUM(packages.security_status='passed'), 0) passed,
                  COALESCE(SUM(packages.security_status='review'), 0) review,
                  COALESCE(SUM(packages.security_status='failed'), 0) failed,
                  COALESCE(SUM(packages.security_severity='critical'), 0) critical,
                  COALESCE(SUM(packages.security_severity='high'), 0) high,
                  COALESCE(ROUND(AVG(packages.security_risk_score), 1), 0) avg_risk
                FROM packages
                JOIN repos ON repos.name = packages.repo_name
                GROUP BY repos.distro_family, repos.release_version
                ORDER BY repos.distro_family, CAST(repos.release_version AS INTEGER) DESC
                """
            )
        ]
        top_risk = [
            dict(row)
            for row in conn.execute(
                """
                SELECT packages.package, packages.version, packages.repo_name, packages.security_status,
                       packages.security_severity, packages.security_risk_score, packages.security_findings,
                       repos.distro_family, repos.release_version
                FROM packages
                JOIN repos ON repos.name = packages.repo_name
                WHERE packages.security_status != 'passed'
                ORDER BY packages.security_risk_score DESC, packages.package
                LIMIT 25
                """
            )
        ]
    for row in top_risk:
        row["security_findings"] = json.loads(row["security_findings"])
        row.update(package_intelligence(row))
    return {"totals": totals, "by_family": by_family, "top_risk": top_risk}


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
    family: str = "",
    version: str = "",
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
    if version:
        where.append("repos.release_version = ?")
        args.append(version)
    sql = """
        SELECT packages.*, repos.distro_family, repos.release_version
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
            row["security_checks"] = json.loads(row["security_checks"])
            row.update(package_intelligence(row))
        totals = dict(
            conn.execute(
                """
                SELECT
                  COUNT(*) total,
                  COALESCE(SUM(security_status='passed'), 0) passed,
                  COALESCE(SUM(security_status='review'), 0) review,
                  COALESCE(SUM(security_status='failed'), 0) failed
                FROM packages
                """
            ).fetchone()
        )
    return {"packages": rows, "totals": totals}


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
    .toolbar { display:grid; grid-template-columns:minmax(240px,1fr) 170px 210px 170px; gap:12px; align-items:center; margin:16px 0; }
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
    .version-strip { display:flex; flex-wrap:wrap; gap:6px; margin-top:14px; }
    .version-pill { display:inline-flex; align-items:center; min-height:28px; border-radius:999px; padding:4px 9px; background:rgba(16,20,24,.07); color:#27333d; font-size:12px; font-weight:740; }
    .security-grid { display:grid; grid-template-columns:minmax(280px,.85fr) minmax(360px,1.15fr); gap:14px; margin:0 0 34px; }
    .security-panel { border-radius:22px; padding:18px; background:rgba(255,255,255,.84); border:1px solid rgba(16,20,24,.08); box-shadow:inset 0 1px 0 rgba(255,255,255,.9); }
    .security-panel h3 { margin:8px 0 0; font-size:clamp(28px,4vw,52px); line-height:1; font-variant-numeric:tabular-nums; }
    .risk-meter { height:12px; border-radius:999px; overflow:hidden; background:rgba(16,20,24,.1); margin:18px 0 8px; }
    .risk-meter span { display:block; height:100%; width:0; background:linear-gradient(90deg, var(--ok), var(--warn), var(--bad)); border-radius:999px; }
    .risk-list { display:grid; gap:8px; margin-top:14px; }
    .risk-item { display:grid; grid-template-columns:1fr auto; gap:10px; align-items:center; padding:10px 0; border-top:1px solid rgba(16,20,24,.08); }
    .risk-item strong { font-size:13px; overflow-wrap:anywhere; }
    .risk-item span { color:var(--muted); font-size:12px; text-align:right; }
    .scan-console { display:grid; grid-template-columns:minmax(280px,.9fr) minmax(360px,1.1fr); gap:14px; margin:0 0 34px; }
    .scan-card, .remediation-card { border-radius:22px; padding:18px; background:rgba(255,255,255,.84); border:1px solid rgba(16,20,24,.08); box-shadow:inset 0 1px 0 rgba(255,255,255,.9); }
    .scan-card h3, .remediation-card h3 { margin:8px 0 12px; font-size:clamp(24px,3vw,38px); line-height:1; }
    .scan-actions { display:flex; gap:10px; flex-wrap:wrap; margin-top:16px; }
    .scan-history { display:grid; gap:8px; margin-top:14px; }
    .scan-run { display:grid; grid-template-columns:auto 1fr auto; gap:10px; align-items:center; padding:10px 0; border-top:1px solid rgba(16,20,24,.08); }
    .scan-run code { font-family:"SFMono-Regular", Consolas, ui-monospace, monospace; font-size:12px; color:#34424e; }
    .remediation-list { display:grid; gap:10px; margin-top:14px; }
    .remediation-item { padding:12px; border-radius:16px; background:rgba(16,20,24,.045); border:1px solid rgba(16,20,24,.07); }
    .remediation-item strong { display:block; margin-bottom:6px; }
    .remediation-item ol { margin:8px 0 0 18px; padding:0; color:#40505c; font-size:13px; line-height:1.5; }
    .package-brief { display:grid; gap:10px; margin-top:14px; }
    .brief-row { padding:12px; border-radius:16px; background:rgba(10,111,100,.055); border:1px solid rgba(10,111,100,.1); }
    .brief-row span { display:block; margin-bottom:5px; color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.12em; }
    .brief-row strong { display:block; line-height:1.35; }
    .details-button { all:unset; cursor:pointer; color:var(--accent); font-weight:760; }
    .details-button:focus-visible { outline:3px solid rgba(10,111,100,.22); outline-offset:3px; border-radius:8px; }
    .badge { display:inline-flex; align-items:center; border-radius:999px; padding:5px 10px; font-size:12px; font-weight:720; text-transform:uppercase; letter-spacing:.08em; }
    .passed { color:#063f27; background:rgba(8,116,67,.13); }
    .review { color:#62440a; background:rgba(138,100,26,.16); }
    .failed { color:#761d18; background:rgba(169,52,44,.14); }
    .critical { color:#761d18; background:rgba(169,52,44,.18); }
    .high { color:#62440a; background:rgba(138,100,26,.18); }
    .medium { color:#27333d; background:rgba(64,74,85,.12); }
    .none { color:#063f27; background:rgba(8,116,67,.11); }
    .pending { color:#404a55; background:rgba(64,74,85,.12); }
    .error { color: var(--bad); }
    .table-shell { border-radius:28px; padding:8px; background:rgba(16,20,24,.06); box-shadow:var(--shadow); }
    .table-wrap { border-radius:22px; overflow:auto; background:rgba(255,255,255,.9); max-height:720px; box-shadow:inset 0 1px 0 rgba(255,255,255,.86); }
    table { width:100%; border-collapse:collapse; table-layout:fixed; min-width:1240px; }
    th, td { border-bottom:1px solid rgba(16,20,24,.08); padding:15px 14px; text-align:left; vertical-align:top; font-size:13px; }
    th { position:sticky; top:0; z-index:1; color:#34424e; background:rgba(255,255,255,.96); font-size:11px; text-transform:uppercase; letter-spacing:.13em; }
    td:nth-child(1) { width:14%; font-weight:750; }
    td:nth-child(2) { width:17%; overflow-wrap:anywhere; font-variant-numeric:tabular-nums; }
    td:nth-child(3) { width:11%; }
    td:nth-child(4) { width:14%; }
    td:nth-child(5), td:nth-child(6), td:nth-child(7), td:nth-child(8) { width:8%; }
    td:nth-child(9), td:nth-child(10) { width:15%; }
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
      .security-grid { grid-template-columns:1fr; }
      .scan-console { grid-template-columns:1fr; }
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
          <button id="scan">Run scan <span class="button-orb" aria-hidden="true">!</span></button>
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
          <div class="eyebrow">Security validation</div>
          <h2>All package checks</h2>
        </div>
        <p class="muted">Every indexed DEB and RPM record is scored for metadata integrity, trusted transport, update-channel context, sensitive behavior, package purpose, and operational impact.</p>
      </div>
      <section class="security-grid" id="security" aria-label="Package validation summary"></section>
      <div class="section-head">
        <div>
          <div class="eyebrow">Scan operations</div>
          <h2>Scan runs and remediation</h2>
        </div>
        <p class="muted">Launch package validation, inspect current run evidence, and turn findings into operator action.</p>
      </div>
      <section class="scan-console" aria-label="Security scan operations">
        <article class="scan-card" id="scan-runs"></article>
        <article class="remediation-card" id="remediation"></article>
      </section>
      <div class="section-head">
        <div>
          <div class="eyebrow">RHEL-family coverage</div>
          <h2>Distribution lanes</h2>
        </div>
        <p class="muted">Each distribution lane keeps the latest five configured OS releases, capped to the public versions with reachable repository metadata.</p>
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
          <h2>Package intelligence table</h2>
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
        <select id="version" aria-label="Filter by operating system version">
          <option value="">All versions</option>
        </select>
      </div>
      <section class="table-shell" id="packages-table">
        <div class="table-wrap">
          <table>
            <thead><tr><th>Package</th><th>Version</th><th>Repo</th><th>Responsible for</th><th>Format</th><th>Status</th><th>Severity</th><th>Risk</th><th>Why unsafe</th><th>Purpose</th></tr></thead>
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
    const skeletonRows = () => Array.from({length: 8}).map(() => '<tr><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td><td><div class="skeleton"></div></td></tr>').join('');
    const statusClass = (value) => ['passed', 'review', 'failed', 'pending'].includes(value) ? value : 'pending';
    const n = (value) => Number(value || 0).toLocaleString();
    async function load() {
      $('packages').innerHTML = skeletonRows();
      try {
        const params = new URLSearchParams({ q: $('q').value, status: $('status').value, family: $('family').value, version: $('version').value, limit: '300' });
        const [repos, families, versions, security, scans, packages] = await Promise.all([fetch('/api/repos').then(r => r.json()), fetch('/api/families').then(r => r.json()), fetch('/api/versions').then(r => r.json()), fetch('/api/security').then(r => r.json()), fetch('/api/scans').then(r => r.json()), fetch('/api/packages?' + params).then(r => r.json())]);
        const totals = packages.totals || {};
        $('hero-summary').innerHTML = [
          ['Indexed packages', n(totals.total)],
          ['Needs review', n(totals.review)],
          ['Failed checks', n(totals.failed)],
          ['Refresh cadence', '6h']
        ].map(([k,v]) => `<div class="scanline"><span>${k}</span><strong>${v}</strong></div>`).join('');
        $('metrics').innerHTML = [['Total', totals.total], ['Passed', totals.passed], ['Review', totals.review], ['Failed', totals.failed]].map(([k,v], i) => `<article class="metric" style="animation-delay:${i * 60}ms"><div class="metric-inner"><strong>${n(v)}</strong><span>${k}</span></div></article>`).join('');
        const securityTotals = security.totals || {};
        const avgRisk = Math.max(0, Math.min(100, Number(securityTotals.avg_risk || 0)));
        const lanes = (security.by_family || []).slice(0, 10).map(row => `<div class="risk-item"><strong>${esc(row.distro_family)} v${esc(row.release_version || 'n/a')}</strong><span>${n(row.review)} review / ${n(row.failed)} failed</span></div>`).join('');
        const topRisk = (security.top_risk || []).slice(0, 8).map(row => `<div class="risk-item"><strong>${esc(row.package)}</strong><span>${esc(row.security_severity)} - ${n(row.security_risk_score)}</span></div>`).join('');
        $('security').innerHTML = `<article class="security-panel"><div class="eyebrow">Average risk</div><h3>${avgRisk.toFixed(1)} / 100</h3><div class="risk-meter"><span style="width:${avgRisk}%"></span></div><p class="muted">${n(securityTotals.total)} packages scanned, ${n(securityTotals.critical)} critical metadata failures, ${n(securityTotals.high)} high review signals.</p><div class="risk-list">${lanes || '<div class="risk-item"><strong>No scan data</strong><span>refresh index</span></div>'}</div></article><article class="security-panel"><div class="eyebrow">Highest risk packages</div><h3>Validation queue</h3><div class="risk-list">${topRisk || '<div class="risk-item"><strong>No packages need review</strong><span>clear</span></div>'}</div></article>`;
        const currentRun = scans.current || {};
        const history = (scans.runs || []).map(run => `<div class="scan-run"><span class="badge ${run.status === 'succeeded' ? 'passed' : run.status === 'running' ? 'pending' : run.status === 'degraded' ? 'review' : 'failed'}">${esc(run.status)}</span><div><code>#${esc(run.id)} ${esc(run.trigger)}</code><br><span class="muted">${esc(run.started_at)}${run.finished_at ? ' to ' + esc(run.finished_at) : ''}</span></div><span>${n(run.packages_total)} pkgs</span></div>`).join('');
        $('scan-runs').innerHTML = `<div class="eyebrow">Current scan</div><h3>${currentRun.id ? '#' + esc(currentRun.id) : 'No scan yet'}</h3><p class="muted">${esc(currentRun.notes || 'Run a scan to validate package metadata and generate remediation guidance.')}</p><div class="scan-actions"><button id="run-scan-inline">Run scan <span class="button-orb" aria-hidden="true">!</span></button><button class="ghost" id="failed-inline">Failed only <span class="button-orb" aria-hidden="true">&gt;</span></button></div><div class="scan-history">${history || '<div class="scan-run"><span class="badge pending">pending</span><div><code>No runs recorded</code><br><span class="muted">Start with Run scan</span></div><span>0 pkgs</span></div>'}</div>`;
        const remediationRows = (security.top_risk || []).slice(0, 4).map(row => `<div class="remediation-item"><strong>${esc(row.package)} <span class="badge ${esc(row.security_severity)}">${esc(row.security_severity)}</span></strong><span class="muted">${esc(row.responsibility || row.category || 'Package intelligence')}</span><br><span class="muted">${esc(row.why_not_safe || (row.security_findings || []).join('; ') || 'manual review')}</span></div>`).join('');
        $('remediation').innerHTML = `<div class="eyebrow">Remediation queue</div><h3>${n(securityTotals.review + securityTotals.failed)} actions</h3><p class="muted">Open a package row to see the exact owner, priority, evidence, and fix steps for each failed or review check.</p><div class="remediation-list">${remediationRows || '<div class="remediation-item"><strong>No active remediation</strong><span class="muted">All current package checks passed.</span></div>'}</div>`;
        $('run-scan-inline').addEventListener('click', runScan);
        $('failed-inline').addEventListener('click', () => { $('status').value = 'failed'; load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
        const familyValue = $('family').value;
        $('family').innerHTML = '<option value="">All families</option>' + families.map(f => `<option value="${esc(f.distro_family)}">${esc(f.distro_family)}</option>`).join('');
        $('family').value = familyValue;
        const selectedFamilyVersions = $('family').value ? versions.filter(v => v.distro_family === $('family').value) : versions;
        const versionValue = $('version').value;
        const versionOptions = [...new Set(selectedFamilyVersions.flatMap(v => v.versions.map(item => item.release_version)))].sort((a, b) => Number(b) - Number(a));
        $('version').innerHTML = '<option value="">All versions</option>' + versionOptions.map(v => `<option value="${esc(v)}">${esc(v)}</option>`).join('');
        $('version').value = versionOptions.includes(versionValue) ? versionValue : '';
        $('families').innerHTML = families.length ? families.map(f => {
          const pills = (f.versions || []).map(v => `<span class="version-pill">v${esc(v.release_version)} - ${n(v.packages)} pkgs</span>`).join('');
          return `<article class="family" data-family="${esc(f.distro_family)}"><h3><span class="family-dot"></span>${esc(f.distro_family)}</h3><dl><div><dt>Repos</dt><dd>${n(f.repos)}</dd></div><div><dt>Versions</dt><dd>${n(f.version_count)}</dd></div><div><dt>Healthy</dt><dd>${n(f.healthy)}</dd></div><div><dt>Errors</dt><dd>${n(f.errors)}</dd></div></dl><div class="version-strip">${pills || '<span class="version-pill">No versions</span>'}</div></article>`;
        }).join('') : '<article class="family"><h3><span class="family-dot"></span>No family data</h3></article>';
        $('repos').innerHTML = repos.length ? repos.map((r, i) => `<article class="repo" style="animation-delay:${i * 70}ms"><div class="repo-core"><h3>${esc(r.name)} <span class="badge ${r.status === 'ok' ? 'passed' : 'failed'}">${esc(r.status)}</span></h3><p><span class="badge pending">${esc(r.distro_family || (r.repo_type || 'apt').toUpperCase())}</span> <span class="badge pending">v${esc(r.release_version || 'n/a')}</span> <span class="badge pending">${esc((r.repo_type || 'apt').toUpperCase())}</span></p><p>${esc(r.base_url)}</p><p>${esc(r.suite)}/${esc(r.component)} - ${n(r.package_count)} packages</p><p>Refreshed ${esc(r.last_refresh || 'never')}</p>${r.error ? `<p class="error">${esc(r.error)}</p>` : ''}</div></article>`).join('') : '<article class="repo"><div class="repo-core"><h3>No repositories configured</h3><p>Add APT_REPOS or RPM_REPOS entries to begin indexing.</p></div></article>';
        $('packages').innerHTML = packages.packages.length ? packages.packages.map(p => `<tr><td><button class="details-button" data-package-id="${esc(p.id)}">${esc(p.package)}</button></td><td>${esc(p.version)}</td><td>${esc(p.repo_name)}<br><span class="muted">${esc(p.distro_family)} v${esc(p.release_version || 'n/a')}</span></td><td>${esc(p.category)}<br><span class="muted">${esc(p.responsibility)}</span></td><td>${esc((p.package_format || 'deb').toUpperCase())}</td><td><span class="badge ${statusClass(p.security_status)}">${esc(p.security_status)}</span></td><td><span class="badge ${esc(p.security_severity || 'none')}">${esc(p.security_severity || 'none')}</span></td><td>${n(p.security_risk_score)}</td><td>${esc(p.why_not_safe || 'none')}</td><td class="muted">${esc(p.primary_purpose || (p.description || '').split('\\n')[0])}</td></tr>`).join('') : '<tr><td colspan="6"><div class="state"><strong>No packages match this filter</strong>Refresh repositories or widen the search criteria.</div></td><td colspan="4"></td></tr>';
        document.querySelectorAll('.details-button').forEach(button => button.addEventListener('click', () => showPackage(button.dataset.packageId)));
      } catch (error) {
        $('packages').innerHTML = `<tr><td colspan="9"><div class="state error"><strong>Could not load package data</strong>${esc(error.message || error)}</div></td></tr>`;
      }
    }
    async function runScan() {
      $('scan').disabled = true;
      $('scan').innerHTML = 'Scanning <span class="button-orb" aria-hidden="true">...</span>';
      await fetch('/api/scans', { method: 'POST' });
      $('scan').disabled = false;
      $('scan').innerHTML = 'Run scan <span class="button-orb" aria-hidden="true">!</span>';
      load();
    }
    async function showPackage(packageId) {
      const p = await fetch('/api/packages/' + encodeURIComponent(packageId)).then(r => r.json());
      const steps = (p.remediation || []).map(item => `<div class="remediation-item"><strong>${esc(item.action)} <span class="badge ${esc(item.priority === 'urgent' ? 'critical' : item.priority === 'high' ? 'high' : 'medium')}">${esc(item.priority)}</span></strong><span class="muted">${esc(item.owner)} - ${esc(item.evidence || '')}</span><ol>${(item.steps || []).map(step => `<li>${esc(step)}</li>`).join('')}</ol></div>`).join('');
      $('remediation').innerHTML = `<div class="eyebrow">Package intelligence</div><h3>${esc(p.package)}</h3><div class="package-brief"><div class="brief-row"><span>Responsible for</span><strong>${esc(p.responsibility)}</strong></div><div class="brief-row"><span>Package purpose</span><strong>${esc(p.primary_purpose)}</strong></div><div class="brief-row"><span>Why it is not safe</span><strong>${esc(p.why_not_safe)}</strong></div><div class="brief-row"><span>Operational owner</span><strong>${esc(p.operational_owner)}</strong></div><div class="brief-row"><span>Impact</span><strong>${esc(p.impact)}</strong></div></div><p class="muted">${esc(p.recommended_action)}</p><div class="remediation-list">${steps || '<div class="remediation-item"><strong>No remediation required</strong><span class="muted">This package currently passes validation.</span></div>'}</div>`;
      document.querySelector('.scan-console').scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    $('refresh').addEventListener('click', async () => { $('refresh').disabled = true; $('refresh').innerHTML = 'Refreshing <span class="button-orb" aria-hidden="true">...</span>'; await fetch('/api/refresh', { method: 'POST' }); $('refresh').disabled = false; $('refresh').innerHTML = 'Refresh index <span class="button-orb" aria-hidden="true">+</span>'; load(); });
    $('scan').addEventListener('click', runScan);
    $('show-review').addEventListener('click', () => { $('status').value = 'review'; load(); document.querySelector('#packages-table').scrollIntoView({ behavior: 'smooth', block: 'start' }); });
    $('q').addEventListener('input', () => clearTimeout(window.__t) || (window.__t = setTimeout(load, 250)));
    $('status').addEventListener('change', load);
    $('family').addEventListener('change', load);
    $('version').addEventListener('change', load);
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
