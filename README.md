# pkgmng

`pkgmng` is a Linux repository manager for APT and RHEL-family RPM sources. It indexes configured repositories, refreshes package metadata on a schedule, runs security validation on every indexed package record, and exposes scan results, package-level remediation guidance, a web UI, and JSON APIs.

## Runtime

- App: FastAPI
- Port: `8080`
- Data: SQLite at `DB_PATH`, default `/data/pkgmng.db` in the container
- Package cap: `MAX_PACKAGES_PER_REPO=0` scans all package metadata; set a positive value only as an emergency runtime cap
- Default repositories:
  - Debian 13, 12, and 11 main
  - Debian 13, 12, and 11 security
  - AlmaLinux 10, 9, and 8 BaseOS
  - Rocky Linux 10, 9, and 8 BaseOS
  - Oracle Linux 10, 9, 8, and 7 BaseOS/latest
  - Red Hat UBI 10, 9, and 8 BaseOS

## Configuration

`APT_REPOS` is a comma-separated list of:

```text
name|base_url|suite|component
```

Example:

```text
debian-bookworm|https://deb.debian.org/debian|bookworm|main,debian-security|https://security.debian.org/debian-security|bookworm-security|main
```

`RPM_REPOS` uses the same shape:

```text
name|base_url|distribution_label|repo_label
```

Default RHEL-family sources track the latest public versions with reachable repository metadata, capped at five versions per OS lane:

```text
alma-10-baseos|https://repo.almalinux.org/almalinux/10/BaseOS/x86_64/os/|AlmaLinux 10|BaseOS,alma-9-baseos|https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/|AlmaLinux 9|BaseOS,alma-8-baseos|https://repo.almalinux.org/almalinux/8/BaseOS/x86_64/os/|AlmaLinux 8|BaseOS,rocky-10-baseos|https://dl.rockylinux.org/pub/rocky/10/BaseOS/x86_64/os/|Rocky Linux 10|BaseOS,rocky-9-baseos|https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/|Rocky Linux 9|BaseOS,rocky-8-baseos|https://dl.rockylinux.org/pub/rocky/8/BaseOS/x86_64/os/|Rocky Linux 8|BaseOS,oracle-10-baseos|https://yum.oracle.com/repo/OracleLinux/OL10/baseos/latest/x86_64/|Oracle Linux 10|BaseOS,oracle-9-baseos|https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64/|Oracle Linux 9|BaseOS,oracle-8-baseos|https://yum.oracle.com/repo/OracleLinux/OL8/baseos/latest/x86_64/|Oracle Linux 8|BaseOS,oracle-7-latest|https://yum.oracle.com/repo/OracleLinux/OL7/latest/x86_64/|Oracle Linux 7|Latest,redhat-ubi10-baseos|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi10/10/x86_64/baseos/os/|Red Hat UBI 10|BaseOS,redhat-ubi9-baseos|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/|Red Hat UBI 9|BaseOS,redhat-ubi8-baseos|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi8/8/x86_64/baseos/os/|Red Hat UBI 8|BaseOS
```

The UI exposes a distribution-family summary, version lanes, and package filters by Debian, AlmaLinux, Rocky Linux, Oracle Linux, Red Hat, and OS version.

For Kubernetes operation, repository-source management, OS-level client setup, and exposure choices, see [docs/operations.md](docs/operations.md).

## LLM wiki

This project includes a persistent markdown LLM wiki under [llm-wiki](llm-wiki/index.md), based on the raw-sources/generated-wiki/schema pattern from Karpathy's LLM Wiki idea file.

Start with:

- [llm-wiki/index.md](llm-wiki/index.md) for the page catalog.
- [llm-wiki/SCHEMA.md](llm-wiki/SCHEMA.md) for maintenance rules.
- [llm-wiki/raw/sources.md](llm-wiki/raw/sources.md) for source evidence.

Repository sources are first-class platform records:

- `GET /api/repos` lists configured APT and RPM sources with mirror health and package counts.
- `POST /api/repos` adds a new source using `name`, `repo_type`, `base_url`, `suite`, and `component`.
- `PUT /api/repos/{name}` edits an existing source.
- `GET /api/repos/{name}/packages` lists only the DEB/RPM package records indexed from that source.
- `GET /api/packages?repo=<name>` applies the same source filter in the general package table API.

Sources added through the API are stored in SQLite and survive app restarts. Default environment-configured sources are upserted on startup, but custom operator-added sources are not deleted when they are absent from `APT_REPOS` or `RPM_REPOS`.

## Security validation

Every indexed DEB and RPM package receives a structured validation profile:

- `security_status`: `passed`, `review`, or `failed`
- `security_severity`: `none`, `medium`, `high`, or `critical`
- `security_risk_score`: normalized `0-100` metadata risk score
- `security_findings`: concise operator-facing findings
- `security_checks`: individual checks for checksum integrity, artifact type, declared size, repository transport, security update channel context, sensitive package areas, high-impact priorities, privileged behavior, and advisory keyword signals

Checksum validation detects the algorithm published by repository metadata where available and falls back to digest length (`40=SHA-1`, `64=SHA-256`, `128=SHA-512`). Legacy RPM repositories that publish SHA-1 metadata are treated as valid metadata instead of critical checksum failures; malformed or unknown digest formats still fail.

Sensitive package review is intentionally weighted toward high-impact areas such as kernel, authentication, privilege management, cryptography, firewall, and remote access. Generic `admin`, `system`, `utils`, or `net` package sections are not failed on section text alone.

Official security update channels are treated as positive source context, not as a risk finding. Packages only enter review when the scanner has concrete evidence such as a high-impact package name/section, priority, privileged behavior wording, advisory wording, or incomplete artifact metadata.

The `/api/security` endpoint returns global totals, OS/version breakdowns, and the highest-risk package records. The dashboard renders the same data in the "All package checks" panel and the package inventory table.

### Status and severity meaning

| Field | Meaning |
|---|---|
| `security_status=passed` | Package passed current metadata and safety checks. No operator action is required. |
| `security_status=review` | Package has a concrete signal that needs a human decision before promotion into trusted mirrors. |
| `security_status=failed` | Package has a blocking validation issue and should be quarantined or blocked until resolved. |
| `security_severity=none` | No active finding. |
| `security_severity=medium` | Review during normal intake. |
| `security_severity=high` | Prioritize review before promotion. |
| `security_severity=critical` | Treat as blocking until fixed or formally waived. |

Operators should start with `failed` packages, then `review` packages sorted by severity/risk score. Open package detail to inspect `why_not_safe`, package purpose, architecture, checksum algorithm, source repository, and remediation steps. Official security update channels are positive or neutral source context, not a risk finding by themselves.

For the full status glossary and operating procedure, see [Package Security Statuses](docs/operations.md#package-security-statuses).

## Sandbox validation

Every package also receives a sandbox preflight profile:

| Field | Meaning |
|---|---|
| `sandbox_status=passed` | UI label: **Preflight passed**. Metadata preflight found no behavior trigger. Keep the package under normal scheduled monitoring. |
| `sandbox_status=review` | UI label: **Needs dynamic test**. The package should be installed and removed in an isolated disposable host lane before production promotion. This is not a failure by itself. |
| `sandbox_status=failed` | UI label: **Blocked**. Do not execute the package yet. Fix blocking identity metadata such as checksum, type, or size first. |
| `sandbox_status=pending` | UI label: **Not checked**. The row has not yet received sandbox preflight evidence. |

Sandbox evidence explains the package format, artifact path, source repository, and reason the package did or did not need dynamic observation. `sandbox_next_action` tells the operator how to proceed. Current sandboxing is a platform decision lane and metadata preflight; dynamic binary execution should run in a disposable VM/container host lane, not inside the web app pod.

## Scan and remediation workflow

- `POST /api/scans` launches a repository refresh plus full package validation run with trigger `manual`.
- `POST /api/sandbox/scans` with no body queues the same validation pipeline with trigger `manual-sandbox`, making an on-demand sandbox preflight run explicit in history.
- `POST /api/sandbox/scans` with `{"package_ids":[1,2,3,4]}` runs targeted sandbox preflight for only those selected RPM/DEB package records. Targeted runs are limited to 20 packages per request.
- Scheduled refreshes record trigger `scheduled`; API refreshes record trigger `manual-refresh`.
- `GET /api/scans` returns recent scan runs with status, trigger, repository health, total packages, pass/review/fail counts, and highest severity. It also marks orphaned `running` scans older than `SCAN_STALE_MINUTES` as failed.
- `GET /api/sandbox/scans` returns the current run, derived operation logs, targeted sandbox run history, package-level sandbox logs, sandbox totals, and next-action guidance for the sandbox lane.
- `GET /api/packages/{id}` returns the package validation profile with remediation guidance.
- `GET /api/packages/{id}/sandbox/logs` returns every targeted sandbox run log for that package, including status, verdict, evidence, findings, and next action.
- The UI includes a scan operations panel, scan history, a remediation queue, package-row detail actions, row checkboxes, and a Sandbox run queue with **Start sandbox preflight**, **Sandbox selected**, **Refresh status**, operation logs, and Pending/Needs sandbox/Blocked shortcuts.
- `GET /api/packages` supports `limit` and `offset` pagination and returns `page.total`, `page.returned`, `page.offset`, and `page.has_more`.
- Package rows expose architecture and checksum algorithm so source/binary variants do not look like duplicates.
- Package detail distinguishes the internal owner lane from the upstream maintainer recorded in package metadata.

State-changing endpoints (`POST /api/refresh`, `POST /api/scans`) support `Authorization: Bearer <ADMIN_TOKEN>` or `X-Pkgmng-Token` when `ADMIN_TOKEN` is configured, and apply a per-client rate limit controlled by `ACTION_RATE_LIMIT_SECONDS`.

Only one scan can run at a time. A second scan request receives HTTP `409` with the active scan id until the current scan completes or the stale-run watchdog marks it failed.

Remediation is generated from the failing or review checks. Each remediation item includes:

- action
- priority
- owner
- evidence
- ordered steps

Failed packages are intended to be blocked or quarantined until metadata issues are resolved. Review packages are routed to manual security review before promotion into trusted mirrors.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest
python -m app.main
```
