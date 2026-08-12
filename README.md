# pkgmng

`pkgmng` is a Linux repository manager for APT and RHEL-family RPM sources. It indexes configured repositories, refreshes package metadata on a schedule, runs lightweight security checks on package records, and exposes a web UI plus JSON APIs.

## Runtime

- App: FastAPI
- Port: `8080`
- Data: SQLite at `DB_PATH`, default `/data/pkgmng.db` in the container
- Default repositories:
  - Debian bookworm main
  - Debian bookworm-security main
  - AlmaLinux 9 BaseOS
  - Rocky Linux 9 BaseOS
  - Oracle Linux 9 BaseOS
  - Red Hat UBI 9 BaseOS

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

Default RHEL-family sources:

```text
alma-9-baseos|https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/|AlmaLinux 9|BaseOS,rocky-9-baseos|https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/|Rocky Linux 9|BaseOS,oracle-9-baseos|https://yum.oracle.com/repo/OracleLinux/OL9/baseos/latest/x86_64/|Oracle Linux 9|BaseOS,redhat-ubi9-baseos|https://cdn-ubi.redhat.com/content/public/ubi/dist/ubi9/9/x86_64/baseos/os/|Red Hat UBI 9|BaseOS
```

The UI exposes a distribution-family summary and can filter packages by Debian, AlmaLinux, Rocky Linux, Oracle Linux, or Red Hat.

## Development

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
pytest
python -m app.main
```
