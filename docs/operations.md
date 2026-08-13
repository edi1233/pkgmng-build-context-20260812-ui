# pkgmng Operations Guide

This guide explains how `pkgmng` is run on Kubernetes, how repository sources are managed, how Linux hosts would consume package repositories, and how to expose the app through Gateway API, NodePort, or LoadBalancer.

## Current Deployment

The production deployment on `pxinf` uses a private in-cluster service with Gateway API for public routing.

| Component | Value |
|---|---|
| Cluster | `pxinf` |
| Namespace | `pkgmng` |
| App port | `8080` |
| Service | `pkgmng.pkgmng.svc:8080` |
| Service type | `ClusterIP` |
| Public hostname | `pkgmng.edi-it.com` |
| Gateway | `envoy-gateway-system/public-gateway` |
| HTTPS route | `k8s-route-https.yaml` |
| HTTP redirect route | `k8s-route-http.yaml` |
| Data volume | PVC `pkgmng-data`, Longhorn, `5Gi` |

The app is reachable inside the cluster at:

```text
http://pkgmng.pkgmng.svc:8080
```

The intended public endpoint is:

```text
https://pkgmng.edi-it.com
```

DNS must point `pkgmng.edi-it.com` to the public gateway address:

```text
A pkgmng.edi-it.com -> 192.168.2.202
```

Until DNS exists, the route can still be tested by forcing the hostname to the gateway IP:

```bash
curl --resolve pkgmng.edi-it.com:443:192.168.2.202 https://pkgmng.edi-it.com/healthz
```

## Repository Source Management

Repository sources are first-class records in `pkgmng`. Operators can add, edit, and inspect them from the web UI under **Repository sources**.

The API supports the same workflow:

| Action | Endpoint |
|---|---|
| List sources | `GET /api/repos` |
| Add source | `POST /api/repos` |
| Edit source | `PUT /api/repos/{name}` |
| List packages in one source | `GET /api/repos/{name}/packages` |
| Filter global inventory by source | `GET /api/packages?repo={name}` |

Sources added through the UI/API are stored in SQLite on the `pkgmng-data` PVC and survive pod restarts.

### Add an APT Source

```bash
curl -X POST http://pkgmng.pkgmng.svc:8080/api/repos \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "debian-12-main",
    "repo_type": "apt",
    "base_url": "https://deb.debian.org/debian",
    "suite": "bookworm",
    "component": "main"
  }'
```

APT source fields:

| Field | Meaning |
|---|---|
| `name` | Unique source key shown in the UI and API |
| `repo_type` | Must be `apt` |
| `base_url` | Repository root URL |
| `suite` | Debian/Ubuntu suite, for example `bookworm` |
| `component` | Component, for example `main`, `contrib`, or `non-free` |

### Add an RPM Source

```bash
curl -X POST http://pkgmng.pkgmng.svc:8080/api/repos \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "rocky-9-baseos",
    "repo_type": "rpm",
    "base_url": "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/",
    "suite": "Rocky Linux 9",
    "component": "BaseOS"
  }'
```

RPM source fields:

| Field | Meaning |
|---|---|
| `name` | Unique source key shown in the UI and API |
| `repo_type` | Must be `rpm` |
| `base_url` | Directory containing `repodata/repomd.xml` |
| `suite` | Distribution label, for example `AlmaLinux 9` |
| `component` | Repository label, for example `BaseOS` or `AppStream` |

### Edit an Existing Source

```bash
curl -X PUT http://pkgmng.pkgmng.svc:8080/api/repos/rocky-9-baseos \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "rocky-9-baseos",
    "repo_type": "rpm",
    "base_url": "https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/",
    "suite": "Rocky Linux 9",
    "component": "BaseOS"
  }'
```

### Authentication For Source Changes

If `ADMIN_TOKEN` is configured on the Deployment, state-changing calls must include one of these headers:

```bash
Authorization: Bearer <token>
```

or:

```bash
X-Pkgmng-Token: <token>
```

`POST /api/refresh` and `POST /api/scans` use the same protection and are also rate-limited by `ACTION_RATE_LIMIT_SECONDS`.

## Viewing All Packages In A Repository

Use the source inventory route to see only packages from one repository:

```bash
curl 'http://pkgmng.pkgmng.svc:8080/api/repos/debian-12-main/packages?limit=50&offset=0'
```

The same filter is available through the global package API:

```bash
curl 'http://pkgmng.pkgmng.svc:8080/api/packages?repo=debian-12-main&limit=50&offset=0'
```

The response includes pagination metadata:

| Field | Meaning |
|---|---|
| `page.total` | Total matching packages |
| `page.returned` | Rows returned in this response |
| `page.offset` | Current offset |
| `page.has_more` | Whether another page exists |

The UI exposes this through the Package intelligence table filters and each repository source action.

## Refresh And Scan Flow

After adding or editing sources, refresh the index:

```bash
curl -X POST http://pkgmng.pkgmng.svc:8080/api/refresh
```

Run a security scan:

```bash
curl -X POST http://pkgmng.pkgmng.svc:8080/api/scans
```

Check scan history:

```bash
curl http://pkgmng.pkgmng.svc:8080/api/scans
```

Only one scan can run at a time. If a scan is active, another scan request returns HTTP `409` with the active scan id.

## Package Security Statuses

Every package record has two related fields:

| Field | Values | Meaning |
|---|---|---|
| `security_status` | `passed`, `review`, `failed` | The operator workflow state for the package |
| `security_severity` | `none`, `medium`, `high`, `critical` | The urgency of the highest active finding |

Status is the main queue operators should work from. Severity explains how urgent the item is inside that queue.

| Status | What It Means | How To Proceed |
|---|---|---|
| `passed` | The package metadata passed the current validation checks. It has a valid known checksum format, expected artifact metadata, and no active scanner finding that needs review. | No action is required. Keep the package in the trusted catalog and let the next scheduled scan revalidate it. |
| `review` | The scanner found a signal that needs a human decision, but it is not strong enough to block the package automatically. Examples include high-impact package areas, privileged behavior wording, advisory keywords, or incomplete but not invalid metadata. | Open package detail, read `why_not_safe`, evidence, architecture, source repo, and remediation. Approve/accept only after confirming the finding is expected for that package and repo. Escalate high-impact packages to the relevant OS/security owner. |
| `failed` | The package has a blocking metadata or safety issue. Examples include malformed checksum data, missing required artifact metadata, unexpected package type, or other concrete validation failure. | Do not promote or mirror the package into trusted client repos. Validate the upstream repo metadata, compare against vendor metadata, refresh the source, and quarantine/block the package until the finding is fixed or explicitly waived by policy. |

### Severity Levels

| Severity | Meaning | Operator Response |
|---|---|---|
| `none` | No active security finding. Normally paired with `passed`. | No immediate action. |
| `medium` | Needs review, but there is no direct blocking evidence. Often used for sensitive package areas or incomplete context. | Review during normal package intake. Confirm source, purpose, and expected behavior. |
| `high` | Higher-impact package or stronger evidence. The package may affect authentication, privilege, kernel, cryptography, firewall, remote access, or similar sensitive areas. | Prioritize review before promotion. Check vendor source, architecture, checksum algorithm, and remediation guidance. |
| `critical` | Blocking issue or very strong anomaly. The package should not be trusted until resolved. | Treat as an incident for the package source. Block/quarantine, inspect upstream metadata, and document the remediation or waiver. |

### Important Interpretation Rules

| Signal | Interpretation |
|---|---|
| Official security channel | Positive or neutral source context. A package is not risky just because it came from a Debian/RHEL security update channel. |
| SHA-1 checksum | Valid for legacy repos when that is the algorithm published by repo metadata. It is displayed as `checksum_algorithm=sha1`; it is not automatically a critical failure. |
| Same package/version repeated | Check `architecture` and package format first. Source, noarch, and binary architecture variants can share the same name/version/repo. |
| Upstream maintainer | Person or project listed by package metadata. This is not the internal remediation owner. |
| Mirror sync errors | Repository fetch/index health. This is separate from package security status. A repo can have zero mirror sync errors while still containing packages in review. |

### Recommended Review Workflow

1. Filter the Package intelligence table by `security_status=review` or `security_status=failed`.
2. Sort by severity or risk score.
3. Open the package detail panel.
4. Read `Why unsafe`, `Purpose`, source repository, OS family/version, architecture, checksum algorithm, and remediation steps.
5. For `review`, decide whether the package behavior is expected for that OS source.
6. For `failed`, block promotion or mirroring until the source metadata is corrected or a documented waiver exists.
7. Run a new scan after source edits, repo refreshes, or remediation changes.

## OS-Level Client Configuration

`pkgmng` currently indexes, scans, and explains upstream package repositories. That means the platform can show repository contents and security posture, but it does not yet act as a full package mirror/proxy for Linux clients.

To make OS hosts install from `pkgmng` itself, the platform needs repo-serving endpoints that expose APT and RPM metadata and package files, for example:

| Format | Required serving path |
|---|---|
| APT | `dists/`, `pool/`, `Release`, `InRelease`, `Packages.gz` |
| RPM | `repodata/repomd.xml`, `primary.xml.gz`, package artifacts |

Once those mirror/proxy endpoints exist, client machines can point at `pkgmng.edi-it.com`.

### Future APT Client Example

```bash
sudo tee /etc/apt/sources.list.d/pkgmng.list >/dev/null <<'EOF'
deb https://pkgmng.edi-it.com/apt/debian/12 bookworm main
EOF

sudo apt update
```

If repository signing is enabled, also install the trusted signing key:

```bash
curl -fsSL https://pkgmng.edi-it.com/keys/pkgmng-archive.gpg \
  | sudo gpg --dearmor -o /usr/share/keyrings/pkgmng-archive.gpg
```

Then use a signed source entry:

```text
deb [signed-by=/usr/share/keyrings/pkgmng-archive.gpg] https://pkgmng.edi-it.com/apt/debian/12 bookworm main
```

### Future RHEL/Alma/Rocky/Oracle Client Example

```ini
[pkgmng-rocky-9-baseos]
name=pkgmng Rocky Linux 9 BaseOS
baseurl=https://pkgmng.edi-it.com/rpm/rocky/9/BaseOS/x86_64/os/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://pkgmng.edi-it.com/keys/RPM-GPG-KEY-pkgmng
```

Save the file as:

```text
/etc/yum.repos.d/pkgmng-rocky-9-baseos.repo
```

Then refresh metadata:

```bash
sudo dnf clean all
sudo dnf makecache
```

For Oracle Linux 7, use `yum` instead of `dnf`:

```bash
sudo yum clean all
sudo yum makecache
```

## Kubernetes Exposure Options

### Option 1: Gateway API, Recommended

Use this for production on `pxinf`. It keeps the app Service private and exposes only the hostname through the shared gateway.

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: pkgmng
  namespace: pkgmng
spec:
  hostnames:
    - pkgmng.edi-it.com
  parentRefs:
    - name: public-gateway
      namespace: envoy-gateway-system
      sectionName: https
  rules:
    - backendRefs:
        - name: pkgmng
          port: 8080
      matches:
        - path:
            type: PathPrefix
            value: /
```

Keep the Service as `ClusterIP`:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pkgmng
  namespace: pkgmng
spec:
  type: ClusterIP
  selector:
    app.kubernetes.io/name: pkgmng
  ports:
    - name: http
      port: 8080
      targetPort: http
```

Use Gateway API when:

- The app needs a real DNS hostname.
- TLS termination should be handled centrally.
- You want one stable public URL.
- You want to avoid exposing raw node ports.

### Option 2: NodePort

Use NodePort only for temporary troubleshooting or lab access. It exposes the app on every Kubernetes node at a fixed high port.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pkgmng
  namespace: pkgmng
spec:
  type: NodePort
  selector:
    app.kubernetes.io/name: pkgmng
  ports:
    - name: http
      port: 8080
      targetPort: http
      nodePort: 30080
```

Access pattern:

```text
http://<node-ip>:30080
```

NodePort tradeoffs:

| Benefit | Cost |
|---|---|
| Simple to test | No friendly hostname by default |
| Does not require a gateway | Usually no TLS termination |
| Useful during gateway debugging | Exposes a raw port on nodes |

### Option 3: LoadBalancer

Use LoadBalancer only if `pxinf` has a load balancer controller such as MetalLB or a cloud/provider integration.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: pkgmng
  namespace: pkgmng
spec:
  type: LoadBalancer
  selector:
    app.kubernetes.io/name: pkgmng
  ports:
    - name: http
      port: 80
      targetPort: http
```

After applying, inspect the assigned external IP and point DNS at that IP:

```text
A pkgmng.edi-it.com -> <load-balancer-ip>
```

LoadBalancer tradeoffs:

| Benefit | Cost |
|---|---|
| Direct external IP per app | Requires LB controller support |
| Simple DNS mapping | TLS still needs ingress/gateway/app handling |
| Good for dedicated services | Uses more scarce external IPs |

## Recommendation For pxinf

Keep the current production shape:

```text
ClusterIP Service -> Gateway API HTTPRoute -> pkgmng.edi-it.com
```

Then add the missing DNS record:

```text
A pkgmng.edi-it.com -> 192.168.2.202
```

Use NodePort only for short-lived troubleshooting. Use LoadBalancer only if a dedicated external IP is required and `pxinf` has a working LB controller.

## Operational Checks

Health:

```bash
curl http://pkgmng.pkgmng.svc:8080/healthz
```

Public route through gateway:

```bash
curl --resolve pkgmng.edi-it.com:443:192.168.2.202 https://pkgmng.edi-it.com/healthz
```

Repository list:

```bash
curl http://pkgmng.pkgmng.svc:8080/api/repos
```

Security summary:

```bash
curl http://pkgmng.pkgmng.svc:8080/api/security
```

Sandbox package lane:

```bash
curl 'http://pkgmng.pkgmng.svc:8080/api/packages?sandbox_status=review&limit=50'
```

Start sandbox preflight on demand:

```bash
curl -X POST http://pkgmng.pkgmng.svc:8080/api/sandbox/scans
```

Start sandbox preflight for only four selected package records:

```bash
curl -X POST http://pkgmng.pkgmng.svc:8080/api/sandbox/scans \
  -H 'Content-Type: application/json' \
  -d '{"package_ids":[101,102,103,104]}'
```

Check sandbox queue, totals, and operation logs:

```bash
curl http://pkgmng.pkgmng.svc:8080/api/sandbox/scans
```

Package detail with sandbox evidence:

```bash
curl http://pkgmng.pkgmng.svc:8080/api/packages/<package-id>
```

Package-specific sandbox logs:

```bash
curl http://pkgmng.pkgmng.svc:8080/api/packages/<package-id>/sandbox/logs
```

Paginated package inventory:

```bash
curl 'http://pkgmng.pkgmng.svc:8080/api/packages?limit=50&offset=0'
```

Scan history:

```bash
curl http://pkgmng.pkgmng.svc:8080/api/scans
```

## Sandbox Statuses

Sandbox status answers a different question than security status. Security status says whether repository metadata has trustworthy identity and risk signals. Sandbox status says what kind of behavior validation is required before the package is promoted.

| Sandbox status | Meaning | Operator action |
|---|---|---|
| `passed` | Metadata preflight found no sandbox trigger. | Keep under normal monitoring. No dynamic execution is required by current checks. |
| `review` | Package affects a high-impact area or suggests install-time behavior. | Run it in an isolated disposable host lane and inspect install scripts, file writes, service changes, network access, capabilities, and privileged execution. |
| `failed` | Package failed blocking identity checks. | Do not execute it. Quarantine or fix checksum/type/size metadata first, then rescan. |
| `pending` | Existing row has not been rescanned since sandbox fields were added. | Run a scan or refresh to backfill sandbox evidence. |

Use the Package intelligence table filter `Sandbox = Needs sandbox` to review `sandbox_status=review` packages. Open a package row to see:

- `sandbox_verdict`
- `sandbox_findings`
- `sandbox_evidence`
- `sandbox_next_action`

In the UI, open **Sandbox** from the sticky navigation. Use **Start sandbox preflight** to queue a full on-demand preflight, **Refresh status** to reload the current queue state, and **Sandbox operation logs** to inspect run status, trigger, package count, package verdicts, evidence, and failure notes. If the button reports that another scan is already running, wait for that run to complete or for the stale-run watchdog to mark it failed.

For a small targeted run, select package rows in the Package intelligence table and click **Sandbox selected**. This is the right path when you only need to inspect a few packages, for example four RPM/DEB records from one repo. Targeted runs are limited to 20 package IDs per request so an operator cannot accidentally launch a full catalog backfill from the small-run control.

Each targeted run creates two levels of log records:

| Log level | Endpoint | Contents |
|---|---|---|
| Run history | `GET /api/sandbox/scans` | Targeted run id, trigger, status, target count, pass/review/fail totals, timestamps, and notes. |
| Package evidence | `GET /api/packages/{id}/sandbox/logs` | Per-package status, verdict, next action, findings, evidence, repo, architecture, package format, and run id. |

Do not run untrusted package payloads inside the `pkgmng` web pod. Dynamic sandboxing should use a disposable VM or tightly confined worker lane that can be destroyed after each package test.
