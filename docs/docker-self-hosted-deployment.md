# ThreatTrace — Self-Hosted Docker Deployment

This document describes the **default, reproducible way to run ThreatTrace**: a single `docker compose up -d --build`, with no host installation of Python, Nmap, Npcap, Nuclei, or ZAP. It supersedes host-native setup as the primary path — host-native development instructions still exist (see [docs/demo-runbook.md](demo-runbook.md)) for contributors who want to run the backend directly under a local Python interpreter, but a first-time user should start here.

This is a **deployment refinement, not a security-boundary change**: every safety guarantee described in [docs/architecture.md](architecture.md) and [SECURITY.md](../SECURITY.md) — the localhost-only target check, the Planner → Tool Permission Policy → Security Governor → closed-adapter execution boundary, the 1&nbsp;MiB output ceiling, the passive/safe-active scan profiles — applies identically whether ThreatTrace is running host-native or inside this Compose stack.

## 1. One-command startup

Prerequisites on the host: **Docker** (with Compose v2, i.e. `docker compose`, not the standalone `docker-compose`) and **Git**. Nothing else.

```bash
git clone https://github.com/RoshiniMlakshmana/ThreatTrace.git
cd ThreatTrace
docker compose up -d --build
```

Then open **http://127.0.0.1:8420**. The dashboard should immediately show accurate System Readiness — Backend/Governor/HTTP Assessor/httpx/Katana/Nmap/Nuclei/ZAP/Threat Intelligence/Detection Engineering all `READY`, Burp DAST clearly under Optional Integrations — even before you start a run.

Shutdown:

```bash
docker compose down
```

Readiness/health check without opening a browser:

```bash
docker compose ps
curl http://127.0.0.1:8420/api/system
```

## 2. Architecture

```
                    host machine (only Docker + Git required)
                    ┌─────────────────────────────────────────────────────┐
                    │         docker-compose.yml  (threattrace-net)        │
                    │                                                       │
  127.0.0.1:8420 ───┼──▶ threattrace  (backend + dashboard + Nmap + Nuclei) │
                    │        │                                              │
                    │        │ http://zap:8080          http://juice-shop:3000
  127.0.0.1:8080 ───┼──▶ zap ◀─────────────────────────▶ juice-shop ◀── 127.0.0.1:3000
                    │  (OWASP ZAP daemon)          (OWASP Juice Shop demo target)
                    └─────────────────────────────────────────────────────┘
```

- **`threattrace`** — the application image: Python runtime, ThreatTrace source (`core/`, `adapters/`, `backend/`, `runtime/`, `dashboard/`), plus Nmap, Nuclei, httpx, and Katana installed *inside the image*. Serves the backend API and the dashboard on `8420`.
- **`zap`** — the official `zaproxy/zap-stable` image, running as its own daemon on the internal network. The backend reaches it at `http://zap:8080` (the Compose service name), never `127.0.0.1:8080` — inside a container, `127.0.0.1` means that container, not a sibling service.
- **`juice-shop`** — the official `bkimminich/juice-shop` image, the default authorized demo scan target, reachable internally at `http://juice-shop:3000`.

All three services sit on one isolated bridge network, `threattrace-net`, created solely for this stack.

## 3. Services, ports, health checks

| Service | Image / build | Internal address | Host-published port | Health check |
|---|---|---|---|---|
| `threattrace` | built from local `Dockerfile` | `threattrace:8420` | `127.0.0.1:8420` | `GET /api/health` |
| `zap` | `zaproxy/zap-stable:latest` | `zap:8080` | `127.0.0.1:8080` | ZAP `core/view/version` API |
| `juice-shop` | `bkimminich/juice-shop:latest` | `juice-shop:3000` | `127.0.0.1:3000` | `GET /` |

Every published port is bound to `127.0.0.1` only — nothing in this stack is reachable from another machine on the network by default. `docker compose ps` reports each service's health state; the backend does not start a demo scan until its declared dependencies are healthy (`depends_on` + Compose health checks, not a fixed `sleep`), and ZAP is allowed to take longer to initialize than Juice Shop without failing startup.

## 4. Demo target mapping (display target vs. execution target)

The dashboard's default Bug Bounty target field shows **`http://localhost:3000/`** — this is what a user submits, and it is exactly what `backend.models.validate_local_only_target` has always accepted (this check is unchanged and unweakened).

Internally, when `THREATTRACE_DEMO_TARGET` is configured (it is, by default, in `docker-compose.yml`), a separate, additive function — `backend.models.resolve_execution_target` — maps that *exact* accepted alias to the real Docker-internal target, `http://juice-shop:3000`, before any tool is invoked. This mapping is:

- **one fixed alias only** (`http://localhost:3000/` → the configured `THREATTRACE_DEMO_TARGET`), never a general hostname-rewriting rule;
- **deterministic and deployment-config-driven**, not inferred from any request the caller controls;
- **never able to widen what `validate_local_only_target` accepts** — a caller submitting `http://juice-shop:3000` directly is still rejected as an invalid *display* target, exactly as any other non-localhost hostname is.

This is why the dashboard can honestly show `http://localhost:3000/` to a human while the backend actually scans the containerized Juice Shop — the alias is a fixed, reviewed deployment decision, not something a request can steer.

## 5. Required vs. optional tools

`/api/system` is the single authoritative source for platform readiness (backed by `runtime.tool_runtime.evaluate_tool_readiness`), organized into six categories:

| Category | Items | Required? |
|---|---|---|
| Core Services | ThreatTrace Backend, Security Governor | required |
| Discovery | HTTP Assessor, httpx, Katana | required |
| Scanners | Nmap, Nuclei, ZAP | required |
| Intelligence | Threat Intelligence | required |
| Detection | Detection Engineering | required |
| Optional Integrations | Burp DAST, Authenticated Testing, Controlled Validation | **optional** |

Nmap, Nuclei, httpx, and Katana are all baked into the `threattrace` image (pinned release binaries for the latter three, same reproducible-build discipline), so all four report `ready` as soon as the image builds successfully — no host install, no `PATH` edits, no admin rights. Nuclei's template set is baked in at build time at a pinned version (`nuclei -update-templates` is run once during image build, never at runtime, and never triggered by LLM output) — deterministic and fully offline-capable after the image exists.

Burp DAST, Authenticated Testing, and Controlled Validation are **not implemented** in this checkpoint. The dashboard shows them under "Optional Integrations" and never renders them as a failed core service — an unconfigured optional integration does not make the platform look unhealthy. Authenticated Testing and Controlled Validation are shown as `not_implemented` (a declared, future capability), not `not_installed` (an unexpectedly missing required one).

## 6. Deployment modes: demo vs. self-hosted

- **Demo mode** (`THREATTRACE_MODE=demo`, the default) — the only pre-approved scan target is the bundled Juice Shop container via the fixed alias in [§4](#4-demo-target-mapping-display-target-vs-execution-target). This is meant for local evaluation, screenshots, and reproducible testing — not for scanning anything you don't already run yourself as part of this stack.
- **Self-hosted / organization mode** — an organization deploying this stack against its own infrastructure must explicitly configure its own approved scope; ThreatTrace does not enable arbitrary remote scanning by default, and nothing in this deployment refinement changes that. Wiring a real organizational scope-configuration mechanism is out of scope for this checkpoint — treat `THREATTRACE_DEMO_TARGET` as a worked example of the *pattern* (fixed, deployment-time-configured, explicit), not as a general-purpose target override a caller can repoint.

## 7. Server / production deployment guidance

The default bind (`127.0.0.1:8420`, hardcoded in `backend/app.py`) is intentionally loopback-only and unchanged by this refinement. If an organization wants to expose ThreatTrace beyond a single operator's machine, this checkpoint does **not** implement that — production exposure requires, at minimum:

- a reverse proxy (e.g. Nginx/Caddy/Traefik) terminating TLS in front of the backend,
- real authentication and SSO, not the current no-auth local-development posture,
- role-based access control (RBAC) over run creation, cancellation, and report access,
- persistent, tamper-evident audit storage for runs/events (today's Run Store is in-memory and lost on backend restart),
- network isolation appropriate to the organization's own environment (this stack's `threattrace-net` isolates the demo services from each other and the host, not from a shared production network).

None of the above is faked or partially stubbed in this checkpoint — it is explicitly out of scope, and the dashboard's own "Limitations & Safety" panel says so.

## 8. Logs and shutdown

```bash
docker compose logs -f threattrace   # backend logs
docker compose logs -f zap           # ZAP daemon logs
docker compose logs -f juice-shop    # demo target logs
docker compose down                  # stop and remove containers (data is in-memory only; nothing persists)
```

## 9. Upgrade considerations

- `docker compose up -d --build` rebuilds the `threattrace` image from the current source tree — always rebuild after pulling new ThreatTrace source changes.
- The pinned Nuclei binary version and baked-in template snapshot are controlled by the `NUCLEI_VERSION` build arg and the template-bake step in `Dockerfile`; bumping either is a deliberate, reviewed image change, never an automatic runtime update.
- `zap` and `juice-shop` use upstream `:latest` tags for demo convenience; pin them to specific tags before relying on this stack for anything beyond local evaluation, so a stack rebuild is fully reproducible.

## 10. Security limitations of this deployment

- No Docker socket is mounted into the `threattrace` container — the backend cannot inspect or control sibling containers, and ZAP readiness is instead verified by a direct HTTP probe against its API.
- The container runs as a dedicated non-root user (`threattrace`), never root.
- No `NET_ADMIN`/`NET_RAW` capability is granted — the committed Nmap scan profile is a bounded TCP connect scan (`-Pn -sT -T3`), which needs no raw sockets.
- No host filesystem is mounted beyond what the image itself contains at build time.
- No host networking mode is used; every service sits on its own bridge network, and every published port is bound to `127.0.0.1`.
- This deployment still has **no production authentication** — see [§7](#7-server--production-deployment-guidance). Treat any Compose-exposed port as reachable by anything else running as the same OS user on the host.
