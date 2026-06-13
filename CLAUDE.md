# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Communication style

**This rule is mandatory and applies from the very first message of every session, including new sessions, compacted sessions, and resumed sessions.**

At the start of every session, invoke `/caveman wenyan` automatically — do not wait for the user to ask.

**Internal reasoning**: always use caveman wenyan — 思考用文言，精簡不失技術。

**Intermediate updates** (tool-call narration, progress notes, mid-task status): always use caveman ultra — maximum compression, no articles, abbreviate prose words, arrows for causality.

**Final response / summary**: always write in normal mode — full sentences, standard English, no caveman compression. The closing summary visible to the user must be clear and professional regardless of active caveman level.

**Enforcement**: if the session hook activates a different caveman level, this project CLAUDE.md takes precedence.

---

## Project: email-server-monitoring

**Author**: maxysoft | **Package/Module**: `github.com/maxysoft/email-server-monitoring`
**Stack**: Go 1.25, standard library only (zero external dependencies)
**Targets**: `linux/amd64` by default (overridable via `TARGETOS`/`TARGETARCH` build args); final image is `scratch`, runs as non-root UID 1000.

A lightweight daemon that periodically probes a mail server's network services and, on
failure, restarts a Docker container (default `stalwart`) via the Docker Engine HTTP API,
sending status notifications to Gotify.

### Architecture

- **Pattern**: Single-binary, single-file (`main.go`) daemon. `main()` runs an immediate
  check, then a `time.Ticker` loop on `CheckInterval` (default 120s). Each tick calls
  `executeCheckCycle` → `runAllChecks` (per-service, per-attempt retry with timeout) →
  on failure: notify → `restartContainer` → post-restart re-check/poll → notify result.
- **DI**: none (plain functions, a single `*Config` struct threaded through).
- **UI**: none (headless daemon; logs to stdout for Docker capture).
- **Network**: probes a configurable host (default `127.0.0.1`) for a configurable service
  list (default `SMTP:25, SMTPS:465, IMAPS:993, HTTPS:443`). Restart issued over the Docker
  unix socket (`/var/run/docker.sock`). Notifications POSTed to Gotify `/message`.
- **DB/Storage**: none. Config is read once from env (preferred) or flags at startup.

### Package / Directory Structure

| Path | Responsibility |
| ---- | -------------- |
| `main.go` | Entire application: config loading, probe loop, per-protocol checks, Docker restart, Gotify notify |
| `Dockerfile` | Multi-stage build (golang:1.25-alpine builder → scratch) |
| `docker-compose.yml` | Example deployment; mounts docker socket, loads config via `env_file: .env` |
| `.env.example` | Documented environment variables |

### Service probe semantics

- `SMTP` → TCP connect + read banner, expect `220` prefix.
- `SMTPS` / `IMAPS` → TLS handshake (`InsecureSkipVerify` — local infra may be self-signed).
- `HTTP` / `HTTPS` → `HEAD` request (plaintext / over TLS), expect a status in `HTTPAcceptStatus`
  (default `200`). Both schemes share the same accepted-status set via `checkHTTPStatus`.
- anything else → plain TCP connect.
- Each service: up to `Retries` attempts, `PerAttemptTimeout` per attempt, `SleepBetweenAttempts` between.

### Configuration (env overrides flags)

`HOST`, `SERVICES` (comma-separated `NAME:PORT`), `RETRIES`, `SLEEP_BETWEEN_ATTEMPTS`,
`PER_ATTEMPT_TIMEOUT`, `POST_RESTART_WAIT`, `POST_RESTART_PER_ATTEMPT_TIMEOUT`,
`POST_RESTART_FINAL_TIMEOUT`, `POST_RESTART_POLL_INTERVAL`, `CHECK_INTERVAL_SECONDS`,
`HTTP_EXPECTED_STATUS` (comma-separated accepted codes for HTTP+HTTPS, default `200`), `CONTAINER_NAME`,
`DOCKER_SOCKET`, `GOTIFY_URL` (required), `GOTIFY_TOKEN` (required), `GOTIFY_PRIORITY`. The
container needs the Docker socket mounted to perform restarts. `.env.example` documents all of
these.

### Knowledge Base

**Always query QMD before starting any task** — collection `email-server-monitoring` indexes
this repo's markdown (README, CLAUDE.md, AGENTS.md). The companion mail server it monitors is
in collection `stalwart-mail`.

Update this file (and re-run `qmd update`) after any change to architecture, probe behavior,
build procedure, or a newly verified gotcha.

### Build & Test (Docker only)

- **Never install packages on the host.** No host `go build`/`go install`, no other package
  managers. All builds run in Docker.
- **If Docker cannot be used**: print the exact reason, then ask for explicit permission
  before any local toolchain use. Never fall back silently.
- Image build: `docker build -t email-server-monitoring:<ver> --build-arg VERSION=<ver> .`
- Quick compile/vet without an image:
  `docker run --rm -v "$PWD":/src -w /src golang:1.25-alpine sh -c 'go mod tidy && go vet ./... && go build ./...'`
- There is no test suite yet; verification = clean `go vet` + successful image build.
- Versioning: pass the release tag via `--build-arg VERSION=vX.Y.Z`; it is stamped into the
  OCI `org.opencontainers.image.version` label. No source-embedded version constant.

### CI / Release (GitHub Actions)

- **CI** (`.github/workflows/ci.yml`, on push to master/release + PRs): `gofmt`, `go vet`,
  `go build`, `staticcheck`, `govulncheck`, `hadolint` (failure-threshold `error` — alpine
  pin warnings stay informational), `gitleaks` (full-history secret scan). **CodeQL**
  (`codeql.yml`) for Go — free on public repos only.
- **Release** (`.github/workflows/release.yml`): builds a **multi-arch** image
  (`linux/amd64,linux/arm64`), pushes to `ghcr.io/<owner>/email-server-monitoring-docker`,
  and **cosign keyless-signs** it (needs `id-token: write`). Runs **only** on push to the
  `release` branch (plus manual `workflow_dispatch`).
- **Version resolution** (precedence): `workflow_dispatch` `version` input → repo Actions
  variable `VERSION` (`vars.VERSION`) → `./VERSION` file → `v0.0.0-<shortsha>`. Tags pushed:
  `:<version>` and `:latest`. Bump `VERSION` (committed) to drive a release.
- **Skip build**: set `skip_build=true` on a manual run, or include `[skip build]` / `[skip ci]`
  in the commit message — the job's `if:` guard then skips.
- **Dockerfile multi-arch**: builder runs on `$BUILDPLATFORM` and Go cross-compiles to
  `$TARGETOS/$TARGETARCH` (no QEMU). Keep that — pinning the builder to the target platform
  would force slow emulation under buildx.

### Known Gotchas

<!-- Append verified gotchas as they're discovered. One bullet each:
     symptom → root cause → rule. -->

- **Socket exhaustion against the monitored server** → `checkHTTPS` created a fresh
  `http.Transport` per probe and discarded it; Go pools keep-alive connections indefinitely
  (no `IdleConnTimeout`), and the transport's `readLoop` goroutine kept each idle conn alive,
  so every probe leaked one ESTABLISHED socket to the target (observed: hundreds of
  `127.0.0.1 ↔ :4443` sockets, eventually starving Stalwart's connection limiter).
  **Rule**: one-shot HTTP probes must set `DisableKeepAlives: true` **and**
  `defer transport.CloseIdleConnections()` (or reuse one shared client). Never abandon a
  live `http.Transport`.
- **TLS-handshake probe timeout leaked a socket** → `checkTLSHandshake` returned on
  `ctx.Done()` while its dial goroutine could still produce a connection that was never
  closed. **Rule**: when abandoning an async dial, drain the result channel and `Close()` any
  connection that arrives late.
- Probes use `InsecureSkipVerify: true` by design (local self-signed certs) — do not "fix"
  this into full verification without confirming the deployment's cert setup.
- **HTTP/HTTPS probes expect a specific status (default `200`)** → a healthy server is expected
  to answer `200`; any other status (or a connection error) counts as "down". Both schemes share
  one accepted-status set. If the deployment fronts the service with a redirect or auth gate,
  widen it via `HTTP_EXPECTED_STATUS` (comma-separated, e.g. `200,301,401`) — do **not** hardcode
  a broader set in code. Empty/all-invalid env falls back to `{200}`.
- **Validate config durations** → a zero/negative env override (e.g. `CHECK_INTERVAL_SECONDS=0`)
  panics `time.NewTicker` at startup, and `POST_RESTART_POLL_INTERVAL=0` busy-spins the poll
  loop. `loadConfigFromEnvOrFlags` clamps non-positive interval/timeout values back to defaults;
  keep that guard if you add new duration settings.
- **Graceful shutdown is context-driven** → `main` uses `signal.NotifyContext` and threads the
  ctx through `executeCheckCycle` → `runAllChecks` → all sleeps (`sleepCtx`). A SIGTERM aborts
  in-flight probes immediately. **Invariant**: aborted probes look like failures, so
  `executeCheckCycle` must check `ctx.Err()` before notifying/restarting — never restart on a
  cancelled cycle. (Probe dials are ctx-native, incl. `checkTLSHandshake` via `tls.Dialer.DialContext` — no lingering dial goroutines.)
