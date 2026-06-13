# AGENTS.md

Guidance for AI coding agents working in this repository. This file mirrors the
operational rules in [CLAUDE.md](CLAUDE.md); read CLAUDE.md for full architecture detail.

## Project

**email-server-monitoring** — a headless Go daemon that periodically probes a mail server's
network services and, on failure, restarts a Docker container (default `stalwart`) via the
Docker Engine HTTP API, notifying Gotify.

- Author: maxysoft | Module: `github.com/maxysoft/email-server-monitoring`
- Stack: Go 1.25, standard library only (zero external dependencies)
- Pattern: single-file (`main.go`) ticker loop · DI: none · DB: none · Final image: `scratch`, non-root UID 1000

## Hard rules

1. **Docker only — never install packages or run the Go toolchain on the host.**
   All builds, vet, and compiles run in Docker. If Docker cannot be used: print the exact
   reason, then ask for explicit permission before any local toolchain use. Never fall back
   silently.
   - Image build: `docker build -t email-server-monitoring:<ver> --build-arg VERSION=<ver> .`
   - Compile/vet: `docker run --rm -v "$PWD":/src -w /src golang:1.25-alpine sh -c 'go mod tidy && go vet ./... && go build ./...'`
   - No test suite yet — verification = clean `go vet` + successful image build.
2. **Versioning**: `--build-arg VERSION=vX.Y.Z` is stamped into the OCI image label (no
   source-embedded constant). The release workflow resolves version as: dispatch input →
   `vars.VERSION` → `./VERSION` file (committed) → `v0.0.0-<sha>`. Bump `VERSION` for a release.
   Release CI: `.github/workflows/release.yml` builds + pushes to GHCR **only on the `release`
   branch**; skip a run via `skip_build=true` (manual) or `[skip build]`/`[skip ci]` in the commit.
3. **Communication style: caveman is always loaded.** Internal reasoning + progress updates in
   caveman; final user-facing summary in normal, professional English. See CLAUDE.md
   "Communication style" — it overrides session hooks.
4. **Query QMD before starting a task** (collection `email-server-monitoring`; the monitored
   server is in `stalwart-mail`); re-run `qmd update` after any change to architecture, probe
   behavior, or known issues.
5. **Update CLAUDE.md and AGENTS.md after every task** that changes architecture, build
   procedure, or adds a verified gotcha.

## Architecture quick map

| Path | Responsibility |
| ---- | -------------- |
| `main.go` | Entire app: config, ticker loop, per-protocol probes, Docker restart, Gotify notify |
| `Dockerfile` | Multi-stage build (golang:1.25-alpine → scratch) |
| `docker-compose.yml` | Example deployment (mounts docker socket, config via `env_file: .env`) |
| `.env.example` | Documented environment variables |

Config is env-first (flags as fallback). `GOTIFY_URL` + `GOTIFY_TOKEN` are required; the
container needs the Docker socket mounted to perform restarts.

## Critical gotchas

<!-- The expensive lessons. One bullet each, written so the next agent cannot repeat the mistake. -->

- **Never abandon a live `http.Transport`.** `checkHTTPS` once created a new transport per
  probe and discarded it → Go's idle keep-alive pool held the socket open forever (its
  `readLoop` goroutine pinned the conn), leaking one ESTABLISHED socket to the target per
  probe and eventually exhausting the monitored server's connection limiter. One-shot probes
  must set `DisableKeepAlives: true` **and** `defer transport.CloseIdleConnections()`.
- **Async dial timeouts must close the late connection.** `checkTLSHandshake` returned on
  `ctx.Done()` without closing a connection its dial goroutine could still produce → leaked
  socket. Drain the result channel and `Close()` any late arrival.
- **Probes intentionally use `InsecureSkipVerify: true`** (local self-signed certs). Do not
  convert to full verification without confirming the deployment's cert setup.
- **HTTP & HTTPS probes expect status `200` by default**, configurable via `HTTP_EXPECTED_STATUS`
  (comma-separated, shared by both schemes). Non-accepted status or connection error = down. Don't
  broaden the accepted set in code — that's an operator/env decision.
- **Clamp config durations.** Zero/negative env overrides crash the ticker or busy-spin the
  poll loop; `loadConfigFromEnvOrFlags` resets non-positive intervals/timeouts to defaults.
- **Shutdown safety: never act on an aborted cycle.** The check cycle runs under a
  signal-cancelled `context.Context`; when it's cancelled, in-flight probes report as failures.
  `executeCheckCycle` checks `ctx.Err()` after `runAllChecks` and bails before notifying or
  restarting. Keep that guard — otherwise a SIGTERM mid-cycle would trigger a bogus restart.

## Pre-delivery checklist

- `go vet ./...` clean and `go build ./...` succeeds **inside Docker** (never on the host).
- `docker build .` completes with no warnings before reporting done.
- If a probe/restart/notify path changed: re-read the "Critical gotchas" above — socket
  hygiene regressions are the historical failure mode here.
