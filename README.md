A small Go service that monitors local service ports (SMTP/SMTPS/IMAPS/HTTPS), sends minimal Gotify notifications on failures, and attempts to restart a target Docker container (default: `stalwart`) via the Docker Engine socket. Designed to run in Docker (docker-compose provided), with small footprint and no heavy SDK dependencies.

I created this service as a temporary workaround against DDoS attacks. On my email server running Stalwart I have various firewall rules, rate-limits, sysctl tweaks, fail2ban, etc., but sometimes the server stops responding and the only solution is restarting Stalwart. I know this is not a real solution, but at least it gives me a bit more peace of mind if the above problem occurs while I look for the root cause. Why I shared this code I don’t know — maybe it could be useful to someone.

IMPORTANT: this code was produced with the help of AI. It may contain mistakes or not cover every edge case. Do NOT run this blindly in production — review, test, and audit carefully before deploying in any production environment.

### Table of contents
- Project summary
- Features
- Requirements
- Configuration (env vars & flags)
- Running with Docker Compose
- Running locally (non-container)
- Logs, metrics and observability
- Security considerations
- Tuning and behavior
- Troubleshooting (common errors)
- Development & building
- Roadmap & wishlist (checklist)
- Tests & CI guidance
- Contributing
- License

#### Project summary
- Periodically checks services (default every 120s) on a configured host (default 127.0.0.1).
- If a service fails after configured retries, sends a single Gotify notification stating which service(s) failed and that a restart is being attempted.
- Attempts to restart the configured container by calling the Docker Engine HTTP API over the host unix socket (no docker CLI or docker SDK used).
- Waits a configurable period, re-checks services with longer timeouts; if recovered, sends a success Gotify notification.
- If services remain unreachable after a final timeout window, sends one high-priority Gotify notification requesting manual intervention.
- Logs to stdout so Docker captures logs (follow Docker logging best practices).

#### Features
- Lightweight Go single-binary (static) image produced by a multi-stage Docker build.
- Minimal notifications (one on failure/start restart, one on success, one on escalation).
- Uses unix socket HTTP API to avoid heavy docker SDK dependency issues.
- Configurable via environment variables or CLI flags (for local testing).
- Runs as a long-lived service on a configurable schedule; handles SIGINT/SIGTERM gracefully.

#### Requirements
- Docker engine running on the host (if restarting containers).
- Gotify server reachable and an application token.
- If running in Docker with docker socket mount: the container process UID:GID must have permission to access `/var/run/docker.sock` (see Security section).
- Go 1.24 (only needed for local builds, not to run the container image).

#### Configuration (env vars & flags)
- GOTIFY_URL (required) — full base URL to your Gotify server (e.g., `https://gotify.example`).
- GOTIFY_TOKEN (required) — Gotify application token (X-Gotify-Key).
- HOST — host to check (default `127.0.0.1`).
- SERVICES — comma-separated list of NAME:PORT entries (default `SMTP:25,SMTPS:465,IMAPS:993,HTTPS:443`).
  - Example: `SERVICES=SMTP:25,IMAPS:993,HTTPS:443`
- CONTAINER_NAME — container name to restart (default `stalwart`).
- DOCKER_SOCKET — path to docker socket inside container (default `/var/run/docker.sock`).
- RETRIES — number of attempts per check (default `3`).
- PER_ATTEMPT_TIMEOUT — seconds timeout per attempt for normal checks (default `5`).
- SLEEP_BETWEEN_ATTEMPTS — seconds to sleep between attempts (default `5`).
- POST_RESTART_WAIT — seconds to wait immediately after restart before first post-check (default `15`).
- POST_RESTART_PER_ATTEMPT_TIMEOUT — seconds timeout per attempt for post-restart checks (default `15`).
- POST_RESTART_FINAL_TIMEOUT — seconds to poll after restart before escalation (default `60`).
- POST_RESTART_POLL_INTERVAL — seconds between post-restart polls (default `10`).
- GOTIFY_PRIORITY — default priority for normal gotify messages (0..10, default `5`).
- CHECK_INTERVAL_SECONDS — seconds between scheduled checks (default `120`).

#### Notes:
- Environment variables and CLI flags are supported; env vars take precedence.
- SERVICES must be comma-separated with no spaces (the app trims individual items).


#### Running with Docker Compose
1. Copy  `.env.example` to `.env` and edit where necessary
2. Build and start:
   ```
   docker compose up -d --build
   ```
3. Follow logs:
   ```
   docker compose logs -f email-server-monitoring
   ```

#### Running locally (non-container)
- To build a Linux static binary:
  ```
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o email-server-monitoring ./main.go
  ```
- Run with environment:
  ```
  GOTIFY_URL=https://gotify.example GOTIFY_TOKEN=token ./email-server-monitoring
  ```

#### Logs, metrics and observability
- The app logs to stdout/stderr. Use `docker logs` or your logging driver to collect logs centrally.
- Recommended: configure Docker logging driver with size rotation (json-file with max-size / max-file) or forward to a centralized logging stack.

#### Security considerations
- Mounting `/var/run/docker.sock` gives the container effective control over Docker and the host. Treat it as sensitive:
  - Limit who can deploy/update the compose stack.
  - Prefer mapping the container user to the docker socket group (PUID/PGID) instead of running as root.
  - Consider using an external orchestration API or more restricted control mechanism if security is critical.
- Gotify token is sensitive. Provide via `.env` or secrets mechanism (Docker secrets).
- The service does not perform authenticated checks against monitored services (non-intrusive checks). If you add auth checks, protect any credentials.
- IMPORTANT: this project was produced with AI assistance. It should be carefully reviewed, tested, and audited before any production use.

#### Tuning and behavior
- Default schedule: runs an immediate check on startup then every CHECK_INTERVAL_SECONDS (default 120s).
- Single failure cycle behavior:
  - If any service fails after RETRIES attempts, send single Gotify failure message, restart container, wait POST_RESTART_WAIT, re-check with longer timeouts.
  - If services recover immediately or within POST_RESTART_FINAL_TIMEOUT, send success message.
  - If not recovered within the final window, send one high-priority escalation message.
- The app does not repeatedly spam notifications: it sends minimal messages per failure cycle.

#### Troubleshooting (common errors)
- Permission denied when accessing docker socket:
  - Check host socket ownership: `stat -c '%U:%G %a %n' /var/run/docker.sock`
  - Ensure container process UID:GID can access socket; set `user: "${PUID}:${PGID}"` in docker-compose and set PUID/PGID in `.env`.
- No logs in `docker logs`:
  - Ensure container runs a long-lived process. Use `docker logs -f` while the process runs.
- Gotify messages not delivered:
  - Verify GOTIFY_URL reachable and GOTIFY_TOKEN is correct.
  - Test manually: `curl -X POST -H "X-Gotify-Key: TOKEN" -d "message=hello" GOTIFY_URL/message`

#### Development & building
- Build image (single-arch):
  ```
  docker build -t email-server-monitoring:latest .
  ```

- Build multi-arch images (recommended for publishing):
  Use Docker Buildx to build and publish multi-arch images that support amd64 and arm64.
  ```bash
  # create and bootstrap a buildx builder (one-time)
  docker buildx create --use --name mybuilder
  docker buildx inspect --bootstrap

  # build and push multi-arch image (example: amd64 + arm64)
  docker buildx build --platform linux/amd64,linux/arm64 -t yourrepo/email-server-monitoring:latest --push .
  ```
  Notes:
  - `--push` publishes the multi-arch manifest to your registry. If you want to load a single-arch image into your local Docker daemon, use `--load` but it only supports a single platform.

- Build with docker-compose and set target architecture (single-arch build):
  You can pass build args in `docker-compose.yml` to set the `TARGETARCH`/`TARGETOS` build args exposed by the Dockerfile. This instructs the build to compile for that architecture.
  ```yaml
  services:
    email-server-monitoring:
      build:
        context: .
        args:
          TARGETOS: linux
          TARGETARCH: arm64
      image: email-server-monitoring:latest
  ```
  Important: passing build args this way produces a single-arch image for the requested arch. To produce a multi-arch manifest/image you should use `docker buildx` (see above) or CI that runs buildx.

- Local binary build (same as before):
  ```
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o email-server-monitoring ./main.go
  ```
- Run unit testing: add tests for check functions (not included by default).
- Local run: see Running locally section.

#### Roadmap & wishlist (maybe)
- [ ] Add Apprise support as an alternative notifier (Apprise supports many backends).
- [ ] Make notifier pluggable (Gotify, Apprise, email, Slack, PagerDuty, etc.).
- [ ] Add optional file logging with rotation (lumberjack) in addition to stdout.
- [ ] Add structured logging (JSON) toggled via env var for log ingestion systems.
- [ ] Configuration hot-reload (SIGHUP or online config API).
- [ ] Deduplication and rate-limiting for notifications (prevent repeated restarts/alerts).
- [ ] Exponential backoff and escalation policy for restart attempts.
- [ ] Better service-specific checks: EHLO for SMTP, optional authenticated IMAP checks, HTTP(s) validation with cert checks.
- [ ] Support for TLS verification options per-service (insecure vs strict).
- [ ] Add unit tests for check functions and integration tests (docker-in-docker or test harness).
- [ ] CI pipeline (lint, vet, test, build, multi-arch images).
- [ ] Harden final images (distroless or minimal base) and signable releases.
- [ ] Add optional persistent store for historical events (sqlite/postgres).
- [ ] Pluggable restart backends (Docker socket, remote API, Kubernetes controller).
- [ ] RBAC and least-privilege patterns to avoid mounting docker.sock where possible.
- [ ] Provide Helm chart / Kubernetes manifests.
- [ ] Add onboarding docs, examples and troubleshooting guides for common platforms (Ubuntu, Debian, RHEL).
- [ ] Localization / i18n for notification messages.

#### Contributing
- Fork, implement changes in a topic branch, open a pull request with tests and description.
- Include unit tests for new behavior and keep changes focused.

#### License
- GPL-3.0