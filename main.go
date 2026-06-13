package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var (
	// Defaults (can be overridden with env or flags)
	defaultHost                         = "127.0.0.1"
	defaultServices                     = []string{"SMTP:25", "SMTPS:465", "IMAPS:993", "HTTPS:443"}
	defaultRetries                      = 3
	defaultSleepBetweenAttemptsSeconds  = 5
	defaultPerAttemptTimeoutSeconds     = 5
	defaultPostRestartWaitSeconds       = 15
	defaultPostRestartPerAttemptSeconds = 15
	defaultPostRestartFinalTimeout      = 60
	defaultPostRestartPollInterval      = 10
	defaultGotifyPriority               = 5
	defaultContainerName                = "stalwart"
	defaultCheckIntervalSeconds         = 120   // 2 minutes
	defaultHTTPExpectedStatus           = "200" // comma-separated acceptable status codes (HTTP and HTTPS)
)

// Config holds runtime configuration, loaded from env or flags.
type Config struct {
	Host                         string
	Services                     []string
	Retries                      int
	SleepBetweenAttempts         time.Duration
	PerAttemptTimeout            time.Duration
	PostRestartWait              time.Duration
	PostRestartPerAttemptTimeout time.Duration
	PostRestartFinalTimeout      time.Duration
	PostRestartPollInterval      time.Duration
	GotifyURL                    string
	GotifyToken                  string
	GotifyPriority               int
	ContainerName                string
	DockerSocket                 string // path to docker socket (default /var/run/docker.sock)
	CheckInterval                time.Duration
	HTTPAcceptStatus             map[int]bool // status codes treated as "service up" for HTTP and HTTPS probes
}

// gotifyPayload matches Gotify's /message API JSON
type gotifyPayload struct {
	Title    string                 `json:"title"`
	Message  string                 `json:"message"`
	Priority int                    `json:"priority,omitempty"`
	Extras   map[string]interface{} `json:"extras,omitempty"`
}

func main() {
	// send logs to stdout (Docker captures stdout)
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg := loadConfigFromEnvOrFlags()

	// Print effective configuration for debugging
	log.Printf("Starting email-server-monitoring with config: host=%s services=%v container=%s retries=%d per_attempt_timeout=%s check_interval=%s",
		cfg.Host, cfg.Services, cfg.ContainerName, cfg.Retries, cfg.PerAttemptTimeout, cfg.CheckInterval)

	// Basic requirements check
	if cfg.GotifyURL == "" || cfg.GotifyToken == "" {
		log.Println("ERROR: GOTIFY_URL and GOTIFY_TOKEN must be set (env or flags). Exiting.")
		fmt.Fprintln(os.Stderr, "GOTIFY_URL and GOTIFY_TOKEN must be set (env or flags). Exiting.")
		os.Exit(2)
	}

	// Setup signal handling for graceful shutdown. The context is cancelled on
	// SIGINT/SIGTERM and threaded through the whole check cycle so a shutdown
	// interrupts in-flight probes and sleeps immediately instead of waiting for
	// the (potentially multi-minute) post-restart polling window to finish.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()

	// Run one immediate check before entering the regular schedule
	executeCheckCycle(ctx, cfg)

	for {
		select {
		case <-ticker.C:
			executeCheckCycle(ctx, cfg)
		case <-ctx.Done():
			log.Println("Received shutdown signal, shutting down.")
			return
		}
	}
}

// sleepCtx sleeps for d, returning early with false if the context is cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// executeCheckCycle runs the check/restart workflow once
func executeCheckCycle(ctx context.Context, cfg *Config) {
	log.Println("Starting scheduled check cycle...")
	allOK, failedList := runAllChecks(ctx, cfg, cfg.PerAttemptTimeout)
	// If we are shutting down, probes were aborted mid-flight and would report
	// false failures — never act on that. Bail out without notifying or restarting.
	if ctx.Err() != nil {
		log.Println("Shutdown in progress; aborting check cycle.")
		return
	}
	if allOK {
		log.Println("All services healthy; nothing to do this cycle.")
		return
	}

	log.Printf("Detected failing services: %v", failedList)

	// Build a concise title that includes the first failing service (if any)
	firstFailed := ""
	if len(failedList) > 0 {
		firstFailed = failedList[0]
	}
	titleServicePart := "service"
	if firstFailed != "" {
		titleServicePart = firstFailed
	}

	// Send a single notification that lists failing ports and states that a restart is being executed
	failMsgTitle := fmt.Sprintf("⚠️ %s unreachable — restarting %s", titleServicePart, cfg.ContainerName)
	failMsgBody := fmt.Sprintf("%s\nThe following services failed after %d attempts: %s\nAction: attempting automatic restart of '%s'.",
		nowUTC(), cfg.Retries, strings.Join(failedList, ", "), cfg.ContainerName)
	if err := sendGotify(cfg, failMsgTitle, failMsgBody, cfg.GotifyPriority); err != nil {
		log.Printf("WARN: sendGotify failed: %v", err)
	} else {
		log.Println("Sent initial failure notification to Gotify.")
	}

	// Attempt restart via Docker API (socket must be available)
	log.Printf("Attempting to restart container '%s' via docker socket '%s'...", cfg.ContainerName, cfg.DockerSocket)
	if err := restartContainer(cfg); err != nil {
		// if restart failed, notify once and return (operator action required)
		log.Printf("ERROR: restart attempt failed: %v", err)
		title := fmt.Sprintf("❌ Failed to restart '%s'", cfg.ContainerName)
		body := fmt.Sprintf("%s\nAttempt to restart '%s' failed: %v\nManual intervention required.", nowUTC(), cfg.ContainerName, err)
		_ = sendGotify(cfg, title, body, 10)
		return
	}
	log.Println("Restart API returned success. Waiting before post-restart checks...")

	// Wait before starting post-restart checks
	if !sleepCtx(ctx, cfg.PostRestartWait) {
		log.Println("Shutdown in progress; aborting post-restart checks.")
		return
	}

	// Do initial post-restart checks with longer per-attempt timeout
	recovered, _ := runAllChecks(ctx, cfg, cfg.PostRestartPerAttemptTimeout)
	if recovered {
		log.Println("All services recovered after restart (initial check).")
		title := fmt.Sprintf("✅ %s restarted successfully — connectivity restored", cfg.ContainerName)
		body := fmt.Sprintf("%s\n'%s' was restarted and all configured services became reachable.", nowUTC(), cfg.ContainerName)
		if err := sendGotify(cfg, title, body, cfg.GotifyPriority); err != nil {
			log.Printf("WARN: sendGotify failed: %v", err)
		}
		return
	}

	log.Println("Not all services recovered after initial post-restart check; will poll for final timeout window.")

	// If not recovered immediately, poll for up to final timeout
	start := time.Now()
	for time.Since(start) < cfg.PostRestartFinalTimeout {
		if !sleepCtx(ctx, cfg.PostRestartPollInterval) {
			log.Println("Shutdown in progress; aborting post-restart poll.")
			return
		}
		recovered, _ = runAllChecks(ctx, cfg, cfg.PostRestartPerAttemptTimeout)
		if recovered {
			log.Printf("Services recovered within %s after restart.", time.Since(start).Round(time.Second))
			title := fmt.Sprintf("✅ %s restarted and connectivity restored", cfg.ContainerName)
			body := fmt.Sprintf("%s\n'%s' recovered within %s after restart.", nowUTC(), cfg.ContainerName, time.Since(start).Round(time.Second))
			if err := sendGotify(cfg, title, body, cfg.GotifyPriority); err != nil {
				log.Printf("WARN: sendGotify failed: %v", err)
			}
			return
		}
		log.Printf("Still waiting; elapsed %s", time.Since(start).Round(time.Second))
	}

	// Not recovered within final timeout — notify manual intervention required
	log.Printf("ERROR: Services did not recover within %s after restart.", cfg.PostRestartFinalTimeout)
	title := fmt.Sprintf("🚨 Manual intervention needed — '%s' still unreachable", cfg.ContainerName)
	_, finalFailed := collectFailedServices(ctx, cfg, cfg.PostRestartPerAttemptTimeout)
	body := fmt.Sprintf("%s\nAfter restarting '%s' and waiting %s, the following services are still unreachable: %s\nPlease investigate and perform manual intervention.",
		nowUTC(), cfg.ContainerName, cfg.PostRestartFinalTimeout, strings.Join(finalFailed, ", "))
	if err := sendGotify(cfg, title, body, 10); err != nil {
		log.Printf("WARN: sendGotify failed: %v", err)
	}
}

// loadConfigFromEnvOrFlags reads config from env or flags and returns Config
func loadConfigFromEnvOrFlags() *Config {
	// Flags for local testing (lower priority than env variables)
	var (
		flagGotifyURL    = flag.String("gotify-url", "", "Gotify server URL (env GOTIFY_URL)")
		flagGotifyToken  = flag.String("gotify-token", "", "Gotify application token (env GOTIFY_TOKEN)")
		flagContainer    = flag.String("container", "", "Container name to restart (env CONTAINER_NAME)")
		flagDockerSocket = flag.String("docker-socket", "/var/run/docker.sock", "Docker socket path")
	)
	flag.Parse()

	containerDefault := flagContainerOrDefault("CONTAINER_NAME", defaultContainerName, *flagContainer)

	checkInterval := time.Duration(getenvIntOr("CHECK_INTERVAL_SECONDS", defaultCheckIntervalSeconds)) * time.Second

	cfg := &Config{
		Host:                         getenvOr("HOST", defaultHost),
		Services:                     defaultServices,
		Retries:                      getenvIntOr("RETRIES", defaultRetries),
		SleepBetweenAttempts:         time.Duration(getenvIntOr("SLEEP_BETWEEN_ATTEMPTS", defaultSleepBetweenAttemptsSeconds)) * time.Second,
		PerAttemptTimeout:            time.Duration(getenvIntOr("PER_ATTEMPT_TIMEOUT", defaultPerAttemptTimeoutSeconds)) * time.Second,
		PostRestartWait:              time.Duration(getenvIntOr("POST_RESTART_WAIT", defaultPostRestartWaitSeconds)) * time.Second,
		PostRestartPerAttemptTimeout: time.Duration(getenvIntOr("POST_RESTART_PER_ATTEMPT_TIMEOUT", defaultPostRestartPerAttemptSeconds)) * time.Second,
		PostRestartFinalTimeout:      time.Duration(getenvIntOr("POST_RESTART_FINAL_TIMEOUT", defaultPostRestartFinalTimeout)) * time.Second,
		PostRestartPollInterval:      time.Duration(getenvIntOr("POST_RESTART_POLL_INTERVAL", defaultPostRestartPollInterval)) * time.Second,
		GotifyURL:                    getenvOr("GOTIFY_URL", *flagGotifyURL),
		GotifyToken:                  getenvOr("GOTIFY_TOKEN", *flagGotifyToken),
		GotifyPriority:               getenvIntOr("GOTIFY_PRIORITY", defaultGotifyPriority),
		ContainerName:                getenvOr("CONTAINER_NAME", containerDefault),
		DockerSocket:                 getenvOr("DOCKER_SOCKET", *flagDockerSocket),
		CheckInterval:                checkInterval,
	}

	// Optional: SERVICES env as comma-separated list
	if s := os.Getenv("SERVICES"); s != "" {
		parts := strings.Split(s, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		cfg.Services = parts
	}

	// Ensure DockerSocket has a value
	if cfg.DockerSocket == "" {
		cfg.DockerSocket = "/var/run/docker.sock"
	}

	// HTTP_EXPECTED_STATUS: comma-separated status codes that count as "service up"
	// for both HTTP and HTTPS probes (default 200). Invalid tokens are ignored; if
	// none parse, fall back to 200.
	cfg.HTTPAcceptStatus = parseStatusSet(getenvOr("HTTP_EXPECTED_STATUS", defaultHTTPExpectedStatus))

	// Guard durations that must be strictly positive. A zero/negative value from
	// a bad env override would otherwise crash or spin:
	//   - CheckInterval == 0      -> time.NewTicker panics ("non-positive interval")
	//   - PollInterval  == 0      -> time.Sleep(0) busy-loops the post-restart poll
	//   - any *Timeout  <= 0      -> context expires instantly -> every probe fails -> restart loop
	clampPositive := func(name string, d time.Duration, def int) time.Duration {
		if d <= 0 {
			log.Printf("WARN: %s must be > 0, got %s; using default %ds", name, d, def)
			return time.Duration(def) * time.Second
		}
		return d
	}
	cfg.CheckInterval = clampPositive("CHECK_INTERVAL_SECONDS", cfg.CheckInterval, defaultCheckIntervalSeconds)
	cfg.PerAttemptTimeout = clampPositive("PER_ATTEMPT_TIMEOUT", cfg.PerAttemptTimeout, defaultPerAttemptTimeoutSeconds)
	cfg.PostRestartPerAttemptTimeout = clampPositive("POST_RESTART_PER_ATTEMPT_TIMEOUT", cfg.PostRestartPerAttemptTimeout, defaultPostRestartPerAttemptSeconds)
	cfg.PostRestartPollInterval = clampPositive("POST_RESTART_POLL_INTERVAL", cfg.PostRestartPollInterval, defaultPostRestartPollInterval)
	cfg.PostRestartFinalTimeout = clampPositive("POST_RESTART_FINAL_TIMEOUT", cfg.PostRestartFinalTimeout, defaultPostRestartFinalTimeout)
	if cfg.Retries < 1 {
		log.Printf("WARN: RETRIES must be >= 1, got %d; using 1", cfg.Retries)
		cfg.Retries = 1
	}

	return cfg
}

func flagContainerOrDefault(envVar, def, flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := os.Getenv(envVar); v != "" {
		return v
	}
	return def
}

func getenvOr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getenvIntOr(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if x, err := strconv.Atoi(v); err == nil {
			return x
		}
	}
	return def
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// parseStatusSet parses a comma-separated list of HTTP status codes into a set.
// Invalid or out-of-range tokens are logged and skipped; if nothing valid
// remains, it falls back to {200}.
func parseStatusSet(s string) map[int]bool {
	set := map[int]bool{}
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		code, err := strconv.Atoi(tok)
		if err != nil || code < 100 || code > 599 {
			log.Printf("WARN: ignoring invalid HTTPS_EXPECTED_STATUS code %q", tok)
			continue
		}
		set[code] = true
	}
	if len(set) == 0 {
		set[http.StatusOK] = true
	}
	return set
}

// runAllChecks runs all configured service checks. It returns (allOK bool, failedList []string).
// The parent ctx is honored: if it is cancelled (shutdown), checks abort early — callers must
// inspect ctx.Err() before acting on the result, since aborted probes report as failures.
func runAllChecks(ctx context.Context, cfg *Config, perAttemptTimeout time.Duration) (bool, []string) {
	failed := []string{}
	for _, svc := range cfg.Services {
		if ctx.Err() != nil {
			break
		}
		parts := strings.SplitN(svc, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		portStr := strings.TrimSpace(parts[1])
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			// Misconfigured entry — skip it rather than probing port 0 (which would
			// always fail and trigger a needless container restart).
			log.Printf("WARN: skipping service %q: invalid port %q", svc, portStr)
			continue
		}

		ok := false
		for attempt := 1; attempt <= cfg.Retries; attempt++ {
			cctx, cancel := context.WithTimeout(ctx, perAttemptTimeout)
			ok = runSingleCheck(cctx, cfg, name, port)
			cancel()
			if ok {
				break
			}
			if attempt < cfg.Retries {
				// Cancellable inter-attempt sleep so shutdown is not delayed.
				if !sleepCtx(ctx, cfg.SleepBetweenAttempts) {
					break
				}
			}
		}
		if !ok {
			failed = append(failed, fmt.Sprintf("%s:%d", name, port))
		}
	}
	return len(failed) == 0, failed
}

// collectFailedServices is like runAllChecks but collects and returns the failed list.
func collectFailedServices(ctx context.Context, cfg *Config, perAttemptTimeout time.Duration) (bool, []string) {
	return runAllChecks(ctx, cfg, perAttemptTimeout)
}

func runSingleCheck(ctx context.Context, cfg *Config, name string, port int) bool {
	switch strings.ToUpper(name) {
	case "SMTP":
		return checkSMTP(ctx, cfg.Host, port)
	case "SMTPS":
		return checkTLSHandshake(ctx, cfg.Host, port)
	case "IMAPS":
		return checkTLSHandshake(ctx, cfg.Host, port) // treat same as SMTPS for handshake
	case "HTTP":
		return checkHTTPStatus(ctx, "http", cfg.Host, port, cfg.HTTPAcceptStatus)
	case "HTTPS":
		return checkHTTPStatus(ctx, "https", cfg.Host, port, cfg.HTTPAcceptStatus)
	default:
		return checkTCP(ctx, cfg.Host, port)
	}
}

func dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

func checkTCP(ctx context.Context, host string, port int) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := dialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func checkSMTP(ctx context.Context, host string, port int) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := dialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// We try to read a banner line. Use ctx deadline to set a read deadline.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetReadDeadline(dl)
	}
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	if err != nil {
		// if we couldn't read a banner, consider failure
		return false
	}
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, "220") || strings.HasPrefix(strings.ToLower(line), "220")
}

func checkTLSHandshake(ctx context.Context, host string, port int) bool {
	// tls.Dialer.DialContext is context-native: cancelling ctx (timeout or
	// shutdown) aborts the dial and TLS handshake directly. This avoids the old
	// goroutine+channel workaround, which could leave a dial goroutine blocked on
	// the OS TCP timeout (~2 min) against a filtered port long after we returned.
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	d := &tls.Dialer{
		Config: &tls.Config{
			InsecureSkipVerify: true, // local infra may use self-signed certs
			ServerName:         host,
		},
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// checkHTTPStatus probes an HTTP or HTTPS endpoint (scheme is "http" or "https")
// and reports whether the response status is in the accepted set.
func checkHTTPStatus(ctx context.Context, scheme, host string, port int, acceptStatus map[int]bool) bool {
	// One-shot connectivity probe: disable keep-alives so the underlying socket is
	// closed as soon as the response is read, and close any idle connection the
	// transport may still hold. Without this every probe leaks one ESTABLISHED
	// socket, since http.Transport pools idle keep-alive connections indefinitely.
	// TLSClientConfig is set for the https case and ignored for plain http.
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
	}
	// Build request with context
	url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	// A healthy server is expected to answer with one of the configured status
	// codes (default 200). Operators that front the service with a redirect or
	// auth gate can widen the accepted set via HTTP_EXPECTED_STATUS.
	if len(acceptStatus) == 0 {
		return resp.StatusCode == http.StatusOK
	}
	return acceptStatus[resp.StatusCode]
}

// sendGotify posts a message to the Gotify server. optional priority override
func sendGotify(cfg *Config, title, body string, priority int) error {
	payload := gotifyPayload{
		Title:    title,
		Message:  body,
		Priority: priority,
		Extras: map[string]interface{}{
			// Put an example icon URL in extras so clients that understand 'extras' can show it.
			// This is optional and may be ignored by some clients.
			"client::display": map[string]interface{}{
				"color":     "#FF9800",
				"largeIcon": map[string]string{"value": "https://raw.githubusercontent.com/edent/SuperTinyIcons/master/images/twitter/twitter.svg"},
			},
		},
	}
	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.GotifyURL, "/")+"/message", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gotify-Key", cfg.GotifyToken)
	// short client timeout
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("gotify returned status %d", resp.StatusCode)
	}
	return nil
}

// restartContainer uses the Docker Engine HTTP API over the unix socket to restart a container by name.
// This avoids pulling the heavy github.com/docker/docker SDK and its transitive dependency issues.
func restartContainer(cfg *Config) error {
	socketPath := cfg.DockerSocket
	if socketPath == "" {
		socketPath = "/var/run/docker.sock"
	}

	// Build HTTP client that dials the unix socket
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// ignore network/addr, use unix socket
			d := &net.Dialer{}
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Docker API allows container name as identifier in the restart endpoint
	url := fmt.Sprintf("http://unix/containers/%s/restart", cfg.ContainerName)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	// some APIs require Host header; not strictly necessary but safe
	req.Host = "docker"

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("docker API returned %d", resp.StatusCode)
}
