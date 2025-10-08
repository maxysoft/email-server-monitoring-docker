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
	defaultCheckIntervalSeconds         = 120 // 2 minutes
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

	// Setup signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()

	// Run one immediate check before entering the regular schedule
	executeCheckCycle(cfg)

	for {
		select {
		case <-ticker.C:
			executeCheckCycle(cfg)
		case s := <-sigCh:
			log.Printf("Received signal %s, shutting down.", s)
			return
		}
	}
}

// executeCheckCycle runs the check/restart workflow once
func executeCheckCycle(cfg *Config) {
	log.Println("Starting scheduled check cycle...")
	allOK, failedList := runAllChecks(cfg, cfg.PerAttemptTimeout)
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
	time.Sleep(cfg.PostRestartWait)

	// Do initial post-restart checks with longer per-attempt timeout
	recovered, _ := runAllChecks(cfg, cfg.PostRestartPerAttemptTimeout)
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
		time.Sleep(cfg.PostRestartPollInterval)
		recovered, _ = runAllChecks(cfg, cfg.PostRestartPerAttemptTimeout)
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
	_, finalFailed := collectFailedServices(cfg, cfg.PostRestartPerAttemptTimeout)
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

// runAllChecks runs all configured service checks. It returns (allOK bool, failedList []string)
func runAllChecks(cfg *Config, perAttemptTimeout time.Duration) (bool, []string) {
	failed := []string{}
	for _, svc := range cfg.Services {
		parts := strings.SplitN(svc, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		portStr := strings.TrimSpace(parts[1])
		port, _ := strconv.Atoi(portStr)

		ok := false
		for attempt := 1; attempt <= cfg.Retries; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), perAttemptTimeout)
			ok = runSingleCheck(ctx, cfg.Host, name, port)
			cancel()
			if ok {
				break
			}
			if attempt < cfg.Retries {
				time.Sleep(cfg.SleepBetweenAttempts)
			}
		}
		if !ok {
			failed = append(failed, fmt.Sprintf("%s:%d", name, port))
		}
	}
	return len(failed) == 0, failed
}

// collectFailedServices is like runAllChecks but collects and returns the failed list.
func collectFailedServices(cfg *Config, perAttemptTimeout time.Duration) (bool, []string) {
	return runAllChecks(cfg, perAttemptTimeout)
}

func runSingleCheck(ctx context.Context, host, name string, port int) bool {
	switch strings.ToUpper(name) {
	case "SMTP":
		return checkSMTP(ctx, host, port)
	case "SMTPS":
		return checkTLSHandshake(ctx, host, port)
	case "IMAPS":
		return checkTLSHandshake(ctx, host, port) // treat same as SMTPS for handshake
	case "HTTPS":
		return checkHTTPS(ctx, host, port)
	default:
		return checkTCP(ctx, host, port)
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
	// Use tls.DialWithDialer with a net.Dialer that uses ctx
	d := &net.Dialer{}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	// Build a context-aware dialer by dialing with a goroutine and channel
	type result struct {
		conn *tls.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
			InsecureSkipVerify: true, // local infra may use self-signed certs
			ServerName:         host,
		})
		ch <- result{conn: conn, err: err}
	}()
	select {
	case <-ctx.Done():
		return false
	case res := <-ch:
		if res.err != nil {
			return false
		}
		_ = res.conn.Close()
		return true
	}
}

func checkHTTPS(ctx context.Context, host string, port int) bool {
	// Use http Client with timeout from ctx
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: transport,
	}
	// Build request with context
	url := fmt.Sprintf("https://%s:%d/", host, port)
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
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
