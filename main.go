// xlate is a bidirectional REST field-translation gateway.
//
// Each account pairs two systems (A and B) that speak different field
// vocabularies. xlate accepts a POST from either side, renames fields
// according to the account's map, forwards to the opposite side's
// target URL with that side's credentials, and reverse-maps the JSON
// response — so both parties only ever see their own field names.
package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const version = "0.4.0"

//go:embed web/admin.html
var adminHTML []byte

func main() {
	var (
		listen     = flag.String("listen", ":8080", "listen address")
		statePath  = flag.String("state", "xlate.state.json", "path to state file")
		adminToken = flag.String("admin-token", "", "admin API token (or env XLATE_ADMIN_TOKEN; generated per-run if unset)")
		logSize    = flag.Int("log-size", 500, "activity ring buffer size")
		maxBody    = flag.Int64("max-body", 2<<20, "max request/response body bytes")
		tlsCert    = flag.String("tls-cert", "", "TLS certificate file (serve HTTPS when set with -tls-key)")
		tlsKey     = flag.String("tls-key", "", "TLS key file")

		auditPath   = flag.String("audit", "xlate.audit.jsonl", "hash-chained audit trail path (empty disables — not recommended)")
		verifyAudit = flag.String("verify-audit", "", "verify an audit trail's hash chain and exit")

		alertWebhook = flag.String("alert-webhook", "", "URL to POST tripwire alerts to (JSON)")
		alertSecret  = flag.String("alert-secret", "", "HMAC-SHA256 secret for X-Xlate-Signature on alerts (or env XLATE_ALERT_SECRET)")

		tripThreshold = flag.Int("trip-threshold", 5, "refused attempts tolerated per account; the tripwire fires when exceeded")
		tripWindow    = flag.Duration("trip-window", 5*time.Minute, "sliding window for counting refused attempts")
		tripLock      = flag.Duration("trip-lock", 15*time.Minute, "lockout duration in mode=lock")
		tripMode      = flag.String("trip-mode", "lock", "tripwire action: lock | freeze | alert")

		trustProxy  = flag.Bool("trust-proxy", false, "trust the first X-Forwarded-For hop for client IPs (only behind a proxy that strips it)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println("xlate " + version)
		return
	}

	if *verifyAudit != "" {
		if err := VerifyAudit(*verifyAudit, os.Stdout); err != nil {
			log.Fatalf("audit verification FAILED: %v", err)
		}
		return
	}
	// Flags are validated up front so a typo fails at start rather than
	// producing a server that is quietly misconfigured.
	switch *tripMode {
	case "lock", "freeze", "alert":
	default:
		log.Fatalf("-trip-mode must be lock, freeze, or alert (got %q)", *tripMode)
	}
	if *tripThreshold < 0 || *tripThreshold > maxTripThreshold {
		log.Fatalf("-trip-threshold must be between 0 and %d (got %d)", maxTripThreshold, *tripThreshold)
	}
	if *tripWindow <= 0 {
		log.Fatalf("-trip-window must be positive (got %s)", *tripWindow)
	}
	if *tripMode == "lock" && *tripLock <= 0 {
		log.Fatalf("-trip-lock must be positive in mode lock (got %s)", *tripLock)
	}
	if *maxBody < 1024 {
		log.Fatalf("-max-body must be at least 1024 bytes (got %d)", *maxBody)
	}
	if *logSize < 1 {
		log.Fatalf("-log-size must be at least 1 (got %d)", *logSize)
	}
	if *listen == "" {
		log.Fatal("-listen must not be empty")
	}
	if (*tlsCert == "") != (*tlsKey == "") {
		log.Fatal("-tls-cert and -tls-key must be set together")
	}
	if *statePath == "" {
		log.Fatal("-state must not be empty")
	}

	token := *adminToken
	if token == "" {
		token = os.Getenv("XLATE_ADMIN_TOKEN")
	}
	generated := false
	if token == "" {
		token = newAdminToken()
		generated = true
	}

	store, err := OpenStore(*statePath)
	if err != nil {
		log.Fatalf("state: %v", err)
	}

	var audit *AuditLog
	if *auditPath != "" {
		audit, err = OpenAudit(*auditPath)
		if err != nil {
			log.Fatalf("audit: %v", err)
		}
	} else {
		log.Print("WARNING: audit trail disabled (-audit \"\")")
	}

	secret := *alertSecret
	if secret == "" {
		secret = os.Getenv("XLATE_ALERT_SECRET")
	}
	if *alertWebhook != "" && secret == "" {
		log.Print("WARNING: alert webhook is unsigned (-alert-secret unset); receivers cannot authenticate alerts")
	}

	srv := NewServer(store, NewRing(*logSize), token, *maxBody, adminHTML)
	srv.audit = audit
	srv.trip = NewTripwire(*tripThreshold, *tripWindow, *tripLock, *tripMode)
	srv.alerter = NewAlerter(*alertWebhook, secret, audit)
	srv.trustProxy = *trustProxy
	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		// No WriteTimeout: the handler blocks on the upstream call,
		// which is already bounded by the per-account timeout.
		//
		// Pinned rather than inherited: this carries bearer credentials,
		// and a future change to Go's default must not quietly lower it.
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	scheme := "http"
	if *tlsCert != "" && *tlsKey != "" {
		scheme = "https"
	}
	log.Printf("xlate %s listening on %s", version, *listen)
	log.Printf("admin ui: %s://%s/admin/", scheme, displayAddr(*listen))
	log.Printf("state: %s (%d accounts)", *statePath, store.Count())
	if audit != nil {
		log.Printf("audit: %s (verify anytime: xlate -verify-audit %s)", *auditPath, *auditPath)
	}
	log.Printf("tripwire: >%d refused in %s -> %s", *tripThreshold, *tripWindow, *tripMode)
	if generated {
		log.Printf("admin token (generated for this run — pin it with -admin-token or XLATE_ADMIN_TOKEN):")
		log.Printf("  %s", token)
	}
	_ = audit.Emit("system", "server.start", map[string]any{
		"version": version, "listen": *listen, "accounts": store.Count(),
		"trip_mode": *tripMode, "trip_threshold": *tripThreshold,
	})

	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		// Drain for as long as the slowest in-flight upstream call could
		// legitimately take, plus a margin — a fixed short window would
		// cut off live requests and close the audit trail under handlers
		// that are still emitting.
		drain := store.MaxTimeout() + 5*time.Second
		log.Printf("shutting down (draining up to %s)", drain)
		ctx, cancel := context.WithTimeout(context.Background(), drain)
		defer cancel()
		if err := hs.Shutdown(ctx); err != nil {
			log.Printf("shutdown: drain window expired with requests still in flight: %v", err)
		}
		_ = audit.Emit("system", "server.stop", map[string]any{"version": version})
		_ = audit.Close()
		close(done)
	}()

	if scheme == "https" {
		err = hs.ListenAndServeTLS(*tlsCert, *tlsKey)
	} else {
		err = hs.ListenAndServe()
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
	<-done
}

func displayAddr(listen string) string {
	if strings.HasPrefix(listen, ":") {
		return "localhost" + listen
	}
	return listen
}
