//go:build e2e

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The TLS serving path (-tls-cert/-tls-key) had never been executed by a
// test, including the deliberately pinned TLS 1.2 floor. Run the real
// binary with a self-signed pair and prove: HTTPS serves, the admin API
// works over it, and a TLS 1.1 client is refused.
func TestE2ETLSServing(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := selfSigned(t, dir)

	port := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	logBuf := &strings.Builder{}
	cmd := exec.Command(binary(t),
		"-listen", addr,
		"-state", filepath.Join(dir, "state.json"),
		"-audit", filepath.Join(dir, "audit.jsonl"),
		"-admin-token", adminTok,
		"-tls-cert", certPath,
		"-tls-key", keyPath,
	)
	cmd.Stdout, cmd.Stderr = logBuf, logBuf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	base := "https://" + addr
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}}

	// Readiness over HTTPS.
	var ready bool
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(base + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("TLS server never became ready\n%s", logBuf.String())
	}

	// The admin API answers over HTTPS.
	req, _ := http.NewRequest("GET", base+"/api/admin/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("admin over TLS: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("admin over TLS: want 200, got %d: %s", resp.StatusCode, b)
	}
	var list any
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("admin over TLS: non-JSON body: %v", err)
	}

	// The pinned floor: a TLS 1.1 client must be refused at handshake.
	old := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS11,
	}
	conn, err := tls.Dial("tcp", addr, old)
	if err == nil {
		conn.Close()
		t.Fatal("TLS 1.1 handshake succeeded; the 1.2 floor is gone")
	}

	// And plain HTTP against the TLS port is not served.
	plain := &http.Client{Timeout: 3 * time.Second}
	if resp, err := plain.Get("http://" + addr + "/healthz"); err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			t.Fatal("plaintext HTTP served on the TLS listener")
		}
	}
}

// selfSigned writes a throwaway ECDSA certificate/key pair for
// 127.0.0.1 and returns their paths.
func selfSigned(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "xlate-e2e"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certOut, err := os.Create(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	certOut.Close()
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyOut, err := os.Create(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		t.Fatal(err)
	}
	keyOut.Close()
	return certPath, keyPath
}
