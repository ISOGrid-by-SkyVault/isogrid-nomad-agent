package stream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// identity writes a key and a self-signed certificate like the ones in a
// bundle and returns their paths.
func identity(t *testing.T, cn string) (keyFile, certFile string, pub *ecdsa.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile = filepath.Join(dir, "client.key")
	certFile = filepath.Join(dir, "client.crt")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyFile, certFile, &key.PublicKey
}

func TestSignVerify(t *testing.T) {
	keyFile, _, pub := identity(t, "cluster-x")
	key, err := LoadKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(key, []byte("nonce"))
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, []byte("nonce"), sig) {
		t.Fatal("signature does not verify")
	}
	if Verify(pub, []byte("other"), sig) {
		t.Fatal("signature verified over another message")
	}
}

func TestNewRefusesMismatchedKeyAndCertificate(t *testing.T) {
	keyFile, _, _ := identity(t, "a")
	_, certFile, _ := identity(t, "b")
	_, err := New(Options{KeyFile: keyFile, CertFile: certFile, Handle: func(context.Context, json.RawMessage) any { return nil }})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want a mismatch error, got %v", err)
	}
}

// TestSessionHandshakeRelayAndRefusal plays the API: challenge, hello check,
// welcome, one intent, one reply, then a refusal close; the client must end
// in the refused state with the reason the API gave.
func TestSessionHandshakeRelayAndRefusal(t *testing.T) {
	keyFile, certFile, pub := identity(t, "cluster-540062ca")
	const nonce = "the-nonce"
	serverErr := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.CloseNow() //nolint:errcheck
		ctx := r.Context()
		fail := func(msg string) { serverErr <- &testError{msg} }
		if err := writeJSON(ctx, conn, map[string]any{"type": "challenge", "nonce": nonce, "version": 1}); err != nil {
			fail("challenge: " + err.Error())
			return
		}
		var hello struct {
			Type         string   `json:"type"`
			ClusterID    string   `json:"cluster_id"`
			Certificate  string   `json:"certificate"`
			Signature    string   `json:"signature"`
			Version      string   `json:"version"`
			Capabilities []string `json:"capabilities"`
		}
		if err := readJSON(ctx, conn, 5*time.Second, &hello); err != nil {
			fail("hello: " + err.Error())
			return
		}
		if hello.Type != "hello" || hello.ClusterID != "c1" || hello.Version != "test" || len(hello.Capabilities) != 1 {
			fail("unexpected hello")
			return
		}
		if !strings.HasPrefix(hello.Certificate, "-----BEGIN CERTIFICATE-----") {
			fail("hello carries no certificate")
			return
		}
		if !Verify(pub, []byte(nonce), hello.Signature) {
			fail("the proof does not verify")
			return
		}
		if err := writeJSON(ctx, conn, map[string]any{"type": "welcome", "organization_id": "o1", "cluster_id": "c1", "heartbeat_seconds": 1}); err != nil {
			fail("welcome: " + err.Error())
			return
		}
		if err := writeJSON(ctx, conn, map[string]any{"type": "intent", "body": map[string]any{"id": "i1", "kind": "ping"}}); err != nil {
			fail("intent: " + err.Error())
			return
		}
		var reply struct {
			Type string `json:"type"`
			Body struct {
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"body"`
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			if err := readJSON(ctx, conn, 5*time.Second, &reply); err != nil {
				fail("reply: " + err.Error())
				return
			}
			if reply.Type == "reply" {
				break
			}
			if time.Now().After(deadline) {
				fail("no reply, only " + reply.Type)
				return
			}
		}
		if reply.Body.ID != "i1" || reply.Body.Status != "ok" {
			fail("unexpected reply body")
			return
		}
		serverErr <- nil
		_ = conn.Close(CloseRefused, "The certificate was replaced; install the new bundle")
	}))
	defer srv.Close()

	client, err := New(Options{
		URL:            "ws://" + strings.TrimPrefix(srv.URL, "http://"),
		KeyFile:        keyFile,
		CertFile:       certFile,
		ClusterID:      "c1",
		OrganizationID: "o1",
		Version:        "test",
		Capabilities:   []string{"ping"},
		Handle: func(_ context.Context, body json.RawMessage) any {
			var in struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(body, &in)
			return map[string]any{"id": in.ID, "status": "ok"}
		},
		Logf: t.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go client.Run(ctx)

	select {
	case err := <-serverErr:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("the server never finished the exchange")
	}
	for {
		s := client.Status()
		if s.State == StateRefused {
			if !strings.Contains(s.Reason, "replaced") || s.RepliesSent != 1 || s.IntentsReceived != 1 || s.HeartbeatSeconds != 1 {
				t.Fatalf("unexpected status %+v", s)
			}
			if s.CertificateCN != "cluster-540062ca" {
				t.Fatalf("certificate CN not reported: %+v", s)
			}
			return
		}
		if ctx.Err() != nil {
			t.Fatalf("never refused; last status %+v", s)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestClassify(t *testing.T) {
	state, reason, wait := classify(websocket.CloseError{Code: CloseRefused, Reason: "no"}, time.Second)
	if state != StateRefused || reason != "no" || wait != refusedBackoff {
		t.Fatalf("refusal misclassified: %s %s %s", state, reason, wait)
	}
	state, reason, wait = classify(websocket.CloseError{Code: CloseIdle}, 3*time.Second)
	if state != StateDisconnected || !strings.Contains(reason, "4008") || wait != 3*time.Second {
		t.Fatalf("idle misclassified: %s %s %s", state, reason, wait)
	}
	state, _, _ = classify(nil, time.Second)
	if state != StateDisconnected {
		t.Fatalf("nil misclassified: %s", state)
	}
}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
