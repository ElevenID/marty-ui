package main

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestReconcileUnsealsWithoutRootToken(t *testing.T) {
	sealed := true
	unsealCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/sys/seal-status":
			json.NewEncoder(w).Encode(map[string]bool{"initialized": true, "sealed": sealed})
		case "/v1/sys/unseal":
			if r.Method != http.MethodPost {
				t.Errorf("unexpected method %s", r.Method)
			}
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload["key"] != "fixture-unseal-key" {
				t.Error("unseal request did not contain the scoped key")
			}
			unsealCalls++
			sealed = false
			json.NewEncoder(w).Encode(map[string]bool{"sealed": sealed})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caFile, ca, 0600); err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(dir, "unseal.key")
	if err := os.WriteFile(keyFile, []byte("fixture-unseal-key\n"), 0400); err != nil {
		t.Fatal(err)
	}
	client, endpoint, err := secureClient(server.URL, caFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := reconcile(context.Background(), client, endpoint, keyFile); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(context.Background(), client, endpoint, keyFile); err != nil {
		t.Fatal(err)
	}
	if unsealCalls != 1 || sealed {
		t.Fatalf("expected one successful unseal, got %d calls", unsealCalls)
	}
	if _, _, err := secureClient("http://openbao:8200", caFile); err == nil {
		t.Fatal("plaintext OpenBao address accepted")
	}
}

func TestReadUnsealKeyRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte("fixture"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(key, filepath.Join(dir, "linked")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readUnsealKey(filepath.Join(dir, "linked")); err == nil {
		t.Fatal("symlinked unseal key accepted")
	}
}

func TestUninitializedNodeWaitsOnlyWithCleanState(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]bool{"initialized": false, "sealed": true})
	}))
	defer server.Close()
	keyFile := filepath.Join(t.TempDir(), "unseal.key")
	if err := reconcile(context.Background(), server.Client(), server.URL, keyFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("fixture"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(context.Background(), server.Client(), server.URL, keyFile); err == nil {
		t.Fatal("existing unseal material was accepted for an uninitialized node")
	}
}

func TestHealthChecksSeparateListenerFromUnsealedReadinessWithoutMutation(t *testing.T) {
	for _, state := range []struct {
		name                string
		initialized, sealed bool
	}{
		{"uninitialized", false, true},
		{"sealed", true, true},
		{"ready", true, false},
	} {
		t.Run(state.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				requests++
				if request.Method != http.MethodGet || request.URL.Path != "/v1/sys/seal-status" {
					t.Error("read-only health check performed a mutation")
					http.Error(w, "invalid", http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]bool{"initialized": state.initialized, "sealed": state.sealed})
			}))
			defer server.Close()
			listener, err := check(context.Background(), server.Client(), server.URL, false)
			if err != nil || !listener.ListenerAvailable || listener.Initialized != state.initialized ||
				listener.Sealed != state.sealed || listener.InstallationReady {
				t.Fatal("listener check claimed incorrect readiness")
			}
			ready := state.initialized && !state.sealed
			observed, err := check(context.Background(), server.Client(), server.URL, true)
			if (err == nil) != ready || observed.UnsealedReady != ready || !observed.ListenerAvailable || observed.InstallationReady || requests != 2 {
				t.Fatal("unsealed check did not preserve health semantics")
			}
		})
	}
}

func TestUnixOptInRejectsConflictingOrMalformedConfiguration(t *testing.T) {
	for _, settings := range [][4]string{
		{"0", "https://openbao:8200", "/bao/data/tls/ca.crt", "/bao/data/unseal.key"},
		{"true", "https://openbao:8200", "/bao/data/tls/ca.crt", "/bao/data/unseal.key"},
		{"1", "http://openbao:8200", "/bao/data/tls/ca.crt", "/bao/data/unseal.key"},
		{"1", "https://elsewhere:8200", "/bao/data/tls/ca.crt", "/bao/data/unseal.key"},
		{"1", "https://openbao:8200", "/other/ca.crt", "/bao/data/unseal.key"},
		{"1", "https://openbao:8200", "/bao/data/tls/ca.crt", "/other/unseal.key"},
	} {
		if _, _, err := configuredClient(settings[0], settings[1], settings[2], settings[3]); err == nil {
			t.Fatal("local control accepted an ambiguous configuration")
		}
	}
}
