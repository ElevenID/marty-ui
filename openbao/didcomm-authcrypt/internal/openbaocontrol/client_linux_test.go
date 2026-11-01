//go:build linux

package openbaocontrol

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func currentOwner() owner { return owner{uint32(os.Geteuid()), uint32(os.Getegid())} }

func unixServer(t *testing.T, handler http.Handler) (string, owner) {
	t.Helper()
	directory, err := os.MkdirTemp("", "bao-control-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "api.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return path, currentOwner()
}

func TestUnixTransportHasNoNetworkOrProxyFallback(t *testing.T) {
	var requests atomic.Int32
	path, expected := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Host != "openbao-local.invalid" || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("unexpected local control authority")
		}
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "http://127.0.0.1:1/should-not-connect")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		_, _ = io.WriteString(w, "local")
	}))
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	client, err := newClientAt(path, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient(client)
	response, err := client.Get(Endpoint + "/v1/sys/seal-status")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if string(body) != "local" || requests.Load() != 1 {
		t.Fatal("fixed Unix request did not reach its listener")
	}
	for _, address := range []string{"http://127.0.0.1:1/", "https://openbao-local.invalid/", "http://elsewhere.invalid/"} {
		if response, err := client.Get(address); err == nil {
			response.Body.Close()
			t.Fatalf("unexpected authority accepted: %s", address)
		}
	}
	response, err = client.Get(Endpoint + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusTemporaryRedirect || requests.Load() != 2 {
		t.Fatal("redirect or alternate authority made an unexpected request")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if response, err := client.Get(Endpoint + "/"); err == nil {
		response.Body.Close()
		t.Fatal("missing socket did not fail closed")
	}
}

func TestUnixTransportRejectsUnsafeSocketCustody(t *testing.T) {
	for _, failure := range []string{"mode", "parent-mode", "file", "symlink", "ancestor-symlink"} {
		t.Run(failure, func(t *testing.T) {
			path, expected := unixServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Error("unsafe socket received an HTTP request")
			}))
			switch failure {
			case "mode":
				_ = os.Chmod(path, 0660)
			case "parent-mode":
				_ = os.Chmod(filepath.Dir(path), 0750)
			case "file":
				_ = os.Remove(path)
				_ = os.WriteFile(path, []byte("not a socket"), 0600)
			case "symlink":
				target := filepath.Join(filepath.Dir(path), "real.sock")
				_ = os.Rename(path, target)
				_ = os.Symlink(target, path)
			case "ancestor-symlink":
				linked := filepath.Join(t.TempDir(), "linked")
				if err := os.Symlink(filepath.Dir(path), linked); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(linked, "api.sock")
			}
			if _, err := newClientAt(path, expected); err == nil {
				t.Fatal("unsafe Unix endpoint accepted")
			}
		})
	}
}

func TestUnixPeerCredentialsMustMatchSocketOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing socket ownership requires root")
	}
	var received atomic.Int32
	path, _ := unixServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { received.Add(1) }))
	// The listening process remains root. Matching filesystem metadata alone
	// must not admit it as the configured non-root OpenBao peer.
	if err := os.Chown(filepath.Dir(path), 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	client, err := newClientAt(path, owner{65534, 65534})
	if err != nil {
		t.Fatal(err)
	}
	defer closeClient(client)
	if response, err := client.Get(Endpoint + "/v1/sys/seal-status"); err == nil {
		response.Body.Close()
		t.Fatal("foreign Unix peer accepted")
	}
	if received.Load() != 0 {
		t.Fatal("HTTP request escaped before peer authentication")
	}
}
