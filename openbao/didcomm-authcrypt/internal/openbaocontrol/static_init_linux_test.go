//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStaticInitializationKeepsSealKeySeparateAndPublishesScopedEvidence(t *testing.T) {
	paths, client, initializationClient, requests, initialized := staticInitFixture(t, "", nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	receipt, err := initializeStaticAt(ctx, testInstallation, testAttempt, paths, currentOwner(), client, initializationClient)
	if err != nil || initialized.Load() != 1 || !receipt.Initialized || !receipt.UnsealedReady || receipt.SealType != "static" ||
		receipt.ClusterID != testCluster || !receipt.RecoveryKeyWritten || !receipt.RootTokenWritten ||
		receipt.RootRetired || receipt.InitializationReplayed || receipt.InstallationReady {
		t.Fatal("fresh static initialization did not produce precise public evidence")
	}
	for _, name := range []string{"root.token", "recovery.key", initialAuthorityName} {
		stat, err := os.Lstat(filepath.Join(paths.state, name))
		if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0400 {
			t.Fatal("private initialization output custody differs")
		}
	}
	directory, err := openDirectory(paths.state, currentOwner(), 0700)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	authority, _, err := readInitialAuthority(directory, currentOwner(), testInstallation)
	rootFile, rootErr := readFile(directory, "root.token", currentOwner(), []uint32{0400}, 4096, false)
	recoveryFile, recoveryErr := readFile(directory, "recovery.key", currentOwner(), []uint32{0400}, 4096, false)
	if err != nil || rootErr != nil || recoveryErr != nil || authority.AttemptID != testAttempt || authority.ClusterID != testCluster || authority.Root != bindAuthorityFile(rootFile) || authority.Recovery != bindAuthorityFile(recoveryFile) {
		t.Fatal("private original initialization authority was not bound before completion")
	}
	for _, name := range []string{"unseal.key", "static.key", "static-init-material.json"} {
		if _, err := os.Lstat(filepath.Join(paths.state, name)); !os.IsNotExist(err) {
			t.Fatal("initialization retained a Shamir unseal key, seal key, or completed material stage")
		}
	}
	for _, name := range []string{"static-init-pending.json", "static-init-result.json"} {
		data, err := os.ReadFile(filepath.Join(paths.output, name))
		if err != nil || bytes.Contains(data, []byte("fixture-static-root")) || bytes.Contains(data, []byte("recovery_key\":")) || bytes.Contains(data, []byte("PRIVATE KEY")) {
			t.Fatal("public initialization evidence contains private material")
		}
	}
	before := requests.Load()
	if _, err := initializeStaticAt(ctx, testInstallation, testAttempt, paths, currentOwner(), client, initializationClient); err == nil || requests.Load() != before {
		t.Fatal("completed initialization was adopted or replayed")
	}
}

func TestStaticInitializationRefusesExistingAndUncertainState(t *testing.T) {
	for _, failure := range []string{
		"existing-output", "existing-root", "existing-recovery", "existing-unseal", "root-symlink", "output-mode", "same-directory",
		"already-initialized", "shamir", "init-response-lost", "unseal-key-returned", "wrong-recovery", "root-collision",
	} {
		t.Run(failure, func(t *testing.T) {
			paths, client, initializationClient, requests, initialized := staticInitFixture(t, failure, nil)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if _, err := initializeStaticAt(ctx, testInstallation, testAttempt, paths, currentOwner(), client, initializationClient); err == nil {
				t.Fatal("unsafe initialization was accepted")
			}
			if initialized.Load() > 0 {
				pending, err := os.ReadFile(filepath.Join(paths.output, "static-init-pending.json"))
				if err != nil || !bytes.Contains(pending, []byte(testAttempt)) {
					t.Fatal("uncertain initialization lost its pre-mutation intent")
				}
				before := requests.Load()
				if _, err := initializeStaticAt(ctx, testInstallation, testAttempt, paths, currentOwner(), client, initializationClient); err == nil || requests.Load() != before {
					t.Fatal("uncertain initialization reached the API again")
				}
			}
		})
	}
}

func staticInitFixture(t *testing.T, failure string, beforeResponse func(*http.Request)) (staticInitPaths, *http.Client, *http.Client, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	return staticInitFixtureWithServer(t, failure, beforeResponse, staticInitUnixClients)
}

type staticInitTestServer func(*testing.T, http.Handler) (*http.Client, *http.Client)

func staticInitFixtureWithServer(t *testing.T, failure string, beforeResponse func(*http.Request), server staticInitTestServer) (staticInitPaths, *http.Client, *http.Client, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	paths := staticInitPaths{state: t.TempDir(), output: t.TempDir(), root: currentOwner()}
	for _, path := range []string{paths.state, paths.output} {
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	switch failure {
	case "existing-output":
		_ = os.WriteFile(filepath.Join(paths.output, "existing"), []byte("retain"), 0600)
	case "existing-root", "existing-recovery", "existing-unseal":
		name := strings.TrimPrefix(failure, "existing-") + ".key"
		if failure == "existing-root" {
			name = "root.token"
		}
		_ = os.WriteFile(filepath.Join(paths.state, name), []byte("retain"), 0400)
	case "root-symlink":
		_ = os.Symlink("missing", filepath.Join(paths.state, "root.token"))
	case "output-mode":
		_ = os.Chmod(paths.output, 0755)
	case "same-directory":
		paths.output = paths.state
	}
	requests, initialized := &atomic.Int32{}, &atomic.Int32{}
	client, initializationClient := server(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.Header.Get("X-Vault-Token") != "" || request.URL.RawQuery != "" {
			t.Error("fresh initialization used an unexpected token or query")
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/sys/seal-status":
			ready := initialized.Load() > 0 || failure == "already-initialized"
			status := map[string]any{"type": "static", "initialized": ready, "sealed": !ready, "recovery_seal": true, "migration": false}
			if ready {
				status["cluster_id"] = testCluster
			}
			if failure == "shamir" {
				status["type"], status["recovery_seal"] = "shamir", false
			}
			_ = json.NewEncoder(w).Encode(status)
		case request.Method == http.MethodPost && request.URL.Path == "/v1/sys/init":
			var payload map[string]int
			if json.NewDecoder(request.Body).Decode(&payload) != nil || len(payload) != 2 || payload["recovery_shares"] != 1 || payload["recovery_threshold"] != 1 {
				t.Error("static initialization sent Shamir or migration parameters")
			}
			if _, err := os.Stat(filepath.Join(paths.output, "static-init-pending.json")); err != nil {
				t.Error("initialization occurred before durable intent")
			}
			initialized.Add(1)
			if beforeResponse != nil {
				beforeResponse(request)
				if request.Context().Err() != nil {
					return
				}
			}
			if failure == "init-response-lost" {
				_, _ = w.Write([]byte(`{"root_token":`))
				return
			}
			recovery := bytes.Repeat([]byte{0x31}, 33)
			body := map[string]any{
				"keys": []string{}, "keys_base64": []string{}, "recovery_keys": []string{hex.EncodeToString(recovery)},
				"recovery_keys_base64": []string{base64.StdEncoding.EncodeToString(recovery)}, "root_token": "hvs.fixture-static-root-never-printed",
			}
			if failure == "unseal-key-returned" {
				body["keys_base64"] = []string{"forbidden"}
			}
			if failure == "wrong-recovery" {
				body["recovery_keys_base64"] = []string{"not-base64"}
			}
			if failure == "root-collision" {
				_ = os.WriteFile(filepath.Join(paths.state, "root.token"), []byte("do not adopt"), 0400)
			}
			_ = json.NewEncoder(w).Encode(body)
		default:
			t.Error("initialization attempted an unseal, replay, or unrelated operation")
			http.NotFound(w, request)
		}
	}))
	return paths, client, initializationClient, requests, initialized
}

func staticInitUnixClients(t *testing.T, handler http.Handler) (*http.Client, *http.Client) {
	t.Helper()
	path, expected := unixServer(t, handler)
	client, err := newClientAt(path, expected)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeClient(client) })
	initializationClient, err := newStaticInitClientAt(path, expected)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeClient(initializationClient) })
	return client, initializationClient
}
