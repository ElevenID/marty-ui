//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

const fixtureInitialRoot = "hvs.fixture-original-initial-root-never-printed"

type retirementFixture struct {
	paths                      rootRetirementPaths
	client                     *http.Client
	root, recovery, authority  retainedFile
	requests, lookups, revokes atomic.Int32
	revoked                    atomic.Bool
}

func retirementFixtureAt(t *testing.T, fault string) *retirementFixture {
	t.Helper()
	control := newRecoveryFixture(t, "")
	f := &retirementFixture{paths: rootRetirementPaths{state: t.TempDir(), identity: control.paths.identity, root: currentOwner()}}
	if os.Chmod(f.paths.state, 0700) != nil {
		t.Fatal("cannot protect retirement fixture")
	}
	state, err := openDirectory(f.paths.state, currentOwner(), 0700)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	f.root, err = writeRootExclusive(state, "root.token", []byte(fixtureInitialRoot), currentOwner(), 0400)
	if err != nil {
		t.Fatal(err)
	}
	f.recovery, err = writeRootExclusive(state, "recovery.key", []byte("fixture-private-original-recovery-share"), currentOwner(), 0400)
	if err != nil {
		t.Fatal(err)
	}
	f.authority, err = writeInitialAuthority(state, currentOwner(), testInstallation, testAttempt, testCluster, f.root, f.recovery)
	if err != nil {
		t.Fatal(err)
	}
	path, expected := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		f.requests.Add(1)
		if request.URL.RawQuery != "" || request.Header.Get("X-Vault-Namespace") != "" {
			t.Error("unexpected retirement query or namespace")
		}
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/v1/sys/seal-status":
			if request.Header.Get("X-Vault-Token") != "" {
				t.Error("retirement status carried root")
			}
			cluster := testCluster
			if fault == "wrong-cluster" {
				cluster = testIssuer
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "static", "initialized": true, "sealed": false, "recovery_seal": true, "migration": false, "cluster_id": cluster})
		case request.Method == http.MethodGet && request.URL.Path == "/v1/auth/token/lookup-self":
			count := f.lookups.Add(1)
			if request.Header.Get("X-Vault-Token") != fixtureInitialRoot {
				t.Error("retirement used another token")
			}
			if fault == "lookup-unavailable-once" && count == 1 {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			if f.revoked.Load() {
				http.Error(w, "permission denied", http.StatusForbidden)
				return
			}
			value := map[string]any{"id": fixtureInitialRoot, "policies": []string{"root"}, "path": "auth/token/root", "type": "service", "orphan": true}
			if fault == "wrong-token-metadata" {
				value["path"] = "auth/token/create"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": value})
		case request.Method == http.MethodPost && request.URL.Path == "/v1/auth/token/revoke-self":
			count := f.revokes.Add(1)
			if request.Header.Get("X-Vault-Token") != fixtureInitialRoot {
				t.Error("retirement revoked another token")
			}
			if fault == "revoke-unavailable-once" && count == 1 {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			f.revoked.Store(true)
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Error("retirement performed setup, init, unseal or an unrelated operation")
			http.NotFound(w, request)
		}
	}))
	f.client, err = newClientAt(path, expected)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeClient(f.client) })
	return f
}
func invokeRetirement(f *retirementFixture, attempt string) (RootRetirementReceipt, error) {
	return retireInitialRootAt(context.Background(), testInstallation, attempt, strings.Repeat("a", 64), f.paths, currentOwner(), f.client)
}
func requireRetiredFixture(t *testing.T, f *retirementFixture, result RootRetirementReceipt) {
	t.Helper()
	if !result.RootRejectionObserved || !result.RootTokenRemoved || !result.RecoveryKeyPreserved || !result.OriginalAuthorityVerified || !result.AuthorityRecordPreserved || result.InitializationReplayed || result.InstallationReady {
		t.Fatal("retirement public observations differ")
	}
	if _, err := os.Lstat(filepath.Join(f.paths.state, "root.token")); !os.IsNotExist(err) {
		t.Fatal("retirement did not remove root")
	}
	state, err := openDirectory(f.paths.state, currentOwner(), 0700)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if unchangedFile(state, "recovery.key", f.recovery, currentOwner(), []uint32{0400}, 4096, false) != nil || unchangedFile(state, initialAuthorityName, f.authority, currentOwner(), []uint32{0400}, 8192, false) != nil {
		t.Fatal("retirement altered original recovery authority")
	}
	data, _ := json.Marshal(result)
	for _, private := range []string{fixtureInitialRoot, string(f.recovery.bytes), fingerprint(f.root.bytes), fingerprint(f.recovery.bytes), fingerprint(f.authority.bytes), testRole, testSecret, "accessor"} {
		if bytes.Contains(data, []byte(private)) {
			t.Fatal("retirement stdout contains private authority or digests")
		}
	}
}

func TestRootRetirementResumesExactAttemptAtEveryCrashBoundary(t *testing.T) {
	for _, point := range []string{"retirement-prepared-staged", "retirement-prepared-durable", "retirement-revoke-requested", "retirement-revocation_observed-staged", "retirement-revocation_observed-durable", "retirement-root-unlinked", "retirement-completed-staged", "retirement-completed-durable"} {
		t.Run(point, func(t *testing.T) {
			f := retirementFixtureAt(t, "")
			reached := false
			f.paths.checkpoint = func(observed string) error {
				if observed == point {
					reached = true
					return errRetirement
				}
				return nil
			}
			if _, err := invokeRetirement(f, testAttempt); err == nil || !reached {
				t.Fatal("retirement crash boundary not exercised")
			}
			f.paths.checkpoint = nil
			result, err := invokeRetirement(f, testAttempt)
			if err != nil {
				t.Fatal(err)
			}
			requireRetiredFixture(t, f, result)
			if f.revokes.Load() != 1 {
				t.Fatal("reconciliation revoked more than the one original token")
			}
			requests := f.requests.Load()
			repeated, err := invokeRetirement(f, testAttempt)
			if err != nil || repeated != result || f.requests.Load() != requests {
				t.Fatal("completed retirement did not return its retained public result")
			}
			if _, err := invokeRetirement(f, replacementAttempt); err == nil || f.requests.Load() != requests {
				t.Fatal("retirement adopted another attempt")
			}
		})
	}
}

func TestRootRetirementTransientLookupAndRevokeRemainResumable(t *testing.T) {
	for _, fault := range []string{"lookup-unavailable-once", "revoke-unavailable-once"} {
		t.Run(fault, func(t *testing.T) {
			f := retirementFixtureAt(t, fault)
			if _, err := invokeRetirement(f, testAttempt); err == nil {
				t.Fatal("uncertain operation claimed retirement")
			}
			if _, err := os.Lstat(filepath.Join(f.paths.state, "root.token")); err != nil {
				t.Fatal("uncertain operation removed root")
			}
			result, err := invokeRetirement(f, testAttempt)
			if err != nil {
				t.Fatal(err)
			}
			requireRetiredFixture(t, f, result)
		})
	}
}

func TestRootRetirementRefusesChangedOriginalAuthorityBeforeRootUse(t *testing.T) {
	for _, fault := range []string{"root-replaced", "recovery-replaced", "authority-mode", "authority-unknown", "authority-duplicate", "material-leftover", "legacy-response-leftover", "wrong-cluster", "wrong-token-metadata", "lock-held"} {
		t.Run(fault, func(t *testing.T) {
			f := retirementFixtureAt(t, fault)
			switch fault {
			case "root-replaced", "recovery-replaced":
				name := "root.token"
				if fault == "recovery-replaced" {
					name = "recovery.key"
				}
				path := filepath.Join(f.paths.state, name)
				data, _ := os.ReadFile(path)
				if os.Rename(path, path+".retained") != nil || os.WriteFile(path, data, 0400) != nil {
					t.Fatal("cannot replace original authority fixture")
				}
			case "authority-mode":
				_ = os.Chmod(filepath.Join(f.paths.state, initialAuthorityName), 0600)
			case "authority-unknown", "authority-duplicate":
				path := filepath.Join(f.paths.state, initialAuthorityName)
				data, _ := os.ReadFile(path)
				prefix := "{\"unknown\":true,"
				if fault == "authority-duplicate" {
					prefix = "{\"schema\":\"duplicate\","
				}
				_ = os.Remove(path)
				_ = os.WriteFile(path, []byte(strings.Replace(string(data), "{", prefix, 1)), 0400)
			case "material-leftover":
				_ = os.WriteFile(filepath.Join(f.paths.state, "static-init-material.json"), []byte("private initial response must not be left behind"), 0400)
			case "legacy-response-leftover":
				_ = os.WriteFile(filepath.Join(f.paths.state, "selfhost-init.json"), []byte("retained initial response"), 0400)
			case "lock-held":
				state, err := openDirectory(f.paths.state, currentOwner(), 0700)
				if err != nil {
					t.Fatal(err)
				}
				defer state.Close()
				lock, err := acquireNamedControlLock(state, currentOwner(), retirementLockName)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			}
			if _, err := invokeRetirement(f, testAttempt); err == nil || f.revokes.Load() != 0 {
				t.Fatal("changed authority was revoked or adopted")
			}
			if fault != "wrong-token-metadata" && f.lookups.Load() != 0 {
				t.Fatal("unverified original authority reached root lookup")
			}
			if _, err := os.Lstat(filepath.Join(f.paths.state, "root.token")); err != nil {
				t.Fatal("refusal removed root authority")
			}
		})
	}
}
