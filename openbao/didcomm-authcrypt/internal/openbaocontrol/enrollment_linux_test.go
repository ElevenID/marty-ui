//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestEnrollmentRefusesExistingAuthorityAndPreservesUncertainSetup(t *testing.T) {
	for _, failure := range []string{"existing-output", "existing-pki", "existing-auth", "existing-policy", "wrong-root", "uncertain-mount"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newRecoveryFixture(t, "")
			if failure != "existing-output" {
				for _, name := range []string{"recovery.json", "enrollment-pending.json", "enrollment-result.json"} {
					if err := os.Remove(filepath.Join(fixture.paths.identity, name)); err != nil {
						t.Fatal(err)
					}
				}
			}
			state := t.TempDir()
			if err := os.Chmod(state, 0700); err != nil {
				t.Fatal(err)
			}
			root := "hvs.fixture-bootstrap-root-never-printed"
			if err := os.WriteFile(filepath.Join(state, "root.token"), []byte(root), 0400); err != nil {
				t.Fatal(err)
			}
			caDER, err := x509.MarshalPKCS8PrivateKey(fixture.caKey)
			if err != nil {
				t.Fatal(err)
			}
			caKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caDER})
			if err := os.WriteFile(filepath.Join(fixture.paths.tls, "ca.key"), caKey, 0600); err != nil {
				t.Fatal(err)
			}
			var requests, mutations atomic.Int32
			var sawPending atomic.Bool
			path, expected := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				requests.Add(1)
				if request.URL.Path != "/v1/sys/health" && request.Header.Get("X-Vault-Token") != root {
					t.Error("bootstrap operation did not use only its fixed root input")
				}
				if request.Method != http.MethodGet {
					mutations.Add(1)
					if request.Method != http.MethodPost || request.URL.Path != "/v1/sys/mounts/selfhost-control-pki" {
						t.Error("unexpected mutation after refusal")
					}
					pending, err := os.ReadFile(filepath.Join(fixture.paths.identity, "enrollment-pending.json"))
					var intent enrollmentIntent
					if err == nil && decodeJSON(pending, &intent, true) == nil &&
						intent.InstallationID == testInstallation && intent.AttemptID == testAttempt {
						sawPending.Store(true)
					}
					http.Error(w, "uncertain response", http.StatusServiceUnavailable)
					return
				}
				switch request.URL.Path {
				case "/v1/sys/health":
					_ = json.NewEncoder(w).Encode(map[string]any{"initialized": true, "sealed": false, "cluster_id": testCluster})
				case "/v1/auth/token/lookup-self":
					policies := []string{"root"}
					if failure == "wrong-root" {
						policies = []string{"default"}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"policies": policies}})
				case "/v1/sys/mounts":
					data := map[string]any{}
					if failure == "existing-pki" {
						data["selfhost-control-pki/"] = map[string]string{"type": "pki"}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
				case "/v1/sys/auth":
					data := map[string]any{}
					if failure == "existing-auth" {
						data["selfhost-control/"] = map[string]string{"type": "approle"}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
				case "/v1/sys/policies/acl/" + recoveryPolicy:
					if failure == "existing-policy" {
						_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"policy": "preexisting"}})
					} else {
						http.NotFound(w, request)
					}
				default:
					t.Error("unexpected preflight operation")
					http.NotFound(w, request)
				}
			}))
			client, err := newClientAt(path, expected)
			if err != nil {
				t.Fatal(err)
			}
			defer closeClient(client)
			paths := enrollmentPaths{state: state, tls: fixture.paths.tls, identity: fixture.paths.identity, root: currentOwner()}
			if _, err := enrollAt(context.Background(), testInstallation, testAttempt, paths, currentOwner(), client, fixture.now); err == nil {
				t.Fatal("existing or uncertain authority was accepted")
			}
			expectedMutations := int32(0)
			if failure == "uncertain-mount" {
				expectedMutations = 1
				if !sawPending.Load() {
					t.Fatal("remote mutation preceded its durable intent file")
				}
				if _, err := os.Stat(filepath.Join(paths.identity, "enrollment-result.json")); !os.IsNotExist(err) {
					t.Fatal("uncertain enrollment produced a completion result")
				}
				before := requests.Load()
				if _, err := enrollAt(context.Background(), testInstallation, testRole, paths, currentOwner(), client, fixture.now); err == nil || requests.Load() != before {
					t.Fatal("uncertain enrollment was retried under another attempt")
				}
			}
			if mutations.Load() != expectedMutations || (failure == "existing-output" && requests.Load() != 0) {
				t.Fatal("refusal did not precede unauthorized mutations")
			}
			actualCAKey, _ := os.ReadFile(filepath.Join(paths.tls, "ca.key"))
			actualNode, _ := os.ReadFile(filepath.Join(paths.tls, "server.pem"))
			if !bytes.Equal(actualCAKey, caKey) || !bytes.Equal(actualNode, fixture.old) {
				t.Fatal("refused enrollment changed existing key custody")
			}
		})
	}
}

func TestControlRoleReadbackRejectsBroaderCertificateAuthority(t *testing.T) {
	for _, failure := range []string{"issuer", "names", "key-usage", "subdomains", "wildcards", "client-auth", "csr-names", "long-ttl"} {
		t.Run(failure, func(t *testing.T) {
			encoded, _ := json.Marshal(signingRoleParameters(testIssuer))
			var data map[string]any
			_ = json.Unmarshal(encoded, &data)
			data["ttl"], data["max_ttl"] = float64(2592000), float64(2592000)
			if requireSigningRole(data, testIssuer) != nil {
				t.Fatal("valid fixed role readback rejected")
			}
			switch failure {
			case "issuer":
				data["issuer_ref"] = "default"
			case "names":
				data["allowed_domains"] = []any{"example.com"}
			case "key-usage":
				data["key_usage"] = []any{"DigitalSignature", "CertSign"}
			case "subdomains":
				data["allow_subdomains"] = true
			case "wildcards":
				data["allow_wildcard_certificates"] = true
			case "client-auth":
				data["client_flag"] = true
			case "csr-names":
				data["use_csr_sans"] = true
			case "long-ttl":
				data["max_ttl"] = float64(31536000)
			}
			if requireSigningRole(data, testIssuer) == nil {
				t.Fatal("broader PKI role readback was accepted")
			}
		})
	}
}
