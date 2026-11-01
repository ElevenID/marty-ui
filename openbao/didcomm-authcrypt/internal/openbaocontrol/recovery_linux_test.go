//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testInstallation = "11111111-1111-4111-8111-111111111111"
	testAttempt      = "22222222-2222-4222-8222-222222222222"
	testCluster      = "33333333-3333-4333-8333-333333333333"
	testRole         = "44444444-4444-4444-8444-444444444444"
	testSecret       = "55555555-5555-4555-8555-555555555555"
	testIssuer       = "66666666-6666-4666-8666-666666666666"
	testToken        = "hvs.fixture-recovery-token-never-printed"
)

type recoveryFixture struct {
	paths    recoveryPaths
	client   *http.Client
	identity recoveryIdentity
	old      []byte
	ca       *x509.Certificate
	caKey    *ecdsa.PrivateKey
	key      *ecdsa.PrivateKey
	issued   *x509.Certificate
	now      time.Time
	requests atomic.Int32
	signed   atomic.Int32
	revoked  atomic.Int32
}

func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testCertificate(t *testing.T, template, issuer *x509.Certificate, public *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, public, signer)
	if err != nil {
		t.Fatal(err)
	}
	result, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func testLeaf(now time.Time, serial int64, expires time.Time) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "openbao"},
		NotBefore: now.Add(-time.Hour), NotAfter: expires,
		DNSNames:    []string{"openbao", "host.docker.internal", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		// Existing selfhost-tls-init leaves omit the optional leaf BasicConstraints.
	}
}

func newRecoveryFixture(t *testing.T, fault string) *recoveryFixture {
	t.Helper()
	fixture := &recoveryFixture{now: time.Now().UTC().Truncate(time.Second)}
	fixture.paths = recoveryPaths{identity: filepath.Join(t.TempDir(), "identity"), tls: filepath.Join(t.TempDir(), "tls"), root: currentOwner()}
	for _, directory := range []string{fixture.paths.identity, fixture.paths.tls} {
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	caKey := testKey(t)
	fixture.caKey = caKey
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Marty self-host OpenBao TLS CA"},
		NotBefore: fixture.now.Add(-24 * time.Hour), NotAfter: fixture.now.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	fixture.ca = testCertificate(t, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	fixture.key = testKey(t)
	old := testCertificate(t, testLeaf(fixture.now, 2, fixture.now.Add(-time.Second)), fixture.ca, &fixture.key.PublicKey, caKey)
	keyDER, err := x509.MarshalPKCS8PrivateKey(fixture.key)
	if err != nil {
		t.Fatal(err)
	}
	fixture.old = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: old.Raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	fixture.identity = recoveryIdentity{
		Schema: identitySchema, InstallationID: testInstallation, ClusterID: testCluster,
		RoleID: testRole, SecretID: testSecret, IssuerID: testIssuer,
		CASHA256: fingerprint(fixture.ca.Raw), SPKISHA256: fingerprint(old.RawSubjectPublicKeyInfo),
	}
	identityBytes, err := json.Marshal(fixture.identity)
	if err != nil {
		t.Fatal(err)
	}
	files := []struct {
		directory, name string
		data            []byte
		mode            os.FileMode
	}{
		{fixture.paths.identity, "recovery.json", identityBytes, 0400},
		{fixture.paths.tls, "ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.ca.Raw}), 0644},
		{fixture.paths.tls, "server.pem", fixture.old, 0600},
	}
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(file.directory, file.name), file.data, file.mode); err != nil {
			t.Fatal(err)
		}
	}
	writeEnrollmentFixture(t, fixture.paths.identity, fixture.identity)
	// No root.token, unseal.key or ca.key exists in this fixture. The operation
	// must succeed using only scoped authentication and the retained node key.
	template := testLeaf(fixture.now, 3, fixture.now.Add(30*24*time.Hour))
	signingKey, signingCA, leafKey := caKey, fixture.ca, fixture.key
	switch fault {
	case "wrong-key":
		leafKey = testKey(t)
	case "wrong-san":
		template.DNSNames = append(template.DNSNames, "unexpected.example")
	case "wrong-ca":
		signingKey = testKey(t)
		signingCA = testCertificate(t, caTemplate, caTemplate, &signingKey.PublicKey, signingKey)
	case "long-lifetime":
		template.NotAfter = fixture.now.AddDate(1, 0, 0)
	}
	fixture.issued = testCertificate(t, template, signingCA, &leafKey.PublicKey, signingKey)
	path, expected := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		fixture.requests.Add(1)
		path := strings.TrimPrefix(request.URL.Path, "/v1/")
		method := http.MethodGet
		if path == loginPath || strings.Contains(path, "/sign/") || path == "auth/token/revoke-self" {
			method = http.MethodPost
		}
		if request.Method != method || request.URL.RawQuery != "" || request.Header.Get("X-Vault-Namespace") != "" {
			t.Error("unexpected control method or query")
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		if path != "sys/health" && path != loginPath && request.Header.Get("X-Vault-Token") != testToken {
			t.Error("missing scoped control token")
			http.Error(w, "invalid", http.StatusForbidden)
			return
		}
		if (path == "sys/health" || path == loginPath) && request.Header.Get("X-Vault-Token") != "" {
			t.Error("an unauthenticated endpoint received a token")
		}
		w.Header().Set("Content-Type", "application/json")
		switch path {
		case "sys/health":
			health := map[string]any{"initialized": true, "sealed": false, "cluster_id": testCluster}
			switch fault {
			case "sealed":
				health["sealed"] = true
			case "uninitialized":
				health["initialized"] = false
			case "wrong-cluster":
				health["cluster_id"] = testIssuer
			case "missing-sealed":
				delete(health, "sealed")
			}
			_ = json.NewEncoder(w).Encode(health)
		case loginPath:
			var body map[string]string
			if json.NewDecoder(request.Body).Decode(&body) != nil || len(body) != 2 || body["role_id"] != testRole || body["secret_id"] != testSecret {
				t.Error("incorrect fixed AppRole login")
			}
			policies := []string{recoveryPolicy}
			if fault == "broad-policy" {
				policies = append(policies, "default")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
				"client_token": testToken, "policies": policies, "token_policies": policies, "lease_duration": 300, "token_type": "service",
			}})
		case "auth/token/lookup-self":
			maxTTL := 300
			if fault == "long-token" {
				maxTTL = 3600
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"policies": []string{recoveryPolicy}, "ttl": 299, "explicit_max_ttl": maxTTL, "path": loginPath,
			}})
		case issuerPrefix + testIssuer:
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
				"issuer_id": testIssuer, "certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.ca.Raw})),
			}})
		case issuerPrefix + testIssuer + "/sign/" + signingRole:
			var body map[string]any
			if json.NewDecoder(request.Body).Decode(&body) != nil || len(body) != 7 ||
				body["common_name"] != "openbao" || body["alt_names"] != "openbao,host.docker.internal,localhost" ||
				body["ip_sans"] != "127.0.0.1" || body["exclude_cn_from_sans"] != true || body["ttl"] != "720h" || body["format"] != "pem" {
				t.Error("unexpected signing parameters")
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			csrPEM, ok := body["csr"].(string)
			block, rest := pem.Decode([]byte(csrPEM))
			if !ok || block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
				t.Error("invalid CSR envelope")
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil || csr.CheckSignature() != nil || !bytes.Equal(csr.RawSubjectPublicKeyInfo, old.RawSubjectPublicKeyInfo) {
				t.Error("CSR did not retain the original node key")
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			fixture.signed.Add(1)
			result := map[string]any{"certificate": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.issued.Raw}))}
			if fault == "private-key" {
				result["private_key"] = "private material must never be admitted"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": result})
		case "auth/token/revoke-self":
			fixture.revoked.Add(1)
			current, _ := os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
			if !bytes.Equal(current, fixture.old) {
				t.Error("certificate changed before transient-token retirement")
			}
			if fault == "changed-file" {
				_ = os.WriteFile(filepath.Join(fixture.paths.tls, "server.pem"), []byte("operator changed the source"), 0600)
			}
			if fault == "revoke-uncertain" {
				http.Error(w, "uncertain", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected operation: %s", path)
			http.NotFound(w, request)
		}
	}))
	fixture.client, err = newClientAt(path, expected)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeClient(fixture.client) })
	return fixture
}

func writeEnrollmentFixture(t *testing.T, path string, identity recoveryIdentity) {
	t.Helper()
	pending, _ := json.Marshal(enrollmentIntent{
		Schema: "elevenid.openbao-control-enrollment-intent/v1", InstallationID: identity.InstallationID,
		AttemptID: testAttempt, ClusterID: identity.ClusterID, CASHA256: identity.CASHA256, SPKISHA256: identity.SPKISHA256,
		RootRetired: false, ExistingCAKeyRetained: true,
	})
	result, _ := json.Marshal(EnrollmentReceipt{
		Schema: "elevenid.openbao-control-enrollment-result/v1", InstallationID: identity.InstallationID,
		AttemptID: testAttempt, ClusterID: identity.ClusterID, IssuerID: identity.IssuerID,
		CASHA256: identity.CASHA256, SPKISHA256: identity.SPKISHA256, PolicySHA256: fingerprint([]byte(controlPolicy(identity.IssuerID))),
		ScopedLoginVerified: true, ScopedSigningVerified: true, ForbiddenOperationsDenied: true, VerificationTokenRevoked: true,
		ExistingCAKeyRetained: true, NodeKeyPreserved: true, RootRetired: false,
	})
	for name, bytes := range map[string][]byte{"enrollment-pending.json": pending, "enrollment-result.json": result} {
		if err := os.WriteFile(filepath.Join(path, name), bytes, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRecoveryPreservesRetainedKeyAndPublishesOnlyValidatedCertificate(t *testing.T) {
	fixture := newRecoveryFixture(t, "")
	receipt, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
	if err != nil {
		t.Fatal(err)
	}
	_, previousKey := pem.Decode(fixture.old)
	certificate, currentKey := pem.Decode(current)
	if certificate == nil || !bytes.Equal(certificate.Bytes, fixture.issued.Raw) || !bytes.Equal(previousKey, currentKey) {
		t.Fatal("certificate publication changed the retained node key")
	}
	if _, err := tls.X509KeyPair(current, current); err != nil {
		t.Fatal(err)
	}
	if fixture.signed.Load() != 1 || fixture.revoked.Load() != 1 || receipt.InstallationID != testInstallation ||
		receipt.AttemptID != testAttempt || receipt.ClusterID != testCluster || !receipt.NodeKeyPreserved ||
		!receipt.CertificatePublished || receipt.ReloadPerformed || receipt.NetworkTLSVerified ||
		receipt.CertificateSHA256 != fingerprint(fixture.issued.Raw) {
		t.Fatal("incorrect public-only recovery result")
	}
	bytes, _ := json.Marshal(receipt)
	for _, secret := range []string{testRole, testSecret, testToken, "PRIVATE KEY"} {
		if strings.Contains(string(bytes), secret) {
			t.Fatal("private input appeared in public recovery evidence")
		}
	}
	entries, _ := os.ReadDir(fixture.paths.tls)
	if len(entries) != 2 {
		t.Fatal("successful publication left an unexpected stage or private key file")
	}
}

func TestRecoveryRefusesIdentityAuthorityAndCertificateChanges(t *testing.T) {
	for _, fault := range []string{
		"sealed", "uninitialized", "wrong-cluster", "missing-sealed", "broad-policy", "long-token",
		"wrong-key", "wrong-san", "wrong-ca", "long-lifetime", "private-key", "revoke-uncertain", "changed-file",
	} {
		t.Run(fault, func(t *testing.T) {
			fixture := newRecoveryFixture(t, fault)
			if _, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil {
				t.Fatal("unsafe recovery completed")
			}
			current, _ := os.ReadFile(filepath.Join(fixture.paths.tls, "server.pem"))
			expected := fixture.old
			if fault == "changed-file" {
				expected = []byte("operator changed the source")
			}
			if !bytes.Equal(current, expected) {
				t.Fatal("refused recovery changed the node certificate")
			}
			if fixture.revoked.Load() > 1 {
				t.Fatal("uncertain token mutation was retried")
			}
		})
	}
}

func TestRecoveryRetainsPendingWorkAndDoesNotReissue(t *testing.T) {
	fixture := newRecoveryFixture(t, "")
	if err := os.WriteFile(filepath.Join(fixture.paths.tls, ".recovery-"+testAttempt+".pem"), []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil {
		t.Fatal("pending replacement was replayed")
	}
	if fixture.requests.Load() != 0 {
		t.Fatal("pending work caused an API mutation")
	}
}

func TestRecoveryRequiresCompletedMatchingEnrollmentBeforeLogin(t *testing.T) {
	for _, failure := range []string{"missing-intent", "missing-result", "issuer-changed", "attempt-mismatch", "root-field-absent", "signing-unproven"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newRecoveryFixture(t, "")
			path := filepath.Join(fixture.paths.identity, "enrollment-result.json")
			data, _ := os.ReadFile(path)
			switch failure {
			case "missing-intent":
				_ = os.Remove(filepath.Join(fixture.paths.identity, "enrollment-pending.json"))
			case "missing-result":
				_ = os.Remove(path)
			case "issuer-changed":
				data = []byte(strings.Replace(string(data), testIssuer, testRole, 1))
			case "attempt-mismatch":
				data = []byte(strings.Replace(string(data), testAttempt, testRole, 1))
			case "root-field-absent":
				data = []byte(strings.Replace(string(data), ",\"root_retired\":false", "", 1))
			case "signing-unproven":
				data = []byte(strings.Replace(string(data), "\"scoped_signing_verified\":true", "\"scoped_signing_verified\":false", 1))
			}
			if failure != "missing-intent" && failure != "missing-result" {
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := recoverAt(context.Background(), testInstallation, testAttempt, fixture.paths, currentOwner(), fixture.client, fixture.now); err == nil {
				t.Fatal("incomplete or unrelated enrollment authorized recovery")
			}
			if fixture.requests.Load() != 0 {
				t.Fatal("an incomplete enrollment reached the control API")
			}
		})
	}
}

func TestRecoveryIdentityRejectsAmbiguousJSONAndScopeChanges(t *testing.T) {
	identity := recoveryIdentity{
		Schema: identitySchema, InstallationID: testInstallation, ClusterID: testCluster, RoleID: testRole,
		SecretID: testSecret, IssuerID: testIssuer, CASHA256: strings.Repeat("a", 64), SPKISHA256: strings.Repeat("b", 64),
	}
	valid, _ := json.Marshal(identity)
	if _, err := parseIdentity(valid, testInstallation); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		append(valid, valid...),
		[]byte(strings.Replace(string(valid), "{", "{\"unexpected\":true,", 1)),
		[]byte(strings.Replace(string(valid), "{", "{\"secret_id\":\"duplicate\",", 1)),
		[]byte(strings.Replace(string(valid), testInstallation, testAttempt, 1)),
		[]byte(strings.Replace(string(valid), testIssuer, "../../root", 1)),
		[]byte(strings.Replace(string(valid), strings.Repeat("a", 64), strings.Repeat("A", 64), 1)),
	} {
		if _, err := parseIdentity(invalid, testInstallation); err == nil {
			t.Fatal("ambiguous or unrelated recovery identity accepted")
		}
	}
}
