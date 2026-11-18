//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

type recordingTransport struct {
	base       http.RoundTripper
	operations []string
}

func (transport *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.operations = append(transport.operations, request.Method+" "+request.URL.Path)
	return transport.base.RoundTrip(request)
}

// This opt-in test executes the actual recovery core against the verified
// official binary. Temporary paths, the current UID and a writable fixture
// identity mount are injected internally; the production command keeps its
// fixed paths, image UID lookup and read-only mount requirement.
func TestOfficialOpenBao255RecoveryCoreAfterNaturalTCPExpiry(t *testing.T) {
	binary := os.Getenv("MARTY_OPENBAO_UNIX_PROOF_BINARY")
	if binary == "" {
		t.Skip("set MARTY_OPENBAO_UNIX_PROOF_BINARY to the verified official OpenBao2.5.5 binary")
	}
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		t.Fatal("official binary path must be absolute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, binary, "version").Output()
	if err != nil || !strings.HasPrefix(string(version), "OpenBao v2.5.5 ") {
		t.Fatal("this compatibility proof requires OpenBao2.5.5")
	}
	directory, err := os.MkdirTemp("", "bao-go-proof-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	paths := recoveryPaths{identity: filepath.Join(directory, "identity"), tls: filepath.Join(directory, "tls"), root: currentOwner()}
	control := filepath.Join(directory, "control")
	data := filepath.Join(directory, "data")
	for _, path := range []string{paths.identity, paths.tls, control, data} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	caKey := testKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Marty self-host OpenBao TLS CA"},
		NotBefore: now.Add(-24 * time.Hour), NotAfter: now.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	ca := testCertificate(t, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	nodeKey := testKey(t)
	old := testCertificate(t, testLeaf(now, 2, now.Add(15*time.Second)), ca, &nodeKey.PublicKey, caKey)
	nodeDER, _ := x509.MarshalPKCS8PrivateKey(nodeKey)
	caDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caDER})
	nodeKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nodeDER})
	oldPEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: old.Raw}), nodeKeyPEM...)
	write := func(path string, value []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, value, mode); err != nil {
			t.Fatal("cannot write private proof input")
		}
	}
	write(filepath.Join(paths.tls, "ca.crt"), caPEM, 0644)
	write(filepath.Join(paths.tls, "ca.key"), caKeyPEM, 0600)
	write(filepath.Join(paths.tls, "server.pem"), oldPEM, 0600)

	// Reserve both ports until immediately before starting our child. A bind
	// race fails this test; it never adopts or signals an existing process.
	apiReservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer apiReservation.Close()
	clusterReservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clusterReservation.Close()
	address, clusterAddress := apiReservation.Addr().String(), clusterReservation.Addr().String()
	socket := filepath.Join(control, "api.sock")
	config := map[string]any{
		"disable_mlock": true, "disable_cache": true, "ui": false,
		"api_addr": "https://" + address, "cluster_addr": "https://" + clusterAddress,
		"storage": map[string]any{"file": map[string]string{"path": data}},
		"listener": []any{
			map[string]any{"unix": map[string]any{
				"address": socket, "socket_mode": "0600", "socket_user": fmt.Sprint(os.Geteuid()), "socket_group": fmt.Sprint(os.Getegid()),
			}},
			map[string]any{"tcp": map[string]any{
				"address": address, "cluster_address": clusterAddress, "tls_min_version": "tls12",
				"tls_cert_file": filepath.Join(paths.tls, "server.pem"), "tls_key_file": filepath.Join(paths.tls, "server.pem"),
			}},
		},
	}
	configBytes, _ := json.Marshal(config)
	configPath := filepath.Join(directory, "server.json")
	write(configPath, configBytes, 0600)
	log, err := os.OpenFile(filepath.Join(directory, "process.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	process := exec.CommandContext(ctx, binary, "server", "-config", configPath, "-log-level=error")
	process.Env = []string{"PATH=/usr/bin:/bin", "GOMAXPROCS=2", "TZ=UTC"}
	process.Dir, process.Stdout, process.Stderr = directory, log, log
	_ = apiReservation.Close()
	_ = clusterReservation.Close()
	if err := process.Start(); err != nil {
		t.Fatal("official binary did not start")
	}
	exited := make(chan struct{})
	go func() { _ = process.Wait(); close(exited) }()
	defer func() {
		_ = process.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = process.Process.Kill()
			<-exited
		}
	}()
	wait := func(condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			select {
			case <-exited:
				t.Fatal("owned OpenBao process exited during proof")
			default:
			}
			if condition() {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("bounded OpenBao observation timed out")
	}
	var client *http.Client
	wait(func() bool {
		client, err = newClientAt(socket, currentOwner())
		if err != nil {
			return false
		}
		var status map[string]any
		return apiRequest(ctx, client, http.MethodGet, "sys/seal-status", "", nil, &status) == nil
	})
	defer closeClient(client)
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	tcp := func() ([]byte, error) {
		connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, &tls.Config{
			RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
		})
		if err != nil {
			return nil, err
		}
		defer connection.Close()
		return connection.ConnectionState().PeerCertificates[0].Raw, nil
	}
	leaf, err := tcp()
	if err != nil || !bytes.Equal(leaf, old.Raw) {
		t.Fatal("initial certificate did not establish verified TCP")
	}
	call := func(method, path, token string, body any) map[string]any {
		t.Helper()
		var result map[string]any
		if err := apiRequest(ctx, client, method, path, token, body, &result); err != nil {
			t.Fatalf("OpenBao fixture operation failed: %s %s", method, path)
		}
		return result
	}
	mutate := func(method, path, token string, body any) {
		t.Helper()
		if err := apiRequest(ctx, client, method, path, token, body, nil); err != nil {
			t.Fatalf("OpenBao fixture mutation failed: %s %s", method, path)
		}
	}
	denied := func(method, path, token string, body string) {
		t.Helper()
		request, _ := http.NewRequestWithContext(ctx, method, Endpoint+"/v1/"+path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		if token != "" {
			request.Header.Set("X-Vault-Token", token)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("cannot observe expected scoped denial")
		}
		response.Body.Close()
		if response.StatusCode != http.StatusForbidden {
			t.Fatal("scope denial was not enforced")
		}
	}
	initialized := call(http.MethodPost, "sys/init", "", map[string]int{"secret_shares": 1, "secret_threshold": 1})
	root := initialized["root_token"].(string)
	mutate(http.MethodPost, "sys/unseal", "", map[string]any{"key": initialized["keys"].([]any)[0]})
	initialized = nil
	health := call(http.MethodGet, "sys/health", "", nil)
	clusterID := health["cluster_id"].(string)
	write(filepath.Join(data, "root.token"), []byte(root), 0400)
	enrollmentRecorder := &recordingTransport{base: client.Transport}
	enrollmentClient := *client
	enrollmentClient.Transport = enrollmentRecorder
	enrollmentPaths := enrollmentPaths{state: data, tls: paths.tls, identity: paths.identity, root: currentOwner()}
	enrollment, err := enrollAt(ctx, testInstallation, testAttempt, enrollmentPaths, currentOwner(), &enrollmentClient, time.Now())
	if err != nil {
		t.Fatalf("actual enrollment core refused official OpenBao responses after %v", enrollmentRecorder.operations)
	}
	if enrollment.ClusterID != clusterID || enrollment.RootRetired || !enrollment.ScopedSigningVerified || !enrollment.ForbiddenOperationsDenied {
		t.Fatal("enrollment did not establish its claimed authority")
	}
	issuerID := enrollment.IssuerID
	publishedIdentity, err := os.ReadFile(filepath.Join(paths.identity, "recovery.json"))
	if err != nil {
		t.Fatal("enrollment did not publish its private identity")
	}
	identity, err := parseIdentity(publishedIdentity, testInstallation)
	if err != nil || identity.IssuerID != issuerID {
		t.Fatal("enrollment identity differs from public result")
	}
	beforeReplay := len(enrollmentRecorder.operations)
	if _, err := enrollAt(ctx, testInstallation, testAttempt, enrollmentPaths, currentOwner(), &enrollmentClient, time.Now()); err == nil || len(enrollmentRecorder.operations) != beforeReplay {
		t.Fatal("completed enrollment was adopted or replayed")
	}
	mutate(http.MethodPost, "auth/token/revoke-self", root, nil)
	denied(http.MethodGet, "auth/token/lookup-self", root, "")
	root = ""
	if err := os.Remove(filepath.Join(data, "root.token")); err != nil {
		t.Fatal("cannot retire the fixture bootstrap root file")
	}

	// Natural expiry is bounded by the 15-second initial leaf. No clock change,
	// TLS bypass, root token, initialization or unseal is used below.
	expiryDeadline := time.Now().Add(20 * time.Second)
	for !time.Now().After(old.NotAfter.Add(100 * time.Millisecond)) {
		if time.Now().After(expiryDeadline) {
			t.Fatal("natural certificate expiry exceeded bound")
		}
		time.Sleep(50 * time.Millisecond)
	}
	expired := func() {
		t.Helper()
		_, err := tcp()
		var invalid x509.CertificateInvalidError
		if !errors.As(err, &invalid) || invalid.Reason != x509.Expired || !bytes.Equal(invalid.Cert.Raw, old.Raw) {
			t.Fatal("expected the original network certificate to be rejected for expiry")
		}
	}
	expired()
	recorder := &recordingTransport{base: client.Transport}
	recoveryClient := *client
	recoveryClient.Transport = recorder
	paths.checkpoint = func(point string) error {
		if point == "candidate-durable" {
			return errRecovery
		}
		return nil
	}
	if _, err := recoverAt(ctx, testInstallation, testAttempt, paths, currentOwner(), &recoveryClient, time.Now()); err == nil {
		t.Fatal("expected interruption after durable public candidate, before publication")
	}
	paths.checkpoint = nil
	receipt, err := recoverAt(ctx, testInstallation, testAttempt, paths, currentOwner(), &recoveryClient, time.Now())
	if err != nil {
		t.Fatalf("actual recovery core refused official OpenBao responses after %v", recorder.operations)
	}
	expectedOperations := []string{
		"GET /v1/sys/health", "POST /v1/" + loginPath, "GET /v1/auth/token/lookup-self",
		"GET /v1/" + issuerPrefix + issuerID, "POST /v1/" + issuerPrefix + issuerID + "/sign/" + signingRole,
		"POST /v1/auth/token/revoke-self",
	}
	if !slices.Equal(recorder.operations, expectedOperations) {
		t.Fatal("recovery performed an unexpected initialization, unseal or authority operation")
	}
	repeated, err := recoverAt(ctx, testInstallation, testAttempt, paths, currentOwner(), &recoveryClient, time.Now())
	if err != nil || repeated != receipt || !slices.Equal(recorder.operations, expectedOperations) {
		t.Fatal("completed recovery did not return retained result without additional API work")
	}
	expired() // Atomic file publication alone must not be mistaken for reload.
	pid := process.Process.Pid
	if err := process.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal("cannot signal the exact owned proof process")
	}
	wait(func() bool {
		leaf, err := tcp()
		return err == nil && fingerprint(leaf) == receipt.CertificateSHA256
	})
	if process.Process.Pid != pid || call(http.MethodGet, "sys/health", "", nil)["cluster_id"] != clusterID {
		t.Fatal("node identity changed during reload")
	}
	current, _ := os.ReadFile(filepath.Join(paths.tls, "server.pem"))
	_, currentKey := pem.Decode(current)
	currentCA, _ := os.ReadFile(filepath.Join(paths.tls, "ca.crt"))
	currentCAKey, _ := os.ReadFile(filepath.Join(paths.tls, "ca.key"))
	if !bytes.Equal(currentKey, nodeKeyPEM) || !bytes.Equal(currentCA, caPEM) || !bytes.Equal(currentCAKey, caKeyPEM) {
		t.Fatal("recovery changed retained private keys or trust anchor")
	}
	binaryFile, err := os.Open(binary)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, err = io.Copy(hash, binaryFile)
	binaryFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	evidence, _ := json.Marshal(map[string]any{
		"schema": "elevenid.openbao-go-recovery-proof/v1", "binary_version": strings.TrimSpace(string(version)),
		"binary_sha256": fmt.Sprintf("%x", hash.Sum(nil)), "root_revocation_verified": true, "actual_recovery_core": true, "actual_enrollment_core": true,
		"natural_leaf_expiry": true, "tcp_verified_after_owned_sighup": true, "scoped_signing_policy_denials": true,
		"candidate_resume_without_additional_api": true, "completed_attempt_reobserved": true,
		"node_key_preserved": true, "existing_file_ca_key_preserved": true, "imported_ca_key_nonexportable": false,
		"tls_verification_disabled": false, "initialization_replayed": false, "same_process": true,
		"production_mount_and_image_uid_qualified": false, "container_image_qualified": false, "reboot_qualified": false,
	})
	t.Log(string(evidence))
}
