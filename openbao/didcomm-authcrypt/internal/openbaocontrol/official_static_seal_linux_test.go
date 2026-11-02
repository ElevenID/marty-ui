//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
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
	"syscall"
	"testing"
	"time"
)

// This proof uses the real fresh-init/readiness core and official2.5.5 with
// persistent Raft storage. Only temporary paths/current UID are injected. It
// does not qualify container mounts, mapped image UIDs, systemd or customer AWS.
func TestOfficialOpenBao255StaticSealRestartsWithoutUnsealReplay(t *testing.T) {
	binary := os.Getenv("MARTY_OPENBAO_UNIX_PROOF_BINARY")
	if binary == "" {
		t.Skip("set MARTY_OPENBAO_UNIX_PROOF_BINARY to the verified official OpenBao2.5.5 binary")
	}
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		t.Fatal("official binary path must be absolute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, binary, "version").Output()
	if err != nil || !strings.HasPrefix(string(version), "OpenBao v2.5.5 ") {
		t.Fatal("static-seal proof requires OpenBao2.5.5")
	}
	directory, err := os.MkdirTemp("", "bao-static-proof-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	paths := staticInitPaths{state: filepath.Join(directory, "data"), output: filepath.Join(directory, "initialization"), root: currentOwner()}
	control, seal := filepath.Join(directory, "control"), filepath.Join(directory, "seal")
	for _, path := range []string{paths.state, paths.output, control, seal} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, data []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatal("cannot write private static-seal proof input")
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(seal, "static.key")
	write(keyPath, key, 0600)
	now := time.Now().UTC()
	caKey, nodeKey := testKey(t), testKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Marty static-seal proof CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	ca := testCertificate(t, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	leaf := testCertificate(t, testLeaf(now, 2, now.Add(24*time.Hour)), ca, &nodeKey.PublicKey, caKey)
	nodeDER, _ := x509.MarshalPKCS8PrivateKey(nodeKey)
	nodePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nodeDER})...)
	nodePath := filepath.Join(directory, "server.pem")
	write(nodePath, nodePEM, 0600)
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
		"disable_mlock": true, "ui": false, "api_addr": "https://" + address, "cluster_addr": "https://" + clusterAddress,
		"storage": map[string]any{"raft": map[string]any{"path": paths.state, "node_id": "marty-static-proof"}},
		"seal":    map[string]any{"static": map[string]any{"current_key_id": "marty-selfhost-static-v1", "current_key": "file://" + keyPath}},
		"listener": []any{
			map[string]any{"unix": map[string]any{"address": socket, "socket_mode": "0600", "socket_user": fmt.Sprint(os.Geteuid()), "socket_group": fmt.Sprint(os.Getegid())}},
			map[string]any{"tcp": map[string]any{"address": address, "cluster_address": clusterAddress, "tls_cert_file": nodePath, "tls_key_file": nodePath, "tls_min_version": "tls12"}},
		},
	}
	configData, _ := json.Marshal(config)
	configPath := filepath.Join(directory, "server.json")
	write(configPath, configData, 0600)
	logPath := filepath.Join(directory, "process.log")
	log, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	var process *exec.Cmd
	var exited chan struct{}
	stop := func(signal os.Signal) {
		t.Helper()
		if process == nil {
			return
		}
		_ = process.Process.Signal(signal)
		select {
		case <-exited:
		case <-time.After(5 * time.Second):
			_ = process.Process.Kill()
			<-exited
		}
		process = nil
	}
	defer func() { stop(syscall.SIGTERM) }()
	start := func() {
		t.Helper()
		if process != nil {
			t.Fatal("proof attempted to adopt an existing process")
		}
		process = exec.CommandContext(ctx, binary, "server", "-config", configPath, "-log-level=error")
		process.Env = []string{"PATH=/usr/bin:/bin", "GOMAXPROCS=2", "TZ=UTC"}
		process.Dir, process.Stdout, process.Stderr = directory, log, log
		if process.Start() != nil {
			t.Fatal("cannot start owned official static-seal process")
		}
		exited = make(chan struct{})
		active, done := process, exited
		go func() { _ = active.Wait(); close(done) }()
	}
	_ = apiReservation.Close()
	_ = clusterReservation.Close()
	start()
	var client *http.Client
	wait := func(ready bool) StaticObservation {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) && ctx.Err() == nil {
			select {
			case <-exited:
				t.Fatal("official static-seal process exited before readiness")
			default:
			}
			if client == nil {
				client, _ = newClientAt(socket, currentOwner())
			}
			if client != nil {
				if observation, err := staticStatus(ctx, client, ready); err == nil {
					return observation
				}
			}
			time.Sleep(25 * time.Millisecond)
		}
		t.Fatal("official static-seal readiness exceeded its bound")
		return StaticObservation{}
	}
	fresh := wait(false)
	defer func() {
		if client != nil {
			closeClient(client)
		}
	}()
	if fresh.Initialized || fresh.UnsealedReady || !fresh.Sealed {
		t.Fatal("fresh static-seal node was already initialized")
	}
	recorder := &recordingTransport{base: client.Transport}
	initializer := *client
	initializer.Transport = recorder
	receipt, err := initializeStaticAt(ctx, testInstallation, testAttempt, paths, currentOwner(), &initializer)
	if err != nil {
		t.Fatalf("actual static initialization core refused official responses after %v", recorder.operations)
	}
	if !receipt.UnsealedReady || receipt.ClusterID == "" {
		t.Fatal("static initialization did not become ready without unseal")
	}
	before := len(recorder.operations)
	if _, err := initializeStaticAt(ctx, testInstallation, testAttempt, paths, currentOwner(), &initializer); err == nil || len(recorder.operations) != before {
		t.Fatal("static initialization was replayed")
	}
	initCalls := 0
	for _, operation := range recorder.operations {
		if operation == "POST /v1/sys/init" {
			initCalls++
		} else if operation != "GET /v1/sys/seal-status" {
			t.Fatal("static initialization performed an unseal or unrelated operation")
		}
	}
	if initCalls != 1 {
		t.Fatal("static initialization did not have exactly one initial request")
	}
	rootBytes, err := os.ReadFile(filepath.Join(paths.state, "root.token"))
	if err != nil {
		t.Fatal(err)
	}
	root := string(rootBytes)
	policy := "path \"auth/token/lookup-self\" { capabilities = [\"read\"] }\npath \"sys/seal\" { capabilities = [\"update\", \"sudo\"] }\n"
	if apiRequest(ctx, client, http.MethodPut, "sys/policies/acl/static-proof", root, map[string]string{"policy": policy}, nil) != nil {
		t.Fatal("cannot create narrowly scoped proof authority")
	}
	var login struct {
		Auth struct {
			Token string `json:"client_token"`
		} `json:"auth"`
	}
	if apiRequest(ctx, client, http.MethodPost, "auth/token/create", root, map[string]any{
		"policies": []string{"static-proof"}, "no_default_policy": true, "no_parent": true,
		"ttl": "10m", "explicit_max_ttl": "10m", "renewable": false,
	}, &login) != nil || login.Auth.Token == "" {
		t.Fatal("cannot create short-lived proof token")
	}
	if apiRequest(ctx, client, http.MethodPost, "auth/token/revoke-self", root, nil, nil) != nil {
		t.Fatal("cannot retire proof bootstrap root")
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, Endpoint+"/v1/auth/token/lookup-self", nil)
	request.Header.Set("X-Vault-Token", root)
	denied, err := client.Do(request)
	if err != nil || denied.StatusCode != http.StatusForbidden {
		t.Fatal("bootstrap root retirement was not verified")
	}
	denied.Body.Close()
	root = ""
	for _, name := range []string{"root.token", "recovery.key"} {
		if os.Remove(filepath.Join(paths.state, name)) != nil {
			t.Fatal("cannot remove fixture-only initialization authority before restart")
		}
	}
	// Readiness must respect a deliberate API seal; it cannot submit recovery
	// shares. Host security-seal intent separately governs permission to restart.
	if apiRequest(ctx, client, http.MethodPut, "sys/seal", login.Auth.Token, nil, nil) != nil {
		t.Fatal("cannot apply scoped proof seal")
	}
	for i := 0; i < 3; i++ {
		status, err := staticStatus(ctx, client, true)
		if err == nil || !status.Initialized || !status.Sealed || status.UnsealedReady {
			t.Fatal("readiness changed or misreported a deliberately sealed node")
		}
	}
	stop(syscall.SIGKILL)
	start()
	restarted := wait(true)
	if restarted.ClusterID != receipt.ClusterID || apiRequest(ctx, client, http.MethodGet, "auth/token/lookup-self", login.Auth.Token, nil, &map[string]any{}) != nil {
		t.Fatal("Raft identity or scoped authentication did not survive static auto-unseal")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", address, &tls.Config{
		RootCAs: pool, ServerName: "openbao", MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal("verified TCP did not recover after process restart")
	}
	connection.Close()
	stop(syscall.SIGTERM)
	if os.Rename(keyPath, keyPath+".retained") != nil {
		t.Fatal("cannot withhold fixture static seal key")
	}
	for _, failure := range []string{"missing", "malformed", "wrong"} {
		if failure == "malformed" {
			write(keyPath, key[:31], 0600)
		} else if failure == "wrong" {
			wrong := make([]byte, 32)
			_, _ = rand.Read(wrong)
			write(keyPath, wrong, 0600)
		}
		start()
		if failure != "wrong" {
			select {
			case <-exited:
			case <-time.After(5 * time.Second):
				t.Fatal("missing or malformed static key did not stop startup")
			}
		} else {
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				if status, err := staticStatus(ctx, client, true); err == nil || status.UnsealedReady {
					t.Fatal("wrong static key opened the retained Raft state")
				}
				time.Sleep(50 * time.Millisecond)
			}
		}
		stop(syscall.SIGTERM)
		_ = os.Remove(keyPath)
	}
	if os.Rename(keyPath+".retained", keyPath) != nil {
		t.Fatal("cannot restore original fixture seal key")
	}
	start()
	if wait(true).ClusterID != receipt.ClusterID || apiRequest(ctx, client, http.MethodGet, "auth/token/lookup-self", login.Auth.Token, nil, &map[string]any{}) != nil {
		t.Fatal("restoring the original static key did not recover the same Raft state")
	}
	stop(syscall.SIGTERM)
	logs, err := os.ReadFile(logPath)
	if err != nil || bytes.Contains(logs, key) || bytes.Contains(logs, []byte(hex.EncodeToString(key))) || bytes.Contains(logs, []byte(base64.StdEncoding.EncodeToString(key))) || bytes.Contains(logs, rootBytes) {
		t.Fatal("private proof material appeared in process output")
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
		"schema": "elevenid.openbao-static-seal-proof/v1", "binary_version": strings.TrimSpace(string(version)), "binary_sha256": fmt.Sprintf("%x", hash.Sum(nil)),
		"actual_static_init_core": true, "initialization_calls": initCalls, "unseal_api_calls": 0,
		"static_key_bytes": len(key), "raft_restart_after_sigkill": true, "same_cluster": true, "scoped_token_survived": true,
		"bootstrap_root_revoked": true, "recovery_key_used_for_restart": false, "manual_seal_unmodified_by_readiness": true,
		"missing_key_fail_closed": true, "malformed_key_fail_closed": true, "wrong_key_not_ready": true, "original_key_restores_access": true,
		"verified_tcp_after_restart": true, "tls_verification_disabled": false, "seal_key_in_args_env_or_logs": false,
		"container_image_qualified": false, "production_projection_qualified": false, "customer_reboot_qualified": false,
	})
	t.Log(string(evidence))
}
