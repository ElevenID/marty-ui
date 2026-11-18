//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
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

// A new, disposable destination needs its own temporary bootstrap so the
// documented authenticated restore API can run. It is never an initialization
// replay against retained source/customer state, or an offline archive unpack.
type restoreNode struct {
	directory, state, tls, identity, socket, keyPath string
	process                                          *exec.Cmd
	exited                                           chan struct{}
	client                                           *http.Client
	log                                              *os.File
}

func startRestoreNode(t *testing.T, ctx context.Context, binary, directory string, sealKey, caPEM, caKeyPEM, nodePEM []byte) *restoreNode {
	t.Helper()
	node := &restoreNode{directory: directory, state: filepath.Join(directory, "data"), tls: filepath.Join(directory, "tls"), identity: filepath.Join(directory, "identity")}
	control := filepath.Join(directory, "control")
	for _, path := range []string{directory, node.state, node.tls, node.identity, control, filepath.Join(directory, "initialization"), filepath.Join(directory, "seal")} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal("cannot create isolated restore directory")
		}
	}
	node.keyPath = filepath.Join(directory, "seal", "static.key")
	for _, file := range []struct {
		path string
		data []byte
		mode os.FileMode
	}{
		{node.keyPath, sealKey, 0600}, {filepath.Join(node.tls, "ca.crt"), caPEM, 0644}, {filepath.Join(node.tls, "ca.key"), caKeyPEM, 0600}, {filepath.Join(node.tls, "server.pem"), nodePEM, 0600},
	} {
		if os.WriteFile(file.path, file.data, file.mode) != nil {
			t.Fatal("cannot write private restore fixture")
		}
	}
	api, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	cluster, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cluster.Close()
	node.socket = filepath.Join(control, "api.sock")
	config := map[string]any{
		"disable_mlock": true, "ui": false, "api_addr": "https://" + api.Addr().String(), "cluster_addr": "https://" + cluster.Addr().String(),
		"storage": map[string]any{"raft": map[string]any{"path": node.state, "node_id": "isolated-restore-node"}},
		"seal":    map[string]any{"static": map[string]any{"current_key_id": "marty-selfhost-static-v1", "current_key": "file://" + node.keyPath}},
		"listener": []any{
			map[string]any{"unix": map[string]any{"address": node.socket, "socket_mode": "0600", "socket_user": fmt.Sprint(os.Geteuid()), "socket_group": fmt.Sprint(os.Getegid())}},
			map[string]any{"tcp": map[string]any{"address": api.Addr().String(), "cluster_address": cluster.Addr().String(), "tls_cert_file": filepath.Join(node.tls, "server.pem"), "tls_key_file": filepath.Join(node.tls, "server.pem"), "tls_min_version": "tls12"}},
		},
	}
	data, _ := json.Marshal(config)
	configPath := filepath.Join(directory, "server.json")
	if os.WriteFile(configPath, data, 0600) != nil {
		t.Fatal("cannot write restore configuration")
	}
	node.log, err = os.OpenFile(filepath.Join(directory, "process.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	node.process = exec.CommandContext(ctx, binary, "server", "-config", configPath, "-log-level=error")
	node.process.Env = []string{"PATH=/usr/bin:/bin", "GOMAXPROCS=2", "TZ=UTC"}
	node.process.Dir, node.process.Stdout, node.process.Stderr = directory, node.log, node.log
	_ = api.Close()
	_ = cluster.Close()
	if node.process.Start() != nil {
		node.log.Close()
		t.Fatal("cannot start isolated owned restore process")
	}
	node.exited = make(chan struct{})
	active := node.process
	go func() { _ = active.Wait(); close(node.exited) }()
	t.Cleanup(func() {
		node.stop(t)
		if node.client != nil {
			closeClient(node.client)
		}
		node.log.Close()
	})
	node.wait(t, ctx, func(status StaticObservation) bool { return !status.Initialized && status.Sealed })
	return node
}
func (node *restoreNode) stop(t *testing.T) {
	t.Helper()
	if node.process == nil {
		return
	}
	_ = node.process.Process.Signal(syscall.SIGTERM)
	select {
	case <-node.exited:
	case <-time.After(5 * time.Second):
		_ = node.process.Process.Kill()
		<-node.exited
	}
	node.process = nil
}
func (node *restoreNode) wait(t *testing.T, ctx context.Context, predicate func(StaticObservation) bool) StaticObservation {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		select {
		case <-node.exited:
			t.Fatal("owned restore process exited early")
		default:
		}
		if node.client == nil {
			node.client, _ = newClientAt(node.socket, currentOwner())
		}
		if node.client != nil {
			status, err := staticStatus(ctx, node.client, false)
			if err == nil && predicate(status) {
				return status
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("isolated restore observation exceeded its bound")
	return StaticObservation{}
}
func (node *restoreNode) initialize(t *testing.T, ctx context.Context, installation, attempt string) (StaticInitReceipt, string) {
	t.Helper()
	initializationClient, err := newStaticInitClientAt(node.socket, currentOwner())
	if err != nil {
		t.Fatal("fresh disposable initialization client refused")
	}
	defer closeClient(initializationClient)
	receipt, err := initializeStaticAt(ctx, installation, attempt, staticInitPaths{state: node.state, output: filepath.Join(node.directory, "initialization"), root: currentOwner()}, currentOwner(), node.client, initializationClient)
	if err != nil {
		t.Fatal("fresh disposable node initialization failed")
	}
	root, err := os.ReadFile(filepath.Join(node.state, "root.token"))
	if err != nil {
		t.Fatal("temporary root input unavailable")
	}
	return receipt, string(root)
}

type restoreRole struct{ role, secret string }

func makeRestoreRole(t *testing.T, ctx context.Context, client *http.Client, root, name, policy string) restoreRole {
	t.Helper()
	if apiRequest(ctx, client, http.MethodPut, "sys/policies/acl/"+name, root, map[string]string{"policy": policy}, nil) != nil ||
		apiRequest(ctx, client, http.MethodPost, "auth/restore-proof/role/"+name, root, map[string]any{"token_policies": []string{name}, "token_no_default_policy": true, "token_ttl": 300, "token_max_ttl": 300, "token_explicit_max_ttl": 300, "secret_id_ttl": 0, "secret_id_num_uses": 0}, nil) != nil {
		t.Fatal("cannot create narrowly scoped restore proof role")
	}
	var role struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	var secret struct {
		Data struct {
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	if apiRequest(ctx, client, http.MethodGet, "auth/restore-proof/role/"+name+"/role-id", root, nil, &role) != nil ||
		apiRequest(ctx, client, http.MethodPost, "auth/restore-proof/role/"+name+"/secret-id", root, map[string]any{}, &secret) != nil || !uuidPattern.MatchString(role.Data.RoleID) || !uuidPattern.MatchString(secret.Data.SecretID) {
		t.Fatal("cannot provision durable scoped restore credentials")
	}
	return restoreRole{role.Data.RoleID, secret.Data.SecretID}
}
func (role restoreRole) login(t *testing.T, ctx context.Context, client *http.Client) string {
	t.Helper()
	var response struct {
		Auth struct {
			Token    string   `json:"client_token"`
			Policies []string `json:"policies"`
		} `json:"auth"`
	}
	if apiRequest(ctx, client, http.MethodPost, "auth/restore-proof/login", "", map[string]string{"role_id": role.role, "secret_id": role.secret}, &response) != nil || len(response.Auth.Token) < 20 || len(response.Auth.Policies) != 1 || response.Auth.Policies[0] == "root" {
		t.Fatal("restored scoped AppRole could not authenticate")
	}
	return response.Auth.Token
}
func requireRejectedRoot(t *testing.T, ctx context.Context, client *http.Client, root string) {
	t.Helper()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, Endpoint+"/v1/auth/token/lookup-self", nil)
	request.Header.Set("X-Vault-Token", root)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("cannot verify retired root rejection")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatal("retired or displaced root remained valid")
	}
}
func snapshotRequest(t *testing.T, ctx context.Context, client *http.Client, method, token string, snapshot []byte) (int, []byte) {
	t.Helper()
	request, _ := http.NewRequestWithContext(ctx, method, Endpoint+"/v1/sys/storage/raft/snapshot", bytes.NewReader(snapshot))
	request.Header.Set("X-Vault-Token", token)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("bounded normal snapshot API request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 8*1024*1024+1))
	if err != nil || len(data) > 8*1024*1024 {
		t.Fatal("snapshot response exceeded proof bound")
	}
	return response.StatusCode, data
}
func transitIdentity(t *testing.T, ctx context.Context, client *http.Client, token string) (string, string) {
	t.Helper()
	var info struct {
		Data struct {
			Type           string `json:"type"`
			Exportable     bool   `json:"exportable"`
			AllowPlaintext bool   `json:"allow_plaintext_backup"`
			Keys           map[string]struct {
				Public string `json:"public_key"`
			} `json:"keys"`
		} `json:"data"`
	}
	if apiRequest(ctx, client, http.MethodGet, "proof-transit/keys/acme-account", token, nil, &info) != nil || info.Data.Type != "ecdsa-p256" || info.Data.Exportable || info.Data.AllowPlaintext || len(info.Data.Keys) != 1 {
		t.Fatal("transit key custody differs")
	}
	public := info.Data.Keys["1"].Public
	block, rest := pem.Decode([]byte(public))
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("transit public key invalid")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if err != nil || !ok {
		t.Fatal("transit public key is not ECDSA")
	}
	input := []byte("Marty isolated restore identity proof")
	var signed struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if apiRequest(ctx, client, http.MethodPost, "proof-transit/sign/acme-account", token, map[string]any{"input": base64.StdEncoding.EncodeToString(input), "hash_algorithm": "sha2-256"}, &signed) != nil {
		t.Fatal("scoped transit signing failed")
	}
	encoded, ok := strings.CutPrefix(signed.Data.Signature, "vault:v1:")
	signature, err := base64.StdEncoding.DecodeString(encoded)
	digest := sha256.Sum256(input)
	if !ok || err != nil || !ecdsa.VerifyASN1(ecdsaKey, digest[:], signature) {
		t.Fatal("transit proof signature did not match retained public key")
	}
	return fingerprint(block.Bytes), public
}

func TestOfficialOpenBao255StaticSnapshotRestorePreservesAuthorities(t *testing.T) {
	binary := os.Getenv("MARTY_OPENBAO_UNIX_PROOF_BINARY")
	if binary == "" {
		t.Skip("set MARTY_OPENBAO_UNIX_PROOF_BINARY to verified official OpenBao2.5.5")
	}
	if !filepath.IsAbs(binary) || filepath.Clean(binary) != binary {
		t.Fatal("official binary path must be absolute")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	version, err := exec.CommandContext(ctx, binary, "version").Output()
	if err != nil || !strings.HasPrefix(string(version), "OpenBao v2.5.5 ") {
		t.Fatal("restore proof requires official OpenBao2.5.5")
	}
	binaryFile, err := os.Open(binary)
	if err != nil {
		t.Fatal("cannot fingerprint the selected restore-proof binary")
	}
	binaryHash := sha256.New()
	_, hashErr := io.Copy(binaryHash, binaryFile)
	closeErr := binaryFile.Close()
	if hashErr != nil || closeErr != nil {
		t.Fatal("cannot fingerprint the selected restore-proof binary")
	}
	// sockaddr_un paths are bounded independently of filesystem path limits.
	// Keep the isolated root short; the full Go test name exceeds that bound.
	rootDir, err := os.MkdirTemp("", "bao-restore-")
	if err != nil {
		t.Fatal("cannot create private restore fixture root")
	}
	t.Cleanup(func() { _ = os.RemoveAll(rootDir) })
	sealKey := make([]byte, 32)
	if _, err := rand.Read(sealKey); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caKey, nodeKey := testKey(t), testKey(t)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Marty restore proof CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	ca := testCertificate(t, template, template, &caKey.PublicKey, caKey)
	leaf := testCertificate(t, testLeaf(now, 2, now.Add(24*time.Hour)), ca, &nodeKey.PublicKey, caKey)
	caDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	nodeDER, _ := x509.MarshalPKCS8PrivateKey(nodeKey)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caDER})
	nodePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: nodeDER})...)
	source := startRestoreNode(t, ctx, binary, filepath.Join(rootDir, "source"), sealKey, caPEM, caKeyPEM, nodePEM)
	initialized, root := source.initialize(t, ctx, testInstallation, testAttempt)
	recoveryBackup, err := os.ReadFile(filepath.Join(source.state, "recovery.key"))
	if err != nil {
		t.Fatal("source recovery share backup unavailable")
	}
	enrollment, err := enrollAt(ctx, testInstallation, testAttempt, enrollmentPaths{state: source.state, tls: source.tls, identity: source.identity, root: currentOwner()}, currentOwner(), source.client, time.Now())
	if err != nil || enrollment.ClusterID != initialized.ClusterID {
		t.Fatal("source recovery enrollment failed")
	}
	if apiRequest(ctx, source.client, http.MethodPost, "sys/mounts/proof-transit", root, map[string]string{"type": "transit"}, nil) != nil ||
		apiRequest(ctx, source.client, http.MethodPost, "proof-transit/keys/acme-account", root, map[string]any{"type": "ecdsa-p256", "exportable": false, "allow_plaintext_backup": false}, nil) != nil ||
		apiRequest(ctx, source.client, http.MethodPost, "sys/auth/restore-proof", root, map[string]string{"type": "approle"}, nil) != nil {
		t.Fatal("cannot establish source signing authority")
	}
	snapshotRole := makeRestoreRole(t, ctx, source.client, root, "snapshot-proof", "path \"sys/storage/raft/snapshot\" { capabilities = [\"read\",\"sudo\"] }\n")
	signingRole := makeRestoreRole(t, ctx, source.client, root, "signing-proof", "path \"proof-transit/keys/acme-account\" { capabilities = [\"read\"] }\npath \"proof-transit/sign/acme-account\" { capabilities = [\"update\"] }\n")
	sourceSigner := signingRole.login(t, ctx, source.client)
	sourceSPKI, sourcePublic := transitIdentity(t, ctx, source.client, sourceSigner)
	retirementPaths := rootRetirementPaths{state: source.state, identity: source.identity, root: currentOwner(), checkpoint: func(point string) error {
		if point == "retirement-revoke-requested" {
			return errRetirement
		}
		return nil
	}}
	if _, err := retireInitialRootAt(ctx, testInstallation, testSecret, strings.Repeat("a", 64), retirementPaths, currentOwner(), source.client); err == nil {
		t.Fatal("retirement did not retain a lost-revoke-result attempt")
	}
	retirementPaths.checkpoint = nil
	retired, err := retireInitialRootAt(ctx, testInstallation, testSecret, strings.Repeat("a", 64), retirementPaths, currentOwner(), source.client)
	if err != nil || !retired.RootRejectionObserved || !retired.RootTokenRemoved || !retired.RecoveryKeyPreserved || !retired.OriginalAuthorityVerified {
		t.Fatal("actual source root retirement core did not resume")
	}
	requireRejectedRoot(t, ctx, source.client, root)
	if _, err := os.Lstat(filepath.Join(source.state, "root.token")); !os.IsNotExist(err) {
		t.Fatal("retirement left a bootstrap root file")
	}
	// Snapshot after retirement; otherwise restoring an older snapshot can
	// restore old token state. The backup role has no write/restore authority.
	status, snapshot := snapshotRequest(t, ctx, source.client, http.MethodGet, snapshotRole.login(t, ctx, source.client), nil)
	if status != http.StatusOK || len(snapshot) == 0 {
		t.Fatal("scoped snapshot acquisition failed")
	}
	snapshotFile := filepath.Join(rootDir, "retained.snap")
	if os.WriteFile(snapshotFile, snapshot, 0600) != nil {
		t.Fatal("cannot retain private snapshot fixture")
	}
	source.stop(t)

	// A valid but different static key cannot pass the normal sealed-hash check.
	wrongKey := make([]byte, 32)
	_, _ = rand.Read(wrongKey)
	wrong := startRestoreNode(t, ctx, binary, filepath.Join(rootDir, "wrong-key-destination"), wrongKey, caPEM, caKeyPEM, nodePEM)
	wrongInit, wrongRoot := wrong.initialize(t, ctx, testRole, testSecret)
	status, _ = snapshotRequest(t, ctx, wrong.client, http.MethodPost, wrongRoot, snapshot)
	if status != http.StatusBadRequest {
		t.Fatal("normal restore did not reject a different static key")
	}
	if got := wrong.wait(t, ctx, func(v StaticObservation) bool { return v.UnsealedReady }); got.ClusterID != wrongInit.ClusterID {
		t.Fatal("rejected snapshot altered destination identity")
	}
	wrong.stop(t)

	destination := startRestoreNode(t, ctx, binary, filepath.Join(rootDir, "restored"), sealKey, caPEM, caKeyPEM, nodePEM)
	disposableInit, disposableRoot := destination.initialize(t, ctx, testRole, testIssuer)
	if disposableInit.ClusterID == initialized.ClusterID {
		t.Fatal("destination was not an independent empty bootstrap")
	}
	status, _ = snapshotRequest(t, ctx, destination.client, http.MethodPost, disposableRoot, snapshot)
	if status != http.StatusOK && status != http.StatusNoContent {
		t.Fatal("normal exact-key snapshot restore failed")
	}
	destination.wait(t, ctx, func(v StaticObservation) bool { return v.UnsealedReady && v.ClusterID == initialized.ClusterID })
	requireRejectedRoot(t, ctx, destination.client, root)
	requireRejectedRoot(t, ctx, destination.client, disposableRoot)
	if os.Remove(filepath.Join(destination.state, "root.token")) != nil {
		t.Fatal("cannot discard disposable destination bootstrap root")
	}
	// The destination bootstrap share is obsolete after the source snapshot is
	// installed. Restore the original protected recovery-share backup separately.
	if os.Remove(filepath.Join(destination.state, "recovery.key")) != nil || os.WriteFile(filepath.Join(destination.state, "recovery.key"), recoveryBackup, 0400) != nil {
		t.Fatal("cannot restore original protected recovery share")
	}
	restoredSPKI, restoredPublic := transitIdentity(t, ctx, destination.client, signingRole.login(t, ctx, destination.client))
	if restoredSPKI != sourceSPKI || restoredPublic != sourcePublic {
		t.Fatal("restored nonexportable transit identity changed")
	}
	// Retained external identity/TLS files are independent backup inputs; Raft
	// does not contain these files. Copy only that exact private fixture bundle.
	for _, name := range []string{"recovery.json", "enrollment-pending.json", "enrollment-result.json"} {
		data, err := os.ReadFile(filepath.Join(source.identity, name))
		if err != nil {
			t.Fatal("retained scoped identity unavailable")
		}
		mode := os.FileMode(0600)
		if name == "recovery.json" {
			mode = 0400
		}
		if os.WriteFile(filepath.Join(destination.identity, name), data, mode) != nil {
			t.Fatal("cannot restore retained scoped identity fixture")
		}
	}
	paths := recoveryPaths{identity: destination.identity, tls: destination.tls, root: currentOwner()}
	identityBytes, _ := os.ReadFile(filepath.Join(destination.identity, "recovery.json"))
	identity, err := parseIdentity(identityBytes, testInstallation)
	if err != nil {
		t.Fatal("restored local identity is malformed")
	}
	token, err := scopedToken(ctx, destination.client, identity)
	if err != nil {
		t.Fatal("restored recovery AppRole could not log in")
	}
	var issuer struct {
		Data struct {
			IssuerID    string `json:"issuer_id"`
			Certificate string `json:"certificate"`
		} `json:"data"`
	}
	issuerErr := apiRequest(ctx, destination.client, http.MethodGet, issuerPrefix+enrollment.IssuerID, token, nil, &issuer)
	issuerCertificate, certificateErr := oneCertificate([]byte(issuer.Data.Certificate))
	if issuerErr != nil || certificateErr != nil || issuer.Data.IssuerID != enrollment.IssuerID || !bytes.Equal(issuerCertificate.Raw, ca.Raw) {
		t.Fatal("restored issuer identity differs")
	}
	revokeKnownToken(destination.client, token)
	recovered, err := recoverAt(ctx, testInstallation, replacementAttempt, paths, currentOwner(), destination.client, time.Now())
	if err != nil || recovered.ClusterID != initialized.ClusterID || recovered.IssuerID != enrollment.IssuerID || recovered.CASHA256 != enrollment.CASHA256 || recovered.SPKISHA256 != enrollment.SPKISHA256 || !recovered.NodeKeyPreserved {
		t.Fatal("restored scoped issuer could not recover the same node key")
	}
	status, again := snapshotRequest(t, ctx, destination.client, http.MethodGet, snapshotRole.login(t, ctx, destination.client), nil)
	if status != http.StatusOK || len(again) == 0 {
		t.Fatal("restored snapshot authority cannot obtain a new backup")
	}
	destination.stop(t)
	for _, node := range []*restoreNode{source, wrong, destination} {
		logs, _ := os.ReadFile(filepath.Join(node.directory, "process.log"))
		for _, private := range [][]byte{sealKey, []byte(hex.EncodeToString(sealKey)), []byte(base64.StdEncoding.EncodeToString(sealKey)), []byte(root), []byte(disposableRoot), []byte(wrongRoot), []byte(snapshotRole.secret), []byte(signingRole.secret)} {
			if len(private) > 0 && bytes.Contains(logs, private) {
				t.Fatal("private restore material appeared in process output")
			}
		}
	}
	evidence, _ := json.Marshal(map[string]any{
		"schema": "elevenid.openbao-static-restore-proof/v1", "binary_version": strings.TrimSpace(string(version)), "binary_sha256": hex.EncodeToString(binaryHash.Sum(nil)), "source_initialization_calls": 1, "disposable_destination_initialization_calls": 2,
		"source_stopped_before_restore": true, "fresh_destination_only": true, "normal_snapshot_endpoint": true, "force_restore_used": false, "exact_static_key_required": true, "wrong_key_rejected_without_restore": true,
		"source_cluster_restored": true, "source_issuer_restored": true, "source_nonexportable_transit_spki_restored": true, "source_scoped_credentials_restored": true, "source_revoked_root_remains_rejected": true,
		"actual_root_retirement_core": true, "lost_revoke_result_reconciled": true, "original_recovery_share_restored_separately": true,
		"disposable_bootstrap_root_rejected_after_restore": true, "restored_scoped_local_recovery_succeeded": true, "restored_snapshot_authority_succeeded": true,
		"external_tls_and_approle_files_restored_separately": true, "imported_control_ca_nonexportable": false, "retained_customer_initialization_replayed": false,
		"container_image_qualified": false, "customer_backup_transport_qualified": false, "customer_restore_qualified": false,
	})
	t.Log(string(evidence))
}
