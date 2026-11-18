//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

var errEnrollment = errors.New("OpenBao control enrollment refused; preserve the pending setup and private outputs")

type enrollmentPaths struct {
	state, tls, identity string
	root                 owner
	readOnly             bool
}

// EnrollmentReceipt records the fresh setup result without private keys,
// credentials or authority to replay the setup transaction.
type EnrollmentReceipt struct {
	Schema                    string `json:"schema"`
	InstallationID            string `json:"installation_id"`
	AttemptID                 string `json:"attempt_id"`
	ClusterID                 string `json:"cluster_id"`
	IssuerID                  string `json:"issuer_id"`
	CASHA256                  string `json:"ca_sha256"`
	SPKISHA256                string `json:"spki_sha256"`
	PolicySHA256              string `json:"policy_sha256"`
	ScopedLoginVerified       bool   `json:"scoped_login_verified"`
	ScopedSigningVerified     bool   `json:"scoped_signing_verified"`
	ForbiddenOperationsDenied bool   `json:"forbidden_operations_denied"`
	VerificationTokenRevoked  bool   `json:"verification_token_revoked"`
	ExistingCAKeyRetained     bool   `json:"existing_ca_key_retained"`
	NodeKeyPreserved          bool   `json:"node_key_preserved"`
	RootRetired               bool   `json:"root_retired"`
}

type enrollmentIntent struct {
	Schema                string `json:"schema"`
	InstallationID        string `json:"installation_id"`
	AttemptID             string `json:"attempt_id"`
	ClusterID             string `json:"cluster_id"`
	CASHA256              string `json:"ca_sha256"`
	SPKISHA256            string `json:"spki_sha256"`
	RootRetired           bool   `json:"root_retired"`
	ExistingCAKeyRetained bool   `json:"existing_ca_key_retained"`
}

func requireEnrollment(output *os.File, root owner, readOnly bool, identity recoveryIdentity) (retainedFile, retainedFile, error) {
	pending, err := readFile(output, "enrollment-pending.json", root, []uint32{0600}, 8192, readOnly)
	if err != nil {
		return retainedFile{}, retainedFile{}, errEnrollment
	}
	completed, err := readFile(output, "enrollment-result.json", root, []uint32{0600}, 16384, readOnly)
	if err != nil {
		return retainedFile{}, retainedFile{}, errEnrollment
	}
	var intent enrollmentIntent
	var result EnrollmentReceipt
	if decodeJSON(pending.bytes, &intent, true) != nil || decodeJSON(completed.bytes, &result, true) != nil ||
		!requiredFalse(pending.bytes, "root_retired") || !requiredFalse(completed.bytes, "root_retired") ||
		intent.Schema != "elevenid.openbao-control-enrollment-intent/v1" || result.Schema != "elevenid.openbao-control-enrollment-result/v1" ||
		intent.InstallationID != identity.InstallationID || result.InstallationID != identity.InstallationID ||
		intent.ClusterID != identity.ClusterID || result.ClusterID != identity.ClusterID ||
		result.IssuerID != identity.IssuerID || intent.AttemptID != result.AttemptID || !uuidPattern.MatchString(result.AttemptID) ||
		intent.CASHA256 != identity.CASHA256 || result.CASHA256 != identity.CASHA256 ||
		intent.SPKISHA256 != identity.SPKISHA256 || result.SPKISHA256 != identity.SPKISHA256 ||
		result.PolicySHA256 != fingerprint([]byte(controlPolicy(identity.IssuerID))) ||
		intent.RootRetired || !intent.ExistingCAKeyRetained || result.RootRetired ||
		!result.ScopedLoginVerified || !result.ScopedSigningVerified || !result.ForbiddenOperationsDenied ||
		!result.VerificationTokenRevoked || !result.ExistingCAKeyRetained || !result.NodeKeyPreserved {
		return retainedFile{}, retainedFile{}, errEnrollment
	}
	return pending, completed, nil
}

func requiredFalse(data []byte, name string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return false
	}
	value, exists := fields[name]
	return exists && bytes.Equal(bytes.TrimSpace(value), []byte("false"))
}

// Enroll runs only in the fresh, owned setup job. The complete /bao/data bind
// must be read-only; only the empty control-identity output is writable.
func Enroll(ctx context.Context, installationID, attemptID string) (EnrollmentReceipt, error) {
	if os.Geteuid() != 0 || !uuidPattern.MatchString(installationID) || !uuidPattern.MatchString(attemptID) {
		return EnrollmentReceipt{}, errEnrollment
	}
	expected, err := imageOwner()
	if err != nil {
		return EnrollmentReceipt{}, errEnrollment
	}
	client, err := NewClient()
	if err != nil {
		return EnrollmentReceipt{}, errEnrollment
	}
	defer closeClient(client)
	return enrollAt(ctx, installationID, attemptID, enrollmentPaths{
		state: "/bao/data", tls: tlsDirectory, identity: identityDirectory, root: owner{0, 0}, readOnly: true,
	}, expected, client, time.Now())
}

func controlPolicy(issuerID string) string {
	return fmt.Sprintf("path %q { capabilities = [\"read\"] }\n", issuerPrefix+issuerID) +
		"path \"auth/token/lookup-self\" { capabilities = [\"read\"] }\n" +
		"path \"auth/token/revoke-self\" { capabilities = [\"update\"] }\n" +
		fmt.Sprintf("path %q {\n capabilities = [\"update\"]\n", issuerPrefix+issuerID+"/sign/"+signingRole) +
		" required_parameters = [\"csr\", \"common_name\", \"alt_names\", \"ip_sans\", \"ttl\", \"format\", \"exclude_cn_from_sans\"]\n" +
		" allowed_parameters = {\n \"csr\" = []\n \"common_name\" = [\"openbao\"]\n" +
		" \"alt_names\" = [\"openbao,host.docker.internal,localhost\"]\n \"ip_sans\" = [\"127.0.0.1\"]\n" +
		" \"ttl\" = [\"720h\"]\n \"format\" = [\"pem\"]\n \"exclude_cn_from_sans\" = [true]\n }\n}\n"
}

func responseStatus(ctx context.Context, client *http.Client, method, path, token string, payload any) (int, error) {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil || len(body) > 65536 {
			return 0, errEnrollment
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, Endpoint+"/v1/"+path, bytes.NewReader(body))
	if err != nil {
		return 0, errEnrollment
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("X-Vault-Token", token)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, errEnrollment
	}
	defer response.Body.Close()
	return response.StatusCode, nil
}

func absentAuthorities(ctx context.Context, client *http.Client, root string) error {
	for _, item := range []struct{ path, key string }{
		{"sys/mounts", "selfhost-control-pki/"}, {"sys/auth", "selfhost-control/"},
	} {
		var result struct {
			Data map[string]json.RawMessage `json:"data"`
		}
		if apiRequest(ctx, client, http.MethodGet, item.path, root, nil, &result) != nil || result.Data == nil {
			return errEnrollment
		}
		if _, exists := result.Data[item.key]; exists {
			return errEnrollment
		}
	}
	status, err := responseStatus(ctx, client, http.MethodGet, "sys/policies/acl/"+recoveryPolicy, root, nil)
	if err != nil || status != http.StatusNotFound {
		return errEnrollment
	}
	return nil
}

func exactStrings(value any, expected []string) bool {
	items, ok := value.([]any)
	if !ok || len(items) != len(expected) {
		return false
	}
	actual := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return false
		}
		actual = append(actual, text)
	}
	slices.Sort(actual)
	wanted := append([]string(nil), expected...)
	slices.Sort(wanted)
	return slices.Equal(actual, wanted)
}

func signingRoleParameters(issuerID string) map[string]any {
	return map[string]any{
		"issuer_ref":         issuerID,
		"allowed_domains":    []string{"openbao", "host.docker.internal", "localhost"},
		"allow_bare_domains": true, "allow_subdomains": false, "allow_glob_domains": false,
		"allow_any_name": false, "allow_localhost": true, "allow_ip_sans": true, "allow_wildcard_certificates": false,
		"enforce_hostnames": true, "require_cn": true, "server_flag": true, "client_flag": false,
		"code_signing_flag": false, "email_protection_flag": false,
		"key_type": "ec", "key_bits": 256, "key_usage": []string{"DigitalSignature"},
		"ttl": "720h", "max_ttl": "720h", "use_csr_common_name": false, "use_csr_sans": false, "no_store": true,
	}
}

func requireSigningRole(data map[string]any, issuerID string) error {
	if data["issuer_ref"] != issuerID || data["key_type"] != "ec" || data["key_bits"] != float64(256) ||
		data["ttl"] != float64(2592000) || data["max_ttl"] != float64(2592000) ||
		!exactStrings(data["allowed_domains"], []string{"openbao", "host.docker.internal", "localhost"}) ||
		!exactStrings(data["key_usage"], []string{"DigitalSignature"}) {
		return errEnrollment
	}
	for _, name := range []string{"allow_bare_domains", "allow_localhost", "allow_ip_sans", "enforce_hostnames", "require_cn", "server_flag", "no_store"} {
		if data[name] != true {
			return errEnrollment
		}
	}
	for _, name := range []string{"allow_subdomains", "allow_glob_domains", "allow_any_name", "allow_wildcard_certificates",
		"client_flag", "code_signing_flag", "email_protection_flag", "use_csr_common_name", "use_csr_sans"} {
		if data[name] != false {
			return errEnrollment
		}
	}
	return nil
}

func requireAppRole(data map[string]any) error {
	if !exactStrings(data["token_policies"], []string{recoveryPolicy}) || data["token_no_default_policy"] != true ||
		data["bind_secret_id"] != true || data["token_type"] != "service" {
		return errEnrollment
	}
	for _, name := range []string{"token_ttl", "token_max_ttl", "token_explicit_max_ttl"} {
		if data[name] != float64(300) {
			return errEnrollment
		}
	}
	for _, name := range []string{"secret_id_ttl", "secret_id_num_uses", "token_period", "token_num_uses"} {
		if data[name] != float64(0) {
			return errEnrollment
		}
	}
	return nil
}

func enrollAt(ctx context.Context, installationID, attemptID string, paths enrollmentPaths, expected owner, client *http.Client, now time.Time) (EnrollmentReceipt, error) {
	var result EnrollmentReceipt
	if !uuidPattern.MatchString(installationID) || !uuidPattern.MatchString(attemptID) {
		return result, errEnrollment
	}
	output, err := openDirectory(paths.identity, paths.root, 0700)
	if err != nil {
		return result, errEnrollment
	}
	defer output.Close()
	if emptyDirectory(output) != nil {
		return result, errEnrollment
	}
	state, err := openDirectory(paths.state, expected, 0700)
	if err != nil {
		return result, errEnrollment
	}
	defer state.Close()
	rootFile, err := readFile(state, "root.token", paths.root, []uint32{0400}, 4096, paths.readOnly)
	if err != nil {
		return result, errEnrollment
	}
	root := strings.TrimSpace(string(rootFile.bytes))
	if len(root) < 20 || len(root) > 4096 || strings.IndexFunc(root, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return result, errEnrollment
	}
	directory, err := openDirectory(paths.tls, expected, 0700)
	if err != nil {
		return result, errEnrollment
	}
	defer directory.Close()
	caFile, err := readFile(directory, "ca.crt", expected, []uint32{0644}, 65536, paths.readOnly)
	if err != nil {
		return result, errEnrollment
	}
	caKeyFile, err := readFile(directory, "ca.key", expected, []uint32{0600}, 65536, paths.readOnly)
	if err != nil {
		return result, errEnrollment
	}
	serverFile, err := readFile(directory, "server.pem", expected, []uint32{0600}, 128*1024, paths.readOnly)
	if err != nil {
		return result, errEnrollment
	}
	ca, err := oneCertificate(caFile.bytes)
	if err != nil {
		return result, errEnrollment
	}
	leafBlock, _ := pem.Decode(serverFile.bytes)
	if leafBlock == nil || leafBlock.Type != "CERTIFICATE" {
		return result, errEnrollment
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return result, errEnrollment
	}
	identity := recoveryIdentity{
		Schema: identitySchema, InstallationID: installationID,
		CASHA256: fingerprint(ca.Raw), SPKISHA256: fingerprint(leaf.RawSubjectPublicKeyInfo),
	}
	retained, err := parseTLS(caFile.bytes, serverFile.bytes, identity, now)
	if err != nil {
		return result, errEnrollment
	}
	caKeyBlock, rest := pem.Decode(caKeyFile.bytes)
	if caKeyBlock == nil || caKeyBlock.Type != "PRIVATE KEY" || len(caKeyBlock.Headers) != 0 ||
		len(bytes.TrimSpace(rest)) != 0 || !bytes.HasPrefix(caKeyFile.bytes, []byte("-----BEGIN PRIVATE KEY-----")) {
		return result, errEnrollment
	}
	private, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	caKey, ok := private.(*ecdsa.PrivateKey)
	if err != nil || !ok || caKey.Curve != elliptic.P256() {
		return result, errEnrollment
	}
	public, err := x509.MarshalPKIXPublicKey(&caKey.PublicKey)
	if err != nil || !bytes.Equal(public, ca.RawSubjectPublicKeyInfo) {
		return result, errEnrollment
	}
	var health struct {
		Initialized *bool  `json:"initialized"`
		Sealed      *bool  `json:"sealed"`
		ClusterID   string `json:"cluster_id"`
	}
	if apiRequest(ctx, client, http.MethodGet, "sys/health", "", nil, &health) != nil ||
		health.Initialized == nil || health.Sealed == nil || !*health.Initialized || *health.Sealed || !uuidPattern.MatchString(health.ClusterID) {
		return result, errEnrollment
	}
	identity.ClusterID = health.ClusterID
	var lookup struct {
		Data struct {
			Policies []string `json:"policies"`
		} `json:"data"`
	}
	if apiRequest(ctx, client, http.MethodGet, "auth/token/lookup-self", root, nil, &lookup) != nil ||
		!slices.Equal(lookup.Data.Policies, []string{"root"}) || absentAuthorities(ctx, client, root) != nil {
		return result, errEnrollment
	}
	unchanged := func() bool {
		return boundDirectory(output, paths.identity, paths.root) == nil &&
			boundDirectory(state, paths.state, expected) == nil && boundDirectory(directory, paths.tls, expected) == nil &&
			unchangedFile(state, "root.token", rootFile, paths.root, []uint32{0400}, 4096, paths.readOnly) == nil &&
			unchangedFile(directory, "ca.crt", caFile, expected, []uint32{0644}, 65536, paths.readOnly) == nil &&
			unchangedFile(directory, "ca.key", caKeyFile, expected, []uint32{0600}, 65536, paths.readOnly) == nil &&
			unchangedFile(directory, "server.pem", serverFile, expected, []uint32{0600}, 128*1024, paths.readOnly) == nil
	}
	if !unchanged() || emptyDirectory(output) != nil {
		return result, errEnrollment
	}
	pending, _ := json.Marshal(enrollmentIntent{
		Schema: "elevenid.openbao-control-enrollment-intent/v1", InstallationID: installationID,
		AttemptID: attemptID, ClusterID: identity.ClusterID, CASHA256: identity.CASHA256, SPKISHA256: identity.SPKISHA256,
		RootRetired: false, ExistingCAKeyRetained: true,
	})
	if writeExclusive(output, "enrollment-pending.json", pending, 0600) != nil {
		return result, errEnrollment
	}
	pendingFile, err := readFile(output, "enrollment-pending.json", paths.root, []uint32{0600}, 8192, false)
	if err != nil || !bytes.Equal(pendingFile.bytes, pending) {
		return result, errEnrollment
	}
	// No authority cleanup or retry is attempted after this durable boundary.
	// A failed/unknown API response leaves the owned pending transaction intact.
	if apiRequest(ctx, client, http.MethodPost, "sys/mounts/selfhost-control-pki", root, map[string]any{
		"type": "pki", "config": map[string]any{"max_lease_ttl": "744h"},
	}, nil) != nil {
		return result, errEnrollment
	}
	var imported struct {
		Data struct {
			Issuers         []string          `json:"imported_issuers"`
			Keys            []string          `json:"imported_keys"`
			ExistingIssuers []string          `json:"existing_issuers"`
			ExistingKeys    []string          `json:"existing_keys"`
			Mapping         map[string]string `json:"mapping"`
		} `json:"data"`
	}
	if apiRequest(ctx, client, http.MethodPost, "selfhost-control-pki/issuers/import/bundle", root, map[string]string{
		"pem_bundle": string(caFile.bytes) + string(caKeyFile.bytes),
	}, &imported) != nil || len(imported.Data.Issuers) != 1 || len(imported.Data.Keys) != 1 ||
		len(imported.Data.ExistingIssuers) != 0 || len(imported.Data.ExistingKeys) != 0 || len(imported.Data.Mapping) != 1 ||
		!uuidPattern.MatchString(imported.Data.Issuers[0]) || !uuidPattern.MatchString(imported.Data.Keys[0]) ||
		imported.Data.Mapping[imported.Data.Issuers[0]] != imported.Data.Keys[0] {
		return result, errEnrollment
	}
	identity.IssuerID = imported.Data.Issuers[0]
	pkiRolePath := "selfhost-control-pki/roles/" + signingRole
	if apiRequest(ctx, client, http.MethodPost, pkiRolePath, root, signingRoleParameters(identity.IssuerID), nil) != nil {
		return result, errEnrollment
	}
	var role struct {
		Data map[string]any `json:"data"`
	}
	if apiRequest(ctx, client, http.MethodGet, pkiRolePath, root, nil, &role) != nil ||
		requireSigningRole(role.Data, identity.IssuerID) != nil {
		return result, errEnrollment
	}
	policy := controlPolicy(identity.IssuerID)
	if apiRequest(ctx, client, http.MethodPut, "sys/policies/acl/"+recoveryPolicy, root, map[string]string{"policy": policy}, nil) != nil {
		return result, errEnrollment
	}
	var policyRead struct {
		Data struct {
			Policy string `json:"policy"`
		} `json:"data"`
	}
	if apiRequest(ctx, client, http.MethodGet, "sys/policies/acl/"+recoveryPolicy, root, nil, &policyRead) != nil || policyRead.Data.Policy != policy ||
		apiRequest(ctx, client, http.MethodPost, "sys/auth/selfhost-control", root, map[string]any{
			"type": "approle", "config": map[string]any{"default_lease_ttl": "300s", "max_lease_ttl": "300s"},
		}, nil) != nil {
		return result, errEnrollment
	}
	appRolePath := "auth/selfhost-control/role/" + signingRole
	if apiRequest(ctx, client, http.MethodPost, appRolePath, root, map[string]any{
		"token_policies": []string{recoveryPolicy}, "token_ttl": "5m", "token_max_ttl": "5m", "token_explicit_max_ttl": "5m",
		"token_no_default_policy": true, "token_type": "service", "bind_secret_id": true,
		"secret_id_ttl": 0, "secret_id_num_uses": 0, "token_period": 0, "token_num_uses": 0,
	}, nil) != nil {
		return result, errEnrollment
	}
	var appRole struct {
		Data map[string]any `json:"data"`
	}
	if apiRequest(ctx, client, http.MethodGet, appRolePath, root, nil, &appRole) != nil || requireAppRole(appRole.Data) != nil {
		return result, errEnrollment
	}
	var roleID struct {
		Data struct {
			RoleID string `json:"role_id"`
		} `json:"data"`
	}
	var secretID struct {
		Data struct {
			SecretID string `json:"secret_id"`
		} `json:"data"`
	}
	if apiRequest(ctx, client, http.MethodGet, appRolePath+"/role-id", root, nil, &roleID) != nil ||
		!uuidPattern.MatchString(roleID.Data.RoleID) ||
		apiRequest(ctx, client, http.MethodPost, appRolePath+"/secret-id", root, map[string]any{}, &secretID) != nil ||
		!uuidPattern.MatchString(secretID.Data.SecretID) {
		return result, errEnrollment
	}
	identity.RoleID, identity.SecretID = roleID.Data.RoleID, secretID.Data.SecretID
	identityBytes, _ := json.Marshal(identity)
	if bytes.Contains(identityBytes, []byte(root)) || !unchanged() || writeExclusive(output, "recovery.json", identityBytes, 0400) != nil {
		return result, errEnrollment
	}
	identityFile, err := readFile(output, "recovery.json", paths.root, []uint32{0400}, 8192, false)
	if err != nil || !bytes.Equal(identityFile.bytes, identityBytes) {
		return result, errEnrollment
	}
	token, err := scopedToken(ctx, client, identity)
	if err != nil {
		return result, errEnrollment
	}
	revoked := false
	defer func() {
		if !revoked {
			revokeKnownToken(client, token)
		}
	}()
	if _, err := issueCertificate(ctx, client, token, identity, retained, time.Now()); err != nil {
		return result, errEnrollment
	}
	// Malformed mutation inputs make these negative probes harmless even if
	// an erroneous broader policy grants access. Every response must be403.
	for _, probe := range []struct {
		method, path, token string
		body                any
	}{
		{http.MethodGet, "sys/mounts", token, nil},
		{http.MethodPost, "selfhost-control-pki/issuers/import/bundle", token, map[string]string{"pem_bundle": "invalid"}},
		{http.MethodPost, "auth/token/create", token, map[string]string{"ttl": "invalid-duration"}},
		{http.MethodPost, issuerPrefix + identity.IssuerID + "/sign/" + signingRole, "", map[string]string{"csr": "invalid"}},
	} {
		status, err := responseStatus(ctx, client, probe.method, probe.path, probe.token, probe.body)
		if err != nil || status != http.StatusForbidden {
			return result, errEnrollment
		}
	}
	if apiRequest(ctx, client, http.MethodPost, "auth/token/revoke-self", token, nil, nil) != nil {
		revoked = true // An uncertain revocation is not retried.
		return result, errEnrollment
	}
	revoked = true
	status, err := responseStatus(ctx, client, http.MethodGet, "auth/token/lookup-self", token, nil)
	if err != nil || status != http.StatusForbidden || !unchanged() ||
		unchangedFile(output, "enrollment-pending.json", pendingFile, paths.root, []uint32{0600}, 8192, false) != nil ||
		unchangedFile(output, "recovery.json", identityFile, paths.root, []uint32{0400}, 8192, false) != nil {
		return result, errEnrollment
	}
	result = EnrollmentReceipt{
		Schema: "elevenid.openbao-control-enrollment-result/v1", InstallationID: installationID, AttemptID: attemptID,
		ClusterID: identity.ClusterID, IssuerID: identity.IssuerID, CASHA256: identity.CASHA256, SPKISHA256: identity.SPKISHA256,
		PolicySHA256: fingerprint([]byte(policy)), ScopedLoginVerified: true, ScopedSigningVerified: true,
		ForbiddenOperationsDenied: true, VerificationTokenRevoked: true, ExistingCAKeyRetained: true, NodeKeyPreserved: true,
		RootRetired: false,
	}
	resultBytes, _ := json.Marshal(result)
	if writeExclusive(output, "enrollment-result.json", resultBytes, 0600) != nil {
		return EnrollmentReceipt{}, errEnrollment
	}
	return result, nil
}
