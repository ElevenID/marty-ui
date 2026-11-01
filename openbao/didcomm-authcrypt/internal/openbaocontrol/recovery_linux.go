//go:build linux

package openbaocontrol

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	identityDirectory = "/bao/control-identity"
	tlsDirectory      = "/bao/data/tls"
	identitySchema    = "elevenid.openbao-tcp-recovery/v1"
	recoveryPolicy    = "selfhost-openbao-tcp-recovery"
	loginPath         = "auth/selfhost-control/login"
	issuerPrefix      = "selfhost-control-pki/issuer/"
	signingRole       = "openbao-network"
)

var (
	errRecovery = errors.New("OpenBao TCP certificate recovery refused; preserve the pending operation")
	// OpenBao IDs are UUID-shaped random identifiers; their version/variant
	// bits are not necessarily RFC UUID v4. Require one canonical path segment.
	uuidPattern = regexp.MustCompile(`\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z`)
)

// recoveryIdentity is private, root-owned and mounted read-only. Fingerprints
// are SHA-256 of DER (CA certificate and node SubjectPublicKeyInfo respectively).
// The existing CA originated in a file and ca.key remains in /bao/data/tls;
// importing it into PKI does not make that CA key nonexportable.
type recoveryIdentity struct {
	Schema         string `json:"schema"`
	InstallationID string `json:"installation_id"`
	ClusterID      string `json:"cluster_id"`
	RoleID         string `json:"role_id"`
	SecretID       string `json:"secret_id"`
	CASHA256       string `json:"ca_sha256"`
	SPKISHA256     string `json:"spki_sha256"`
	IssuerID       string `json:"issuer_id"`
}

// RecoveryReceipt contains public observations only. Its publication proves a
// file replacement, not a listener reload or a successful verified TCP request.
type RecoveryReceipt struct {
	Schema               string `json:"schema"`
	InstallationID       string `json:"installation_id"`
	AttemptID            string `json:"attempt_id"`
	ClusterID            string `json:"cluster_id"`
	IssuerID             string `json:"issuer_id"`
	PreviousSHA256       string `json:"previous_certificate_sha256"`
	CertificateSHA256    string `json:"certificate_sha256"`
	CASHA256             string `json:"ca_sha256"`
	SPKISHA256           string `json:"spki_sha256"`
	NotAfter             string `json:"not_after"`
	NodeKeyPreserved     bool   `json:"node_key_preserved"`
	CertificatePublished bool   `json:"certificate_published"`
	ReloadPerformed      bool   `json:"reload_performed"`
	NetworkTLSVerified   bool   `json:"network_tls_verified"`
}

type recoveryPaths struct {
	identity, tls string
	root          owner
	readOnly      bool
}

// Recover has no caller-selected URL, filesystem path, signing role, identity,
// TTL or signal. The installation owner must hold its lock, record intent, bind
// the exact container and retain uncertainty before invoking this helper.
func Recover(ctx context.Context, installationID, attemptID string) (RecoveryReceipt, error) {
	if os.Geteuid() != 0 || !uuidPattern.MatchString(installationID) || !uuidPattern.MatchString(attemptID) {
		return RecoveryReceipt{}, errRecovery
	}
	expected, err := imageOwner()
	if err != nil {
		return RecoveryReceipt{}, errRecovery
	}
	client, err := NewClient()
	if err != nil {
		return RecoveryReceipt{}, errRecovery
	}
	defer closeClient(client)
	return recoverAt(ctx, installationID, attemptID, recoveryPaths{
		identity: identityDirectory, tls: tlsDirectory, root: owner{0, 0}, readOnly: true,
	}, expected, client, time.Now())
}

func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func exactHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}

func parseIdentity(bytes []byte, installationID string) (recoveryIdentity, error) {
	var identity recoveryIdentity
	if len(bytes) > 8192 || decodeJSON(bytes, &identity, true) != nil || identity.Schema != identitySchema ||
		identity.InstallationID != installationID || !uuidPattern.MatchString(installationID) ||
		!uuidPattern.MatchString(identity.ClusterID) || !uuidPattern.MatchString(identity.RoleID) ||
		!uuidPattern.MatchString(identity.SecretID) || !uuidPattern.MatchString(identity.IssuerID) ||
		!exactHash(identity.CASHA256) || !exactHash(identity.SPKISHA256) {
		return recoveryIdentity{}, errRecovery
	}
	return identity, nil
}

// Duplicate fields are rejected before Go's ordinary JSON decoder can silently
// choose the last value. This also bounds nesting and rejects trailing values.
func decodeJSON(data []byte, output any, strict bool) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 24 {
			return errRecovery
		}
		token, err := decoder.Token()
		if err != nil {
			return errRecovery
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				name, ok := key.(string)
				if err != nil || !ok || seen[name] {
					return errRecovery
				}
				seen[name] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errRecovery
		}
		closing, err := decoder.Token()
		if err != nil || (delimiter == '{' && closing != json.Delim('}')) || (delimiter == '[' && closing != json.Delim(']')) {
			return errRecovery
		}
		return nil
	}
	if walk(0) != nil {
		return errRecovery
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errRecovery
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	if strict {
		decoder.DisallowUnknownFields()
	}
	if decoder.Decode(output) != nil {
		return errRecovery
	}
	return nil
}

func apiRequest(ctx context.Context, client *http.Client, method, path, token string, payload, result any) error {
	var data []byte
	var err error
	if payload != nil {
		data, err = json.Marshal(payload)
		if err != nil || len(data) > 64*1024 {
			return errRecovery
		}
	}
	request, err := http.NewRequestWithContext(ctx, method, Endpoint+"/v1/"+path, bytes.NewReader(data))
	if err != nil {
		return errRecovery
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("X-Vault-Token", token)
	}
	response, err := client.Do(request)
	if err != nil {
		return errRecovery
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK && !(result == nil && response.StatusCode == http.StatusNoContent) {
		return errRecovery
	}
	data, err = io.ReadAll(io.LimitReader(response.Body, 128*1024+1))
	if err != nil || len(data) > 128*1024 {
		return errRecovery
	}
	if result != nil {
		return decodeJSON(data, result, false)
	}
	return nil
}

func oneCertificate(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
		!bytes.HasPrefix(data, []byte("-----BEGIN CERTIFICATE-----")) {
		return nil, errRecovery
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errRecovery
	}
	return certificate, nil
}

type retainedTLS struct {
	ca, leaf *x509.Certificate
	key      *ecdsa.PrivateKey
	keyPEM   []byte
}

func exactNames(certificate *x509.Certificate) bool {
	names := append([]string(nil), certificate.DNSNames...)
	slices.Sort(names)
	return slices.Equal(names, []string{"host.docker.internal", "localhost", "openbao"}) &&
		len(certificate.IPAddresses) == 1 && certificate.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) &&
		len(certificate.URIs) == 0 && len(certificate.EmailAddresses) == 0 && certificate.Subject.CommonName == "openbao"
}

func verifyNode(certificate, ca *x509.Certificate, spki []byte, now time.Time) error {
	public, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() || !bytes.Equal(certificate.RawSubjectPublicKeyInfo, spki) ||
		!exactNames(certificate) || certificate.IsCA ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature || len(certificate.ExtKeyUsage) != 1 ||
		certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(certificate.UnknownExtKeyUsage) != 0 ||
		!bytes.Equal(certificate.RawIssuer, ca.RawSubject) {
		return errRecovery
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: now, DNSName: "openbao", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return errRecovery
	}
	return nil
}

func parseTLS(caBytes, combined []byte, identity recoveryIdentity, now time.Time) (retainedTLS, error) {
	var result retainedTLS
	ca, err := oneCertificate(caBytes)
	if err != nil || fingerprint(ca.Raw) != identity.CASHA256 || !ca.IsCA || !ca.BasicConstraintsValid ||
		ca.KeyUsage&x509.KeyUsageCertSign == 0 || ca.CheckSignatureFrom(ca) != nil || ca.NotBefore.After(now) ||
		!ca.NotAfter.After(now.Add(31*24*time.Hour)) {
		return result, errRecovery
	}
	block, keyPEM := pem.Decode(combined)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || !bytes.HasPrefix(combined, []byte("-----BEGIN CERTIFICATE-----")) {
		return result, errRecovery
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || fingerprint(leaf.RawSubjectPublicKeyInfo) != identity.SPKISHA256 {
		return result, errRecovery
	}
	keyBlock, rest := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" || len(keyBlock.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 ||
		!bytes.HasPrefix(keyPEM, []byte("-----BEGIN PRIVATE KEY-----")) {
		return result, errRecovery
	}
	private, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	key, ok := private.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return result, errRecovery
	}
	if _, err := tls.X509KeyPair(combined, combined); err != nil {
		return result, errRecovery
	}
	// The retired leaf may be expired; validate its former chain and exact
	// identity at its final valid instant, while requiring a currently valid CA.
	checkAt := now
	if !leaf.NotAfter.After(now) {
		checkAt = leaf.NotAfter.Add(-time.Second)
	}
	if verifyNode(leaf, ca, leaf.RawSubjectPublicKeyInfo, checkAt) != nil {
		return result, errRecovery
	}
	return retainedTLS{ca: ca, leaf: leaf, key: key, keyPEM: keyPEM}, nil
}

func makeCSR(retained retainedTLS) (string, error) {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "openbao"}, SignatureAlgorithm: x509.ECDSAWithSHA256,
		DNSNames:    []string{"openbao", "host.docker.internal", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}, retained.key)
	if err != nil {
		return "", errRecovery
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr})), nil
}

func samePolicy(policies []string) bool {
	return len(policies) == 1 && policies[0] == recoveryPolicy
}

func revokeKnownToken(client *http.Client, token string) {
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = apiRequest(cleanup, client, http.MethodPost, "auth/token/revoke-self", token, nil, nil)
}

func scopedToken(ctx context.Context, client *http.Client, identity recoveryIdentity) (string, error) {
	var login struct {
		Auth struct {
			Token         string   `json:"client_token"`
			Policies      []string `json:"policies"`
			TokenPolicies []string `json:"token_policies"`
			LeaseDuration int64    `json:"lease_duration"`
			TokenType     string   `json:"token_type"`
		} `json:"auth"`
	}
	if apiRequest(ctx, client, http.MethodPost, loginPath, "", map[string]string{
		"role_id": identity.RoleID, "secret_id": identity.SecretID,
	}, &login) != nil {
		return "", errRecovery
	}
	token := login.Auth.Token
	if len(token) < 20 || len(token) > 4096 || strings.IndexFunc(token, func(r rune) bool { return r < 33 || r > 126 }) >= 0 {
		return "", errRecovery
	}
	accepted := false
	defer func() {
		if !accepted {
			revokeKnownToken(client, token)
		}
	}()
	if !samePolicy(login.Auth.Policies) || !samePolicy(login.Auth.TokenPolicies) || login.Auth.LeaseDuration <= 0 ||
		login.Auth.LeaseDuration > 300 || login.Auth.TokenType != "service" {
		return "", errRecovery
	}
	var lookup struct {
		Data struct {
			Policies       []string `json:"policies"`
			TTL            int64    `json:"ttl"`
			ExplicitMaxTTL int64    `json:"explicit_max_ttl"`
			Path           string   `json:"path"`
		} `json:"data"`
	}
	if apiRequest(ctx, client, http.MethodGet, "auth/token/lookup-self", token, nil, &lookup) != nil ||
		!samePolicy(lookup.Data.Policies) || lookup.Data.TTL <= 0 || lookup.Data.TTL > 300 ||
		lookup.Data.ExplicitMaxTTL <= 0 || lookup.Data.ExplicitMaxTTL > 300 || lookup.Data.Path != loginPath {
		return "", errRecovery
	}
	accepted = true
	return token, nil
}

func issueCertificate(ctx context.Context, client *http.Client, token string, identity recoveryIdentity, retained retainedTLS, now time.Time) (*x509.Certificate, error) {
	var issuer struct {
		Data struct {
			Certificate string `json:"certificate"`
			IssuerID    string `json:"issuer_id"`
		} `json:"data"`
	}
	issuerPath := issuerPrefix + identity.IssuerID
	if apiRequest(ctx, client, http.MethodGet, issuerPath, token, nil, &issuer) != nil || issuer.Data.IssuerID != identity.IssuerID {
		return nil, errRecovery
	}
	issuerCert, err := oneCertificate([]byte(issuer.Data.Certificate))
	if err != nil || !bytes.Equal(issuerCert.Raw, retained.ca.Raw) {
		return nil, errRecovery
	}
	csr, err := makeCSR(retained)
	if err != nil {
		return nil, errRecovery
	}
	var issued struct {
		Data struct {
			Certificate string `json:"certificate"`
			PrivateKey  string `json:"private_key"`
		} `json:"data"`
	}
	if apiRequest(ctx, client, http.MethodPost, issuerPath+"/sign/"+signingRole, token, map[string]any{
		"csr": csr, "common_name": "openbao", "alt_names": "openbao,host.docker.internal,localhost",
		"ip_sans": "127.0.0.1", "exclude_cn_from_sans": true, "ttl": "720h", "format": "pem",
	}, &issued) != nil || issued.Data.PrivateKey != "" {
		return nil, errRecovery
	}
	certificate, err := oneCertificate([]byte(issued.Data.Certificate))
	if err != nil || verifyNode(certificate, retained.ca, retained.leaf.RawSubjectPublicKeyInfo, now) != nil ||
		!certificate.NotAfter.After(now.Add(24*time.Hour)) || certificate.NotAfter.After(now.Add(31*24*time.Hour)) ||
		certificate.NotAfter.Sub(certificate.NotBefore) > 31*24*time.Hour ||
		certificate.SerialNumber.Cmp(retained.leaf.SerialNumber) == 0 {
		return nil, errRecovery
	}
	return certificate, nil
}

func recoverAt(ctx context.Context, installationID, attemptID string, paths recoveryPaths, expected owner, client *http.Client, now time.Time) (RecoveryReceipt, error) {
	var receipt RecoveryReceipt
	if !uuidPattern.MatchString(installationID) || !uuidPattern.MatchString(attemptID) {
		return receipt, errRecovery
	}
	identityDir, err := openDirectory(paths.identity, paths.root, 0700)
	if err != nil {
		return receipt, errRecovery
	}
	defer identityDir.Close()
	identityFile, err := readFile(identityDir, "recovery.json", paths.root, []uint32{0400, 0600}, 8192, paths.readOnly)
	if err != nil {
		return receipt, errRecovery
	}
	identity, err := parseIdentity(identityFile.bytes, installationID)
	if err != nil {
		return receipt, errRecovery
	}
	enrollmentPending, enrollmentResult, err := requireEnrollment(identityDir, paths.root, paths.readOnly, identity)
	if err != nil {
		return receipt, errRecovery
	}
	directory, err := openDirectory(paths.tls, expected, 0700)
	if err != nil {
		return receipt, errRecovery
	}
	defer directory.Close()
	if noPendingReplacement(directory) != nil {
		return receipt, errRecovery
	}
	caFile, err := readFile(directory, "ca.crt", expected, []uint32{0644}, 64*1024, false)
	if err != nil {
		return receipt, errRecovery
	}
	serverFile, err := readFile(directory, "server.pem", expected, []uint32{0600}, 128*1024, false)
	if err != nil {
		return receipt, errRecovery
	}
	retained, err := parseTLS(caFile.bytes, serverFile.bytes, identity, now)
	if err != nil {
		return receipt, errRecovery
	}
	var health struct {
		Initialized *bool  `json:"initialized"`
		Sealed      *bool  `json:"sealed"`
		ClusterID   string `json:"cluster_id"`
	}
	if apiRequest(ctx, client, http.MethodGet, "sys/health", "", nil, &health) != nil ||
		health.Initialized == nil || health.Sealed == nil || !*health.Initialized || *health.Sealed || health.ClusterID != identity.ClusterID {
		return receipt, errRecovery
	}
	token, err := scopedToken(ctx, client, identity)
	if err != nil {
		return receipt, errRecovery
	}
	revoked := false
	defer func() {
		if !revoked {
			// A known transient credential is retired even if validation fails.
			revokeKnownToken(client, token)
		}
	}()
	certificate, err := issueCertificate(ctx, client, token, identity, retained, now)
	if err != nil {
		return receipt, errRecovery
	}
	combined := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}), retained.keyPEM...)
	if _, err := tls.X509KeyPair(combined, combined); err != nil {
		return receipt, errRecovery
	}
	if apiRequest(ctx, client, http.MethodPost, "auth/token/revoke-self", token, nil, nil) != nil {
		// Do not retry a token mutation with an uncertain response.
		revoked = true
		return receipt, errRecovery
	}
	revoked = true
	if boundDirectory(identityDir, paths.identity, paths.root) != nil ||
		unchangedFile(identityDir, "recovery.json", identityFile, paths.root, []uint32{0400, 0600}, 8192, paths.readOnly) != nil ||
		unchangedFile(identityDir, "enrollment-pending.json", enrollmentPending, paths.root, []uint32{0600}, 8192, paths.readOnly) != nil ||
		unchangedFile(identityDir, "enrollment-result.json", enrollmentResult, paths.root, []uint32{0600}, 16384, paths.readOnly) != nil ||
		unchangedFile(directory, "ca.crt", caFile, expected, []uint32{0644}, 64*1024, false) != nil ||
		replaceCertificate(directory, paths.tls, attemptID, expected, serverFile, combined) != nil {
		return receipt, errRecovery
	}
	return RecoveryReceipt{
		Schema: "elevenid.openbao-tcp-recovery-result/v1", InstallationID: installationID, AttemptID: attemptID,
		ClusterID: identity.ClusterID, IssuerID: identity.IssuerID,
		PreviousSHA256: fingerprint(retained.leaf.Raw), CertificateSHA256: fingerprint(certificate.Raw),
		CASHA256: identity.CASHA256, SPKISHA256: identity.SPKISHA256, NotAfter: certificate.NotAfter.UTC().Format(time.RFC3339),
		NodeKeyPreserved: true, CertificatePublished: true, ReloadPerformed: false, NetworkTLSVerified: false,
	}, nil
}
