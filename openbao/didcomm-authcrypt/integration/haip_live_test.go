package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func liveClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func requestJSON(t *testing.T, client *http.Client, base, method, path, authHeader, token string, body any) (int, map[string]any) {
	t.Helper()
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, strings.TrimRight(base, "/")+"/"+strings.TrimLeft(path, "/"), payload)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(authHeader, token)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(io.LimitReader(response.Body, 2<<20)).Decode(&result); err == io.EOF {
		return response.StatusCode, map[string]any{}
	} else if err != nil {
		t.Fatalf("%s %s returned non-JSON status %d: %v", method, path, response.StatusCode, err)
	}
	return response.StatusCode, result
}

func encryptForHaip(t *testing.T, public map[string]any, plaintext []byte) string {
	t.Helper()
	x, xErr := base64.RawURLEncoding.DecodeString(public["x"].(string))
	y, yErr := base64.RawURLEncoding.DecodeString(public["y"].(string))
	if xErr != nil || yErr != nil {
		t.Fatal("invalid remote P-256 public JWK")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: pub}, nil)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := encrypted.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func TestHaipScopedLiveOpenBao(t *testing.T) {
	base := strings.TrimRight(os.Getenv("MARTY_TEST_OPENBAO_URL"), "/")
	root := os.Getenv("MARTY_TEST_OPENBAO_TOKEN")
	if base == "" || root == "" {
		t.Skip("requires a disposable OpenBao with the Marty plugin mounted")
	}
	client := liveClient()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	tenant := "org_" + hex.EncodeToString(random[:])
	flow := "flow_a"
	request := func(method, path, token string, body any) (int, map[string]any) {
		return requestJSON(t, client, base, method, "v1/"+path, "X-Vault-Token", token, body)
	}
	keyPath := "didcomm/haip/keys/" + tenant + "/" + flow
	status, created := request(http.MethodPost, keyPath, root, map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("remote key creation status %d", status)
	}
	data := created["data"].(map[string]any)
	version := data["version"].(string)
	public := data["public_jwk"].(map[string]any)
	if len(version) != 32 || public["d"] != nil || data["private_key"] != nil {
		t.Fatal("remote create returned invalid version or private key")
	}
	status, again := request(http.MethodPost, keyPath, root, map[string]any{})
	if status != http.StatusOK || again["data"].(map[string]any)["version"] != version {
		t.Fatal("remote create did not preserve the version")
	}
	policy := "haip-test-" + hex.EncodeToString(random[:])
	acl := "path \"" + keyPath + "\" { capabilities = [\"read\"] }\n" +
		"path \"didcomm/haip/decrypt/" + tenant + "/" + flow + "/" + version + "\" { capabilities = [\"update\"] }"
	status, _ = request(http.MethodPut, "sys/policies/acl/"+policy, root, map[string]any{"policy": acl})
	if status != http.StatusNoContent {
		t.Fatalf("policy creation status %d", status)
	}
	status, issued := request(http.MethodPost, "auth/token/create", root, map[string]any{
		"policies": []string{policy}, "no_default_policy": true, "ttl": "10m",
	})
	if status != http.StatusOK {
		t.Fatalf("scoped token creation status %d", status)
	}
	scoped := issued["auth"].(map[string]any)["client_token"].(string)
	status, _ = request(http.MethodPost, "didcomm/haip/keys/"+tenant+"/forbidden", scoped, map[string]any{})
	if status != http.StatusForbidden {
		t.Fatalf("scoped token created a key: status %d", status)
	}
	status, read := request(http.MethodGet, keyPath, scoped, nil)
	if status != http.StatusOK || read["data"].(map[string]any)["version"] != version {
		t.Fatalf("scoped public key read failed: status %d", status)
	}
	plaintext := []byte(`{"vp_token":"live-holder","state":"flow_a"}`)
	compact := encryptForHaip(t, public, plaintext)
	decryptPath := "didcomm/haip/decrypt/" + tenant + "/" + flow + "/" + version
	status, opened := request(http.MethodPost, decryptPath, scoped, map[string]any{"jwe": compact})
	if status != http.StatusOK {
		t.Fatalf("remote JWE decryption status %d", status)
	}
	decoded, err := base64.StdEncoding.DecodeString(opened["data"].(map[string]any)["plaintext_base64"].(string))
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatal("remote JWE plaintext mismatch")
	}
	status, _ = request(http.MethodPost, "didcomm/haip/decrypt/"+tenant+"/other/"+version, scoped, map[string]any{"jwe": compact})
	if status != http.StatusForbidden {
		t.Fatalf("scoped token decrypted outside its flow: status %d", status)
	}
	workloadPolicyPath := os.Getenv("MARTY_TEST_HAIP_WORKLOAD_POLICY")
	if workloadPolicyPath == "" {
		return
	}
	workloadPolicy, err := os.ReadFile(workloadPolicyPath)
	if err != nil {
		t.Fatal(err)
	}
	status, _ = request(http.MethodPut, "sys/policies/acl/"+policy+"-workload", root, map[string]any{"policy": string(workloadPolicy)})
	if status != http.StatusNoContent {
		t.Fatalf("workload policy creation status %d", status)
	}
	status, issued = request(http.MethodPost, "auth/token/create", root, map[string]any{
		"policies": []string{policy + "-workload"}, "no_default_policy": true, "ttl": "10m",
	})
	if status != http.StatusOK {
		t.Fatalf("workload token creation status %d", status)
	}
	workload := issued["auth"].(map[string]any)["client_token"].(string)
	status, lookup := request(http.MethodPost, "auth/token/lookup", root, map[string]any{"token": workload})
	if status != http.StatusOK {
		t.Fatalf("workload token lookup status %d", status)
	}
	lookupData := lookup["data"].(map[string]any)
	policies := lookupData["policies"].([]any)
	if len(policies) != 1 || policies[0] != policy+"-workload" {
		t.Fatalf("workload token had unexpected policies: %v", policies)
	}
	if entityID, ok := lookupData["entity_id"].(string); ok && entityID != "" {
		t.Fatalf("workload token unexpectedly attached to an identity: %s", entityID)
	}
	workloadFlow := "flow_b"
	workloadKeyPath := "didcomm/haip/keys/" + tenant + "/" + workloadFlow
	status, created = request(http.MethodPost, workloadKeyPath, workload, map[string]any{})
	if status != http.StatusOK {
		t.Fatalf("workload token could not create an HAIP key: status %d", status)
	}
	workloadVersion := created["data"].(map[string]any)["version"].(string)
	status, _ = request(http.MethodGet, workloadKeyPath, workload, nil)
	if status != http.StatusOK {
		t.Fatalf("workload token could not read its HAIP public key: status %d", status)
	}
	status, opened = request(http.MethodPost, decryptPath, workload, map[string]any{"jwe": compact})
	if status != http.StatusOK {
		t.Fatalf("workload token could not decrypt an HAIP response: status %d", status)
	}
	decoded, err = base64.StdEncoding.DecodeString(opened["data"].(map[string]any)["plaintext_base64"].(string))
	if err != nil || !bytes.Equal(decoded, plaintext) {
		t.Fatal("workload token remote plaintext mismatch")
	}
	status, _ = request(http.MethodPost, "didcomm/haip/decrypt/"+tenant+"/"+workloadFlow+"/"+workloadVersion, workload, map[string]any{"jwe": compact})
	if status != http.StatusBadRequest {
		t.Fatalf("workload token unexpectedly decrypted with the wrong key: status %d", status)
	}
	status, _ = request(http.MethodGet, "sys/mounts", workload, nil)
	if status != http.StatusForbidden {
		t.Fatalf("workload token accessed plugin administration: status %d", status)
	}
	status, _ = request(http.MethodPost, "didcomm/authcrypt/keys/"+tenant+"/forbidden", workload, map[string]any{})
	if status != http.StatusForbidden {
		t.Fatalf("workload token accessed DIDComm sender keys: status %d", status)
	}
}

func TestHaipRustSigningRouteLiveOpenBao(t *testing.T) {
	base := os.Getenv("MARTY_TEST_SIGNING_KEYS_URL")
	apiKey := os.Getenv("MARTY_TEST_SIGNING_KEYS_API_KEY")
	if base == "" || apiKey == "" {
		t.Skip("requires a Rust signing-keys service with a dedicated HAIP OpenBao token")
	}
	client := liveClient()
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	tenant := "org_" + hex.EncodeToString(random[:])
	flow := "flow_rust"
	createPath := "internal/haip-response-keys/create"
	createBody := map[string]any{"organization_id": tenant, "flow_instance_id": flow}
	status, _ := requestJSON(t, client, base, http.MethodPost, createPath, "X-API-Key", "wrong-key", createBody)
	if status != http.StatusUnauthorized {
		t.Fatalf("unauthorized HAIP create status %d", status)
	}
	status, created := requestJSON(t, client, base, http.MethodPost, createPath, "X-API-Key", apiKey, createBody)
	if status != http.StatusOK {
		t.Fatalf("Rust HAIP create status %d: %v", status, created)
	}
	version := created["version"].(string)
	public := created["public_jwk"].(map[string]any)
	if created["organization_id"] != tenant || created["flow_instance_id"] != flow || public["d"] != nil {
		t.Fatal("Rust HAIP create returned wrong scope or private material")
	}
	if created["key_reference"] != "didcomm/haip/keys/"+tenant+"/"+flow+"/versions/"+version {
		t.Fatal("Rust HAIP create returned wrong key reference")
	}
	status, resolved := requestJSON(t, client, base, http.MethodPost, "internal/haip-response-keys/resolve", "X-API-Key", apiKey, map[string]any{
		"organization_id": tenant, "flow_instance_id": flow, "version": version,
	})
	if status != http.StatusOK || resolved["key_reference"] != created["key_reference"] || resolved["version"] != version {
		t.Fatalf("Rust HAIP read-only resolution failed: status %d: %v", status, resolved)
	}
	status, _ = requestJSON(t, client, base, http.MethodPost, "internal/haip-response-keys/resolve", "X-API-Key", apiKey, map[string]any{
		"organization_id": tenant, "flow_instance_id": flow, "version": strings.Repeat("0", 32),
	})
	if status != http.StatusServiceUnavailable {
		t.Fatalf("Rust HAIP missing-version resolve status %d", status)
	}
	plaintext := []byte(`{"vp_token":"rust-live-holder","state":"flow_rust"}`)
	compact := encryptForHaip(t, public, plaintext)
	decryptPath := "internal/haip-response-keys/decrypt"
	decryptBody := map[string]any{"organization_id": tenant, "flow_instance_id": flow, "version": version, "jwe": compact}
	status, opened := requestJSON(t, client, base, http.MethodPost, decryptPath, "X-API-Key", apiKey, decryptBody)
	if status != http.StatusOK {
		t.Fatalf("Rust HAIP decrypt status %d: %v", status, opened)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(opened["plaintext_b64"].(string))
	if err != nil || !bytes.Equal(decoded, plaintext) || opened["version"] != version {
		t.Fatal("Rust HAIP decrypted wrong response")
	}
	if outputPath := os.Getenv("MARTY_TEST_HAIP_FLOW_INPUT"); outputPath != "" {
		input, err := json.Marshal(map[string]any{
			"organization_id":  tenant,
			"flow_instance_id": flow,
			"key_reference":    created["key_reference"],
			"public_jwk":       public,
			"jwe":              compact,
			"plaintext":        string(plaintext),
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(outputPath, input, 0600); err != nil {
			t.Fatal(err)
		}
	}
	decryptBody["flow_instance_id"] = "other_flow"
	status, _ = requestJSON(t, client, base, http.MethodPost, decryptPath, "X-API-Key", apiKey, decryptBody)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("Rust HAIP cross-flow decrypt status %d", status)
	}
}
