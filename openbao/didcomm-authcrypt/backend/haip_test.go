package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestHaipKeyStaysInOpenBaoAndDecryptsBoundResponse(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	engine, err := Factory(ctx, &logical.BackendConfig{StorageView: storage})
	if err != nil {
		t.Fatal(err)
	}
	request := func(op logical.Operation, path string, data map[string]any) *logical.Response {
		t.Helper()
		response, err := engine.HandleRequest(ctx, &logical.Request{Operation: op, Path: path, Storage: storage, Data: data})
		if err != nil && err != logical.ErrInvalidRequest {
			t.Fatalf("%s %s: %v", op, path, err)
		}
		return response
	}
	keyPath := "haip/keys/tenant_a/flow_a"
	created := request(logical.UpdateOperation, keyPath, nil)
	if created == nil || created.IsError() {
		t.Fatalf("HAIP key creation failed: %#v", created)
	}
	public := created.Data["public_jwk"].(map[string]any)
	version := created.Data["version"].(string)
	if !versionID.MatchString(version) || public["d"] != nil || created.Data["private_key"] != nil {
		t.Fatalf("private key escaped or version is invalid: %#v", created.Data)
	}
	if repeat := request(logical.UpdateOperation, keyPath, nil); repeat.Data["version"] != version {
		t.Fatal("retry generated a different flow key")
	}
	if read := request(logical.ReadOperation, keyPath, nil); read.Data["version"] != version {
		t.Fatal("stored key was not restartable")
	}
	if supplied := request(logical.UpdateOperation, "haip/keys/tenant_a/flow_b", map[string]any{"private_key": "forbidden"}); supplied == nil || !supplied.IsError() {
		t.Fatal("caller-supplied private key was accepted")
	}
	imported, importErr := engine.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "haip/import/tenant_a/flow_a", Storage: storage,
		Data: map[string]any{"private_jwk": "forbidden"},
	})
	if importErr == nil && imported != nil && !imported.IsError() {
		t.Fatal("private-JWK import route is available")
	}
	x, err := base64.RawURLEncoding.DecodeString(public["x"].(string))
	if err != nil {
		t.Fatal(err)
	}
	y, err := base64.RawURLEncoding.DecodeString(public["y"].(string))
	if err != nil {
		t.Fatal(err)
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	encrypter, err := jose.NewEncrypter(jose.A256GCM, jose.Recipient{Algorithm: jose.ECDH_ES, Key: pub}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"vp_token":"synthetic","state":"flow_a"}`)
	encrypted, err := encrypter.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := encrypted.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	decryptPath := "haip/decrypt/tenant_a/flow_a/" + version
	opened := request(logical.UpdateOperation, decryptPath, map[string]any{"jwe": compact})
	if opened == nil || opened.IsError() {
		t.Fatalf("HAIP decryption failed: %#v", opened)
	}
	decoded, err := base64.StdEncoding.DecodeString(opened.Data["plaintext_base64"].(string))
	if err != nil || string(decoded) != string(plaintext) {
		t.Fatalf("HAIP plaintext mismatch: %v", err)
	}
	// A competing worker may select a different advisory current version.
	// The already-published key reference must still decrypt after that race.
	competing, err := newHaipKey("tenant_a", "flow_a")
	if err != nil {
		t.Fatal(err)
	}
	if err := putJSON(ctx, storage, haipVersionPath("tenant_a", "flow_a", competing.Version), competing); err != nil {
		t.Fatal(err)
	}
	if err := putJSON(ctx, storage, haipMetaPath("tenant_a", "flow_a"), map[string]string{"version": competing.Version}); err != nil {
		t.Fatal(err)
	}
	clear(competing.PrivateKey)
	if old := request(logical.UpdateOperation, decryptPath, map[string]any{"jwe": compact}); old == nil || old.IsError() {
		t.Fatal("old HAIP key version was lost after concurrent selection")
	}
	for _, path := range []string{
		"haip/decrypt/tenant_b/flow_a/" + version,
		"haip/decrypt/tenant_a/flow_b/" + version,
		"haip/decrypt/tenant_a/flow_a/00000000000000000000000000000000",
	} {
		denied := request(logical.UpdateOperation, path, map[string]any{"jwe": compact})
		if denied != nil && !denied.IsError() {
			t.Fatalf("wrong-scope decryption succeeded: %s", path)
		}
	}
	parts := strings.Split(compact, ".")
	parts[3] = strings.Repeat("A", len(parts[3]))
	denied := request(logical.UpdateOperation, decryptPath, map[string]any{"jwe": strings.Join(parts, ".")})
	if denied == nil || !denied.IsError() {
		t.Fatal("tampered HAIP ciphertext decrypted")
	}
	encoded, _ := json.Marshal(created.Data)
	if strings.Contains(string(encoded), "private_key") || strings.Contains(string(encoded), `"d":`) {
		t.Fatal("HAIP public response contains private key material")
	}
}

func TestHaipMissingCurrentKeyDoesNotSilentlyRegenerate(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	engine, err := Factory(ctx, &logical.BackendConfig{StorageView: storage})
	if err != nil {
		t.Fatal(err)
	}
	missing := "00000000000000000000000000000000"
	if err := putJSON(ctx, storage, haipMetaPath("tenant_a", "flow_a"), map[string]string{"version": missing}); err != nil {
		t.Fatal(err)
	}
	response, err := engine.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "haip/keys/tenant_a/flow_a", Storage: storage,
	})
	if err == nil || (response != nil && !response.IsError()) {
		t.Fatal("missing current key was silently regenerated")
	}
	entry, err := storage.Get(ctx, haipMetaPath("tenant_a", "flow_a"))
	if err != nil || entry == nil || !strings.Contains(string(entry.Value), missing) {
		t.Fatal("failed create changed the existing current pointer")
	}
}
