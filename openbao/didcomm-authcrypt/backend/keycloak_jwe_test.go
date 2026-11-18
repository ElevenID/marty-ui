package backend

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestKeycloakJWEVersionedCustody(t *testing.T) {
	ctx := context.Background()
	storage := transactionalTestStorage(t)
	engine, err := Factory(ctx, &logical.BackendConfig{StorageView: storage})
	if err != nil {
		t.Fatal(err)
	}
	call := func(operation logical.Operation, path string, data map[string]any) *logical.Response {
		t.Helper()
		response, err := engine.HandleRequest(ctx, &logical.Request{
			Operation: operation, Path: path, Storage: storage, Data: data,
		})
		if err != nil || response == nil || response.IsError() {
			t.Fatalf("Keycloak JWE request %s failed: %v %v", path, err, response)
		}
		return response
	}
	created := call(logical.UpdateOperation, "keycloak/keys/11id/cookie", nil)
	version := created.Data["version"].(string)
	if len(version) != 32 || created.Data["kid"] != "keycloak-11id-cookie-"+version ||
		created.Data["cek"] != nil || created.Data["private_key"] != nil {
		t.Fatal("Keycloak JWE key response exposed material or omitted its reference")
	}
	if again := call(logical.UpdateOperation, "keycloak/keys/11id/cookie", nil); again.Data["version"] != version {
		t.Fatal("create did not preserve current key version")
	}
	plaintext := []byte("disposable-cookie-payload")
	encoded := call(logical.UpdateOperation,
		"keycloak/jwe/encode/11id/cookie/"+version,
		map[string]any{"plaintext_base64": base64.StdEncoding.EncodeToString(plaintext)})
	compact := encoded.Data["jwe"].(string)
	if strings.Contains(compact, string(plaintext)) {
		t.Fatal("JWE exposed plaintext")
	}
	decoded := call(logical.UpdateOperation,
		"keycloak/jwe/decode/11id/cookie/"+version,
		map[string]any{"jwe": compact})
	if decoded.Data["plaintext_base64"] != base64.StdEncoding.EncodeToString(plaintext) {
		t.Fatal("Keycloak JWE did not round trip")
	}
	ciba := call(logical.UpdateOperation, "keycloak/keys/11id/ciba", nil)
	response, err := engine.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keycloak/jwe/decode/11id/ciba/" + ciba.Data["version"].(string),
		Storage:   storage, Data: map[string]any{"jwe": compact},
	})
	if err == nil || response == nil || !response.IsError() {
		t.Fatal("cookie ciphertext crossed the CIBA purpose boundary")
	}
	parts := strings.Split(compact, ".")
	parts[4] = strings.Repeat("A", len(parts[4]))
	response, err = engine.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "keycloak/jwe/decode/11id/cookie/" + version,
		Storage:   storage, Data: map[string]any{"jwe": strings.Join(parts, ".")},
	})
	if err == nil || response == nil || !response.IsError() {
		t.Fatal("tampered Keycloak JWE was accepted")
	}
	rotated := call(logical.UpdateOperation, "keycloak/keys/11id/cookie/rotate", nil)
	newVersion := rotated.Data["version"].(string)
	if newVersion == version {
		t.Fatal("rotation reused the same version")
	}
	if current := call(logical.ReadOperation, "keycloak/keys/11id/cookie", nil); current.Data["version"] != newVersion {
		t.Fatal("current Keycloak JWE pointer did not rotate")
	}
	call(logical.UpdateOperation, "keycloak/jwe/decode/11id/cookie/"+version,
		map[string]any{"jwe": compact})
	newEncoded := call(logical.UpdateOperation,
		"keycloak/jwe/encode/11id/cookie/"+newVersion,
		map[string]any{"plaintext_base64": base64.StdEncoding.EncodeToString(plaintext)})
	call(logical.UpdateOperation, "keycloak/jwe/decode/11id/cookie/"+newVersion,
		map[string]any{"jwe": newEncoded.Data["jwe"]})
	fault := failMetadataStorage{storage.(logical.TransactionalStorage)}
	failed, err := engine.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "keycloak/keys/11id/cookie/rotate",
		Storage: fault,
	})
	if err == nil || failed != nil {
		t.Fatal("failed metadata write rotated the Keycloak JWE key")
	}
	if current := call(logical.ReadOperation, "keycloak/keys/11id/cookie", nil); current.Data["version"] != newVersion {
		t.Fatal("failed rotation changed the current Keycloak JWE key")
	}
	versions, err := storage.List(ctx, "keycloak/secret/11id/cookie/")
	if err != nil || len(versions) != 2 {
		t.Fatalf("failed rotation retained an uncommitted version: %v %v", versions, err)
	}
}
