package backend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
)

func TestVersionedSenderKeyAndBoundPack(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	engine, err := Factory(ctx, &logical.BackendConfig{StorageView: storage})
	if err != nil {
		t.Fatal(err)
	}
	request := func(op logical.Operation, path string, data map[string]any) *logical.Response {
		t.Helper()
		response, err := engine.HandleRequest(ctx, &logical.Request{
			Operation: op, Path: path, Storage: storage, Data: data,
		})
		if err != nil && !errors.Is(err, logical.ErrInvalidRequest) {
			t.Fatalf("%s %s: %v (%#v)", op, path, err, response)
		}
		return response
	}
	keyPath := "keys/tenant_a/sender"
	created := request(logical.UpdateOperation, keyPath, map[string]any{
		"sender_did": "did:example:alice", "sender_key_id": "did:example:alice#agreement-1",
	})
	if created == nil || created.IsError() {
		t.Fatalf("create failed: %#v", created)
	}
	assertPublicOnly(t, created)
	initialVersion, ok := created.Data["version"].(string)
	if !ok || !versionID.MatchString(initialVersion) {
		t.Fatalf("unexpected initial version: %#v", created.Data)
	}
	privateInput := request(logical.UpdateOperation, "keys/tenant_a/reject_private", map[string]any{
		"sender_did": "did:example:alice", "sender_key_id": "did:example:alice#agreement-2",
		"private_key": "forbidden-synthetic-value",
	})
	if privateInput == nil || !privateInput.IsError() {
		t.Fatal("accepted caller-supplied private key field")
	}
	read := request(logical.ReadOperation, keyPath, nil)
	assertPublicOnly(t, read)
	if read.Data["public_key"] != created.Data["public_key"] {
		t.Fatal("public key changed without rotation")
	}
	rotated := request(logical.UpdateOperation, keyPath+"/rotate", nil)
	assertPublicOnly(t, rotated)
	rotatedVersion, ok := rotated.Data["version"].(string)
	if !ok || !versionID.MatchString(rotatedVersion) || rotatedVersion == initialVersion || rotated.Data["public_key"] == created.Data["public_key"] {
		t.Fatalf("rotation did not advance key: %#v", rotated.Data)
	}
	old := request(logical.ReadOperation, keyPath+"/versions/"+initialVersion, nil)
	assertPublicOnly(t, old)
	if old.Data["public_key"] != created.Data["public_key"] {
		t.Fatal("old key version was not preserved")
	}
	plaintext := []byte(`{"id":"urn:test:1","from":"did:example:alice","to":["did:example:bob"],"type":"https://didcomm.org/test/1.0/message","body":{}}`)
	publicRecipient := "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E" // Published DIDComm 2.1 Bob public key.
	recipients, _ := json.Marshal([]map[string]string{{
		"kid": "did:example:bob#key-x25519-1", "public_key": publicRecipient,
	}})
	packed := request(logical.UpdateOperation, "pack/tenant_a/sender/"+initialVersion, map[string]any{
		"recipient_did": "did:example:bob", "recipients": string(recipients),
		"plaintext_base64": base64.StdEncoding.EncodeToString(plaintext),
	})
	if packed == nil || packed.IsError() {
		t.Fatalf("pack failed: %#v", packed)
	}
	if packed.Data["version"] != initialVersion || !strings.Contains(packed.Data["jwe"].(string), `"recipients"`) {
		t.Fatalf("invalid pack response: %#v", packed.Data)
	}
	multiple, _ := json.Marshal([]map[string]string{
		{"kid": "did:example:bob#key-x25519-2", "public_key": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM"},
		{"kid": "did:example:bob#key-x25519-1", "public_key": publicRecipient},
	})
	multiPacked := request(logical.UpdateOperation, "pack/tenant_a/sender/"+initialVersion, map[string]any{
		"recipient_did": "did:example:bob", "recipients": string(multiple),
		"plaintext_base64": base64.StdEncoding.EncodeToString(plaintext),
	})
	if multiPacked == nil || multiPacked.IsError() {
		t.Fatalf("multi-recipient pack failed: %#v", multiPacked)
	}
	var multiEnvelope struct {
		Recipients []struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"recipients"`
	}
	if err := json.Unmarshal([]byte(multiPacked.Data["jwe"].(string)), &multiEnvelope); err != nil ||
		len(multiEnvelope.Recipients) != 2 ||
		multiEnvelope.Recipients[0].EncryptedKey == multiEnvelope.Recipients[1].EncryptedKey {
		t.Fatal("multi-recipient envelope is missing distinct wrapped keys")
	}
	zeroPublic := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	lowOrder, _ := json.Marshal([]map[string]string{{
		"kid": "did:example:bob#low-order", "public_key": zeroPublic,
	}})
	lowOrderResult := request(logical.UpdateOperation, "pack/tenant_a/sender/"+initialVersion, map[string]any{
		"recipient_did": "did:example:bob", "recipients": string(lowOrder),
		"plaintext_base64": base64.StdEncoding.EncodeToString(plaintext),
	})
	if lowOrderResult == nil || !lowOrderResult.IsError() {
		t.Fatal("accepted an all-zero X25519 recipient point")
	}
	duplicateRecipient := request(logical.UpdateOperation, "pack/tenant_a/sender/"+initialVersion, map[string]any{
		"recipient_did":    "did:example:bob",
		"recipients":       `[{"kid":"did:example:bob#key-x25519-1","kid":"did:example:bob#key-x25519-2","public_key":"GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E"}]`,
		"plaintext_base64": base64.StdEncoding.EncodeToString(plaintext),
	})
	if duplicateRecipient == nil || !duplicateRecipient.IsError() {
		t.Fatal("accepted duplicate recipient key ID field")
	}
	foreign := request(logical.UpdateOperation, "pack/tenant_a/sender/"+initialVersion, map[string]any{
		"recipient_did": "did:example:mallory", "recipients": string(recipients),
		"plaintext_base64": base64.StdEncoding.EncodeToString(plaintext),
	})
	if foreign == nil || !foreign.IsError() {
		t.Fatal("accepted a foreign recipient DID")
	}
	wrongSender := request(logical.UpdateOperation, "pack/tenant_a/sender/"+initialVersion, map[string]any{
		"recipient_did": "did:example:bob", "recipients": string(recipients),
		"plaintext_base64": base64.StdEncoding.EncodeToString([]byte(`{"from":"did:example:mallory","to":["did:example:bob"]}`)),
	})
	if wrongSender == nil || !wrongSender.IsError() {
		t.Fatal("accepted a foreign plaintext sender")
	}
	duplicateSender := request(logical.UpdateOperation, "pack/tenant_a/sender/"+initialVersion, map[string]any{
		"recipient_did": "did:example:bob", "recipients": string(recipients),
		"plaintext_base64": base64.StdEncoding.EncodeToString([]byte(`{"from":"did:example:mallory","from":"did:example:alice","to":["did:example:bob"]}`)),
	})
	if duplicateSender == nil || !duplicateSender.IsError() {
		t.Fatal("accepted duplicate plaintext sender")
	}
	entry, err := storage.Get(ctx, versionPath("tenant_a", "sender", initialVersion))
	if err != nil || entry == nil {
		t.Fatalf("stored key version is missing: %v", err)
	}
	var stored map[string]json.RawMessage
	if err := json.Unmarshal(entry.Value, &stored); err != nil {
		t.Fatal(err)
	}
	stored["public_key"], _ = json.Marshal(make([]byte, 32))
	entry.Value, err = json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}
	corruptRead, readErr := engine.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: keyPath + "/versions/" + initialVersion, Storage: storage,
	})
	if readErr == nil && corruptRead != nil && !corruptRead.IsError() {
		t.Fatal("published a stored public key that does not match its private key")
	}
	corruptPack, packErr := engine.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "pack/tenant_a/sender/" + initialVersion, Storage: storage,
		Data: map[string]any{
			"recipient_did": "did:example:bob", "recipients": string(recipients),
			"plaintext_base64": base64.StdEncoding.EncodeToString(plaintext),
		},
	})
	if packErr == nil && corruptPack != nil && !corruptPack.IsError() {
		t.Fatal("packed with a stored public/private key mismatch")
	}
}

func assertPublicOnly(t *testing.T, response *logical.Response) {
	t.Helper()
	if response == nil || response.IsError() {
		t.Fatalf("expected public response: %#v", response)
	}
	serialized, err := json.Marshal(response.Data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(serialized), "private") {
		t.Fatalf("public response exposes private-key field: %s", serialized)
	}
}

func TestConcurrentRotationsKeepUniqueVersions(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	engine, err := Factory(ctx, &logical.BackendConfig{StorageView: storage})
	if err != nil {
		t.Fatal(err)
	}
	path := "keys/tenant_a/concurrent"
	created, err := engine.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: path, Storage: storage,
		Data: map[string]any{"sender_did": "did:example:alice", "sender_key_id": "did:example:alice#agreement-1"},
	})
	if err != nil || created == nil || created.IsError() {
		t.Fatalf("create: %v %#v", err, created)
	}
	const rotations = 12
	var wg sync.WaitGroup
	results := make(chan string, rotations)
	errors := make(chan error, rotations)
	for i := 0; i < rotations; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response, err := engine.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation, Path: path + "/rotate", Storage: storage,
			})
			if err != nil {
				errors <- err
				return
			}
			if response == nil || response.IsError() {
				errors <- fmt.Errorf("rotation error: %#v", response)
				return
			}
			results <- response.Data["version"].(string)
		}()
	}
	wg.Wait()
	close(results)
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	seen := make(map[string]bool)
	for version := range results {
		if !versionID.MatchString(version) || seen[version] {
			t.Errorf("invalid or duplicate rotation version %s", version)
		}
		seen[version] = true
	}
	if len(seen) != rotations {
		t.Fatalf("only %d distinct versions after %d rotations", len(seen), rotations)
	}
	current, err := engine.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: path, Storage: storage,
	})
	if err != nil || current == nil || current.IsError() || !seen[current.Data["version"].(string)] {
		t.Fatalf("current version did not advance: %v %#v", err, current)
	}
	for version := range seen {
		prior, err := engine.HandleRequest(ctx, &logical.Request{
			Operation: logical.ReadOperation, Path: path + "/versions/" + version, Storage: storage,
		})
		if err != nil || prior == nil || prior.IsError() || prior.Data["version"] != version {
			t.Fatalf("concurrent version %s was lost: %v %#v", version, err, prior)
		}
	}
}
