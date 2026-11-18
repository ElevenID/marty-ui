package jwe

import (
	"bytes"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

func TestDirectJWEInteropAndTamperDenial(t *testing.T) {
	// Synthetic test key stays in the plugin package; no key is exported by an
	// OpenBao endpoint or persisted in a product fixture.
	cek := make([]byte, 64)
	for i := range cek {
		cek[i] = byte(i + 1)
	}
	defer clear(cek)
	for _, size := range []int{1, 16, 17, 1024} {
		plaintext := bytes.Repeat([]byte("p"), size)
		compact, err := EncodeDirect(cek, "keycloak-11id-v1", plaintext)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := jose.ParseEncrypted(compact,
			[]jose.KeyAlgorithm{jose.DIRECT},
			[]jose.ContentEncryption{jose.A256CBC_HS512})
		if err != nil {
			t.Fatalf("standard JOSE parser rejected compact JWE: %v", err)
		}
		independent, err := parsed.Decrypt(cek)
		if err != nil || !bytes.Equal(independent, plaintext) {
			t.Fatalf("standard JOSE decryption failed: %v", err)
		}
		decoded, err := DecodeDirect(cek, "keycloak-11id-v1", compact)
		if err != nil || !bytes.Equal(decoded, plaintext) {
			t.Fatalf("plugin decryption failed: %v", err)
		}
		if _, err := DecodeDirect(cek, "keycloak-master-v1", compact); err == nil {
			t.Fatal("wrong remote key reference was accepted")
		}
		parts := strings.Split(compact, ".")
		parts[4] = strings.Repeat("A", len(parts[4]))
		if _, err := DecodeDirect(cek, "keycloak-11id-v1", strings.Join(parts, ".")); err == nil {
			t.Fatal("modified authentication tag was accepted")
		}
	}
}

func TestDirectJWERejectsBadInputs(t *testing.T) {
	cek := make([]byte, 64)
	if _, err := EncodeDirect(cek[:32], "keycloak-11id-v1", []byte("x")); err == nil {
		t.Fatal("short CEK was accepted")
	}
	if _, err := EncodeDirect(cek, "keycloak-11id-v1", nil); err == nil {
		t.Fatal("empty plaintext was accepted")
	}
	if _, err := EncodeDirect(cek, "keycloak-11id-v1", make([]byte, maxDirectPlaintext+1)); err == nil {
		t.Fatal("oversized plaintext was accepted")
	}
	if _, err := DecodeDirect(cek, "keycloak-11id-v1", "a.b.c"); err == nil {
		t.Fatal("malformed compact JWE was accepted")
	}
}
