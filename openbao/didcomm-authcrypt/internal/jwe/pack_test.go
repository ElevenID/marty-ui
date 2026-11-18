package jwe

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestAESKeyWrapRFC3394Vector(t *testing.T) {
	// RFC 3394 section 4.1: 128-bit KEK wrapping a 128-bit key.
	kek, _ := hex.DecodeString("000102030405060708090A0B0C0D0E0F")
	key, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
	want, _ := hex.DecodeString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
	got, err := wrapAESKey(kek, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("AES-KW mismatch: got %X, want %X", got, want)
	}
}

func TestAESKeyWrapRejectsInvalidLength(t *testing.T) {
	if _, err := wrapAESKey(make([]byte, 32), make([]byte, 9)); err == nil {
		t.Fatal("accepted partial 64-bit block")
	}
}

func TestECDH1PUConcatKDFDraftAppendixB(t *testing.T) {
	// Published ECDH-1PU draft -04 Appendix B.9 KDF intermediate values.
	// The example uses A128KW; the same KDF encodes A256KW with a 256-bit output.
	z, _ := hex.DecodeString("32810896e0fe4d570ed1acfcedf67117dc194ed5daac21d8ff7af3244694897f2157612c9048edfae77cb2e4237140605967c05c7f77a48eeaf2cf29a5737c4a")
	tag, _ := hex.DecodeString("1cb6f87d3966f2ca469a28f74723acda02780e91cce21855470745fe119bdd64")
	want, _ := hex.DecodeString("df4c37a0668306a11e3d6b0074b5d8df")
	got := concatKDF(z, []byte("ECDH-1PU+A128KW"), []byte("Alice"), []byte("Bob and Charlie"), tag, 16)
	if !bytes.Equal(got, want) {
		t.Fatalf("ECDH-1PU KDF mismatch: got %X, want %X", got, want)
	}
}
