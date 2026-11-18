package jwe

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Direct JWE keeps the complete A256CBC-HS512 CEK inside the OpenBao plugin.
// The returned compact JWE contains only authenticated ciphertext and a
// versioned public key reference. It is intended for Keycloak cookie/CIBA
// payloads after the pinned Keycloak call sites have been made remote-aware.
type directHeader struct {
	Alg string `json:"alg"`
	Enc string `json:"enc"`
	Kid string `json:"kid"`
}

const maxDirectPlaintext = 1 << 20

func validDirectInput(cek []byte, kid string) bool {
	return len(cek) == 64 && kid != "" && len(kid) <= 256 &&
		!strings.ContainsAny(kid, "\x00\r\n")
}

func EncodeDirect(cek []byte, kid string, plaintext []byte) (string, error) {
	if !validDirectInput(cek, kid) || len(plaintext) == 0 || len(plaintext) > maxDirectPlaintext {
		return "", errors.New("invalid direct JWE input")
	}
	header, err := json.Marshal(directHeader{Alg: "dir", Enc: contentAlg, Kid: kid})
	if err != nil {
		return "", err
	}
	protected := b64.EncodeToString(header)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	ciphertext, tag, err := encryptContent(cek, iv, []byte(protected), plaintext)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{protected, "", b64.EncodeToString(iv),
		b64.EncodeToString(ciphertext), b64.EncodeToString(tag)}, "."), nil
}

func DecodeDirect(cek []byte, kid, compact string) ([]byte, error) {
	if !validDirectInput(cek, kid) || len(compact) > 2*maxDirectPlaintext {
		return nil, errors.New("invalid direct JWE input")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 5 || parts[1] != "" {
		return nil, errors.New("invalid direct JWE format")
	}
	headerBytes, err := b64.DecodeString(parts[0])
	if err != nil || len(headerBytes) > 512 {
		return nil, errors.New("invalid direct JWE header")
	}
	var header directHeader
	if json.Unmarshal(headerBytes, &header) != nil ||
		header.Alg != "dir" || header.Enc != contentAlg || header.Kid != kid {
		return nil, errors.New("direct JWE key or algorithm mismatch")
	}
	canonical, err := json.Marshal(header)
	if err != nil || !bytes.Equal(headerBytes, canonical) {
		return nil, errors.New("noncanonical direct JWE header")
	}
	iv, ivErr := b64.DecodeString(parts[2])
	ciphertext, ciphertextErr := b64.DecodeString(parts[3])
	tag, tagErr := b64.DecodeString(parts[4])
	if ivErr != nil || ciphertextErr != nil || tagErr != nil ||
		len(iv) != aes.BlockSize || len(ciphertext) == 0 ||
		len(ciphertext)%aes.BlockSize != 0 || len(tag) != 32 {
		return nil, errors.New("invalid direct JWE ciphertext")
	}
	if !hmac.Equal(contentTag(cek, iv, []byte(parts[0]), ciphertext), tag) {
		return nil, errors.New("direct JWE authentication failed")
	}
	block, err := aes.NewCipher(cek[32:])
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	pad := int(plaintext[len(plaintext)-1])
	if pad < 1 || pad > aes.BlockSize ||
		!bytes.Equal(plaintext[len(plaintext)-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
		clear(plaintext)
		return nil, errors.New("invalid direct JWE padding")
	}
	result := bytes.Clone(plaintext[:len(plaintext)-pad])
	clear(plaintext)
	if len(result) == 0 || len(result) > maxDirectPlaintext {
		clear(result)
		return nil, errors.New("invalid direct JWE plaintext length")
	}
	return result, nil
}
