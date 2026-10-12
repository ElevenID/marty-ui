// Package jwe constructs DIDComm ECDH-1PU authenticated envelopes inside the
// OpenBao plugin process. Callers must never return the sender key or agreement
// intermediates from the plugin boundary.
package jwe

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

const (
	maxRecipients = 32
	maxPlaintext  = 1 << 20
	keyWrapAlg    = "ECDH-1PU+A256KW"
	contentAlg    = "A256CBC-HS512"
)

var b64 = base64.RawURLEncoding

// Recipient is a DID-authorized X25519 key, verified by the caller and again
// bound to its kid by the secrets engine before Pack is invoked.
type Recipient struct {
	KeyID     string
	PublicKey []byte
}

type protectedHeader struct {
	Type string          `json:"typ"`
	Alg  string          `json:"alg"`
	Enc  string          `json:"enc"`
	Skid string          `json:"skid"`
	Apu  string          `json:"apu"`
	Apv  string          `json:"apv"`
	Epk  ephemeralKeyJWK `json:"epk"`
}

type ephemeralKeyJWK struct {
	Type  string `json:"kty"`
	Curve string `json:"crv"`
	X     string `json:"x"`
}

type envelopeRecipient struct {
	Header struct {
		KeyID string `json:"kid"`
	} `json:"header"`
	EncryptedKey string `json:"encrypted_key"`
}

type envelope struct {
	Protected  string              `json:"protected"`
	Recipients []envelopeRecipient `json:"recipients"`
	IV         string              `json:"iv"`
	Ciphertext string              `json:"ciphertext"`
	Tag        string              `json:"tag"`
}

// Pack returns one complete DIDComm authcrypt JWE. The sender private key and
// all derived secrets remain inside the caller's OpenBao plugin process.
// Authorization, DID resolution, key lifecycle, and request binding belong to
// the secrets engine, not this crypto primitive.
func Pack(senderKeyID string, sender *ecdh.PrivateKey, recipients []Recipient, plaintext []byte) ([]byte, error) {
	if sender == nil || sender.Curve() != ecdh.X25519() {
		return nil, errors.New("sender must be an X25519 key")
	}
	if senderKeyID == "" || len(senderKeyID) > 1024 || strings.ContainsAny(senderKeyID, "\x00\r\n") {
		return nil, errors.New("invalid sender key ID")
	}
	if len(recipients) == 0 || len(recipients) > maxRecipients {
		return nil, errors.New("invalid recipient count")
	}
	if len(plaintext) == 0 || len(plaintext) > maxPlaintext {
		return nil, errors.New("invalid plaintext length")
	}
	ids := make([]string, 0, len(recipients))
	publics := make([]*ecdh.PublicKey, 0, len(recipients))
	seen := make(map[string]bool, len(recipients))
	for _, recipient := range recipients {
		if recipient.KeyID == "" || len(recipient.KeyID) > 1024 || strings.ContainsAny(recipient.KeyID, "\x00\r\n") || seen[recipient.KeyID] {
			return nil, errors.New("invalid or duplicate recipient key ID")
		}
		public, err := ecdh.X25519().NewPublicKey(recipient.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient public key: %w", err)
		}
		seen[recipient.KeyID] = true
		ids = append(ids, recipient.KeyID)
		publics = append(publics, public)
	}
	sort.Strings(ids)
	apv := sha256.Sum256([]byte(strings.Join(ids, ".")))
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ephemeral key generation failed: %w", err)
	}
	headerJSON, err := json.Marshal(protectedHeader{
		Type: "application/didcomm-encrypted+json",
		Alg:  keyWrapAlg,
		Enc:  contentAlg,
		Skid: senderKeyID,
		Apu:  b64.EncodeToString([]byte(senderKeyID)),
		Apv:  b64.EncodeToString(apv[:]),
		Epk:  ephemeralKeyJWK{Type: "OKP", Curve: "X25519", X: b64.EncodeToString(eph.PublicKey().Bytes())},
	})
	if err != nil {
		return nil, err
	}
	protected := b64.EncodeToString(headerJSON)
	cek := make([]byte, 64)
	iv := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, cek); err != nil {
		return nil, err
	}
	defer clear(cek)
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	ciphertext, tag, err := encryptContent(cek, iv, []byte(protected), plaintext)
	if err != nil {
		return nil, err
	}
	result := envelope{
		Protected:  protected,
		IV:         b64.EncodeToString(iv),
		Ciphertext: b64.EncodeToString(ciphertext),
		Tag:        b64.EncodeToString(tag),
		Recipients: make([]envelopeRecipient, 0, len(recipients)),
	}
	for i, recipient := range recipients {
		ze, err := eph.ECDH(publics[i])
		if err != nil {
			return nil, errors.New("ephemeral agreement failed")
		}
		zs, err := sender.ECDH(publics[i])
		if err != nil {
			clear(ze)
			return nil, errors.New("sender agreement failed")
		}
		z := append(ze, zs...)
		kek := concatKDF(z, []byte(keyWrapAlg), []byte(senderKeyID), apv[:], tag, 32)
		clear(z)
		clear(ze)
		clear(zs)
		wrapped, err := wrapAESKey(kek, cek)
		clear(kek)
		if err != nil {
			return nil, err
		}
		entry := envelopeRecipient{EncryptedKey: b64.EncodeToString(wrapped)}
		entry.Header.KeyID = recipient.KeyID
		result.Recipients = append(result.Recipients, entry)
	}
	return json.Marshal(result)
}

func encryptContent(cek, iv, aad, plaintext []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(cek[32:])
	if err != nil {
		return nil, nil, err
	}
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+pad)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	defer clear(padded)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	mac := hmac.New(sha512.New, cek[:32])
	_, _ = mac.Write(aad)
	_, _ = mac.Write(iv)
	_, _ = mac.Write(ciphertext)
	var aadLength [8]byte
	binary.BigEndian.PutUint64(aadLength[:], uint64(len(aad))*8)
	_, _ = mac.Write(aadLength[:])
	return ciphertext, mac.Sum(nil)[:32], nil
}

func concatKDF(z, algorithm, apu, apv, tag []byte, size int) []byte {
	h := sha256.New()
	var sizeWord [4]byte
	binary.BigEndian.PutUint32(sizeWord[:], 1)
	_, _ = h.Write(sizeWord[:])
	_, _ = h.Write(z)
	writeLengthPrefixed(h, algorithm)
	writeLengthPrefixed(h, apu)
	writeLengthPrefixed(h, apv)
	binary.BigEndian.PutUint32(sizeWord[:], uint32(size*8))
	_, _ = h.Write(sizeWord[:])
	writeLengthPrefixed(h, tag)
	return h.Sum(nil)[:size]
}

func writeLengthPrefixed(w io.Writer, value []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	_, _ = w.Write(size[:])
	_, _ = w.Write(value)
}

// wrapAESKey implements the RFC 3394 AES key wrap transform. Input is an
// integral number of 64-bit blocks and is never returned unwrapped by Pack.
func wrapAESKey(kek, key []byte) ([]byte, error) {
	if len(key) < 16 || len(key)%8 != 0 {
		return nil, errors.New("invalid key-wrap input length")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(key) / 8
	wrapped := make([]byte, len(key)+8)
	for i := range wrapped[:8] {
		wrapped[i] = 0xa6
	}
	copy(wrapped[8:], key)
	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(b[:8], wrapped[:8])
			copy(b[8:], wrapped[i*8:(i+1)*8])
			block.Encrypt(b[:], b[:])
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(wrapped[:8], binary.BigEndian.Uint64(b[:8])^t)
			copy(wrapped[i*8:(i+1)*8], b[8:])
		}
	}
	clear(b[:])
	return wrapped, nil
}
