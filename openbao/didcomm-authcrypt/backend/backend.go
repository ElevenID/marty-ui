package backend

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"sync"

	"github.com/ElevenID/marty-ui/openbao/didcomm-authcrypt/internal/jwe"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

var pathPart = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var versionID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// Lifecycle operations share a process-wide lock because logical storage
// transactions do not by themselves serialize concurrent metadata updates.
// Random version identifiers prevent different plugin processes from writing
// the same private-key slot; HA selection of the advisory current pointer
// still requires qualification before a multi-writer deployment.
var keyLifecycleMu sync.Mutex

type keyMeta struct {
	Tenant         string `json:"tenant"`
	Name           string `json:"name"`
	SenderDID      string `json:"sender_did"`
	SenderKeyID    string `json:"sender_key_id"`
	CurrentVersion string `json:"current_version"`
}

type keyVersion struct {
	Version    string `json:"version"`
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
}

type packRecipient struct {
	KeyID     string `json:"kid"`
	PublicKey string `json:"public_key"`
}

type plaintextMessage struct {
	From string   `json:"from"`
	To   []string `json:"to"`
}

func parsePlaintextParties(plaintext []byte) (plaintextMessage, error) {
	var message plaintextMessage
	if len(bytes.TrimSpace(plaintext)) == 0 || bytes.TrimSpace(plaintext)[0] != '{' {
		return message, errors.New("plaintext must be a JSON object")
	}
	if err := rejectDuplicateJSONKeys(plaintext); err != nil {
		return message, err
	}
	if err := json.Unmarshal(plaintext, &message); err != nil {
		return message, err
	}
	return message, nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("trailing JSON data")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 128 {
		return errors.New("JSON nesting limit exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			name, err := decoder.Token()
			if err != nil {
				return err
			}
			field, ok := name.(string)
			if !ok || seen[field] {
				return errors.New("duplicate or invalid JSON field")
			}
			seen[field] = true
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim(map[json.Delim]rune{'{': '}', '[': ']'}[delim]) {
		return errors.New("invalid JSON structure")
	}
	return nil
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "Non-exportable DIDComm X25519 sender and HAIP P-256 response keys",
		Paths: []*framework.Path{
			haipKeyPath(),
			haipReadVersionPath(),
			haipDecryptPath(),
			{
				Pattern: `keys/(?P<tenant>[A-Za-z0-9_-]{1,64})/(?P<name>[A-Za-z0-9_-]{1,64})`,
				Fields: map[string]*framework.FieldSchema{
					"tenant":        {Type: framework.TypeString},
					"name":          {Type: framework.TypeString},
					"sender_did":    {Type: framework.TypeString, Required: true},
					"sender_key_id": {Type: framework.TypeString, Required: true},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.CreateOperation: &framework.PathOperation{Callback: createKey},
					logical.UpdateOperation: &framework.PathOperation{Callback: createKey},
					logical.ReadOperation:   &framework.PathOperation{Callback: readCurrentKey},
				},
			},
			{
				Pattern: `keys/(?P<tenant>[A-Za-z0-9_-]{1,64})/(?P<name>[A-Za-z0-9_-]{1,64})/rotate`,
				Fields: map[string]*framework.FieldSchema{
					"tenant": {Type: framework.TypeString},
					"name":   {Type: framework.TypeString},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{Callback: rotateKey},
				},
			},
			{
				Pattern: `keys/(?P<tenant>[A-Za-z0-9_-]{1,64})/(?P<name>[A-Za-z0-9_-]{1,64})/versions/(?P<version>[0-9a-f]{32})`,
				Fields: map[string]*framework.FieldSchema{
					"tenant":  {Type: framework.TypeString},
					"name":    {Type: framework.TypeString},
					"version": {Type: framework.TypeString},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.ReadOperation: &framework.PathOperation{Callback: readKeyVersion},
				},
			},
			{
				Pattern: `pack/(?P<tenant>[A-Za-z0-9_-]{1,64})/(?P<name>[A-Za-z0-9_-]{1,64})/(?P<version>[0-9a-f]{32})`,
				Fields: map[string]*framework.FieldSchema{
					"tenant":           {Type: framework.TypeString},
					"name":             {Type: framework.TypeString},
					"version":          {Type: framework.TypeString},
					"recipient_did":    {Type: framework.TypeString, Required: true},
					"recipients":       {Type: framework.TypeString, Required: true},
					"plaintext_base64": {Type: framework.TypeString, Required: true},
				},
				Operations: map[logical.Operation]framework.OperationHandler{
					logical.UpdateOperation: &framework.PathOperation{Callback: pack},
				},
			},
		},
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func names(d *framework.FieldData) (string, string, error) {
	tenant := d.Get("tenant").(string)
	name := d.Get("name").(string)
	if !pathPart.MatchString(tenant) || !pathPart.MatchString(name) {
		return "", "", errors.New("invalid tenant or key name")
	}
	return tenant, name, nil
}

func onlyFields(data map[string]any, allowed ...string) bool {
	for field := range data {
		found := false
		for _, name := range allowed {
			if field == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func didOwnsKeyID(did, keyID string) bool {
	return strings.HasPrefix(did, "did:") && len(did) <= 1024 && len(keyID) <= 1024 &&
		strings.HasPrefix(keyID, did+"#") && len(keyID) > len(did)+1 &&
		!strings.ContainsAny(did+keyID, "\x00\r\n")
}

func metadataPath(tenant, name string) string { return "meta/" + tenant + "/" + name }
func versionPath(tenant, name, version string) string {
	return "secret/" + tenant + "/" + name + "/" + version
}

func loadMeta(ctx context.Context, storage logical.Storage, tenant, name string) (*keyMeta, error) {
	entry, err := storage.Get(ctx, metadataPath(tenant, name))
	if err != nil || entry == nil {
		return nil, err
	}
	var meta keyMeta
	if err := json.Unmarshal(entry.Value, &meta); err != nil {
		return nil, err
	}
	if meta.Tenant != tenant || meta.Name != name || !versionID.MatchString(meta.CurrentVersion) || !didOwnsKeyID(meta.SenderDID, meta.SenderKeyID) {
		return nil, errors.New("stored key metadata is invalid")
	}
	return &meta, nil
}

func loadVersion(ctx context.Context, storage logical.Storage, meta *keyMeta, version string) (*keyVersion, error) {
	if !versionID.MatchString(version) {
		return nil, errors.New("key version not found")
	}
	entry, err := storage.Get(ctx, versionPath(meta.Tenant, meta.Name, version))
	if err != nil || entry == nil {
		return nil, err
	}
	var key keyVersion
	if err := json.Unmarshal(entry.Value, &key); err != nil {
		clear(key.PrivateKey)
		return nil, err
	}
	if key.Version != version || len(key.PrivateKey) != 32 || len(key.PublicKey) != 32 {
		clear(key.PrivateKey)
		return nil, errors.New("stored key version is invalid")
	}
	private, err := ecdh.X25519().NewPrivateKey(key.PrivateKey)
	if err != nil || !bytes.Equal(private.PublicKey().Bytes(), key.PublicKey) {
		clear(key.PrivateKey)
		return nil, errors.New("stored key version has mismatched key material")
	}
	return &key, nil
}

func newVersion() (*keyVersion, error) {
	var identifier [16]byte
	if _, err := rand.Read(identifier[:]); err != nil {
		return nil, err
	}
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &keyVersion{Version: hex.EncodeToString(identifier[:]), PrivateKey: private.Bytes(), PublicKey: private.PublicKey().Bytes()}, nil
}

func putJSON(ctx context.Context, storage logical.Storage, path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	// Storage implementations may retain Value without copying it. The stored
	// bytes must remain intact for the backend's lifetime.
	return storage.Put(ctx, &logical.StorageEntry{Key: path, Value: data})
}

func requireTransactionalStorage(storage logical.Storage) error {
	if _, ok := storage.(logical.TransactionalStorage); !ok {
		return errors.New("key lifecycle requires transactional OpenBao storage")
	}
	return nil
}

func publicResponse(meta *keyMeta, key *keyVersion) *logical.Response {
	return &logical.Response{Data: map[string]any{
		"tenant": meta.Tenant, "name": meta.Name,
		"sender_did": meta.SenderDID, "sender_key_id": meta.SenderKeyID,
		"version": key.Version, "public_key": base64.RawURLEncoding.EncodeToString(key.PublicKey),
	}}
}

func createKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keyLifecycleMu.Lock()
	defer keyLifecycleMu.Unlock()
	if !onlyFields(req.Data, "tenant", "name", "sender_did", "sender_key_id") {
		return logical.ErrorResponse("unexpected key creation field"), logical.ErrInvalidRequest
	}
	tenant, name, err := names(d)
	if err != nil {
		return logical.ErrorResponse("invalid key path"), logical.ErrInvalidRequest
	}
	did := d.Get("sender_did").(string)
	kid := d.Get("sender_key_id").(string)
	if !didOwnsKeyID(did, kid) {
		return logical.ErrorResponse("sender key ID must belong to sender DID"), logical.ErrInvalidRequest
	}
	if err := requireTransactionalStorage(req.Storage); err != nil {
		return nil, err
	}
	rollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer rollback()
	meta, err := loadMeta(ctx, req.Storage, tenant, name)
	if err != nil {
		return nil, err
	}
	if meta != nil {
		return logical.ErrorResponse("key already exists"), logical.ErrInvalidRequest
	}
	key, err := newVersion()
	if err != nil {
		return nil, err
	}
	defer clear(key.PrivateKey)
	meta = &keyMeta{Tenant: tenant, Name: name, SenderDID: did, SenderKeyID: kid, CurrentVersion: key.Version}
	if err := putJSON(ctx, req.Storage, versionPath(tenant, name, key.Version), key); err != nil {
		return nil, err
	}
	if err := putJSON(ctx, req.Storage, metadataPath(tenant, name), meta); err != nil {
		return nil, err
	}
	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}
	return publicResponse(meta, key), nil
}

func rotateKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keyLifecycleMu.Lock()
	defer keyLifecycleMu.Unlock()
	if !onlyFields(req.Data, "tenant", "name") {
		return logical.ErrorResponse("unexpected key rotation field"), logical.ErrInvalidRequest
	}
	tenant, name, err := names(d)
	if err != nil {
		return logical.ErrorResponse("invalid key path"), logical.ErrInvalidRequest
	}
	if err := requireTransactionalStorage(req.Storage); err != nil {
		return nil, err
	}
	rollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer rollback()
	meta, err := loadMeta(ctx, req.Storage, tenant, name)
	if err != nil {
		return nil, err
	}
	if meta == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}
	key, err := newVersion()
	if err != nil {
		return nil, err
	}
	defer clear(key.PrivateKey)
	if err := putJSON(ctx, req.Storage, versionPath(tenant, name, key.Version), key); err != nil {
		return nil, err
	}
	meta.CurrentVersion = key.Version
	if err := putJSON(ctx, req.Storage, metadataPath(tenant, name), meta); err != nil {
		return nil, err
	}
	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}
	return publicResponse(meta, key), nil
}

func readCurrentKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keyLifecycleMu.Lock()
	defer keyLifecycleMu.Unlock()
	tenant, name, err := names(d)
	if err != nil {
		return nil, logical.ErrInvalidRequest
	}
	meta, err := loadMeta(ctx, req.Storage, tenant, name)
	if err != nil || meta == nil {
		return nil, err
	}
	key, err := loadVersion(ctx, req.Storage, meta, meta.CurrentVersion)
	if err != nil || key == nil {
		return nil, err
	}
	defer clear(key.PrivateKey)
	return publicResponse(meta, key), nil
}

func readKeyVersion(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keyLifecycleMu.Lock()
	defer keyLifecycleMu.Unlock()
	tenant, name, err := names(d)
	if err != nil {
		return nil, logical.ErrInvalidRequest
	}
	version := d.Get("version").(string)
	if !versionID.MatchString(version) {
		return nil, logical.ErrInvalidRequest
	}
	meta, err := loadMeta(ctx, req.Storage, tenant, name)
	if err != nil || meta == nil {
		return nil, err
	}
	key, err := loadVersion(ctx, req.Storage, meta, version)
	if err != nil || key == nil {
		return nil, err
	}
	defer clear(key.PrivateKey)
	return publicResponse(meta, key), nil
}

func pack(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if !onlyFields(req.Data, "tenant", "name", "version", "recipient_did", "recipients", "plaintext_base64") {
		return logical.ErrorResponse("unexpected authcrypt field"), logical.ErrInvalidRequest
	}
	tenant, name, err := names(d)
	if err != nil {
		return logical.ErrorResponse("invalid key path"), logical.ErrInvalidRequest
	}
	version := d.Get("version").(string)
	if !versionID.MatchString(version) {
		return logical.ErrorResponse("invalid key version"), logical.ErrInvalidRequest
	}
	meta, err := loadMeta(ctx, req.Storage, tenant, name)
	if err != nil || meta == nil {
		return nil, err
	}
	key, err := loadVersion(ctx, req.Storage, meta, version)
	if err != nil || key == nil {
		return nil, err
	}
	defer clear(key.PrivateKey)
	recipientDID := d.Get("recipient_did").(string)
	encodedRecipients := d.Get("recipients").(string)
	if len(encodedRecipients) > 64*1024 || rejectDuplicateJSONKeys([]byte(encodedRecipients)) != nil {
		return logical.ErrorResponse("invalid recipients"), logical.ErrInvalidRequest
	}
	var recipientInputs []packRecipient
	decoder := json.NewDecoder(strings.NewReader(encodedRecipients))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&recipientInputs); err != nil || len(recipientInputs) == 0 || len(recipientInputs) > 32 {
		return logical.ErrorResponse("invalid recipients"), logical.ErrInvalidRequest
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return logical.ErrorResponse("invalid recipients"), logical.ErrInvalidRequest
	}
	recipients := make([]jwe.Recipient, 0, len(recipientInputs))
	for _, item := range recipientInputs {
		if !didOwnsKeyID(recipientDID, item.KeyID) {
			return logical.ErrorResponse("recipient key ID does not belong to recipient DID"), logical.ErrInvalidRequest
		}
		public, err := base64.RawURLEncoding.DecodeString(item.PublicKey)
		if err != nil {
			return logical.ErrorResponse("invalid recipient public key"), logical.ErrInvalidRequest
		}
		recipients = append(recipients, jwe.Recipient{KeyID: item.KeyID, PublicKey: public})
	}
	encodedPlaintext := d.Get("plaintext_base64").(string)
	if len(encodedPlaintext) > 4*(((1<<20)+2)/3) {
		return logical.ErrorResponse("invalid plaintext"), logical.ErrInvalidRequest
	}
	plaintext, err := base64.StdEncoding.DecodeString(encodedPlaintext)
	if err != nil || len(plaintext) == 0 || len(plaintext) > 1<<20 {
		return logical.ErrorResponse("invalid plaintext"), logical.ErrInvalidRequest
	}
	defer clear(plaintext)
	message, err := parsePlaintextParties(plaintext)
	if err != nil || message.From != meta.SenderDID || len(message.To) != 1 || message.To[0] != recipientDID {
		return logical.ErrorResponse("plaintext from/to does not match key and recipient"), logical.ErrInvalidRequest
	}
	private, err := ecdh.X25519().NewPrivateKey(key.PrivateKey)
	if err != nil {
		return nil, errors.New("stored private key is invalid")
	}
	if !bytes.Equal(private.PublicKey().Bytes(), key.PublicKey) {
		return nil, errors.New("stored public/private key mismatch")
	}
	envelope, err := jwe.Pack(meta.SenderKeyID, private, recipients, plaintext)
	if err != nil {
		return logical.ErrorResponse("authcrypt packing failed"), logical.ErrInvalidRequest
	}
	return &logical.Response{Data: map[string]any{
		"jwe": string(envelope), "version": key.Version,
		"sender_key_id": meta.SenderKeyID,
	}}, nil
}
