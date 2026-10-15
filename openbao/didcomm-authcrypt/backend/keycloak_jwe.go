package backend

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/ElevenID/marty-ui/openbao/didcomm-authcrypt/internal/jwe"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

type keycloakJWEKey struct {
	Realm   string `json:"realm"`
	Purpose string `json:"purpose"`
	Version string `json:"version"`
	CEK     []byte `json:"cek"`
}

func keycloakJWEPaths() []*framework.Path {
	scope := `(?P<realm>[A-Za-z0-9_-]{1,64})/(?P<purpose>cookie|ciba)`
	fields := map[string]*framework.FieldSchema{
		"realm":   {Type: framework.TypeString},
		"purpose": {Type: framework.TypeString},
	}
	versionFields := map[string]*framework.FieldSchema{
		"realm":   {Type: framework.TypeString},
		"purpose": {Type: framework.TypeString},
		"version": {Type: framework.TypeString},
	}
	return []*framework.Path{
		{
			Pattern: `keycloak/keys/` + scope,
			Fields:  fields,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: createKeycloakJWEKey},
				logical.UpdateOperation: &framework.PathOperation{Callback: createKeycloakJWEKey},
				logical.ReadOperation:   &framework.PathOperation{Callback: readCurrentKeycloakJWEKey},
			},
		},
		{
			Pattern: `keycloak/keys/` + scope + `/rotate`,
			Fields:  fields,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: rotateKeycloakJWEKey},
			},
		},
		{
			Pattern: `keycloak/keys/` + scope + `/versions/(?P<version>[0-9a-f]{32})`,
			Fields:  versionFields,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: readKeycloakJWEKeyVersion},
			},
		},
		{
			Pattern: `keycloak/jwe/encode/` + scope + `/(?P<version>[0-9a-f]{32})`,
			Fields: map[string]*framework.FieldSchema{
				"realm":            {Type: framework.TypeString},
				"purpose":          {Type: framework.TypeString},
				"version":          {Type: framework.TypeString},
				"plaintext_base64": {Type: framework.TypeString, Required: true},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: encodeKeycloakJWE},
			},
		},
		{
			Pattern: `keycloak/jwe/decode/` + scope + `/(?P<version>[0-9a-f]{32})`,
			Fields: map[string]*framework.FieldSchema{
				"realm":   {Type: framework.TypeString},
				"purpose": {Type: framework.TypeString},
				"version": {Type: framework.TypeString},
				"jwe":     {Type: framework.TypeString, Required: true},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: decodeKeycloakJWE},
			},
		},
	}
}

func keycloakJWEScope(d *framework.FieldData) (string, string, error) {
	realm, purpose := d.Get("realm").(string), d.Get("purpose").(string)
	if !pathPart.MatchString(realm) || (purpose != "cookie" && purpose != "ciba") {
		return "", "", errors.New("invalid Keycloak JWE scope")
	}
	return realm, purpose, nil
}

func keycloakJWEMetaPath(realm, purpose string) string {
	return "keycloak/meta/" + realm + "/" + purpose
}

func keycloakJWEVersionPath(realm, purpose, version string) string {
	return "keycloak/secret/" + realm + "/" + purpose + "/" + version
}

func keycloakJWEKid(key *keycloakJWEKey) string {
	return "keycloak-" + key.Realm + "-" + key.Purpose + "-" + key.Version
}

func loadKeycloakJWEKey(ctx context.Context, storage logical.Storage, realm, purpose, version string) (*keycloakJWEKey, error) {
	if !versionID.MatchString(version) {
		return nil, errors.New("invalid Keycloak JWE version")
	}
	entry, err := storage.Get(ctx, keycloakJWEVersionPath(realm, purpose, version))
	if err != nil || entry == nil {
		return nil, err
	}
	var key keycloakJWEKey
	if err := json.Unmarshal(entry.Value, &key); err != nil {
		return nil, err
	}
	if key.Realm != realm || key.Purpose != purpose || key.Version != version || len(key.CEK) != 64 {
		clear(key.CEK)
		return nil, errors.New("stored Keycloak JWE key is invalid")
	}
	return &key, nil
}

func currentKeycloakJWEKey(ctx context.Context, storage logical.Storage, realm, purpose string) (*keycloakJWEKey, error) {
	entry, err := storage.Get(ctx, keycloakJWEMetaPath(realm, purpose))
	if err != nil || entry == nil {
		return nil, err
	}
	var current struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(entry.Value, &current); err != nil {
		return nil, err
	}
	key, err := loadKeycloakJWEKey(ctx, storage, realm, purpose, current.Version)
	if err != nil || key == nil {
		return nil, errors.New("current Keycloak JWE key version is unavailable")
	}
	return key, nil
}

func keycloakJWEPublic(key *keycloakJWEKey) *logical.Response {
	return &logical.Response{Data: map[string]any{
		"realm": key.Realm, "purpose": key.Purpose, "version": key.Version,
		"kid": keycloakJWEKid(key), "alg": "dir", "enc": "A256CBC-HS512",
	}}
}

func createKeycloakJWEKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return mutateKeycloakJWEKey(ctx, req, d, false)
}

func rotateKeycloakJWEKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	return mutateKeycloakJWEKey(ctx, req, d, true)
}

func mutateKeycloakJWEKey(ctx context.Context, req *logical.Request, d *framework.FieldData, rotate bool) (*logical.Response, error) {
	keyLifecycleMu.Lock()
	defer keyLifecycleMu.Unlock()
	if !onlyFields(req.Data, "realm", "purpose") {
		return logical.ErrorResponse("unexpected Keycloak JWE key field"), logical.ErrInvalidRequest
	}
	realm, purpose, err := keycloakJWEScope(d)
	if err != nil {
		return logical.ErrorResponse("invalid Keycloak JWE scope"), logical.ErrInvalidRequest
	}
	if err := requireTransactionalStorage(req.Storage); err != nil {
		return nil, err
	}
	rollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer rollback()
	key, err := currentKeycloakJWEKey(ctx, req.Storage, realm, purpose)
	if err != nil {
		return nil, err
	}
	if rotate && key == nil {
		return logical.ErrorResponse("Keycloak JWE key does not exist"), logical.ErrInvalidRequest
	}
	if key == nil || rotate {
		if key != nil {
			clear(key.CEK)
		}
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return nil, err
		}
		key = &keycloakJWEKey{Realm: realm, Purpose: purpose,
			Version: hex.EncodeToString(id[:]), CEK: make([]byte, 64)}
		if _, err := rand.Read(key.CEK); err != nil {
			clear(key.CEK)
			return nil, err
		}
		versionPath := keycloakJWEVersionPath(realm, purpose, key.Version)
		existing, err := req.Storage.Get(ctx, versionPath)
		if err != nil || existing != nil {
			clear(key.CEK)
			if err != nil {
				return nil, err
			}
			return nil, errors.New("Keycloak JWE key version collision")
		}
		if err := putJSON(ctx, req.Storage, versionPath, key); err != nil {
			clear(key.CEK)
			return nil, err
		}
		if err := putJSON(ctx, req.Storage, keycloakJWEMetaPath(realm, purpose), map[string]string{"version": key.Version}); err != nil {
			clear(key.CEK)
			return nil, err
		}
	}
	defer clear(key.CEK)
	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}
	return keycloakJWEPublic(key), nil
}

func readCurrentKeycloakJWEKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	realm, purpose, err := keycloakJWEScope(d)
	if err != nil {
		return nil, logical.ErrInvalidRequest
	}
	key, err := currentKeycloakJWEKey(ctx, req.Storage, realm, purpose)
	if err != nil || key == nil {
		return nil, err
	}
	defer clear(key.CEK)
	return keycloakJWEPublic(key), nil
}

func readKeycloakJWEKeyVersion(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	realm, purpose, err := keycloakJWEScope(d)
	if err != nil {
		return nil, logical.ErrInvalidRequest
	}
	key, err := loadKeycloakJWEKey(ctx, req.Storage, realm, purpose, d.Get("version").(string))
	if err != nil || key == nil {
		return nil, err
	}
	defer clear(key.CEK)
	return keycloakJWEPublic(key), nil
}

func encodeKeycloakJWE(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if !onlyFields(req.Data, "realm", "purpose", "version", "plaintext_base64") {
		return logical.ErrorResponse("unexpected Keycloak JWE encode field"), logical.ErrInvalidRequest
	}
	realm, purpose, err := keycloakJWEScope(d)
	if err != nil {
		return nil, logical.ErrInvalidRequest
	}
	key, err := loadKeycloakJWEKey(ctx, req.Storage, realm, purpose, d.Get("version").(string))
	if err != nil || key == nil {
		return nil, err
	}
	defer clear(key.CEK)
	encoded := d.Get("plaintext_base64").(string)
	if len(encoded) > (1<<20)*4/3+4 {
		return logical.ErrorResponse("Keycloak JWE plaintext too large"), logical.ErrInvalidRequest
	}
	plaintext, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return logical.ErrorResponse("invalid Keycloak JWE plaintext"), logical.ErrInvalidRequest
	}
	defer clear(plaintext)
	compact, err := jwe.EncodeDirect(key.CEK, keycloakJWEKid(key), plaintext)
	if err != nil {
		return logical.ErrorResponse("Keycloak JWE encoding failed"), logical.ErrInvalidRequest
	}
	return &logical.Response{Data: map[string]any{"jwe": compact}}, nil
}

func decodeKeycloakJWE(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if !onlyFields(req.Data, "realm", "purpose", "version", "jwe") {
		return logical.ErrorResponse("unexpected Keycloak JWE decode field"), logical.ErrInvalidRequest
	}
	realm, purpose, err := keycloakJWEScope(d)
	if err != nil {
		return nil, logical.ErrInvalidRequest
	}
	key, err := loadKeycloakJWEKey(ctx, req.Storage, realm, purpose, d.Get("version").(string))
	if err != nil || key == nil {
		return nil, err
	}
	defer clear(key.CEK)
	plaintext, err := jwe.DecodeDirect(key.CEK, keycloakJWEKid(key), d.Get("jwe").(string))
	if err != nil {
		return logical.ErrorResponse("Keycloak JWE authentication failed"), logical.ErrInvalidRequest
	}
	defer clear(plaintext)
	return &logical.Response{Data: map[string]any{
		"plaintext_base64": base64.StdEncoding.EncodeToString(plaintext),
	}}, nil
}
