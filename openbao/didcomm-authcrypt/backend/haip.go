package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"strings"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/logical"
)

// HAIP response keys remain in OpenBao storage across Flow process restarts.
// A scoped caller can obtain only a public JWK and request decryption for its
// exact tenant, flow, and immutable key version.
type haipKey struct {
	Tenant     string `json:"tenant"`
	Flow       string `json:"flow"`
	Version    string `json:"version"`
	PrivateKey []byte `json:"private_key"`
	PublicX    []byte `json:"public_x"`
	PublicY    []byte `json:"public_y"`
}

func haipKeyPath() *framework.Path {
	return &framework.Path{
		Pattern: `haip/keys/(?P<tenant>[A-Za-z0-9_-]{1,64})/(?P<flow>[A-Za-z0-9_-]{1,64})`,
		Fields: map[string]*framework.FieldSchema{
			"tenant": {Type: framework.TypeString},
			"flow":   {Type: framework.TypeString},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{Callback: createHaipKey},
			logical.UpdateOperation: &framework.PathOperation{Callback: createHaipKey},
			logical.ReadOperation:   &framework.PathOperation{Callback: readHaipKey},
		},
	}
}

func haipReadVersionPath() *framework.Path {
	return &framework.Path{
		Pattern: `haip/keys/(?P<tenant>[A-Za-z0-9_-]{1,64})/(?P<flow>[A-Za-z0-9_-]{1,64})/versions/(?P<version>[0-9a-f]{32})`,
		Fields: map[string]*framework.FieldSchema{
			"tenant":  {Type: framework.TypeString},
			"flow":    {Type: framework.TypeString},
			"version": {Type: framework.TypeString},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{Callback: readHaipKeyVersion},
		},
	}
}

func haipDecryptPath() *framework.Path {
	return &framework.Path{
		Pattern: `haip/decrypt/(?P<tenant>[A-Za-z0-9_-]{1,64})/(?P<flow>[A-Za-z0-9_-]{1,64})/(?P<version>[0-9a-f]{32})`,
		Fields: map[string]*framework.FieldSchema{
			"tenant":  {Type: framework.TypeString},
			"flow":    {Type: framework.TypeString},
			"version": {Type: framework.TypeString},
			"jwe":     {Type: framework.TypeString, Required: true},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: decryptHaipResponse},
		},
	}
}

func haipNames(d *framework.FieldData) (string, string, error) {
	tenant := d.Get("tenant").(string)
	flow := d.Get("flow").(string)
	if !pathPart.MatchString(tenant) || !pathPart.MatchString(flow) {
		return "", "", errors.New("invalid HAIP key scope")
	}
	return tenant, flow, nil
}

func haipMetaPath(tenant, flow string) string { return "haip/meta/" + tenant + "/" + flow }
func haipVersionPath(tenant, flow, version string) string {
	return "haip/secret/" + tenant + "/" + flow + "/" + version
}

func loadHaipKey(ctx context.Context, storage logical.Storage, tenant, flow, version string) (*haipKey, error) {
	if !versionID.MatchString(version) {
		return nil, errors.New("invalid HAIP key version")
	}
	entry, err := storage.Get(ctx, haipVersionPath(tenant, flow, version))
	if err != nil || entry == nil {
		return nil, err
	}
	var key haipKey
	if err := json.Unmarshal(entry.Value, &key); err != nil {
		return nil, err
	}
	if key.Tenant != tenant || key.Flow != flow || key.Version != version ||
		len(key.PrivateKey) != 32 || len(key.PublicX) != 32 || len(key.PublicY) != 32 ||
		!validP256KeyMaterial(key.PrivateKey, key.PublicX, key.PublicY) {
		clear(key.PrivateKey)
		return nil, errors.New("stored HAIP key is invalid")
	}
	return &key, nil
}

func loadCurrentHaipKey(ctx context.Context, storage logical.Storage, tenant, flow string) (*haipKey, error) {
	entry, err := storage.Get(ctx, haipMetaPath(tenant, flow))
	if err != nil || entry == nil {
		return nil, err
	}
	var current struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(entry.Value, &current); err != nil {
		return nil, err
	}
	key, err := loadHaipKey(ctx, storage, tenant, flow, current.Version)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, errors.New("current HAIP key version is missing")
	}
	return key, nil
}

func newHaipKey(tenant, flow string) (*haipKey, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	return &haipKey{
		Tenant: tenant, Flow: flow, Version: hex.EncodeToString(id[:]),
		PrivateKey: private.D.FillBytes(make([]byte, 32)),
		PublicX:    private.X.FillBytes(make([]byte, 32)),
		PublicY:    private.Y.FillBytes(make([]byte, 32)),
	}, nil
}

func validP256KeyMaterial(private, x, y []byte) bool {
	if len(private) != 32 || len(x) != 32 || len(y) != 32 {
		return false
	}
	scalar := new(big.Int).SetBytes(private)
	if scalar.Sign() <= 0 || scalar.Cmp(elliptic.P256().Params().N) >= 0 {
		return false
	}
	derivedX, derivedY := elliptic.P256().ScalarBaseMult(private)
	return subtle.ConstantTimeCompare(derivedX.FillBytes(make([]byte, 32)), x) == 1 &&
		subtle.ConstantTimeCompare(derivedY.FillBytes(make([]byte, 32)), y) == 1
}

func haipPublicResponse(key *haipKey) *logical.Response {
	return &logical.Response{Data: map[string]any{
		"tenant":  key.Tenant,
		"flow":    key.Flow,
		"version": key.Version,
		"public_jwk": map[string]any{
			"kty": "EC", "crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(key.PublicX),
			"y":   base64.RawURLEncoding.EncodeToString(key.PublicY),
			"kid": "oid4vp-haip-" + key.Version,
			"alg": "ECDH-ES", "use": "enc",
		},
	}}
}

func createHaipKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keyLifecycleMu.Lock()
	defer keyLifecycleMu.Unlock()
	if !onlyFields(req.Data, "tenant", "flow") {
		return logical.ErrorResponse("unexpected HAIP key creation field"), logical.ErrInvalidRequest
	}
	tenant, flow, err := haipNames(d)
	if err != nil {
		return logical.ErrorResponse("invalid HAIP key scope"), logical.ErrInvalidRequest
	}
	if err := requireTransactionalStorage(req.Storage); err != nil {
		return nil, err
	}
	rollback, err := logical.StartTxStorage(ctx, req)
	if err != nil {
		return nil, err
	}
	defer rollback()
	key, err := loadCurrentHaipKey(ctx, req.Storage, tenant, flow)
	if err != nil {
		return nil, err
	}
	if key == nil {
		key, err = newHaipKey(tenant, flow)
		if err != nil {
			return nil, err
		}
		if err := putJSON(ctx, req.Storage, haipVersionPath(tenant, flow, key.Version), key); err != nil {
			clear(key.PrivateKey)
			return nil, err
		}
		if err := putJSON(ctx, req.Storage, haipMetaPath(tenant, flow), map[string]string{"version": key.Version}); err != nil {
			clear(key.PrivateKey)
			return nil, err
		}
	}
	defer clear(key.PrivateKey)
	if err := logical.EndTxStorage(ctx, req); err != nil {
		return nil, err
	}
	return haipPublicResponse(key), nil
}

func readHaipKey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tenant, flow, err := haipNames(d)
	if err != nil {
		return nil, logical.ErrInvalidRequest
	}
	key, err := loadCurrentHaipKey(ctx, req.Storage, tenant, flow)
	if err != nil || key == nil {
		return nil, err
	}
	defer clear(key.PrivateKey)
	return haipPublicResponse(key), nil
}

func readHaipKeyVersion(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tenant, flow, err := haipNames(d)
	if err != nil {
		return nil, logical.ErrInvalidRequest
	}
	key, err := loadHaipKey(ctx, req.Storage, tenant, flow, d.Get("version").(string))
	if err != nil || key == nil {
		return nil, err
	}
	defer clear(key.PrivateKey)
	return haipPublicResponse(key), nil
}

func decryptHaipResponse(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if !onlyFields(req.Data, "tenant", "flow", "version", "jwe") {
		return logical.ErrorResponse("unexpected HAIP decryption field"), logical.ErrInvalidRequest
	}
	tenant, flow, err := haipNames(d)
	if err != nil {
		return logical.ErrorResponse("invalid HAIP key scope"), logical.ErrInvalidRequest
	}
	version := d.Get("version").(string)
	key, err := loadHaipKey(ctx, req.Storage, tenant, flow, version)
	if err != nil || key == nil {
		return nil, err
	}
	defer clear(key.PrivateKey)
	compact := d.Get("jwe").(string)
	if err := validateHaipJWE(compact, "oid4vp-haip-"+key.Version); err != nil {
		return logical.ErrorResponse("invalid HAIP response JWE"), logical.ErrInvalidRequest
	}
	private := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(key.PublicX), Y: new(big.Int).SetBytes(key.PublicY)},
		D:         new(big.Int).SetBytes(key.PrivateKey),
	}
	parsed, err := jose.ParseEncrypted(compact, []jose.KeyAlgorithm{jose.ECDH_ES}, []jose.ContentEncryption{jose.A256GCM})
	if err != nil {
		return logical.ErrorResponse("invalid HAIP response JWE"), logical.ErrInvalidRequest
	}
	plaintext, err := parsed.Decrypt(private)
	if err != nil || len(plaintext) == 0 || len(plaintext) > 1<<20 {
		return logical.ErrorResponse("HAIP response decryption failed"), logical.ErrInvalidRequest
	}
	defer clear(plaintext)
	return &logical.Response{Data: map[string]any{
		"tenant": tenant, "flow": flow, "version": version,
		"plaintext_base64": base64.StdEncoding.EncodeToString(plaintext),
	}}, nil
}

func validateHaipJWE(compact, kid string) error {
	if len(compact) == 0 || len(compact) > 2<<20 {
		return errors.New("invalid JWE size")
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 5 || parts[1] != "" {
		return errors.New("expected direct ECDH-ES compact JWE")
	}
	protected, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(protected) > 4096 || rejectDuplicateJSONKeys(protected) != nil {
		return errors.New("invalid protected header")
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(protected, &header); err != nil || len(header) == 0 {
		return errors.New("invalid protected header")
	}
	for field := range header {
		switch field {
		case "alg", "enc", "epk", "apu", "apv", "kid", "typ", "cty":
		default:
			return errors.New("unsupported protected header")
		}
	}
	var alg, enc, declaredKid string
	_ = json.Unmarshal(header["alg"], &alg)
	_ = json.Unmarshal(header["enc"], &enc)
	_ = json.Unmarshal(header["kid"], &declaredKid)
	if alg != "ECDH-ES" || enc != "A256GCM" || (declaredKid != "" && declaredKid != kid) {
		return errors.New("unsupported HAIP algorithms or key ID")
	}
	var epk map[string]json.RawMessage
	if err := json.Unmarshal(header["epk"], &epk); err != nil || len(epk) != 4 || rejectDuplicateJSONKeys(header["epk"]) != nil {
		return errors.New("invalid ephemeral public key")
	}
	var kty, curve, xEncoded, yEncoded string
	_ = json.Unmarshal(epk["kty"], &kty)
	_ = json.Unmarshal(epk["crv"], &curve)
	_ = json.Unmarshal(epk["x"], &xEncoded)
	_ = json.Unmarshal(epk["y"], &yEncoded)
	x, xErr := base64.RawURLEncoding.DecodeString(xEncoded)
	y, yErr := base64.RawURLEncoding.DecodeString(yEncoded)
	if kty != "EC" || curve != "P-256" || xErr != nil || yErr != nil || len(x) != 32 || len(y) != 32 ||
		!elliptic.P256().IsOnCurve(new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)) {
		return errors.New("invalid P-256 ephemeral public key")
	}
	return nil
}
