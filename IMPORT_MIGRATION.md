# Import Migration Summary

## Completed: Import Path Updates

All import statements in marty-ui have been updated to use the new package structure.

### Changed Imports

#### 1. marty_common Package (Infrastructure)

**Old:** `from marty_plugin.common.*`  
**New:** `from marty_common.*`

**Updated Files:**
- [src/oid4vc_api.py](src/oid4vc_api.py#L172) - Error handling
- [src/open_badges/router.py](src/open_badges/router.py#L46) - Crypto bridge functions
- [src/client_errors.py](src/client_errors.py#L23) - Error classes

**Affected Modules:**
- `marty_common.errors` - Exception handlers and error classes
- `marty_common.crypto_bridge` - Cryptographic operations (RSA, certificates, Open Badges)

#### 2. marty_credentials Package (Credential Adapters)

**Old:** `from marty_plugin.adapters.credentials.*`  
**New:** `from marty_credentials.adapters.credentials.*`

**Updated Files:**
- [src/oid4vc_api.py](src/oid4vc_api.py#L392) - Lazy adapter initialization
- [src/issuance/signing.py](src/issuance/signing.py#L108) - Key manager access

**Updated Comments:**
- [src/issuance/adapters.py](src/issuance/adapters.py#L8)
- [src/issuance/ports.py](src/issuance/ports.py#L9)
- [src/issuance/__init__.py](src/issuance/__init__.py#L17)
- [src/issuance/router.py](src/issuance/router.py#L968)

**Affected Modules:**
- `marty_credentials.adapters.credentials.spruceid` - SpruceID key manager
- `marty_credentials.adapters.credentials` - Issuer, verifier, wallet adapters

#### 3. status_list Package (Unchanged Path)

**Path:** `from status_list.*`  
**Status:** No changes needed (still `status_list.*`)

**Files Using This:**
- [src/open_badges/status_integration.py](src/open_badges/status_integration.py#L14-L15)
- [src/oid4vc_api.py](src/oid4vc_api.py#L121-L132)

**Note:** `status_list` package was moved to marty-credentials but maintains the same import path.

### Verification

All imports have been updated to reference the new package locations:

```python
# ✅ Updated imports
from marty_common.crypto_bridge import verify_certificate
from marty_common.errors import register_exception_handlers
from marty_credentials.adapters.credentials import get_key_manager
from status_list.application.services import StatusListService

# ❌ Old imports (removed)
# from marty_plugin.common.crypto_bridge import verify_certificate
# from marty_plugin.common.errors import register_exception_handlers
# from marty_plugin.adapters.credentials import get_key_manager
```

### Package Structure

```
marty-credentials/
├── python/
│   ├── marty_credentials/
│   │   └── adapters/          ← Copied from marty_plugin/adapters
│   │       └── credentials/
│   │           ├── __init__.py
│   │           ├── spruceid.py
│   │           ├── multipaz.py
│   │           └── persistence.py
│   └── status_list/           ← Moved from Marty/src/status_list
│       ├── domain/
│       ├── application/
│       └── infrastructure/

Marty/packages/marty-common/
└── marty_common/              ← Copied from marty_plugin/common
    ├── crypto_bridge.py
    ├── errors/
    ├── grpc*/
    ├── database/
    ├── monitoring/
    └── ... (all infrastructure)
```

### Next Steps

1. ✅ Import statements updated
2. ⏳ Test with local development mode (`docker-compose up`)
3. ⏳ Publish packages to GitHub Packages
4. ⏳ Test with production mode (GitHub Packages)

### Testing Local Development

```bash
cd marty-ui

# Install with local editable packages
pip install -r src/requirements.dev.txt

# Or use Docker with auto-loaded override
docker-compose up
```

The [docker-compose.override.yml](docker-compose.override.yml) automatically mounts local packages and installs them in editable mode.
