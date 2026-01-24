# Crypto Bridge Analysis - Breaking Changes Investigation

## Summary

**CRITICAL FINDING**: The Open Badges functionality (`open_badge_ob2_*` and `open_badge_ob3_*` functions) **is not available** in the marty-credentials marty-rs build. This will break the Open Badges router in marty-ui.

## What We Found

### 1. Open Badges in marty-ui

Location: [marty-ui/src/open_badges/router.py](../marty-ui/src/open_badges/router.py)

The router tries to import 4 functions:
```python
from marty_common.crypto_bridge import (
    open_badge_ob2_issue,
    open_badge_ob2_verify,
    open_badge_ob3_issue,
    open_badge_ob3_verify,
)
```

Used in endpoints:
- `/v1/credential-requests/open-badge` (issue endpoint)
- `/v1/credentials/verify/open-badge` (verify endpoint)

### 2. marty-rs Builds Comparison

**marty-credentials/rust/marty-rs/** (NEW - what we built):
- ✅ Has: `generate_did_key`, `create_verifiable_credential`, `verify_jwt`, status lists
- ❌ Missing: `open_badge_*` functions
- 18 total Python functions exported

**Marty/rust/marty-rs/** (OLD - to be removed):
- This version may have had different functions
- To be removed during cleanup

**Marty/src/marty_plugin/common/crypto_bridge.py** (OLD - to be removed):
- Lines 89, 198: Imports `open_badge_*` from `marty_plugin._marty_rs`
- Lines 1364+: Wrapper functions for open_badge operations
- This file (2679 lines) to be removed during cleanup

### 3. Current State

**marty-common/marty_common/crypto_bridge.py** (NEW - 164 lines):
- ✅ Imports what's available from _marty_rs
- ✅ Tries to import open_badge functions (lines 125-137)
- ✅ Sets them to None if not available (graceful degradation)
- ✅ Has helper functions to check availability

## Impact Assessment

### Will Break
1. ❌ **Open Badges endpoints in marty-ui** - Will return errors when open_badge functions are called
   - `/v1/credential-requests/open-badge`
   - `/v1/credentials/verify/open-badge`

### Will Work
2. ✅ **Core credential operations** - All working
   - Key generation (DID, P256, P384, RSA)
   - Credential creation and verification
   - Status lists (revocation/suspension)
   - JWT operations

3. ✅ **Graceful degradation** - Code won't crash
   - Router checks if functions are None
   - Returns warning: "Open Badge signing unavailable"
   - Issues unsigned credentials as fallback

## Options to Fix

### Option 1: Add Open Badges to marty-rs (RECOMMENDED)
**Action**: Add open_badge modules to marty-credentials/rust/marty-rs/src/

```rust
// In marty-credentials/rust/marty-rs/src/lib.rs
mod open_badges;  // New module

// In pymodule registration:
m.add_function(wrap_pyfunction!(open_badge_ob2_issue, m)?)?;
m.add_function(wrap_pyfunction!(open_badge_ob2_verify, m)?)?;
m.add_function(wrap_pyfunction!(open_badge_ob3_issue, m)?)?;
m.add_function(wrap_pyfunction!(open_badge_ob3_verify, m)?)?;
```

**Pros**: Complete functionality, native performance
**Cons**: Requires Rust development, rebuild wheel (7min)

### Option 2: Implement in Python
**Action**: Implement open_badge functions in pure Python using existing libraries

**Pros**: No Rust required, faster iteration
**Cons**: Slower performance, more dependencies

### Option 3: Document as Unsupported
**Action**: Remove Open Badges endpoints from marty-ui or mark as experimental

**Pros**: No immediate work needed
**Cons**: Feature loss, breaking change for users

## Recommendation

**SHORT TERM** (Now):
1. ✅ Keep current crypto_bridge.py (graceful degradation works)
2. ✅ Document that Open Badges require additional Rust implementation
3. ✅ Test that endpoints return helpful error messages

**LONG TERM** (When Open Badges needed):
1. Port open_badge functions from old marty_plugin._marty_rs to new marty-credentials/rust/marty-rs
2. Rebuild marty-rs wheel
3. Deploy updated marty-credentials package

## What Was Removed That's Actually Needed?

**Nothing critical was removed from marty-common/crypto_bridge.py**. The functions we removed:
- ❌ `hash_data`, `sha256`, etc. - Use Python's `hashlib` instead
- ❌ Certificate operations - Not used in marty-ui
- ❌ MRZ parsing - Not used in marty-ui  
- ❌ CRL operations - Not used in marty-ui
- ❌ Ed25519/ECDSA/RSA signing - Use higher-level functions instead

**The only missing functionality is Open Badges**, which:
1. Is detected and handled gracefully by marty-ui
2. Was never in the marty-credentials marty-rs build
3. Needs to be implemented if Open Badges support is required

## Conclusion

✅ **The cleanup is safe to proceed** - No critical functions were mistakenly removed.

⚠️ **Open Badges will not work** - But this is expected and handled gracefully. If Open Badges support is needed, it must be implemented in the marty-credentials marty-rs Rust code.

🎯 **Next Step**: Decide if Open Badges support is needed before cleanup, or implement it later as a separate task.
