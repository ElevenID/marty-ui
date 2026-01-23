# Cleanup Guide - Files to Remove After Extraction

## Summary

After extracting marty-ui and consolidating packages, the following files/directories in the Marty repository should be cleaned up:

## 🗑️ Directories to Remove

### 1. **`/Volumes/Heart of Gold/Github/work/Marty/marty-ui/`**
**Status:** ✅ Extracted to standalone repo  
**Location:** Now at `/Volumes/Heart of Gold/Github/work/marty-ui/`  
**Action:** 
```bash
rm -rf "/Volumes/Heart of Gold/Github/work/Marty/marty-ui"
```

### 2. **`/Volumes/Heart of Gold/Github/work/Marty/src/status_list/`**
**Status:** ✅ Moved to marty-credentials  
**New Location:** `marty-credentials/python/status_list/`  
**Action:**
```bash
rm -rf "/Volumes/Heart of Gold/Github/work/Marty/src/status_list"
```

### 3. **`/Volumes/Heart of Gold/Github/work/Marty/src/marty_plugin/common/`**
**Status:** ✅ Moved to marty-common package  
**New Location:** `Marty/packages/marty-common/marty_common/`  
**Action:**
```bash
rm -rf "/Volumes/Heart of Gold/Github/work/Marty/src/marty_plugin/common"
```

### 4. **`/Volumes/Heart of Gold/Github/work/Marty/src/marty_plugin/adapters/`**
**Status:** ✅ Copied to marty-credentials  
**New Location:** `marty-credentials/python/marty_credentials/adapters/`  
**Action:**
```bash
rm -rf "/Volumes/Heart of Gold/Github/work/Marty/src/marty_plugin/adapters"
```

### 5. **`/Volumes/Heart of Gold/Github/work/Marty/rust/marty-rs/`**
**Status:** ✅ Consolidated into marty-credentials  
**New Location:** `marty-credentials/rust/marty-rs/`  
**Action:**
```bash
rm -rf "/Volumes/Heart of Gold/Github/work/Marty/rust/marty-rs"
```

## 📝 Files to Update

### 1. **Makefile** (if it references marty-ui)
**Check for:**
- marty-ui build targets
- marty-ui docker commands
- marty-ui deployment scripts

**Action:** Remove or comment out marty-ui related targets

### 2. **docker-compose.yml** (if it includes marty-ui services)
**Check for:**
- oid4vc-api service
- demo-ui service
- wallet-ui service
- verifier-service (marty-ui specific)
- issuer-service (marty-ui specific)

**Action:** Remove marty-ui services or move to standalone compose file

### 3. **Update imports in remaining Marty services**

Any remaining Python services in Marty that import from the moved modules:

**Search for:**
```bash
grep -r "from marty_plugin.common" /Volumes/Heart\ of\ Gold/Github/work/Marty/src/
grep -r "from status_list" /Volumes/Heart\ of\ Gold/Github/work/Marty/src/
```

**Replace with:**
```python
# Old
from marty_plugin.common.crypto_bridge import verify_certificate
from marty_plugin.common.errors import register_exception_handlers
from status_list.application.services import StatusListService

# New
from marty_common.crypto_bridge import verify_certificate
from marty_common.errors import register_exception_handlers
from status_list.application.services import StatusListService  # Now from marty-credentials package
```

## 🔍 Verification Steps

### 1. Check for remaining references to removed directories

```bash
# In Marty repo
cd "/Volumes/Heart of Gold/Github/work/Marty"

# Check for imports of moved modules
grep -r "marty_plugin.common" src/ --include="*.py" || echo "✓ No references found"
grep -r "marty_plugin.adapters" src/ --include="*.py" || echo "✓ No references found"

# Check for status_list imports (should be none in Marty repo now)
grep -r "from status_list" src/ --include="*.py" || echo "✓ No references found"

# Check Makefile
grep "marty-ui" Makefile || echo "✓ No references found"

# Check docker-compose
grep "marty-ui" docker-compose*.yml || echo "✓ No references found"
```

### 2. Verify marty_plugin structure

After cleanup, `marty_plugin` should only contain:
- Core business logic services (PKD, trust anchor, document processing)
- NOT `common/` (moved to marty-common)
- NOT `adapters/` (moved to marty-credentials)

```bash
ls -la "/Volumes/Heart of Gold/Github/work/Marty/src/marty_plugin/"
```

Expected remaining:
```
csca_service/
document_processing/
dtc_engine/
inspection_system/
iso18013/
legacy_apps/
lib/              # Core business logic libraries
mdl_engine/
mdoc_engine/
passport_engine/
pkd_service/
trust_anchor/
trust_svc/
```

## ⚠️ Before Cleanup

**IMPORTANT:** Before removing any directories:

1. **Commit all changes** to the new repositories:
   ```bash
   cd marty-ui && git add -A && git commit -m "Complete extraction with updated imports"
   cd ../marty-credentials && git add -A && git commit -m "Add status_list and adapters"
   cd ../Marty && git add packages/marty-common && git commit -m "Add marty-common package"
   ```

2. **Verify builds work:**
   ```bash
   # Test marty-ui with local packages
   cd marty-ui && docker-compose up -d
   
   # Test marty-common can be imported
   cd ../Marty/packages/marty-common
   pip install -e .
   python -c "import marty_common; print(marty_common.__version__)"
   
   # Test marty-credentials can be imported
   cd ../../../marty-credentials
   pip install -e .
   python -c "import marty_credentials, status_list; print('✓ Imports work')"
   ```

3. **Create backup branch** (optional but recommended):
   ```bash
   cd "/Volumes/Heart of Gold/Github/work/Marty"
   git checkout -b backup-before-cleanup
   git checkout main  # or your working branch
   ```

## 🚀 Cleanup Script

Here's a safe cleanup script that removes the extracted directories:

```bash
#!/bin/bash
set -e

MARTY_DIR="/Volumes/Heart of Gold/Github/work/Marty"

echo "🧹 Starting cleanup of extracted marty-ui components..."

# Confirm before proceeding
read -p "Have you committed all changes and verified builds? (yes/no): " confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborting cleanup. Please commit changes first."
    exit 1
fi

cd "$MARTY_DIR"

# Remove extracted directories
echo "Removing marty-ui..."
rm -rf "marty-ui"

echo "Removing status_list..."
rm -rf "src/status_list"

echo "Removing marty_plugin/common..."
rm -rf "src/marty_plugin/common"

echo "Removing marty_plugin/adapters..."
rm -rf "src/marty_plugin/adapters"

echo "Removing rust/marty-rs..."
rm -rf "rust/marty-rs"

echo "✅ Cleanup complete!"
echo ""
echo "Next steps:"
echo "1. Update Makefile if needed"
echo "2. Update docker-compose.yml if needed"
echo "3. Update imports in remaining services"
echo "4. Run tests to verify everything still works"
echo "5. Commit cleanup changes"
```

## 📋 Post-Cleanup Checklist

- [ ] Removed `Marty/marty-ui/`
- [ ] Removed `Marty/src/status_list/`
- [ ] Removed `Marty/src/marty_plugin/common/`
- [ ] Removed `Marty/src/marty_plugin/adapters/`
- [ ] Removed `Marty/rust/marty-rs/`
- [ ] Updated Makefile
- [ ] Updated docker-compose.yml
- [ ] Updated imports in remaining Marty services
- [ ] Verified builds work
- [ ] Committed changes
- [ ] Updated CI/CD pipelines if affected

## 🔗 Related Documentation

- [EXTRACTION_SUMMARY.md](../marty-ui/EXTRACTION_SUMMARY.md) - Complete extraction details
- [IMPORT_MIGRATION.md](../marty-ui/IMPORT_MIGRATION.md) - Import path changes
- [DEVELOPMENT_SETUP.md](../marty-ui/DEVELOPMENT_SETUP.md) - Setup guide
