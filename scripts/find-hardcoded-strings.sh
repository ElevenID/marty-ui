#!/bin/bash

# String Extraction Helper Script
# This script helps identify hardcoded strings in React components
# that need to be extracted to translation files.

# Usage: ./scripts/find-hardcoded-strings.sh [directory]
# Example: ./scripts/find-hardcoded-strings.sh ui/src/components/console

SEARCH_DIR="${1:-ui/src/components}"

echo "======================================"
echo "Searching for hardcoded strings in:"
echo "$SEARCH_DIR"
echo "======================================"
echo ""

# Find JSX text content (strings between > and <)
echo "1. JSX Text Content:"
echo "   (Strings between > and <)"
echo "--------------------------------------"
grep -r -n --include="*.jsx" --include="*.js" ">[A-Z][^<>{]*<" "$SEARCH_DIR" | head -20
echo ""
echo "(Showing first 20 matches. Run without 'head' to see all.)"
echo ""

# Find string literals in attributes (excluding common props like className, data-testid)
echo "2. String Literals in Props:"
echo "   (label=\"...\", title=\"...\", etc.)"
echo "--------------------------------------"
grep -r -n --include="*.jsx" --include="*.js" -E "(label|title|placeholder|helperText|alt|aria-label)=\"[^{]" "$SEARCH_DIR" | head -20
echo ""
echo "(Showing first 20 matches)"
echo ""

# Find Button/MenuItem/Typography with string children
echo "3. Common Components with Text:"
echo "   (<Button>Text</Button>, <MenuItem>Text</MenuItem>)"
echo "--------------------------------------"
grep -r -n --include="*.jsx" --include="*.js" -E "<(Button|MenuItem|Typography|Link|ListItemText)>" "$SEARCH_DIR" | grep -v "{" | head -20
echo ""
echo "(Showing first 20 matches)"
echo ""

echo "======================================"
echo "Next Steps:"
echo "======================================"
echo "1. Review identified strings above"
echo "2. Add to appropriate translation file:"
echo "   ui/public/locales/en/[namespace].json"
echo "3. Replace in component:"
echo "   Before: <Button>Save</Button>"
echo "   After:  <Button>{t('actions.save')}</Button>"
echo ""
echo "4. Run component-specific search:"
echo "   grep -n 'hardcoded-string' ui/src/components/MyComponent.jsx"
echo ""
echo "See LOCALIZATION.md for full guidance."
