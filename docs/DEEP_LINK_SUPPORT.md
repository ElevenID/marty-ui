# Deep Link Support for OID4VCI Credential Offers

## Overview

The Marty platform supports OID4VCI deep links for mobile wallet integration, allowing users to receive credentials without scanning QR codes. This is particularly useful when users are already on mobile devices.

## Deep Link Format

According to the OpenID for Verifiable Credential Issuance (OID4VCI) specification, credential offers use the following URI scheme:

```
openid-credential-offer://?credential_offer_uri=<url-encoded-endpoint>
```

### Example

```
openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example.com%2Fapi%2Fissuance%2Foffers%2F123
```

## Backend Implementation

### Credential Offer URI Generation

The backend automatically generates deep link URIs when creating credential offers:

**File:** `src/issuance/router.py`

```python
def _build_credential_offer_uri(
    offer_id: str,
    issuer_url: str,
) -> str:
    """Build credential offer URI for wallet.
    
    Returns:
        openid-credential-offer:// URI
    """
    offer_endpoint = f"{issuer_url}/api/issuance/offers/{offer_id}"
    params = urlencode({"credential_offer_uri": offer_endpoint})
    return f"openid-credential-offer://?{params}"
```

### Response Fields

The `CredentialOfferResponse` includes multiple URI representations:

```python
class CredentialOfferResponse(BaseModel):
    transaction_id: str
    credential_offer_uri: str        # Deep link format
    offer_endpoint: Optional[str]    # HTTP endpoint for retrieval
    deep_link_uri: Optional[str]     # Explicit deep link (same as credential_offer_uri)
    pre_authorized_code: Optional[str]
    expires_at: datetime
    status: IssuanceStatus
    qr_code_data: Optional[str]      # Base64-encoded QR image
```

- **`credential_offer_uri`**: Primary field containing the deep link
- **`offer_endpoint`**: HTTP endpoint extracted from the deep link (for debugging/reference)
- **`deep_link_uri`**: Explicit deep link field (alias for `credential_offer_uri`)
- **`qr_code_data`**: QR code image encoding the deep link

## Frontend Implementation

### QRCodeDisplay Component

**File:** `ui/src/components/issuance/QRCodeDisplay.jsx`

The QRCodeDisplay component provides multiple ways to share credential offers:

1. **QR Code**: Visual QR code encoding the deep link
2. **"Open in Wallet" Button**: Direct deep link activation
3. **"Copy Link" Button**: Copies deep link to clipboard

```jsx
<QRCodeDisplay
  offerUri={offer.credential_offer_uri}
  qrPayload={offer.qr_code_data}
  expiresAt={offer.expires_at}
  showDeepLink={true}
  showCopyLink={true}
/>
```

#### Deep Link Handling

The component automatically detects whether the `offerUri` is already in deep link format:

```javascript
const handleOpenLink = () => {
  let deepLinkUrl = offerUri;
  if (!offerUri.startsWith('openid-credential-offer://')) {
    deepLinkUrl = `openid-credential-offer://?credential_offer_uri=${encodeURIComponent(offerUri)}`;
  }
  window.location.href = deepLinkUrl;
};
```

### CredentialOfferDialog

**File:** `ui/src/components/issuance/CredentialOfferDialog.jsx`

The credential offer dialog provides multiple sharing methods:

- QR code display for desktop/cross-device scenarios
- Deep link buttons for mobile-native scenarios
- Copy buttons for sharing via messaging apps, email, SMS

```jsx
{generatedOffer && (
  <>
    <QRCodeDisplay
      offerUri={generatedOffer.credential_offer_uri}
      showDeepLink={true}
      showCopyLink={true}
    />
    
    {/* Additional sharing options */}
    <Paper>
      <Chip label="Copy Deep Link" onClick={() => {
        navigator.clipboard.writeText(generatedOffer.credential_offer_uri);
      }} />
      {generatedOffer.offer_endpoint && (
        <Chip label="Copy HTTP URL" onClick={() => {
          navigator.clipboard.writeText(generatedOffer.offer_endpoint);
        }} />
      )}
    </Paper>
  </>
)}
```

## Usage Scenarios

### Scenario 1: Desktop to Mobile (QR Code)

1. Admin generates credential offer on desktop
2. QR code is displayed
3. User scans QR with mobile wallet
4. Wallet opens credential offer via deep link

### Scenario 2: Mobile to Mobile (Deep Link)

1. Admin generates credential offer on mobile device
2. Admin clicks "Open in Wallet" or "Copy Link"
3. Deep link is shared via SMS/messaging app
4. Recipient opens link directly in wallet

### Scenario 3: Automated Issuance (Event-Driven)

1. Application approval triggers OID4VCI flow
2. System generates credential offer with deep link
3. Deep link is embedded in notification email/SMS
4. User clicks link on mobile device
5. Wallet opens credential offer automatically

## Flow Service Integration

### Artifact Storage

The Flow service stores deep links in `FlowInstanceArtifact`:

```python
class FlowInstanceArtifact:
    id: str
    flow_instance_id: str
    credential_offer_uri: str | None    # Deep link format
    qr_payload: str | None              # Base64 QR image
    pre_authorized_code: str | None
    expires_at: datetime | None
    status: ArtifactStatus
```

### Auto-Triggering with Deep Links

When application approval triggers OID4VCI flows:

```python
artifact = await _create_oid4vci_artifact(instance, flow_def, repo)

# artifact.credential_offer_uri contains deep link
# Can be sent via email, SMS, push notification, etc.
```

## Testing Deep Links

### Desktop Browser

Deep links won't work on desktop browsers (no wallet app installed). Use QR code instead.

### Mobile Browser

1. Generate credential offer
2. Click "Copy Deep Link"
3. Paste into mobile browser
4. Browser should prompt to open wallet app

### Wallet App Development

For testing during wallet development:

1. Use the `offer_endpoint` field to fetch offer payload directly:
   ```
   GET https://issuer.example.com/api/issuance/offers/123
   ```

2. Parse the credential offer payload
3. Implement deep link handler in wallet app:
   ```javascript
   // React Native example
   Linking.addEventListener('url', handleDeepLink);
   
   function handleDeepLink(event) {
     const url = event.url;
     // Parse openid-credential-offer:// URL
     // Extract credential_offer_uri parameter
     // Fetch and process offer
   }
   ```

## Security Considerations

### Deep Link Interception

- Deep links can be intercepted by malicious apps registering the same URI scheme
- Use pre-authorized codes with short expiry times (5-15 minutes)
- Implement rate limiting on offer redemption
- Monitor for suspicious patterns (multiple redemption attempts)

### URL Encoding

- Always URL-encode the `credential_offer_uri` parameter
- Validate decoded URLs on the wallet side
- Reject URLs with suspicious characters or malformed structure

### HTTPS Enforcement

- The `offer_endpoint` should always use HTTPS
- Validate SSL certificates when fetching offers
- Reject offers from non-HTTPS issuers in production

## Browser Compatibility

| Browser | Desktop | Mobile | Notes |
|---------|---------|--------|-------|
| Chrome | ❌ | ✅ | Mobile opens wallet if installed |
| Safari | ❌ | ✅ | iOS Universal Links supported |
| Firefox | ❌ | ✅ | Android Intent URLs supported |
| Edge | ❌ | ✅ | Windows Phone apps supported |

## Troubleshooting

### Deep Link Doesn't Open Wallet

**Problem**: Clicking deep link does nothing on mobile

**Solutions**:
1. Ensure wallet app is installed
2. Check wallet app has registered `openid-credential-offer://` URI scheme
3. Try copying link and opening in new browser tab
4. Verify offer hasn't expired

### QR Code Encodes Wrong Format

**Problem**: Scanning QR shows HTTP URL instead of opening wallet

**Solutions**:
1. Backend should generate QR from `credential_offer_uri` (deep link format)
2. Verify `_build_credential_offer_uri()` returns deep link format
3. Check QR code generation uses correct URI field

### Double-Wrapped Deep Links

**Problem**: Deep link appears as `openid-credential-offer://?credential_offer_uri=openid-credential-offer://...`

**Solutions**:
1. Frontend should detect existing deep link format
2. Don't wrap if already starts with `openid-credential-offer://`
3. Backend should store deep link format, not HTTP URL

## References

- [OpenID for Verifiable Credential Issuance](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html)
- [RFC 8252: OAuth 2.0 for Native Apps](https://datatracker.ietf.org/doc/html/rfc8252)
- [Custom URL Schemes (iOS)](https://developer.apple.com/documentation/xcode/defining-a-custom-url-scheme-for-your-app)
- [Android App Links](https://developer.android.com/training/app-links)
