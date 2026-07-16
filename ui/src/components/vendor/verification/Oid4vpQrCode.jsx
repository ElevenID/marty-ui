import { QRCodeSVG } from 'qrcode.react';

function Oid4vpQrCode({ value, size = 220 }) {
  if (!value) return null;

  return (
    <span
      role="img"
      aria-label="OID4VP QR Code"
      data-testid="oid4vp-qr-code"
      data-qr-value={value}
      style={{ display: 'block', width: size, height: size }}
    >
      <QRCodeSVG
        value={value}
        size={size}
        level="M"
        includeMargin
      />
    </span>
  );
}

export default Oid4vpQrCode;
