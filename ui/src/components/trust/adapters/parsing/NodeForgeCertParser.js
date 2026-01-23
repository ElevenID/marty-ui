/**
 * Node-Forge Certificate Parser Adapter
 * 
 * Implements ICertParser using node-forge for client-side X.509 parsing.
 * Lazy-loads node-forge to minimize initial bundle size.
 */

import { SUPPORTED_CERT_EXTENSIONS } from '../../ports/ICertParser';

// Lazy-loaded forge module
let forgePromise = null;

/**
 * Lazy load node-forge module.
 * @private
 */
const getForge = async () => {
  if (!forgePromise) {
    forgePromise = import('node-forge').then(mod => mod.default || mod);
  }
  return forgePromise;
};

/**
 * Node-Forge Certificate Parser - implements ICertParser interface.
 */
class NodeForgeCertParser {
  constructor() {
    this._forge = null;
  }

  /**
   * Ensure forge is loaded.
   * @private
   */
  async _ensureForge() {
    if (!this._forge) {
      this._forge = await getForge();
    }
    return this._forge;
  }

  /**
   * Parse a PEM-encoded X.509 certificate.
   * @param {string} pemData - PEM-encoded certificate
   * @returns {Promise<import('../ports/types').CertificateData>}
   */
  async parseCertificate(pemData) {
    const forge = await this._ensureForge();
    
    try {
      const cert = forge.pki.certificateFromPem(pemData);
      return this._mapCertToData(cert, pemData, forge);
    } catch (error) {
      throw new Error(`Failed to parse certificate: ${error.message}`);
    }
  }

  /**
   * Parse a PEM file containing multiple certificates (chain).
   * @param {string} pemData - PEM data with one or more certs
   * @returns {Promise<import('../ports/types').CertificateData[]>}
   */
  async parseChain(pemData) {
    const forge = await this._ensureForge();
    
    // Split PEM into individual certificates
    const pemRegex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
    const matches = pemData.match(pemRegex);
    
    if (!matches || matches.length === 0) {
      throw new Error('No valid certificates found in PEM data');
    }

    const certs = [];
    for (const pem of matches) {
      try {
        const cert = forge.pki.certificateFromPem(pem);
        certs.push(this._mapCertToData(cert, pem, forge));
      } catch (error) {
        console.warn('Skipping invalid certificate in chain:', error.message);
      }
    }

    return certs;
  }

  /**
   * Read a certificate file and return PEM string.
   * @param {File} file - File object from input
   * @returns {Promise<string>} - PEM-encoded certificate(s)
   */
  async readCertificateFile(file) {
    const forge = await this._ensureForge();
    const extension = this._getFileExtension(file.name);
    
    if (!SUPPORTED_CERT_EXTENSIONS.includes(extension)) {
      throw new Error(`Unsupported file format: ${extension}`);
    }

    const arrayBuffer = await file.arrayBuffer();
    const bytes = new Uint8Array(arrayBuffer);
    
    // Check if it's already PEM format
    const textContent = new TextDecoder().decode(bytes);
    if (this.isPemFormat(textContent)) {
      return textContent;
    }

    // Handle DER format
    if (extension === '.der' || extension === '.cer' || extension === '.crt') {
      return this.derToPem(arrayBuffer);
    }

    // Handle P7B/PKCS#7 format
    if (extension === '.p7b' || extension === '.p7c') {
      return this._p7bToPem(arrayBuffer, forge);
    }

    // If we can't detect format, try as DER
    try {
      return this.derToPem(arrayBuffer);
    } catch {
      throw new Error(`Unable to parse certificate file: ${file.name}`);
    }
  }

  /**
   * Check if a string is in PEM format.
   * @param {string} data - String to check
   * @returns {boolean}
   */
  isPemFormat(data) {
    return data.includes('-----BEGIN') && data.includes('-----END');
  }

  /**
   * Convert DER-encoded certificate to PEM format.
   * @param {ArrayBuffer} derData - DER-encoded certificate
   * @returns {string} - PEM-encoded certificate
   */
  derToPem(derData) {
    const bytes = new Uint8Array(derData);
    const binary = String.fromCharCode.apply(null, bytes);
    const base64 = btoa(binary);
    
    // Format with line breaks every 64 characters
    const lines = base64.match(/.{1,64}/g) || [];
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----`;
  }

  /**
   * Convert P7B/PKCS#7 to PEM format.
   * @private
   */
  async _p7bToPem(arrayBuffer, forge) {
    try {
      const bytes = new Uint8Array(arrayBuffer);
      const binary = forge.util.createBuffer(bytes);
      
      // Parse as ASN.1
      const asn1 = forge.asn1.fromDer(binary);
      const p7 = forge.pkcs7.messageFromAsn1(asn1);
      
      // Extract certificates
      const certs = p7.certificates || [];
      if (certs.length === 0) {
        throw new Error('No certificates found in P7B file');
      }

      // Convert each cert to PEM
      const pems = certs.map(cert => forge.pki.certificateToPem(cert));
      return pems.join('\n');
    } catch (error) {
      throw new Error(`Failed to parse P7B file: ${error.message}`);
    }
  }

  /**
   * Map forge certificate to CertificateData type.
   * @private
   */
  _mapCertToData(cert, pemData, forge) {
    const now = new Date();
    const validFrom = cert.validity.notBefore;
    const validUntil = cert.validity.notAfter;
    const isValid = now >= validFrom && now <= validUntil;
    
    // Check if expiring within 30 days
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
    const isExpiringSoon = validUntil - now <= thirtyDaysMs && now <= validUntil;

    // Get subject and issuer as readable strings
    const subject = this._dnToString(cert.subject);
    const issuer = this._dnToString(cert.issuer);

    // Calculate SHA-256 fingerprint
    const derBytes = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
    const md = forge.md.sha256.create();
    md.update(derBytes);
    const fingerprint = md.digest().toHex().toUpperCase().match(/.{2}/g).join(':');

    return {
      subject,
      issuer,
      validFrom,
      validUntil,
      serialNumber: cert.serialNumber,
      algorithm: this._getSignatureAlgorithm(cert),
      fingerprint,
      isValid,
      isExpiringSoon,
      pemData,
    };
  }

  /**
   * Convert DN (Distinguished Name) to readable string.
   * @private
   */
  _dnToString(dn) {
    const parts = [];
    
    // Common attributes in order of preference
    const attrs = ['CN', 'O', 'OU', 'L', 'ST', 'C'];
    
    for (const attr of attrs) {
      const value = dn.getField(attr);
      if (value) {
        parts.push(`${attr}=${value.value || value}`);
      }
    }

    return parts.join(', ') || 'Unknown';
  }

  /**
   * Get signature algorithm name.
   * @private
   */
  _getSignatureAlgorithm(cert) {
    const oid = cert.signatureOid;
    const oidMap = {
      '1.2.840.113549.1.1.11': 'SHA256withRSA',
      '1.2.840.113549.1.1.12': 'SHA384withRSA',
      '1.2.840.113549.1.1.13': 'SHA512withRSA',
      '1.2.840.10045.4.3.2': 'ECDSA-SHA256',
      '1.2.840.10045.4.3.3': 'ECDSA-SHA384',
      '1.2.840.10045.4.3.4': 'ECDSA-SHA512',
      '1.3.101.112': 'Ed25519',
    };
    return oidMap[oid] || oid || 'Unknown';
  }

  /**
   * Get file extension from filename.
   * @private
   */
  _getFileExtension(filename) {
    const lastDot = filename.lastIndexOf('.');
    return lastDot !== -1 ? filename.substring(lastDot).toLowerCase() : '';
  }
}

export default NodeForgeCertParser;
