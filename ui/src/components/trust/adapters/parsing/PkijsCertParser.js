/** Browser X.509 and PKCS#7 certificate parser. The ASN.1 library loads on demand. */

import { SUPPORTED_CERT_EXTENSIONS } from '../../ports/ICertParser';

let parserModulesPromise;
const getParserModules = () => {
  parserModulesPromise ||= Promise.all([import('pkijs'), import('asn1js')]);
  return parserModulesPromise;
};

const PEM_CERTIFICATE = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/g;

const bytesToHex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');

class PkijsCertParser {
  async parseCertificate(pemData) {
    try {
      const [pkijs, asn1js] = await getParserModules();
      const match = PEM_CERTIFICATE.exec(pemData);
      PEM_CERTIFICATE.lastIndex = 0;
      if (!match) throw new Error('No PEM certificate found');
      const bytes = Uint8Array.from(atob(match[1].replace(/\s/g, '')), char => char.charCodeAt(0));
      const asn1 = asn1js.fromBER(bytes.buffer);
      if (asn1.offset !== bytes.length) throw new Error('Invalid certificate ASN.1');
      const cert = new pkijs.Certificate({ schema: asn1.result });
      return await this._mapCertToData(cert, bytes, pemData);
    } catch (error) {
      throw new Error(`Failed to parse certificate: ${error.message}`, { cause: error });
    }
  }

  async parseChain(pemData) {
    const matches = pemData.match(PEM_CERTIFICATE);
    if (!matches?.length) throw new Error('No valid certificates found in PEM data');

    const certs = [];
    for (const pem of matches) {
      try {
        certs.push(await this.parseCertificate(pem));
      } catch (error) {
        console.warn('Skipping invalid certificate in chain:', error.message);
      }
    }
    return certs;
  }

  async readCertificateFile(file) {
    const extension = this._getFileExtension(file.name);
    if (!SUPPORTED_CERT_EXTENSIONS.includes(extension)) {
      throw new Error(`Unsupported file format: ${extension}`);
    }

    const arrayBuffer = await file.arrayBuffer();
    const textContent = new TextDecoder().decode(arrayBuffer);
    if (this.isPemFormat(textContent)) return textContent;
    if (['.der', '.cer', '.crt'].includes(extension)) return this.derToPem(arrayBuffer);
    if (['.p7b', '.p7c'].includes(extension)) return this._p7bToPem(arrayBuffer);
    try {
      return this.derToPem(arrayBuffer);
    } catch {
      throw new Error(`Unable to parse certificate file: ${file.name}`);
    }
  }

  isPemFormat(data) {
    return data.includes('-----BEGIN') && data.includes('-----END');
  }

  derToPem(derData) {
    const bytes = new Uint8Array(derData);
    let binary = '';
    for (let index = 0; index < bytes.length; index += 0x8000) {
      binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
    }
    const lines = (btoa(binary).match(/.{1,64}/g) || []).join('\n');
    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
  }

  async _p7bToPem(arrayBuffer) {
    try {
      const [pkijs, asn1js] = await getParserModules();
      const asn1 = asn1js.fromBER(arrayBuffer);
      if (asn1.offset !== arrayBuffer.byteLength) throw new Error('Invalid P7B ASN.1');
      const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
      if (contentInfo.contentType !== pkijs.ContentInfo.SIGNED_DATA) {
        throw new Error('P7B is not SignedData');
      }
      const signedData = new pkijs.SignedData({ schema: contentInfo.content });
      const certs = (signedData.certificates || []).filter(cert => cert instanceof pkijs.Certificate);
      if (!certs.length) throw new Error('No certificates found in P7B file');
      return certs.map(cert => this.derToPem(cert.toSchema().toBER(false))).join('\n');
    } catch (error) {
      throw new Error(`Failed to parse P7B file: ${error.message}`, { cause: error });
    }
  }

  async _mapCertToData(cert, derBytes, pemData) {
    const now = new Date();
    const validFrom = cert.notBefore.value;
    const validUntil = cert.notAfter.value;
    const thirtyDaysMs = 30 * 24 * 60 * 60 * 1000;
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', derBytes));
    return {
      subject: this._dnToString(cert.subject),
      issuer: this._dnToString(cert.issuer),
      validFrom,
      validUntil,
      serialNumber: bytesToHex(cert.serialNumber.valueBlock.valueHexView),
      algorithm: this._getSignatureAlgorithm(cert.signatureAlgorithm.algorithmId),
      fingerprint: bytesToHex(digest).toUpperCase().match(/../g).join(':'),
      isValid: now >= validFrom && now <= validUntil,
      isExpiringSoon: validUntil - now <= thirtyDaysMs && now <= validUntil,
      pemData,
    };
  }

  _dnToString(dn) {
    const oidMap = {
      CN: '2.5.4.3', O: '2.5.4.10', OU: '2.5.4.11',
      L: '2.5.4.7', ST: '2.5.4.8', C: '2.5.4.6',
    };
    const parts = [];
    for (const [name, oid] of Object.entries(oidMap)) {
      const attribute = dn.typesAndValues.find(item => item.type === oid);
      if (attribute) parts.push(`${name}=${attribute.value.valueBlock.value}`);
    }
    return parts.join(', ') || 'Unknown';
  }

  _getSignatureAlgorithm(oid) {
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

  _getFileExtension(filename) {
    const lastDot = filename.lastIndexOf('.');
    return lastDot !== -1 ? filename.substring(lastDot).toLowerCase() : '';
  }
}

export default PkijsCertParser;
