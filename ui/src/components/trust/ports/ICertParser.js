/**
 * Certificate Parser Port (Interface)
 * 
 * Defines the contract for client-side certificate parsing.
 * Implementation: NodeForgeCertParser
 */

/**
 * @interface ICertParser
 * 
 * Certificate parser interface for client-side X.509 parsing.
 */

/**
 * @typedef {Object} ICertParser
 * @property {function(string): Promise<import('./types').CertificateData>} parseCertificate
 *   Parse a PEM-encoded certificate
 * @property {function(string): Promise<import('./types').CertificateData[]>} parseChain
 *   Parse a PEM file containing multiple certificates (chain)
 * @property {function(File): Promise<string>} readCertificateFile
 *   Read certificate file and return PEM string
 * @property {function(string): boolean} isPemFormat
 *   Check if string is PEM formatted
 * @property {function(ArrayBuffer): string} derToPem
 *   Convert DER to PEM format
 */

/**
 * Validates that an object implements ICertParser interface.
 * @param {Object} parser - Parser to validate
 * @returns {boolean} - True if valid implementation
 */
export function isValidCertParser(parser) {
  const requiredMethods = [
    'parseCertificate',
    'parseChain',
    'readCertificateFile',
    'isPemFormat',
  ];

  return requiredMethods.every(
    method => typeof parser[method] === 'function'
  );
}

/**
 * Certificate parser method signatures for documentation.
 */
export const CertParserMethods = {
  /**
   * Parse a PEM-encoded X.509 certificate.
   * @param {string} pemData - PEM-encoded certificate
   * @returns {Promise<import('./types').CertificateData>}
   * @throws {Error} If parsing fails
   */
  parseCertificate: async (pemData) => {},

  /**
   * Parse a PEM file containing multiple certificates (chain).
   * @param {string} pemData - PEM data with one or more certs
   * @returns {Promise<import('./types').CertificateData[]>}
   */
  parseChain: async (pemData) => {},

  /**
   * Read a certificate file (PEM, DER, or P7B) and return PEM string.
   * @param {File} file - File object from input
   * @returns {Promise<string>} - PEM-encoded certificate(s)
   * @throws {Error} If file format is unsupported
   */
  readCertificateFile: async (file) => {},

  /**
   * Check if a string is in PEM format.
   * @param {string} data - String to check
   * @returns {boolean}
   */
  isPemFormat: (data) => {},

  /**
   * Convert DER-encoded certificate to PEM format.
   * @param {ArrayBuffer} derData - DER-encoded certificate
   * @returns {string} - PEM-encoded certificate
   */
  derToPem: (derData) => {},
};

/**
 * Supported certificate file extensions.
 */
export const SUPPORTED_CERT_EXTENSIONS = [
  '.pem',
  '.cer',
  '.crt',
  '.der',
  '.p7b',
  '.p7c',
];

/**
 * MIME types for certificate files.
 */
export const CERT_MIME_TYPES = {
  pem: 'application/x-pem-file',
  cer: 'application/pkix-cert',
  crt: 'application/x-x509-ca-cert',
  der: 'application/x-x509-ca-cert',
  p7b: 'application/x-pkcs7-certificates',
  p7c: 'application/pkcs7-mime',
};
