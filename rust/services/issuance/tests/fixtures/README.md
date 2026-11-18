# Public passport signer vectors

`passport_public_signatures.json` contains two synthetic CSCA/DSC certificate
chains, CMS signature encodings, and signed SODs for DG1=`01`, DG2=`02`.
Only public certificates and signatures are retained. The two chains exercise
profile rotation; the recorded SHA-256 binds mock signer responses to the
exact CMS input assembled by the service. No signing key or key-generation
code is present in the service tests.

These vectors test parsing, chain validation, SOD verification, rotation, and
reconciliation behavior. They do not establish remote key custody; the
separate disposable OpenBao and packaged-service acceptance gates do that.
