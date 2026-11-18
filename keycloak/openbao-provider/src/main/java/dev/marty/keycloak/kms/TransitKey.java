package dev.marty.keycloak.kms;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;
import org.keycloak.util.JsonSerialization;

/** Exact-version RS256 operations; private material never enters this JVM. */
final class TransitKey {
    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9_-]+");
    private final BaoHttp bao;
    private final String name;
    private final int version;

    private TransitKey(BaoHttp bao, String name, int version) {
        this.bao = bao;
        this.name = name;
        this.version = version;
    }

    static TransitKey forRealm(String realm, String algorithm) {
        try {
            String prefix = BaoHttp.required("MARTY_KEYCLOAK_KMS_KEY_PREFIX");
            if (!"rs256".equals(algorithm) && !"hs512".equals(algorithm)) {
                throw new IllegalArgumentException("Unsupported remote key algorithm");
            }
            String name = prefix + "-" + realm + "-" + algorithm;
            if (!SAFE_NAME.matcher(name).matches()) {
                throw new IllegalArgumentException("Invalid KMS key name");
            }
            int version = Integer.parseInt(BaoHttp.required("MARTY_KEYCLOAK_KMS_KEY_VERSION"));
            if (version < 1) {
                throw new IllegalArgumentException("KMS key version must be positive");
            }
            BaoHttp bao = BaoHttp.forToken(Path.of(BaoHttp.required("BAO_TOKEN_FILE")));
            return new TransitKey(bao, name, version);
        } catch (Exception error) {
            throw new IllegalStateException("Remote RS256 identity is unavailable", error);
        }
    }

    String kid() {
        return name + "-v" + version;
    }

    PublicKey publicKey() {
        try {
            Map<?, ?> data = BaoHttp.data(bao.request("GET", "transit/keys/" + name, null));
            if (!"rsa-2048".equals(data.get("type"))
                    || !Boolean.FALSE.equals(data.get("exportable"))) {
                throw new IllegalStateException("OpenBao key must be non-exportable RSA-2048");
            }
            Map<?, ?> keys = asMap(data.get("keys"));
            Map<?, ?> selected = asMap(keys.get(Integer.toString(version)));
            String pem = string(selected.get("public_key"));
            String encoded = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "").replaceAll("\\s", "");
            return KeyFactory.getInstance("RSA").generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(encoded)));
        } catch (Exception error) {
            throw new IllegalStateException("Remote RS256 public key is unavailable", error);
        }
    }

    X509Certificate certificate(PublicKey expected) {
        Path certificateFile = Path.of(BaoHttp.required("MARTY_KEYCLOAK_RS256_CERT_DIR"),
                name + ".crt");
        try (var input = Files.newInputStream(certificateFile)) {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(input);
            certificate.checkValidity();
            if (!java.util.Arrays.equals(certificate.getPublicKey().getEncoded(),
                    expected.getEncoded())) {
                throw new IllegalStateException("RS256 certificate does not match OpenBao key");
            }
            return certificate;
        } catch (Exception error) {
            throw new IllegalStateException("Remote RS256 certificate is invalid", error);
        }
    }

    void requireHmacKey() {
        try {
            Map<?, ?> data = BaoHttp.data(bao.request("GET", "transit/keys/" + name, null));
            if (!"hmac".equals(data.get("type"))
                    || !Boolean.FALSE.equals(data.get("exportable"))
                    || !(data.get("latest_version") instanceof Number latest)
                    || latest.intValue() < version
                    || !(data.get("min_available_version") instanceof Number minimum)
                    || minimum.intValue() > version) {
                throw new IllegalStateException("OpenBao key must be non-exportable HMAC");
            }
        } catch (Exception error) {
            throw new IllegalStateException("Remote HS512 key is unavailable", error);
        }
    }

    byte[] hmac(byte[] input) {
        try {
            String body = JsonSerialization.writeValueAsString(Map.of(
                    "input", Base64.getEncoder().encodeToString(input),
                    "key_version", version));
            String wrapped = string(BaoHttp.data(bao.request("POST", "transit/hmac/" + name
                    + "/sha2-512", body)).get("hmac"));
            String prefix = "vault:v" + version + ":";
            if (!wrapped.startsWith(prefix)) {
                throw new IllegalStateException("OpenBao HMAC used the wrong key version");
            }
            return Base64.getDecoder().decode(wrapped.substring(prefix.length()));
        } catch (Exception error) {
            throw new IllegalStateException("Remote HS512 signing failed", error);
        }
    }

    boolean verifyHmac(byte[] input, byte[] signature) {
        try {
            String body = JsonSerialization.writeValueAsString(Map.of(
                    "input", Base64.getEncoder().encodeToString(input),
                    "hmac", "vault:v" + version + ":"
                            + Base64.getEncoder().encodeToString(signature)));
            return Boolean.TRUE.equals(BaoHttp.data(bao.request("POST", "transit/verify/" + name
                    + "/sha2-512", body)).get("valid"));
        } catch (Exception error) {
            throw new IllegalStateException("Remote HS512 verification failed", error);
        }
    }

    byte[] sign(byte[] input, PublicKey expectedPublicKey) {
        try {
            String body = JsonSerialization.writeValueAsString(Map.of(
                    "input", Base64.getEncoder().encodeToString(input),
                    "key_version", version,
                    "hash_algorithm", "sha2-256",
                    "signature_algorithm", "pkcs1v15"));
            String wrapped = string(BaoHttp.data(bao.request("POST", "transit/sign/" + name, body))
                    .get("signature"));
            String prefix = "vault:v" + version + ":";
            if (!wrapped.startsWith(prefix)) {
                throw new IllegalStateException("OpenBao signed with the wrong key version");
            }
            byte[] signature = Base64.getDecoder().decode(wrapped.substring(prefix.length()));
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(expectedPublicKey);
            verifier.update(input);
            if (!verifier.verify(signature)) {
                throw new IllegalStateException("OpenBao signature did not match the pinned public key");
            }
            return signature;
        } catch (Exception error) {
            throw new IllegalStateException("Remote RS256 signing failed", error);
        }
    }

    private static Map<?, ?> asMap(Object value) {
        if (!(value instanceof Map<?, ?> map)) {
            throw new IllegalStateException("OpenBao response is missing key metadata");
        }
        return map;
    }

    private static String string(Object value) {
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalStateException("OpenBao response is missing a required value");
        }
        return text;
    }

}
