package dev.marty.keycloak.kms;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.keycloak.util.JsonSerialization;

/** Exact-version RS256 operations; private material never enters this JVM. */
final class TransitKey {
    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9_-]+");
    private final URI base;
    private final HttpClient http;
    private final Path tokenFile;
    private final String name;
    private final int version;

    private TransitKey(URI base, HttpClient http, Path tokenFile, String name, int version) {
        this.base = base;
        this.http = http;
        this.tokenFile = tokenFile;
        this.name = name;
        this.version = version;
    }

    static TransitKey forRealm(String realm, String algorithm) {
        try {
            String prefix = required("MARTY_KEYCLOAK_KMS_KEY_PREFIX");
            if (!"rs256".equals(algorithm) && !"hs512".equals(algorithm)) {
                throw new IllegalArgumentException("Unsupported remote key algorithm");
            }
            String name = prefix + "-" + realm + "-" + algorithm;
            if (!SAFE_NAME.matcher(name).matches()) {
                throw new IllegalArgumentException("Invalid KMS key name");
            }
            int version = Integer.parseInt(required("MARTY_KEYCLOAK_KMS_KEY_VERSION"));
            if (version < 1) {
                throw new IllegalArgumentException("KMS key version must be positive");
            }
            URI base = URI.create(required("BAO_ADDR"));
            if (!"https".equals(base.getScheme()) || base.getHost() == null
                    || base.getUserInfo() != null || base.getQuery() != null
                    || base.getFragment() != null) {
                throw new IllegalArgumentException("HTTPS OpenBao address is required");
            }
            Certificate ca;
            try (var input = Files.newInputStream(Path.of(required("BAO_CACERT")))) {
                ca = CertificateFactory.getInstance("X.509").generateCertificate(input);
            }
            KeyStore trust = KeyStore.getInstance(KeyStore.getDefaultType());
            trust.load(null);
            trust.setCertificateEntry("openbao", ca);
            TrustManagerFactory managers = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            managers.init(trust);
            SSLContext tls = SSLContext.getInstance("TLS");
            tls.init(null, managers.getTrustManagers(), null);
            HttpClient http = HttpClient.newBuilder().sslContext(tls)
                    .connectTimeout(Duration.ofSeconds(5))
                    .followRedirects(HttpClient.Redirect.NEVER).build();
            return new TransitKey(base, http, Path.of(required("BAO_TOKEN_FILE")), name, version);
        } catch (Exception error) {
            throw new IllegalStateException("Remote RS256 identity is unavailable", error);
        }
    }

    String kid() {
        return name + "-v" + version;
    }

    PublicKey publicKey() {
        try {
            Map<?, ?> data = data(request("GET", "transit/keys/" + name, null));
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
        try (var input = Files.newInputStream(Path.of(required("MARTY_KEYCLOAK_RS256_CERT_FILE")))) {
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
            Map<?, ?> data = data(request("GET", "transit/keys/" + name, null));
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
            String wrapped = string(data(request("POST", "transit/hmac/" + name
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
            return Boolean.TRUE.equals(data(request("POST", "transit/verify/" + name
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
            String wrapped = string(data(request("POST", "transit/sign/" + name, body))
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

    private Map<?, ?> request(String method, String path, String body)
            throws IOException, InterruptedException {
        URI url = base.resolve(base.getPath().replaceAll("/$", "") + "/v1/" + path);
        String token = Files.readString(tokenFile, StandardCharsets.UTF_8).trim();
        if (token.isEmpty()) {
            throw new IllegalStateException("OpenBao token is empty");
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder(url)
                .timeout(Duration.ofSeconds(10)).header("X-Vault-Token", token);
        if (body == null) {
            builder.GET();
        } else {
            builder.header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body));
        }
        HttpResponse<String> response = http.send(builder.build(),
                HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IllegalStateException("OpenBao operation failed with HTTP "
                    + response.statusCode());
        }
        return JsonSerialization.readValue(response.body(), Map.class);
    }

    private static Map<?, ?> data(Map<?, ?> response) {
        return asMap(response.get("data"));
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

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required");
        }
        return value;
    }
}
