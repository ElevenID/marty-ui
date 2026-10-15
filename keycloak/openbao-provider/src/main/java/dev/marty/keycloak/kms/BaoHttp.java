package dev.marty.keycloak.kms;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.time.Duration;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.keycloak.util.JsonSerialization;

/** Scoped OpenBao HTTPS client shared by transit and direct-JWE operations. */
final class BaoHttp {
    private final URI base;
    private final HttpClient http;
    private final Path tokenFile;

    private BaoHttp(URI base, HttpClient http, Path tokenFile) {
        this.base = base;
        this.http = http;
        this.tokenFile = tokenFile;
    }

    static BaoHttp forToken(Path tokenFile) {
        try {
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
            return new BaoHttp(base, http, tokenFile);
        } catch (Exception error) {
            throw new IllegalStateException("Authenticated OpenBao client is unavailable", error);
        }
    }

    Map<?, ?> request(String method, String path, String body) {
        try {
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
        } catch (Exception error) {
            throw new IllegalStateException("OpenBao operation is unavailable", error);
        }
    }

    static Map<?, ?> data(Map<?, ?> response) {
        if (!(response.get("data") instanceof Map<?, ?> data)) {
            throw new IllegalStateException("OpenBao response is missing data");
        }
        return data;
    }

    static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " is required");
        }
        return value;
    }
}
