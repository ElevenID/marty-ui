package dev.marty.keycloak.kms;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.util.JsonSerialization;

/** Remote cookie/CIBA JWE; no CEK or Java SecretKey enters this process. */
public final class RemoteDirectJwe {
    private static final Pattern SAFE_NAME = Pattern.compile("[A-Za-z0-9_-]{1,64}");
    private static final Pattern VERSION = Pattern.compile("[0-9a-f]{32}");

    private RemoteDirectJwe() {}

    public static String encode(KeycloakSession session, String purpose, byte[] plaintext) {
        String realm = realm(session);
        BaoHttp bao = client(realm, purpose);
        String prefix = pathPrefix(realm, purpose);
        Map<?, ?> current = BaoHttp.data(bao.request("GET", prefix + "keys/" + realm
                + "/" + purpose, null));
        String version = string(current.get("version"));
        if (!VERSION.matcher(version).matches()
                || !kid(realm, purpose, version).equals(current.get("kid"))) {
            throw new IllegalStateException("Remote JWE reference is invalid");
        }
        String body;
        try {
            body = JsonSerialization.writeValueAsString(Map.of(
                    "plaintext_base64", Base64.getEncoder().encodeToString(plaintext)));
        } catch (Exception error) {
            throw new IllegalStateException("Remote JWE request could not be encoded", error);
        }
        Map<?, ?> encrypted = BaoHttp.data(bao.request("POST", prefix + "jwe/encode/"
                + realm + "/" + purpose + "/" + version, body));
        String compact = string(encrypted.get("jwe"));
        requireHeader(compact, realm, purpose, version);
        return compact;
    }

    public static byte[] decode(KeycloakSession session, String purpose, String compact) {
        String realm = realm(session);
        if (compact == null || compact.length() > 2 << 20) {
            throw new IllegalStateException("Remote JWE input is invalid");
        }
        String[] parts = compact.split("\\.", -1);
        if (parts.length != 5 || !parts[1].isEmpty()) {
            throw new IllegalStateException("Remote JWE format is invalid");
        }
        Map<?, ?> header = header(parts[0]);
        String keyPrefix = "keycloak-" + realm + "-" + purpose + "-";
        String keyID = string(header.get("kid"));
        if (!keyID.startsWith(keyPrefix)) {
            throw new IllegalStateException("Remote JWE realm or purpose mismatch");
        }
        String version = keyID.substring(keyPrefix.length());
        if (!VERSION.matcher(version).matches()) {
            throw new IllegalStateException("Remote JWE key version is invalid");
        }
        requireHeader(compact, realm, purpose, version);
        BaoHttp bao = client(realm, purpose);
        String body;
        try {
            body = JsonSerialization.writeValueAsString(Map.of("jwe", compact));
        } catch (Exception error) {
            throw new IllegalStateException("Remote JWE request could not be encoded", error);
        }
        Map<?, ?> decrypted = BaoHttp.data(bao.request("POST", pathPrefix(realm, purpose)
                + "jwe/decode/" + realm + "/" + purpose + "/" + version, body));
        byte[] plaintext = Base64.getDecoder().decode(string(decrypted.get("plaintext_base64")));
        if (plaintext.length == 0 || plaintext.length > 1 << 20) {
            throw new IllegalStateException("Remote JWE plaintext length is invalid");
        }
        return plaintext;
    }

    private static void requireHeader(String compact, String realm, String purpose, String version) {
        String[] parts = compact.split("\\.", -1);
        if (parts.length != 5 || !parts[1].isEmpty()) {
            throw new IllegalStateException("Remote JWE format is invalid");
        }
        Map<?, ?> parsed = header(parts[0]);
        if (!"dir".equals(parsed.get("alg"))
                || !"A256CBC-HS512".equals(parsed.get("enc"))
                || !kid(realm, purpose, version).equals(parsed.get("kid"))) {
            throw new IllegalStateException("Remote JWE header is invalid");
        }
    }

    private static Map<?, ?> header(String encoded) {
        byte[] raw = Base64.getUrlDecoder().decode(encoded);
        if (raw.length == 0 || raw.length > 512) {
            throw new IllegalStateException("Remote JWE header length is invalid");
        }
        try {
            Object decoded = JsonSerialization.readValue(new String(raw, StandardCharsets.UTF_8), Map.class);
            if (!(decoded instanceof Map<?, ?> map)) {
                throw new IllegalStateException("Remote JWE header is invalid");
            }
            return map;
        } catch (Exception error) {
            throw new IllegalStateException("Remote JWE header is invalid", error);
        }
    }

    private static BaoHttp client(String realm, String purpose) {
        String directory = BaoHttp.required("MARTY_KEYCLOAK_JWE_TOKEN_DIR");
        return BaoHttp.forToken(Path.of(directory, realm + "-" + purpose + ".token"));
    }

    private static String pathPrefix(String realm, String purpose) {
        String mount = BaoHttp.required("MARTY_KEYCLOAK_JWE_MOUNT");
        if (!SAFE_NAME.matcher(mount).matches()) {
            throw new IllegalStateException("Remote JWE mount is invalid");
        }
        return mount + "/keycloak/";
    }

    private static String realm(KeycloakSession session) {
        RealmModel current = session.getContext().getRealm();
        if (current == null || !SAFE_NAME.matcher(current.getName()).matches()) {
            throw new IllegalStateException("Remote JWE realm is invalid");
        }
        return current.getName();
    }

    private static String kid(String realm, String purpose, String version) {
        if (!"cookie".equals(purpose) && !"ciba".equals(purpose)) {
            throw new IllegalStateException("Remote JWE purpose is invalid");
        }
        return "keycloak-" + realm + "-" + purpose + "-" + version;
    }

    private static String string(Object value) {
        if (!(value instanceof String text) || text.isBlank()) {
            throw new IllegalStateException("Remote JWE response is missing a value");
        }
        return text;
    }
}
