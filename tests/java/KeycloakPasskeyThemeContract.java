import freemarker.cache.FileTemplateLoader;
import freemarker.cache.MultiTemplateLoader;
import freemarker.cache.TemplateLoader;
import freemarker.core.HTMLOutputFormat;
import freemarker.core.TemplateClassResolver;
import freemarker.template.Configuration;
import freemarker.template.TemplateExceptionHandler;
import freemarker.template.TemplateMethodModelEx;
import java.io.StringWriter;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Render the shipped login theme with the real version-matched parent macro. */
public final class KeycloakPasskeyThemeContract {
    public static void main(String[] args) throws Exception {
        Configuration config = new Configuration(Configuration.VERSION_2_3_32);
        config.setOutputFormat(HTMLOutputFormat.INSTANCE);
        config.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
        config.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        config.setLogTemplateExceptions(false);
        config.setTemplateLoader(new MultiTemplateLoader(new TemplateLoader[] {
            new FileTemplateLoader(Path.of(args[0]).toFile()),
            new FileTemplateLoader(Path.of(args[1]).toFile())
        }));
        Map<String, Object> data = new HashMap<>();
        data.put("realm", Map.of("password", true, "registrationAllowed", true,
            "loginWithEmailAllowed", true, "registrationEmailAsUsername", true,
            "rememberMe", true, "resetPasswordAllowed", true,
            "internationalizationEnabled", false, "displayName", "Synthetic Realm"));
        data.put("properties", Map.of("credentialLoginUrl", "/custom-badge-login"));
        data.put("client", Map.of("baseUrl", "/"));
        data.put("url", Map.of("loginAction", "/realms/test/login-actions/authenticate?client_id=marty-ui&tab_id=synthetic",
            "loginResetCredentialsUrl", "/reset", "registrationUrl", "/register",
            "loginRestartFlowUrl", "/restart", "resourcesPath", "/resources/11id",
            "resourcesCommonPath", "/resources/common"));
        data.put("login", Map.of("username", "synthetic@example.invalid"));
        data.put("auth", Map.of("selectedCredential", "", "attemptedUsername", "synthetic@example.invalid"));
        data.put("messagesPerField", Map.of("existsError", (TemplateMethodModelEx) values -> false));
        data.put("msg", (TemplateMethodModelEx) values -> values.get(0).toString());
        data.put("kcSanitize", (TemplateMethodModelEx) values -> values.get(0));
        boolean reauth = args[4].equals("reauth");
        data.put("social", Map.of("providers", reauth ? List.of() : List.of(Map.of(
            "alias", "google", "loginUrl", "/broker/google/login?state=synthetic", "displayName", "Google"))));
        if (reauth) data.put("usernameHidden", true);
        if (args[3].equals("enabled")) {
            data.put("enableWebAuthnConditionalUI", true);
            // Attributes emitted by Keycloak's WebAuthnConditionalUIAuthenticator.
            data.put("isUserIdentified", reauth ? "true" : "false");
            data.put("challenge", "synthetic-challenge");
            data.put("userVerification", "required");
            data.put("rpId", "example.invalid");
            data.put("createTimeout", "60000");
            data.put("authenticatorAttachment", "");
            if (reauth) data.put("authenticators", Map.of("authenticators", List.of(
                Map.of("credentialId", "synthetic-credential"))));
        }
        StringWriter result = new StringWriter();
        config.getTemplate(args[2], "UTF-8").process(data, result);
        System.out.print(result);
    }
}
