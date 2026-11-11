import freemarker.cache.FileTemplateLoader;
import freemarker.core.HTMLOutputFormat;
import freemarker.core.TemplateClassResolver;
import freemarker.template.Configuration;
import freemarker.template.TemplateExceptionHandler;
import freemarker.template.TemplateMethodModelEx;
import java.io.Reader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

/** Render the shipped login templates with synthetic Keycloak form models. */
public final class KeycloakLoginThemeContract {
    private static final String USERNAME = "fixture\"<user>&@example.invalid";
    private static final Map<String, String> PAGES = Map.of(
            "update", "login-update-password.ftl",
            "update-aia", "login-update-password.ftl",
            "login", "login.ftl",
            "reauth", "login.ftl",
            "username", "login-username.ftl",
            "register", "register.ftl",
            "register-email", "register.ftl");

    public static void main(String[] args) throws Exception {
        if (args.length != 3 || !PAGES.containsKey(args[1])
                || !List.of("en", "de", "nl", "ja", "es", "fr").contains(args[2])) {
            throw new IllegalArgumentException("Expected theme directory, scenario, and locale");
        }
        Path theme = Path.of(args[0]);
        String scenario = args[1];
        String language = args[2];
        // Same configuration and artifact as Keycloak 26.8.0.
        Configuration config = new Configuration(Configuration.VERSION_2_3_32);
        config.setOutputFormat(HTMLOutputFormat.INSTANCE);
        config.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
        config.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        config.setLogTemplateExceptions(false);
        config.setTemplateLoader(new FileTemplateLoader(theme.toFile()));

        Properties messages = new Properties();
        // Inherited Keycloak labels; custom theme messages are read from disk.
        messages.putAll(Map.of("updatePasswordTitle", "Update password",
                "passwordNew", "New password", "passwordConfirm", "Confirm password",
                "doSubmit", "Submit", "doCancel", "Cancel",
                "showPassword", "Show password", "hidePassword", "Hide password"));
        for (String tag : language.equals("en") ? List.of("en") : List.of("en", language)) {
            try (Reader source = Files.newBufferedReader(
                    theme.resolve("messages/messages_" + tag + ".properties"), StandardCharsets.UTF_8)) {
                messages.load(source);
            }
        }
        Map<String, Object> data = new HashMap<>();
        data.put("msg", (TemplateMethodModelEx) values -> {
            String key = values.get(0).toString();
            return messages.getProperty(key, key);
        });
        data.put("kcSanitize", (TemplateMethodModelEx) values -> values.get(0));
        data.put("messagesPerField", Map.of("existsError", (TemplateMethodModelEx) values -> false));
        data.put("realm", Map.of("internationalizationEnabled", true,
                "displayName", "Synthetic Realm", "password", true,
                "registrationAllowed", true, "loginWithEmailAllowed", true,
                "registrationEmailAsUsername", scenario.equals("register-email"),
                "rememberMe", true, "resetPasswordAllowed", true));
        data.put("locale", Map.of("currentLanguageTag", language, "supported", List.of()));
        data.put("client", Map.of("baseUrl", "/"));
        // Relevant inherited properties from Keycloak 26.8.0's keycloak login theme.
        data.put("properties", Map.ofEntries(
                Map.entry("kcFormClass", "form-horizontal"),
                Map.entry("kcFormGroupClass", "form-group"),
                Map.entry("kcLabelClass", "pf-c-form__label pf-c-form__label-text"),
                Map.entry("kcInputClass", "pf-c-form-control"),
                Map.entry("kcButtonClass", "pf-c-button"),
                Map.entry("kcButtonPrimaryClass", "pf-m-primary"),
                Map.entry("kcButtonDefaultClass", "btn-default"),
                Map.entry("kcButtonLargeClass", "btn-lg"),
                Map.entry("kcButtonBlockClass", "pf-m-block"),
                Map.entry("styles", "css/marty.css")));
        data.put("url", Map.of("loginAction", "/realms/fixture/login-actions/authenticate",
                "registrationAction", "/realms/fixture/login-actions/registration",
                "registrationUrl", "/realms/fixture/register",
                "loginResetCredentialsUrl", "/realms/fixture/reset-credentials",
                "loginUrl", "/realms/fixture/login",
                "loginRestartFlowUrl", "/realms/fixture/restart",
                "resourcesPath", "/resources/fixture/login/11id",
                "resourcesCommonPath", "/resources/fixture/common/keycloak"));
        data.put("auth", Map.of("attemptedUsername", USERNAME));
        data.put("social", Map.of("providers", List.of()));
        data.put("login", Map.of("username", USERNAME));
        data.put("username", USERNAME);
        data.put("register", Map.of("formData", Map.of("firstName", "Fixture",
                "lastName", "User", "email", USERNAME, "username", USERNAME)));
        if (scenario.startsWith("register")) data.put("passwordRequired", true);
        if (scenario.equals("reauth")) data.put("usernameHidden", true);
        if (scenario.equals("update-aia")) data.put("isAppInitiatedAction", true);

        StringWriter result = new StringWriter();
        config.getTemplate(PAGES.get(scenario), "UTF-8").process(data, result);
        System.out.print(result);
    }
}
