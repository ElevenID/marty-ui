import freemarker.cache.FileTemplateLoader;
import freemarker.cache.MultiTemplateLoader;
import freemarker.cache.TemplateLoader;
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
    private static final Map<String, String> PAGES = Map.ofEntries(
            Map.entry("update", "login-update-password.ftl"),
            Map.entry("update-aia", "login-update-password.ftl"),
            Map.entry("login", "login.ftl"),
            Map.entry("login-no-i18n", "login.ftl"),
            Map.entry("login-missing-locale", "login.ftl"),
            Map.entry("login-empty-locale", "login.ftl"),
            Map.entry("login-error", "login.ftl"),
            Map.entry("login-error-reset-disabled", "login.ftl"),
            Map.entry("reauth", "login.ftl"),
            Map.entry("username", "login-username.ftl"),
            Map.entry("register", "register.ftl"),
            Map.entry("register-email", "register.ftl"),
            Map.entry("login-external", "login.ftl"),
            Map.entry("login-no-credential", "login.ftl"),
            Map.entry("login-empty-credential", "login.ftl"),
            Map.entry("login-google-no-credential", "login.ftl"),
            Map.entry("otp", "login-otp.ftl"),
            Map.entry("otp-error", "login-otp.ftl"),
            Map.entry("otp-multiple", "login-otp.ftl"),
            Map.entry("info-success", "info.ftl"),
            Map.entry("info-local", "info.ftl"),
            Map.entry("info-native", "info.ftl"),
            Map.entry("info-remote-http", "info.ftl"),
            Map.entry("info-action", "info.ftl"),
            Map.entry("info-pending", "info.ftl"),
            Map.entry("info-hidden", "info.ftl"),
            Map.entry("info-error", "info.ftl"),
            Map.entry("info-no-destination", "info.ftl"),
            Map.entry("info-action-with-destination", "info.ftl"));

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
        Path repository = theme;
        for (int i = 0; i < 5; i++) repository = repository.getParent();
        config.setTemplateLoader(new MultiTemplateLoader(new TemplateLoader[] {
                new FileTemplateLoader(theme.toFile()),
                new FileTemplateLoader(repository.resolve("tests/fixtures/keycloak-26.8.0").toFile())}));

        Properties messages = new Properties();
        // Inherited Keycloak labels; custom theme messages are read from disk.
        messages.putAll(Map.of("updatePasswordTitle", "Update password",
                "passwordNew", "New password", "passwordConfirm", "Confirm password",
                "doSubmit", "Submit", "doCancel", "Cancel",
                "showPassword", "Show password", "hidePassword", "Hide password",
                "backToApplication", "Back to application", "proceedWithAction", "Continue"));
        messages.put("doLogIn", "Sign in");
        messages.put("loginOtpOneTime", "Authenticator code");
        messages.put("requiredAction.UPDATE_PASSWORD", "Update password");
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
        data.put("messagesPerField", Map.of(
                "existsError", (TemplateMethodModelEx) values -> scenario.startsWith("login-error") || scenario.equals("otp-error"),
                "getFirstError", (TemplateMethodModelEx) values -> "Invalid sign-in credentials",
                "get", (TemplateMethodModelEx) values -> "Invalid authenticator code"));
        data.put("realm", Map.of("internationalizationEnabled", !scenario.equals("login-no-i18n") && !scenario.equals("login-missing-locale"),
                "displayName", "Synthetic Realm", "password", true,
                "registrationAllowed", true, "loginWithEmailAllowed", true,
                "registrationEmailAsUsername", scenario.equals("register-email"),
                "rememberMe", true, "resetPasswordAllowed", !scenario.equals("login-error-reset-disabled")));
        if (!scenario.equals("login-missing-locale")) {
            data.put("locale", Map.of("currentLanguageTag",
                    scenario.equals("login-empty-locale") ? "" : language, "supported", List.of()));
        }
        data.put("client", Map.of("baseUrl", "/"));
        // Relevant inherited properties from Keycloak 26.8.0's keycloak login theme.
        Map<String, String> properties = new HashMap<>(Map.ofEntries(
                Map.entry("kcFormClass", "form-horizontal"),
                Map.entry("kcFormGroupClass", "form-group"),
                Map.entry("kcLabelClass", "pf-c-form__label pf-c-form__label-text"),
                Map.entry("kcInputClass", "pf-c-form-control"),
                Map.entry("kcInputWrapperClass", "col-xs-12 col-sm-12 col-md-12 col-lg-12"),
                Map.entry("kcLabelWrapperClass", "col-xs-12 col-sm-12 col-md-12 col-lg-12"),
                Map.entry("kcFormOptionsClass", "col-xs-12 col-sm-12 col-md-12 col-lg-12"),
                Map.entry("kcFormButtonsClass", "col-xs-12 col-sm-12 col-md-12 col-lg-12"),
                Map.entry("kcInputErrorMessageClass", "pf-c-form__helper-text pf-m-error required kc-feedback-text"),
                Map.entry("kcLoginOTPListClass", "pf-c-tile"),
                Map.entry("kcLoginOTPListInputClass", "pf-c-tile__input"),
                Map.entry("kcLoginOTPListItemHeaderClass", "pf-c-tile__header"),
                Map.entry("kcLoginOTPListItemIconBodyClass", "pf-c-tile__icon"),
                Map.entry("kcLoginOTPListItemIconClass", "fa fa-mobile"),
                Map.entry("kcLoginOTPListItemTitleClass", "pf-c-tile__title"),
                Map.entry("kcButtonClass", "pf-c-button"),
                Map.entry("kcButtonPrimaryClass", "pf-m-primary"),
                Map.entry("kcButtonDefaultClass", "btn-default"),
                Map.entry("kcButtonLargeClass", "btn-lg"),
                Map.entry("kcButtonBlockClass", "pf-m-block"),
                Map.entry("styles", "css/marty.css"),
                Map.entry("homeUrl", ""),
                Map.entry("credentialLoginEnabled", "true"),
                Map.entry("credentialLoginUrl", "/v1/auth/credential-login")));
        if (scenario.equals("login-external")) {
            properties.put("homeUrl", "https://website.example.invalid/");
            properties.put("credentialLoginUrl", "https://console.example.invalid/v1/auth/credential-login");
        }
        if (scenario.equals("login-no-credential") || scenario.equals("login-google-no-credential")) {
            properties.put("credentialLoginEnabled", "false");
        }
        if (scenario.equals("login-empty-credential")) {
            properties.put("credentialLoginUrl", "");
        }
        data.put("properties", properties);
        data.put("url", Map.of("loginAction", "/realms/fixture/login-actions/authenticate",
                "registrationAction", "/realms/fixture/login-actions/registration",
                "registrationUrl", "/realms/fixture/register",
                "loginResetCredentialsUrl", "/realms/fixture/reset-credentials",
                "loginUrl", "/realms/fixture/login",
                "loginRestartFlowUrl", "/realms/fixture/restart",
                "resourcesPath", "/resources/fixture/login/11id",
                "resourcesCommonPath", "/resources/fixture/common/keycloak"));
        if (scenario.startsWith("otp")) {
            List<Map<String, String>> credentials = scenario.equals("otp-multiple")
                    ? List.of(Map.of("id", "fixture-otp-1", "userLabel", "Authenticator app"),
                              Map.of("id", "fixture-otp-2", "userLabel", "Backup authenticator device"))
                    : List.of(Map.of("id", "fixture-otp-1", "userLabel", "Authenticator app"));
            data.put("otpLogin", Map.of("userOtpCredentials", credentials,
                    "selectedCredentialId", "fixture-otp-1"));
        }
        if (scenario.startsWith("info-")) {
            String kind = scenario.equals("info-error") ? "error"
                    : scenario.equals("info-action") ? "info" : "success";
            data.put("message", Map.of("type", kind, "summary", "Your account has been updated."));
            if (!scenario.equals("info-action") && !scenario.equals("info-no-destination")) {
                String destination = "https://console.example.invalid/v1/auth/callback?code=synthetic-code&state=synthetic-state";
                if (scenario.equals("info-local")) destination = "http://127.0.0.1:9999/callback";
                if (scenario.equals("info-native")) destination = "elevenid-test://callback";
                if (scenario.equals("info-remote-http")) destination = "http://console.example.invalid/callback";
                data.put("pageRedirectUri", destination);
            }
            if (scenario.equals("info-action") || scenario.equals("info-action-with-destination")) {
                data.put("actionUri", "/realms/fixture/login-actions/action-token?key=synthetic");
            }
            if (scenario.equals("info-action") || scenario.equals("info-pending")) {
                data.put("requiredActions", List.of("UPDATE_PASSWORD"));
            }
            if (scenario.equals("info-hidden")) data.put("skipLink", true);
        }
        data.put("auth", Map.of("attemptedUsername", USERNAME));
        List<Map<String, String>> providers = scenario.equals("login-google-no-credential")
                ? List.of(Map.of("alias", "google", "displayName", "Google",
                        "loginUrl", "/realms/fixture/broker/google/login"))
                : List.of();
        data.put("social", Map.of("providers", providers));
        data.put("login", Map.of("username", USERNAME));
        data.put("username", USERNAME);
        data.put("register", Map.of("formData", Map.of("firstName", "Fixture",
                "lastName", "User", "email", USERNAME, "username", USERNAME)));
        if (scenario.startsWith("register")) data.put("passwordRequired", true);
        if (scenario.equals("reauth")) data.put("usernameHidden", true);
        if (scenario.equals("update-aia")) data.put("isAppInitiatedAction", true);

        StringWriter result = new StringWriter();
        config.getTemplate(PAGES.get(scenario), "UTF-8").process(data, result);
        // Windows console encoding can differ from both the template and Python.
        System.out.write(result.toString().getBytes(StandardCharsets.UTF_8));
        System.out.flush();
    }
}
