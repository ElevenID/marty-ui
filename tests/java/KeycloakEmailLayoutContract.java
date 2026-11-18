import freemarker.cache.FileTemplateLoader;
import freemarker.cache.MultiTemplateLoader;
import freemarker.cache.StringTemplateLoader;
import freemarker.cache.TemplateLoader;
import freemarker.core.HTMLOutputFormat;
import freemarker.core.TemplateClassResolver;
import freemarker.template.Configuration;
import freemarker.template.TemplateExceptionHandler;
import freemarker.template.TemplateMethodModelEx;
import java.io.StringWriter;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/** Render the actual layout with the inherited Keycloak emailLayout contract. */
public final class KeycloakEmailLayoutContract {
    public static void main(String[] args) throws Exception {
        if (args.length != 2 || !Set.of("VERIFY", "RESET").contains(args[1])) {
            throw new IllegalArgumentException("Expected layout path and synthetic action");
        }
        Path layout = Path.of(args[0]);
        String action = args[1];
        StringTemplateLoader caller = new StringTemplateLoader();
        caller.putTemplate("caller.ftl", "<#import \"template.ftl\" as layout>"
                + "<@layout.emailLayout>" + action + "_BODY_SENTINEL"
                + "<a href=\"https://example.invalid/" + action.toLowerCase(Locale.ROOT)
                + "\">Continue</a></@layout.emailLayout>");
        // Match DefaultFreeMarkerProvider in Keycloak 26.8.0.
        Configuration config = new Configuration(Configuration.VERSION_2_3_32);
        config.setOutputFormat(HTMLOutputFormat.INSTANCE);
        config.setNewBuiltinClassResolver(TemplateClassResolver.ALLOWS_NOTHING_RESOLVER);
        config.setTemplateExceptionHandler(TemplateExceptionHandler.RETHROW_HANDLER);
        config.setLogTemplateExceptions(false);
        config.setTemplateLoader(new MultiTemplateLoader(new TemplateLoader[] {
                caller, new FileTemplateLoader(layout.getParent().toFile())
        }));
        Map<String, Object> data = new HashMap<>();
        data.put("realmName", "Synthetic <Realm>");
        // These stubs make the old layout fail at its unsupported realmUrl,
        // rather than at a missing message helper. The corrected wrapper must
        // render the caller's content instead of this fallback message.
        data.put("msg", (TemplateMethodModelEx) values -> "UNEXPECTED_FALLBACK");
        data.put("kcSanitize", (TemplateMethodModelEx) values -> values.get(0));
        StringWriter result = new StringWriter();
        config.getTemplate("caller.ftl", "UTF-8").process(data, result);
        System.out.print(result);
    }
}
