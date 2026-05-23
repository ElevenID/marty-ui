<#macro googleIcon>
    <svg class="elevenid-social-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
    </svg>
</#macro>

<#macro credentialIcon>
    <svg class="elevenid-social-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
        <path fill="currentColor" d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/>
    </svg>
</#macro>

<#macro renderGoogleFallback>
    <#-- During some re-auth/username-first executions, Keycloak may not expose
         social.providers even when the browser flow can still reach the broker.
         Reuse the active login-action query string so state/client/tab context is
         preserved. If Google is disabled, setup-keycloak disables the provider and
         social.providers remains empty on the normal path. -->
    <#assign googleBrokerUrl = url.loginAction?replace("/login-actions/authenticate", "/broker/google/login")>
    <a id="social-google"
       class="elevenid-social-btn elevenid-social-btn--google"
       href="${googleBrokerUrl}"
       data-testid="social-login-google">
        <@googleIcon />
        <span>Sign in with Google</span>
    </a>
</#macro>

<#macro renderAuthOptions allowGoogleFallback=false>
    <div id="kc-social-providers" class="elevenid-social-providers">
        <div class="elevenid-social-separator"><span>${msg("identity-provider-login-label")!"Or sign in with"}</span></div>

        <#if social.providers?? && (social.providers?size > 0)>
            <#list social.providers as p>
                <a id="social-${p.alias}"
                   class="elevenid-social-btn elevenid-social-btn--${p.alias}"
                   href="${p.loginUrl}"
                   data-testid="social-login-${p.alias}">
                    <#if p.alias == "google">
                        <@googleIcon />
                    </#if>
                    <span>${p.displayName!}</span>
                </a>
            </#list>
        <#elseif allowGoogleFallback>
            <@renderGoogleFallback />
        </#if>

        <a id="credential-login"
           class="elevenid-social-btn elevenid-social-btn--credential"
           href="${properties.credentialLoginUrl!"/v1/auth/credential-login"}"
           data-testid="social-login-credential">
            <@credentialIcon />
            <span>Present Open Badge Credential</span>
        </a>
    </div>
</#macro>