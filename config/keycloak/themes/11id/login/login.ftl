<#import "template.ftl" as layout>
<#-- Marty custom login template with test-friendly IDs and language switcher -->
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') && !usernameHidden?? displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
    <#if section = "header">
        <#-- Header content handled by template.ftl -->
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <p class="elevenid-login-title">${msg("loginAccountTitle")}</p>
                <p class="elevenid-context-hint">${msg("contextHint")}</p>
                <#if realm.password>
                    <form id="kc-form-login" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
                        <#if !usernameHidden??>
                            <div class="${properties.kcFormGroupClass!}">
                                <label for="username" class="${properties.kcLabelClass!}">
                                    <#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>
                                </label>

                                <input tabindex="1" 
                                       id="username" 
                                       data-testid="username-input"
                                       class="${properties.kcInputClass!}" 
                                       name="username" 
                                       value="${(login.username!'')}"
                                       type="text" 
                                       autofocus 
                                       autocomplete="username"
                                       aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                                />
                                <#if messagesPerField.existsError('username','password')>
                                    <span id="input-error" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                        ${kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc}
                                    </span>
                                </#if>
                            </div>
                        </#if>

                        <#if usernameHidden??>
                            <#assign attemptedUser = (auth.attemptedUsername)!''>
                            <div class="elevenid-reauth-user">
                                <span class="elevenid-reauth-username">${attemptedUser}</span>
                            </div>
                        </#if>

                        <div class="${properties.kcFormGroupClass!}">
                            <label for="password" class="${properties.kcLabelClass!}">${msg("password")}</label>

                            <input tabindex="2" 
                                   id="password" 
                                   data-testid="password-input"
                                   class="${properties.kcInputClass!}" 
                                   name="password" 
                                   type="password" 
                                   autocomplete="current-password"
                                   aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"
                            />
                            <#if usernameHidden?? && messagesPerField.existsError('username','password')>
                                <span id="input-error" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                    ${kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc}
                                </span>
                            </#if>
                        </div>

                        <div class="${properties.kcFormGroupClass!} ${properties.kcFormSettingClass!}">
                            <div id="kc-form-options">
                                <#if realm.rememberMe && !usernameHidden??>
                                    <div class="checkbox">
                                        <label>
                                            <#if login.rememberMe??>
                                                <input tabindex="3" id="rememberMe" data-testid="remember-me-checkbox" name="rememberMe" type="checkbox" checked> ${msg("rememberMe")}
                                            <#else>
                                                <input tabindex="3" id="rememberMe" data-testid="remember-me-checkbox" name="rememberMe" type="checkbox"> ${msg("rememberMe")}
                                            </#if>
                                        </label>
                                    </div>
                                </#if>
                            </div>
                            <div class="${properties.kcFormOptionsWrapperClass!}">
                                <#if realm.resetPasswordAllowed>
                                    <span><a tabindex="5" href="${url.loginResetCredentialsUrl}" data-testid="forgot-password-link">${msg("doForgotPassword")}</a></span>
                                </#if>
                            </div>
                        </div>

                        <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                            <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
                            <input tabindex="4" 
                                   class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" 
                                   name="login" 
                                   id="kc-login" 
                                   data-testid="login-submit-button"
                                   type="submit" 
                                   value="${msg("doLogIn")}"
                            />
                        </div>

                        <#if usernameHidden??>
                            <div class="elevenid-different-user">
                                <a href="${url.loginRestartFlowUrl}" class="elevenid-different-user-link" data-testid="different-user-link">Sign in as a different user</a>
                            </div>
                        </#if>
                    </form>
                </#if>
            </div>
        </div>
    <#elseif section = "info">
        <#if realm.password && realm.registrationAllowed && !registrationDisabled??>
            <div id="kc-registration-container">
                <div id="kc-registration">
                    <span>${msg("noAccount")} <a tabindex="6" href="${url.registrationUrl}" data-testid="register-link">${msg("doRegister")}</a></span>
                </div>
            </div>
        </#if>
    <#elseif section = "socialProviders">
        <div id="kc-social-providers" class="elevenid-social-providers">
            <div class="elevenid-social-separator"><span>${msg("identity-provider-login-label")!"Or sign in with"}</span></div>

            <#if social.providers??>
                <#list social.providers as p>
                    <a id="social-${p.alias}"
                       class="elevenid-social-btn elevenid-social-btn--${p.alias}"
                       href="${p.loginUrl}"
                       data-testid="social-login-${p.alias}">
                        <#if p.alias == "google">
                            <svg class="elevenid-social-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                                <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                                <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                                <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
                                <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                            </svg>
                        </#if>
                        <span>${p.displayName!}</span>
                    </a>
                </#list>
            <#elseif usernameHidden??>
                <#-- During re-auth the IDP redirector is not in the flow so social.providers is empty.
                     Construct the Google broker URL from the existing session parameters in url.loginAction. -->
                <#assign googleBrokerUrl = url.loginAction?replace("/login-actions/authenticate", "/broker/google/login")>
                <a id="social-google"
                   class="elevenid-social-btn elevenid-social-btn--google"
                   href="${googleBrokerUrl}"
                   data-testid="social-login-google">
                    <svg class="elevenid-social-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
                        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
                    </svg>
                    <span>Sign in with Google</span>
                </a>
            </#if>

            <a id="credential-login"
               class="elevenid-social-btn elevenid-social-btn--credential"
               href="${properties.credentialLoginUrl!"/v1/auth/credential-login"}"
               data-testid="social-login-credential">
                <svg class="elevenid-social-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                    <path fill="currentColor" d="M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/>
                </svg>
                <span>Login with Marty Badge</span>
            </a>
        </div>
    </#if>
</@layout.registrationLayout>
