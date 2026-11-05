<#import "template.ftl" as layout>
<#import "auth-options.ftl" as authOptions>
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

                        <#assign loginErrorText = "">
                        <#if messagesPerField.existsError('username','password')>
                            <#assign loginErrorText = messagesPerField.getFirstError('username','password')!"">
                        <#elseif message?has_content && message.type = 'error'>
                            <#assign loginErrorText = (message.summary!'')?replace('<[^>]+>', '', 'r')>
                        </#if>
                        <#if loginErrorText?has_content>
                            <div class="elevenid-login-error" role="alert" aria-live="polite" data-testid="login-error-text">
                                ${kcSanitize(loginErrorText)?no_esc}
                            </div>
                            <div class="elevenid-login-help" data-testid="login-password-help">
                                <p class="elevenid-login-help-text">
                                    If you usually sign in with Google, your account may not have a local password yet.
                                </p>
                                <a class="elevenid-login-help-link"
                                   href="${url.loginResetCredentialsUrl}"
                                   data-testid="set-password-email-link">
                                    Set or reset password by email
                                </a>
                            </div>
                        </#if>

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
        <@authOptions.renderAuthOptions allowGoogleFallback=usernameHidden?? />
    </#if>
</@layout.registrationLayout>
