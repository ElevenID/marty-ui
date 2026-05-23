<#import "template.ftl" as layout>
<#import "auth-options.ftl" as authOptions>
<#-- Username-first login page. Keep the auth option footer shared with login.ftl
     so Google and Open Badge login remain visually and behaviorally consistent. -->
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
    <#if section = "header">
        <#-- Header content handled by template.ftl -->
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <p class="elevenid-login-title">${msg("loginAccountTitle")}</p>
                <p class="elevenid-context-hint">${msg("contextHint")}</p>
                <form id="kc-form-login" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
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
                               aria-invalid="<#if messagesPerField.existsError('username')>true</#if>"
                        />
                        <#if messagesPerField.existsError('username')>
                            <span id="input-error" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${kcSanitize(messagesPerField.getFirstError('username'))?no_esc}
                            </span>
                        </#if>
                    </div>

                    <div id="kc-form-buttons" class="${properties.kcFormGroupClass!}">
                        <input tabindex="2"
                               class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                               name="login"
                               id="kc-login"
                               data-testid="login-submit-button"
                               type="submit"
                               value="${msg("doLogIn")}"
                        />
                    </div>
                </form>
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
        <@authOptions.renderAuthOptions />
    </#if>
</@layout.registrationLayout>