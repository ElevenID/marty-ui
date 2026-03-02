<#import "template.ftl" as layout>
<#-- Marty custom update-password template with live password requirements indicator -->
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('password','password-confirm') displayInfo=false; section>
    <#if section = "header">
        <#-- Header content handled by template.ftl -->
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <p class="elevenid-login-title">${msg("updatePasswordTitle")}</p>
                <p class="elevenid-context-hint">${msg("updatePasswordBody"!"Choose a new password for your account")}</p>

                <form id="kc-passwd-update-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post">
                    <input type="text"
                           id="username"
                           name="username"
                           value="${username!""}
                           autocomplete="username"
                           readonly="readonly"
                           style="display:none;"
                    />
                    <input type="password"
                           id="password"
                           name="password"
                           autocomplete="current-password"
                           style="display:none;"
                    />

                    <div class="${properties.kcFormGroupClass!}">
                        <label for="password-new" class="${properties.kcLabelClass!}">${msg("passwordNew")}</label>
                        <input type="password"
                               id="password-new"
                               data-testid="password-new-input"
                               class="${properties.kcInputClass!}"
                               name="password-new"
                               autocomplete="new-password"
                               autofocus
                               aria-invalid="<#if messagesPerField.existsError('password','password-confirm')>true</#if>"
                        />
                        <#if messagesPerField.existsError('password')>
                            <span id="input-error-password" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${kcSanitize(messagesPerField.get('password'))?no_esc}
                            </span>
                        </#if>

                        <div class="pwd-requirements" id="password-requirements">
                            <p class="pwd-req-title">Password requirements</p>
                            <ul>
                                <li id="req-length"  class="pwd-req"><span class="pwd-req-icon">✗</span> At least 8 characters</li>
                                <li id="req-upper"   class="pwd-req"><span class="pwd-req-icon">✗</span> At least 1 uppercase letter</li>
                                <li id="req-lower"   class="pwd-req"><span class="pwd-req-icon">✗</span> At least 1 lowercase letter</li>
                                <li id="req-digit"   class="pwd-req"><span class="pwd-req-icon">✗</span> At least 1 number</li>
                                <li id="req-special" class="pwd-req"><span class="pwd-req-icon">✗</span> At least 1 special character</li>
                            </ul>
                        </div>
                        <script>
                        (function () {
                            var pwdInput = document.getElementById('password-new');
                            if (!pwdInput) return;
                            var rules = {
                                'req-length':  function (v) { return v.length >= 8; },
                                'req-upper':   function (v) { return /[A-Z]/.test(v); },
                                'req-lower':   function (v) { return /[a-z]/.test(v); },
                                'req-digit':   function (v) { return /[0-9]/.test(v); },
                                'req-special': function (v) { return /[^A-Za-z0-9]/.test(v); }
                            };
                            pwdInput.addEventListener('input', function () {
                                var val = pwdInput.value;
                                var hasTyped = val.length > 0;
                                Object.keys(rules).forEach(function (id) {
                                    var li   = document.getElementById(id);
                                    var icon = li && li.querySelector('.pwd-req-icon');
                                    if (!li) return;
                                    var ok = rules[id](val);
                                    li.classList.toggle('met',          ok);
                                    li.classList.toggle('unmet-active', !ok && hasTyped);
                                    if (icon) icon.textContent = ok ? '✓' : '✗';
                                });
                            });
                        })();
                        </script>
                    </div>

                    <div class="${properties.kcFormGroupClass!}">
                        <label for="password-confirm" class="${properties.kcLabelClass!}">${msg("passwordConfirm")}</label>
                        <input type="password"
                               id="password-confirm"
                               data-testid="password-confirm-input"
                               class="${properties.kcInputClass!}"
                               name="password-confirm"
                               autocomplete="new-password"
                               aria-invalid="<#if messagesPerField.existsError('password-confirm')>true</#if>"
                        />
                        <#if messagesPerField.existsError('password-confirm')>
                            <span id="input-error-password-confirm" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${kcSanitize(messagesPerField.get('password-confirm'))?no_esc}
                            </span>
                        </#if>
                    </div>

                    <div class="${properties.kcFormGroupClass!}">
                        <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                            <#if isAppInitiatedAction??>
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                                       type="submit"
                                       data-testid="update-password-submit-button"
                                       value="${msg("doSubmit")}"
                                />
                                <button class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!} ${properties.kcButtonBlockClass!}"
                                        type="submit"
                                        name="cancel-aia"
                                        value="true"
                                        formnovalidate>
                                    ${msg("doCancel")}
                                </button>
                            <#else>
                                <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}"
                                       type="submit"
                                       data-testid="update-password-submit-button"
                                       value="${msg("doSubmit")}"
                                />
                            </#if>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </#if>
</@layout.registrationLayout>
