<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${kcSanitize(msg("errorTitle"))?no_esc}
    <#elseif section = "form">
        <div id="kc-error-message">
            <p class="instruction">${kcSanitize(message.summary)?no_esc}</p>
            
            <div style="margin-top: 20px; text-align: center;">
                <p style="color: #666; font-size: 14px;">
                    Redirecting to home page in <span id="countdown">5</span> seconds...
                </p>
                <a href="http://localhost:9080" style="color: #1976d2; text-decoration: none; font-weight: 500;">
                    Click here if not redirected automatically
                </a>
            </div>
        </div>
        
        <script>
            (function() {
                var seconds = 5;
                var countdownEl = document.getElementById('countdown');
                var redirectUrl = 'http://localhost:9080';
                
                var interval = setInterval(function() {
                    seconds--;
                    if (countdownEl) {
                        countdownEl.textContent = seconds;
                    }
                    if (seconds <= 0) {
                        clearInterval(interval);
                        window.location.href = redirectUrl;
                    }
                }, 1000);
            })();
        </script>
    </#if>
</@layout.registrationLayout>
