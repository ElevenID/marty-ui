<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false showAnotherWayIfPresent=true>
<!DOCTYPE html>
<html<#if realm.internationalizationEnabled> lang="${locale.currentLanguageTag}"</#if>>
<head>
    <meta charset="utf-8">
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="robots" content="noindex, nofollow">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <#if properties.meta?has_content>
        <#list properties.meta?split(' ') as meta>
            <meta name="${meta?split('==')[0]}" content="${meta?split('==')[1]}"/>
        </#list>
    </#if>
    <title>${msg("loginTitle",(realm.displayName!''))}</title>
    <link rel="icon" href="/favicon.ico?v=2" type="image/x-icon" />
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap" rel="stylesheet">
    <#if properties.stylesCommon?has_content>
        <#list properties.stylesCommon?split(' ') as style>
            <link href="${url.resourcesCommonPath}/${style}" rel="stylesheet" />
        </#list>
    </#if>
    <#if properties.styles?has_content>
        <#list properties.styles?split(' ') as style>
            <link href="${url.resourcesPath}/${style}" rel="stylesheet" />
        </#list>
    </#if>
    <#if properties.scripts?has_content>
        <#list properties.scripts?split(' ') as script>
            <script src="${url.resourcesPath}/${script}" type="text/javascript"></script>
        </#list>
    </#if>
</head>
<body>
    <#-- ===== MUI-style AppBar — direct child of <body>, no wrappers ===== -->
    <header class="elevenid-appbar" role="banner">
        <div class="elevenid-toolbar">
            <div class="elevenid-brand">ElevenID LLC</div>
            <div class="elevenid-toolbar-actions">
                <#if realm.internationalizationEnabled && locale.supported?has_content && (locale.supported?size > 1)>
                    <div class="elevenid-lang-switcher">
                        <svg class="elevenid-lang-icon" focusable="false" aria-hidden="true" viewBox="0 0 24 24" width="20" height="20"><path fill="currentColor" d="M11.99 2C6.47 2 2 6.48 2 12s4.47 10 9.99 10C17.52 22 22 17.52 22 12S17.52 2 11.99 2zm6.93 6h-2.95c-.32-1.25-.78-2.45-1.38-3.56 1.84.63 3.37 1.91 4.33 3.56zM12 4.04c.83 1.2 1.48 2.53 1.91 3.96h-3.82c.43-1.43 1.08-2.76 1.91-3.96zM4.26 14C4.1 13.36 4 12.69 4 12s.1-1.36.26-2h3.38c-.08.66-.14 1.32-.14 2 0 .68.06 1.34.14 2H4.26zm.82 2h2.95c.32 1.25.78 2.45 1.38 3.56-1.84-.63-3.37-1.9-4.33-3.56zm2.95-8H5.08c.96-1.66 2.49-2.93 4.33-3.56C8.81 5.55 8.35 6.75 8.03 8zM12 19.96c-.83-1.2-1.48-2.53-1.91-3.96h3.82c-.43 1.43-1.08 2.76-1.91 3.96zM14.34 14H9.66c-.09-.66-.16-1.32-.16-2 0-.68.07-1.35.16-2h4.68c.09.65.16 1.32.16 2 0 .68-.07 1.34-.16 2zm.25 5.56c.6-1.11 1.06-2.31 1.38-3.56h2.95c-.96 1.65-2.49 2.93-4.33 3.56zM16.36 14c.08-.66.14-1.32.14-2 0-.68-.06-1.34-.14-2h3.38c.16.64.26 1.31.26 2s-.1 1.36-.26 2h-3.38z"></path></svg>
                        <select class="elevenid-lang-select" onchange="if(this.value)window.location.href=this.value;" aria-label="Language selector">
                            <#list locale.supported as l>
                                <option value="${l.url}" <#if locale.currentLanguageTag == l.languageTag>selected</#if>>${l.label}</option>
                            </#list>
                        </select>
                    </div>
                </#if>
                <a class="elevenid-home-btn" href="${(client.baseUrl)!'/'}">HOME</a>
            </div>
        </div>
    </header>

    <#-- ===== Page content ===== -->
    <main class="elevenid-page">
        <div class="elevenid-content">
            <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
                <div class="elevenid-alert elevenid-alert-${message.type}">
                    <span class="elevenid-alert-text">${kcSanitize(message.summary)?no_esc}</span>
                </div>
            </#if>

            <#-- The "header" section — page title, etc. -->
            <#nested "header">

            <#-- The "form" section — main form content -->
            <#nested "form">

            <#if displayInfo>
                <div class="elevenid-info">
                    <#nested "info">
                </div>
            </#if>

            <#nested "socialProviders">
        </div>
    </main>
</body>
</html>
</#macro>
