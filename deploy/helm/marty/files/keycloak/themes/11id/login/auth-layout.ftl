<#-- Generated from ui/src/shared/web-layout; run node scripts/sync-web-layout.mjs. -->
<#macro authLayout>
<header class="elevenid-appbar" role="banner"><div class="elevenid-toolbar"><div class="elevenid-brand" id="brand-name">ElevenID LLC</div><div class="elevenid-toolbar-actions"><#nested "actions"></div></div></header>
<main class="elevenid-page">
    <div class="elevenid-content"><#nested "content"></div>
</main>
</#macro>
