// Canonical header structure for React, static auth pages and Keycloak.
// Pass the consumer's element factory; keep provider and routing behavior outside.
export const DEFAULT_BRAND = "ElevenID LLC";

export function createHeader(createElement, {
  brandName = DEFAULT_BRAND, logoUrl = null, primaryColor, brandContent, center = null, actions = null,
} = {}) {
  return createElement("header", {
    className: "elevenid-appbar", role: "banner",
    ...(primaryColor ? { style: { "--elevenid-header-primary": primaryColor } } : {}),
  }, createElement("div", { className: "elevenid-toolbar" },
    logoUrl ? createElement("img", { className: "elevenid-brand-logo", src: logoUrl, alt: brandName }) : null,
    createElement("div", { className: "elevenid-brand", id: "brand-name" }, brandContent === undefined ? brandName : brandContent),
    ...(center == null || center === false ? [] : [createElement("div", { className: "elevenid-toolbar-center" }, center)]),
    createElement("div", { className: "elevenid-toolbar-actions" }, actions),
  ));
}
