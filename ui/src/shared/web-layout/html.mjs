import { createHeader, DEFAULT_BRAND } from "./header.mjs";

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (character) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  })[character]);
}

// Only reviewed, repository-owned template slots become trusted markup.
// Branding always travels through the ordinary escaped text/attribute paths.
class Markup {
  constructor(value) { this.value = value; }
}
const renderChild = (child) => child instanceof Markup ? child.value
  : child == null || child === false ? "" : escapeHtml(child);
function htmlElement(tag, attributes, ...children) {
  const renderedAttributes = Object.entries(attributes ?? {}).map(([name, value]) => {
    if (name === "style") throw new Error("Static auth headers must not contain inline styles");
    return ` ${name === "className" ? "class" : name}="${escapeHtml(value)}"`;
  }).join("");
  const body = children.flat().map(renderChild).join("");
  return new Markup(`<${tag}${renderedAttributes}>${body}${tag === "img" ? "" : `</${tag}>`}`);
}

export function renderHeaderHtml({ brandName = DEFAULT_BRAND, actionsMarkup = "" } = {}) {
  return createHeader(htmlElement, { brandName, actions: new Markup(actionsMarkup) }).value;
}

export function renderAuthLayout({ brandName = DEFAULT_BRAND, actionsMarkup = "", contentMarkup = "" } = {}) {
  return `${renderHeaderHtml({ brandName, actionsMarkup })}\n<main class="elevenid-page">\n    <div class="elevenid-content">${contentMarkup}</div>\n</main>`;
}

export function renderKeycloakAuthLayout() {
  return `<#-- Generated from ui/src/shared/web-layout; run node scripts/sync-web-layout.mjs. -->\n<#macro authLayout>\n${renderAuthLayout({ actionsMarkup: '<#nested "actions">', contentMarkup: '<#nested "content">' })}\n</#macro>\n`;
}

export function renderAuthStyles(headerCss, pageCss) {
  return `/* Generated from ui/src/shared/web-layout; run node scripts/sync-web-layout.mjs. */\n${headerCss}\n${pageCss}`;
}
