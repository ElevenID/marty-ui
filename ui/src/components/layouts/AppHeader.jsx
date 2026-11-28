import { createElement } from 'react';
import { createHeader } from '../../shared/web-layout/header.mjs';
import '../../shared/web-layout/header.css';

/** Shared structure; callers retain their existing navigation and account actions. */
export default function AppHeader({ brandName, logoUrl, primaryColor, brandContent, center, children }) {
  return createHeader(createElement, { brandName, logoUrl, primaryColor, brandContent, center, actions: children });
}
