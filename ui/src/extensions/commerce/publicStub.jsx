import { Fragment } from 'react';

export const commerceExtensionEnabled = false;

export function CommerceProvider({ children }) {
  return <Fragment>{children}</Fragment>;
}

export function configureCommerceApi() {}

export function renderCommercePublicRoutes() {
  return null;
}

export function renderCommerceConsoleRoutes() {
  return null;
}
