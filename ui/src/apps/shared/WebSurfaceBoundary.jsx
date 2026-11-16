import { useLocation } from 'react-router';
import { redirectBrowser, shouldBrowserRedirect } from '../../application/routing/appHandoff';

/** Keep existing Link components, but hand cross-surface links to the browser. */
export default function WebSurfaceBoundary({ children, surface }) {
  const location = useLocation();
  const onClick = (event) => {
    if (event.defaultPrevented || event.button !== 0 || event.altKey || event.ctrlKey
      || event.metaKey || event.shiftKey) return;
    const link = event.target?.closest?.('a[href]');
    if (!link || link.hasAttribute('download') || (link.target && link.target !== '_self')) return;
    const destination = link.getAttribute('href');
    if (!shouldBrowserRedirect({ currentPathname: location.pathname, destination, surface })) return;
    event.preventDefault();
    event.stopPropagation();
    redirectBrowser(destination, { replace: false });
  };
  return <div style={{ display: 'contents' }} onClickCapture={onClick}>{children}</div>;
}
