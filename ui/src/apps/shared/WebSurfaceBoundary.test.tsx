import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { Link, MemoryRouter, useLocation } from 'react-router';
import WebSurfaceBoundary from './WebSurfaceBoundary';
import { redirectBrowser } from '../../application/routing/appHandoff';

vi.mock('../../application/routing/appHandoff', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../application/routing/appHandoff')>(),
  redirectBrowser: vi.fn(() => true),
}));

afterEach(() => { cleanup(); vi.clearAllMocks(); });

function CurrentRoute() { const location = useLocation(); return <output>{location.pathname}</output>; }
function Fixture({ destination = '/login?next=%2Fconsole%3Ftab%3Dkeys%23active', attributes = {} }) {
  return <MemoryRouter initialEntries={['/product']}>
    <WebSurfaceBoundary surface="website">
      <Link to={destination} {...attributes}>Continue</Link><CurrentRoute />
    </WebSurfaceBoundary>
  </MemoryRouter>;
}

describe('WebSurfaceBoundary', () => {
  it('loads the application document and preserves the full destination before React Router handles a link', () => {
    render(<Fixture />);
    fireEvent.click(screen.getByRole('link'), { button: 0 });
    expect(redirectBrowser).toHaveBeenCalledWith('/login?next=%2Fconsole%3Ftab%3Dkeys%23active', { replace: false });
    expect(screen.getByRole('status').textContent).toBe('/product');
  });
  it('keeps website route changes in the website router', () => {
    render(<Fixture destination="/solutions" />);
    fireEvent.click(screen.getByRole('link'), { button: 0 });
    expect(redirectBrowser).not.toHaveBeenCalled();
    expect(screen.getByRole('status').textContent).toBe('/solutions');
  });
  it.each([
    { target: '_blank' }, { download: true },
  ])('preserves native link behavior for %j', (attributes) => {
    render(<Fixture attributes={attributes} />);
    fireEvent.click(screen.getByRole('link'), { button: 0 });
    expect(redirectBrowser).not.toHaveBeenCalled();
  });
  it.each([{ ctrlKey: true }, { metaKey: true }, { shiftKey: true }, { button: 1 }])('preserves native modified clicks %j', (event) => {
    render(<Fixture />);
    fireEvent.click(screen.getByRole('link'), { button: 0, ...event });
    expect(redirectBrowser).not.toHaveBeenCalled();
  });
});
