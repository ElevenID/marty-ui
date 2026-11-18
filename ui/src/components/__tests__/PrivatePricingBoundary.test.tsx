import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import EudiWalletVerificationPage from '../pages/EudiWalletVerificationPage';
import IsoMdocVerificationPage from '../pages/IsoMdocVerificationPage';
import VerifiableCredentialApiPage from '../pages/VerifiableCredentialApiPage';
import { PUBLIC_TABS, SHOW_PUBLIC_PRICING_BUTTONS, DISABLE_PUBLIC_PRICING_BUTTONS } from '../../variants/publicConfig.public';
import { PUBLIC_NAV } from '../../config/navigation';

vi.mock('../../application/routing/useSurfaceNavigate', () => ({ useSurfaceNavigate: () => vi.fn() }));
vi.mock('../seo', () => ({ SEOHead: () => null, softwareApplicationSchema: () => ({}) }));

describe('private commercial terms', () => {
  it('removes pricing from both public navigation configurations', () => {
    expect(SHOW_PUBLIC_PRICING_BUTTONS).toBe(false);
    expect(DISABLE_PUBLIC_PRICING_BUTTONS).toBe(true);
    expect([...PUBLIC_TABS, ...PUBLIC_NAV].some((link) => link.path.startsWith('/pricing'))).toBe(false);
  });

  it.each([['EUDI', EudiWalletVerificationPage], ['mDoc', IsoMdocVerificationPage], ['VC API', VerifiableCredentialApiPage]] as const)(
    'does not expose a commercial-scope action on %s', (_name, Page) => {
      render(<Page />);
      expect(screen.queryByRole('button', { name: 'Review Commercial Scope' })).not.toBeInTheDocument();
      expect(document.querySelector('a[href*="/pricing"]')).toBeNull();
    },
  );
});
