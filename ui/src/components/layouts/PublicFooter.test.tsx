import { describe, expect, it } from 'vitest';
import { render, screen } from '@test/utils';

import PublicFooter from './PublicFooter';

describe('PublicFooter', () => {
  it('renders durable legal and public information links', () => {
    render(<PublicFooter />);

    expect(screen.getByTestId('public-footer')).toBeInTheDocument();
    expect(screen.getByTestId('public-footer-privacy-link')).toHaveAttribute('href', '/privacy-policy');
    expect(screen.getByTestId('public-footer-terms-link')).toHaveAttribute('href', '/terms-of-service');
    expect(screen.getByTestId('public-footer-security-link')).toHaveAttribute('href', '/security');
    expect(screen.getByTestId('public-footer-resources-link')).toHaveAttribute('href', '/resources');
    expect(screen.getByTestId('public-footer-contact-link')).toHaveAttribute('href', 'mailto:sales@elevenidllc.com');
  });
});