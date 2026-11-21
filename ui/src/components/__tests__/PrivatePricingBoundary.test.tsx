import { describe, expect, it } from 'vitest';
import { PUBLIC_TABS, SHOW_PUBLIC_PRICING_BUTTONS, DISABLE_PUBLIC_PRICING_BUTTONS } from '../../variants/publicConfig.application';
import { PUBLIC_NAV } from '../../config/navigation';

describe('private commercial terms', () => {
  it('keeps private pricing out of application and website handoff navigation', () => {
    expect(SHOW_PUBLIC_PRICING_BUTTONS).toBe(false);
    expect(DISABLE_PUBLIC_PRICING_BUTTONS).toBe(true);
    expect([...PUBLIC_TABS, ...PUBLIC_NAV].some((link) => link.path.startsWith('/pricing'))).toBe(false);
  });

});
