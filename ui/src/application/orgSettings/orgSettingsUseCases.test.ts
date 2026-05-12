import { describe, expect, it, vi } from 'vitest';
import { loadOrgSettings, saveOrgSettings } from './orgSettingsUseCases';

describe('orgSettingsUseCases', () => {
  describe('loadOrgSettings', () => {
    it('loads and parses org settings', async () => {
      const fetchSettings = vi.fn().mockResolvedValue({
        organization_name: 'Acme',
        is_discoverable: true,
        membership_mode: 'open',
      });

      const result = await loadOrgSettings({ organizationName: 'Fallback', fetchSettings });

      expect(result.error).toBeNull();
      expect(result.org.name).toBe('Acme');
      expect(result.org.isDiscoverable).toBe(true);
    });

    it('returns error on fetch failure', async () => {
      const fetchSettings = vi.fn().mockRejectedValue(new Error('network'));
      const result = await loadOrgSettings({ fetchSettings });
      expect(result.org).toBeNull();
      expect(result.error).toBeTruthy();
    });
  });

  describe('saveOrgSettings', () => {
    it('builds and sends the save body', async () => {
      const save = vi.fn().mockResolvedValue({});
      const org = {
        isDiscoverable: true,
        membershipMode: 'open',
        allowedEmailDomains: [],
        domainJoinPolicy: 'approval',
        defaultRole: 'applicant',
        requireDeviceRegistration: false,
        allowPushNotifications: true,
        deviceRegistrationPrompt: 'first_action',
      };

      const result = await saveOrgSettings({ org, save });

      expect(result.error).toBeNull();
      expect(save).toHaveBeenCalledWith(expect.objectContaining({
        is_discoverable: true,
        membership_mode: 'open',
      }));
    });

    it('returns error on save failure', async () => {
      const save = vi.fn().mockRejectedValue(new Error('forbidden'));
      const result = await saveOrgSettings({ org: {}, save });
      expect(result.error).toBeTruthy();
    });
  });
});
