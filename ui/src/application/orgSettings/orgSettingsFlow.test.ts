import { describe, expect, it } from 'vitest';
import {
  buildOrgSettingsSaveBody,
  parseOrgSettingsResponse,
} from './orgSettingsFlow';

describe('orgSettingsFlow', () => {
  describe('parseOrgSettingsResponse', () => {
    it('maps API response fields to component state', () => {
      const data = {
        organization_name: 'Acme Corp',
        display_name: 'Acme',
        description: 'Corp',
        website: 'https://acme.com',
        contact_email: 'admin@acme.com',
        address: '1 Main St',
        country: 'US',
        is_discoverable: true,
        membership_mode: 'open',
        allowed_email_domains: ['acme.com'],
        domain_join_policy: 'auto',
        default_role: 'viewer',
        require_device_registration: true,
        allow_push_notifications: false,
        device_registration_prompt: 'setup',
      };

      const result = parseOrgSettingsResponse(data);

      expect(result).toEqual({
        name: 'Acme Corp',
        displayName: 'Acme',
        description: 'Corp',
        website: 'https://acme.com',
        contactEmail: 'admin@acme.com',
        address: '1 Main St',
        country: 'US',
        isDiscoverable: true,
        membershipMode: 'open',
        allowedEmailDomains: ['acme.com'],
        domainJoinPolicy: 'auto',
        defaultRole: 'viewer',
        requireDeviceRegistration: true,
        allowPushNotifications: false,
        deviceRegistrationPrompt: 'setup',
      });
    });

    it('uses defaults for missing fields', () => {
      const result = parseOrgSettingsResponse({}, { organizationName: 'Fallback' });
      expect(result.name).toBe('Fallback');
      expect(result.membershipMode).toBe('invite_only');
      expect(result.allowPushNotifications).toBe(true);
    });
  });

  describe('buildOrgSettingsSaveBody', () => {
    it('maps component state back to API field names', () => {
      const org = {
        isDiscoverable: true,
        membershipMode: 'open',
        allowedEmailDomains: ['acme.com'],
        domainJoinPolicy: 'auto',
        defaultRole: 'viewer',
        requireDeviceRegistration: true,
        allowPushNotifications: false,
        deviceRegistrationPrompt: 'setup',
      };

      const body = buildOrgSettingsSaveBody(org);

      expect(body).toEqual({
        is_discoverable: true,
        membership_mode: 'open',
        allowed_email_domains: ['acme.com'],
        domain_join_policy: 'auto',
        default_role: 'viewer',
        require_device_registration: true,
        allow_push_notifications: false,
        device_registration_prompt: 'setup',
      });
    });
  });
});
