/**
 * Vendor User Invitation Tests
 * 
 * Tests for inviting users to an organization.
 * Uses MailHog to capture invitation emails.
 * 
 * SKIPPED: User invitation UI not yet implemented
 */
const { test, expect } = require('@playwright/test');
const { 
  AuthHelpers, 
  EmailTestHelpers,
  SEEDED_USERS,
  generateTestEmail,
} = require('../../../utils/test-helpers');
const { createAdminClient } = require('../../../utils/keycloak-admin');

test.describe.skip('User Invitations', () => {
  let auth;
  let emailHelper;
  let keycloakAdmin;

  test.beforeEach(async ({ page }) => {
    auth = new AuthHelpers(page);
    emailHelper = new EmailTestHelpers(page);
    keycloakAdmin = createAdminClient();
    
    // Clear emails before each test
    await emailHelper.clearAllEmails();
    
    // Login as vendor
    await page.goto('/');
    await auth.loginAsSeededUser('vendor');
  });

  test('vendor can invite new user to organization', async ({ page }) => {
    const inviteeEmail = generateTestEmail('invitee');
    
    // Navigate to users/invitations
    await page.click('text=Users, text=Team, text=Invitations');
    
    // Click invite button
    await page.click('button:has-text("Invite"), button:has-text("Add User")');
    
    // Fill invitation form
    await page.waitForSelector('input[name="email"], input[placeholder*="Email"]');
    await page.fill('input[name="email"], input[placeholder*="Email"]', inviteeEmail);
    
    // Select role
    await page.click('[role="button"]:has-text("Role"), select[name="role"]');
    await page.click('[role="option"]:has-text("Applicant"), option[value="applicant"]');
    
    // Send invitation
    await page.click('button:has-text("Send"), button:has-text("Invite")');
    
    // Should see success message
    await expect(page.locator('.MuiAlert-success, [role="alert"]')).toContainText(/invite|sent/i);
    
    // Check email was sent
    const email = await emailHelper.waitForEmail(inviteeEmail, 'Invitation');
    expect(email).toBeTruthy();
  });

  test('invited user can complete registration via email link', async ({ page, context }) => {
    const inviteeEmail = generateTestEmail('invited');
    
    // Send invitation
    await page.click('text=Users, text=Team');
    await page.click('button:has-text("Invite")');
    await page.fill('input[name="email"], input[placeholder*="Email"]', inviteeEmail);
    await page.click('button:has-text("Send")');
    
    // Wait for email
    const email = await emailHelper.waitForEmail(inviteeEmail, 'Invitation', 30000);
    const inviteLink = emailHelper.extractLink(email);
    expect(inviteLink).toBeTruthy();
    
    // Logout current user
    await auth.logout();
    
    // Open invite link in new page
    const invitePage = await context.newPage();
    await invitePage.goto(inviteLink);
    
    // Should see password setup or onboarding
    await invitePage.waitForSelector(
      '#password, input[name="password"], text=Set Password, text=Complete Registration'
    );
    
    // Set password
    const newPassword = 'InvitedUser123!';
    await invitePage.fill('#password, input[name="password"]', newPassword);
    await invitePage.fill('#password-confirm, input[name="password-confirm"]', newPassword);
    await invitePage.click('button[type="submit"], button:has-text("Continue")');
    
    // Should be logged in and associated with org
    await invitePage.waitForURL(/\/(dashboard|main)/);
    await expect(invitePage.locator('body')).toContainText(SEEDED_USERS.vendor.organization);
    
    await invitePage.close();
  });

  test('vendor can cancel pending invitation', async ({ page }) => {
    const inviteeEmail = generateTestEmail('to-cancel');
    
    // Create invitation
    await page.click('text=Users, text=Team');
    await page.click('button:has-text("Invite")');
    await page.fill('input[name="email"]', inviteeEmail);
    await page.click('button:has-text("Send")');
    
    // Should see pending invitation
    await expect(page.locator(`tr:has-text("${inviteeEmail}")`)).toBeVisible();
    
    // Cancel invitation
    await page.click(`tr:has-text("${inviteeEmail}") button:has-text("Cancel"), tr:has-text("${inviteeEmail}") [data-testid="cancel-invite"]`);
    
    // Confirm cancellation
    await page.click('button:has-text("Confirm"), button:has-text("Yes")');
    
    // Invitation should be removed or marked cancelled
    await expect(page.locator(`tr:has-text("${inviteeEmail}"):has-text("Pending")`)).not.toBeVisible();
  });

  test('vendor can resend invitation', async ({ page }) => {
    const inviteeEmail = generateTestEmail('resend');
    
    // Create initial invitation
    await page.click('text=Users, text=Team');
    await page.click('button:has-text("Invite")');
    await page.fill('input[name="email"]', inviteeEmail);
    await page.click('button:has-text("Send")');
    
    // Clear emails
    await emailHelper.clearAllEmails();
    
    // Resend invitation
    await page.click(`tr:has-text("${inviteeEmail}") button:has-text("Resend"), tr:has-text("${inviteeEmail}") [data-testid="resend-invite"]`);
    
    // Should see success
    await expect(page.locator('.MuiAlert-success')).toContainText(/resent|sent/i);
    
    // New email should arrive
    const email = await emailHelper.waitForEmail(inviteeEmail, 'Invitation');
    expect(email).toBeTruthy();
  });

  test.describe('Email Content Verification', () => {
    test('invitation email contains correct subject and content', async ({ page }) => {
      const inviteeEmail = generateTestEmail('verify-content');
      
      // Send invitation
      await page.click('text=Users, text=Team');
      await page.click('button:has-text("Invite")');
      await page.fill('input[name="email"], input[placeholder*="Email"]', inviteeEmail);
      await page.click('button:has-text("Send")');
      
      // Wait for email and verify content
      const email = await emailHelper.waitForEmail(inviteeEmail, 'Invitation');
      
      // Verify subject
      emailHelper.verifyEmailSubject(email, 'Invitation');
      
      // Verify email contains invitation text
      emailHelper.verifyEmailContains(email, 'invited you');
      
      // Verify sender
      emailHelper.verifyEmailFrom(email, 'marty.demo');
      
      // Verify recipient
      emailHelper.verifyEmailTo(email, inviteeEmail);
      
      // Verify link exists
      const hasLink = emailHelper.verifyLinkExists(email, /verify|invite|accept/i);
      expect(hasLink).toBe(true);
    });

    test('can extract invitation link by button text', async ({ page }) => {
      const inviteeEmail = generateTestEmail('extract-button');
      
      // Send invitation
      await page.click('text=Users, text=Team');
      await page.click('button:has-text("Invite")');
      await page.fill('input[name="email"]', inviteeEmail);
      await page.click('button:has-text("Send")');
      
      // Wait for email
      const email = await emailHelper.waitForEmail(inviteeEmail, 'Invitation');
      
      // Extract HTML body
      const htmlBody = emailHelper.getHtmlBody(email);
      expect(htmlBody).toBeTruthy();
      
      // Try to extract link by common button texts
      const buttonTexts = ['Accept Invitation', 'Join', 'Get Started', 'Continue'];
      let buttonLink = null;
      
      for (const text of buttonTexts) {
        buttonLink = emailHelper.extractLinksByText(email, text);
        if (buttonLink) break;
      }
      
      // If no specific button text found, get action button link
      if (!buttonLink) {
        buttonLink = emailHelper.extractActionButtonLink(email);
      }
      
      // Should have a link (either from button or general extraction)
      const allLinks = emailHelper.getAllLinks(email);
      expect(allLinks.length).toBeGreaterThan(0);
    });

    test('can extract email details and sender info', async ({ page }) => {
      const inviteeEmail = generateTestEmail('details-check');
      
      // Send invitation
      await page.click('text=Users, text=Team');
      await page.click('button:has-text("Invite")');
      await page.fill('input[name="email"]', inviteeEmail);
      await page.click('button:has-text("Send")');
      
      // Wait for email
      const email = await emailHelper.waitForEmail(inviteeEmail, 'Invitation');
      
      // Extract subject
      const subject = emailHelper.getEmailSubject(email);
      expect(subject).toContain('Invitation');
      
      // Extract sender info
      const sender = emailHelper.getSenderInfo(email);
      expect(sender.email).toContain('marty.demo');
      expect(sender.name).toBeTruthy();
      
      // Extract recipients
      const recipients = emailHelper.getRecipients(email);
      expect(recipients).toContain(inviteeEmail);
      
      // Get both HTML and text body
      const body = emailHelper.getEmailBody(email);
      expect(body.text).toBeTruthy();
    });
  });
});
