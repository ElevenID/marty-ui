import { beforeEach, describe, expect, it, vi } from 'vitest';
const { get, post } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock('../api', () => ({ get, post }));
import { generateCurrentCanvasLtiClaim, getCurrentCanvasLtiClaim, storeCanvasLtiSession } from '../canvasLtiExperience';

const path = '/v1/integrations/canvas/lti/experience-sessions/current/claim';
describe('Canvas learner claim transport', () => {
  beforeEach(() => { vi.clearAllMocks(); window.sessionStorage.clear(); });
  it('uses the launch bearer for both operations without caller-selected scope', async () => {
    storeCanvasLtiSession({ session_token: 'launch-token', expires_at: '2099-01-01T00:00:00Z' });
    const claim = { id: 'canonical-app', organization_id: 'bound-org', offer_url: 'offer' };
    post.mockResolvedValue(claim); get.mockResolvedValue(claim);
    expect(await generateCurrentCanvasLtiClaim('canonical-app')).toEqual(claim);
    expect(await getCurrentCanvasLtiClaim()).toEqual(claim);
    expect(post).toHaveBeenCalledExactlyOnceWith(path, {}, { headers: { Authorization: 'Bearer launch-token' } });
    expect(get).toHaveBeenCalledExactlyOnceWith(path, { headers: { Authorization: 'Bearer launch-token' } });
  });
  it('rejects a changed session application before displaying its bearer offer', async () => {
    storeCanvasLtiSession({ session_token: 'launch-token' });
    post.mockResolvedValue({ id: 'other-app', offer_url: 'foreign-offer' });
    await expect(generateCurrentCanvasLtiClaim('canonical-app')).rejects.toThrow('current application');
  });
  it('cannot fall back to ordinary login credentials after session expiry', async () => {
    storeCanvasLtiSession({ session_token: 'expired-token', expires_at: '2000-01-01T00:00:00Z' });
    await expect(generateCurrentCanvasLtiClaim('canonical-app')).rejects.toThrow('missing or expired');
    expect(() => getCurrentCanvasLtiClaim()).toThrow('missing or expired');
    expect(post).not.toHaveBeenCalled(); expect(get).not.toHaveBeenCalled();
  });
});
