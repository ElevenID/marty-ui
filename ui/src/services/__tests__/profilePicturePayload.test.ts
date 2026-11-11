import { describe, expect, it } from 'vitest';
import { createProfilePictureBody, MAX_PROFILE_PICTURE_FILE_BYTES } from '../profilePicturePayload';

describe('native profile picture request size', () => {
  const limit = 2 * 1024 * 1024;
  const bytes = (body: string) => new TextEncoder().encode(body).byteLength;

  it('fits the advertised 1.5 MB file after base64 encoding and the JSON envelope', () => {
    expect(MAX_PROFILE_PICTURE_FILE_BYTES).toBe(1_500_000);
    const picture = `data:image/jpeg;base64,${'A'.repeat(Math.ceil(1_500_000 / 3) * 4)}`;
    const body = createProfilePictureBody(picture);
    expect(bytes(body)).toBeLessThan(limit);
    expect(JSON.parse(body)).toEqual({ picture });
  });

  it('accepts exactly the native JSON boundary and rejects one extra encoded byte', () => {
    const prefix = 'data:image/png;base64,';
    const picture = prefix + 'A'.repeat(limit - bytes(JSON.stringify({ picture: prefix })));
    expect(bytes(createProfilePictureBody(picture))).toBe(limit);
    expect(() => createProfilePictureBody(`${picture}A`)).toThrow('Image must be 1.5 MB or smaller.');
  });

  it('measures UTF-8 bytes after JSON escaping, including all envelope overhead', () => {
    const picture = '💡'.repeat(Math.floor(limit / 4));
    expect(picture.length).toBeLessThan(limit);
    expect(bytes(JSON.stringify({ picture }))).toBeGreaterThan(limit);
    expect(() => createProfilePictureBody(picture)).toThrow('Image must be 1.5 MB or smaller.');
  });
});
