// The native auth endpoint limits the complete JSON body to 2 MiB. A 1.5 MB
// file leaves room for base64 encoding, the data URL prefix, and the envelope.
export const MAX_PROFILE_PICTURE_FILE_BYTES = 1_500_000;
export const PROFILE_PICTURE_SIZE_ERROR = 'Image must be 1.5 MB or smaller.';
const MAX_PROFILE_PICTURE_REQUEST_BYTES = 2 * 1024 * 1024;

export function createProfilePictureBody(picture) {
  const body = JSON.stringify({ picture });
  if (new TextEncoder().encode(body).byteLength > MAX_PROFILE_PICTURE_REQUEST_BYTES) {
    throw new Error(PROFILE_PICTURE_SIZE_ERROR);
  }
  return body;
}
