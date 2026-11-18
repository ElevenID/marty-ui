import assert from 'node:assert/strict';
import test from 'node:test';

import { generatedTextMatches, normalizeGeneratedText } from './generated-text.mjs';

test('generated text comparison is independent of platform line endings', () => {
  const generated = 'first\nsecond\n';

  assert.equal(generatedTextMatches('first\r\nsecond\r\n', generated), true);
  assert.equal(generatedTextMatches('first\rsecond\r', generated), true);
  assert.equal(normalizeGeneratedText(generated), generated);
});

test('generated text comparison still detects content drift', () => {
  assert.equal(generatedTextMatches('first\r\nchanged\r\n', 'first\nsecond\n'), false);
});
