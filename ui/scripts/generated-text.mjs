export function normalizeGeneratedText(value) {
  return value.replace(/\r\n?/g, '\n');
}

export function generatedTextMatches(current, generated) {
  return normalizeGeneratedText(current) === normalizeGeneratedText(generated);
}
