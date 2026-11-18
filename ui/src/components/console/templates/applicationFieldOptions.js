export function formatFieldOptions(options) {
  if (!Array.isArray(options)) return '';
  return options.map((option) => {
    if (typeof option === 'string') return option.trim();
    if (!option || typeof option !== 'object') return '';
    const label = String(option.label || '').trim();
    const value = String(option.value || '').trim();
    return label && value ? `${label}=${value}` : '';
  }).filter(Boolean).join(', ');
}

export function parseFieldOptions(input) {
  return String(input || '').split(',').map((item) => item.trim()).filter(Boolean).map((item) => {
    const separator = item.indexOf('=');
    if (separator <= 0 || separator === item.length - 1) return item;
    const label = item.slice(0, separator).trim();
    const value = item.slice(separator + 1).trim();
    return label && value ? { label, value } : item;
  });
}
