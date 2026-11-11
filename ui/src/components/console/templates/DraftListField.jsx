import { useEffect, useRef, useState } from 'react';
import { TextField } from '@mui/material';

const formatList = (items) => (items || []).join(', ');
const parseList = (text) => text.split(',').map((item) => item.trim()).filter(Boolean);

/** Keep separators and partially typed values intact until the user leaves the field. */
export default function DraftListField({ value, onChange, format = formatList, parse = parseList, ...props }) {
  const formatted = format(value);
  const [draft, setDraft] = useState(formatted);
  const dirty = useRef(false);

  useEffect(() => {
    setDraft(formatted);
    dirty.current = false;
  }, [formatted]);

  const commit = () => {
    if (!dirty.current) return;
    const parsed = parse(draft);
    setDraft(format(parsed));
    dirty.current = false;
    onChange(parsed);
  };

  return <TextField
    {...props}
    value={draft}
    onChange={(event) => {
      dirty.current = true;
      setDraft(event.target.value);
    }}
    onBlur={commit}
  />;
}
