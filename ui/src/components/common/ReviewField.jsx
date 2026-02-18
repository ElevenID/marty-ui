import { Typography } from '@mui/material';

/**
 * Shared label/value field used across wizard review pages.
 */
const ReviewField = ({
  label,
  value,
  placeholder,
  valueVariant = 'body1',
  valueSx,
  gutterBottom,
}) => {
  const hasValue = value !== undefined && value !== null && value !== '';

  return (
    <>
      <Typography variant="subtitle2" color="text.secondary">
        {label}
      </Typography>
      <Typography variant={valueVariant} gutterBottom={gutterBottom} sx={valueSx}>
        {hasValue ? value : <em>{placeholder}</em>}
      </Typography>
    </>
  );
};

export default ReviewField;
