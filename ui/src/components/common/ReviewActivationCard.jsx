import { Card, CardContent, Typography, FormControlLabel, Switch } from '@mui/material';

/**
 * Shared activation card used in wizard review screens.
 */
const ReviewActivationCard = ({
  title,
  label,
  checked,
  onChange,
  activeDescription,
  inactiveDescription,
  switchProps,
}) => {
  return (
    <Card>
      <CardContent>
        <Typography variant="subtitle1" gutterBottom sx={{ fontWeight: 600 }}>
          {title}
        </Typography>

        <FormControlLabel
          control={<Switch checked={checked} onChange={onChange} color="primary" {...switchProps} />}
          label={label}
        />
        <Typography variant="caption" color="text.secondary" display="block" sx={{ ml: 4 }}>
          {checked ? activeDescription : inactiveDescription}
        </Typography>
      </CardContent>
    </Card>
  );
};

export default ReviewActivationCard;
