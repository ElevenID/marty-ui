import { Box, Typography, FormControlLabel, Switch } from '@mui/material';

/**
 * Shared toggle option row used in wizard review screens.
 */
const ReviewToggleOption = ({ checked, onChange, title, description, sx, switchProps }) => {
  return (
    <Box sx={{ p: 2, bgcolor: 'action.hover', borderRadius: 1, ...sx }}>
      <FormControlLabel
        control={<Switch checked={checked} onChange={onChange} {...switchProps} />}
        label={
          <Box>
            <Typography variant="subtitle2">{title}</Typography>
            <Typography variant="body2" color="text.secondary">
              {description}
            </Typography>
          </Box>
        }
      />
    </Box>
  );
};

export default ReviewToggleOption;
