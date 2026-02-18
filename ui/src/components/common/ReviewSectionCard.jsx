import { Box, Typography, Card, CardContent, Button } from '@mui/material';
import EditIcon from '@mui/icons-material/Edit';

/**
 * Shared section card used by wizard review steps.
 */
const ReviewSectionCard = ({
  title,
  icon,
  onEdit,
  editLabel = 'Edit',
  children,
  sx,
}) => {
  return (
    <Card sx={sx}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
          <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {icon}
            {title}
          </Typography>
          {onEdit && (
            <Button size="small" startIcon={<EditIcon />} onClick={onEdit}>
              {editLabel}
            </Button>
          )}
        </Box>

        {children}
      </CardContent>
    </Card>
  );
};

export default ReviewSectionCard;
