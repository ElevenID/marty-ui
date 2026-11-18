import React from 'react';
import {
  Box,
  Paper,
  Skeleton,
  Stack,
} from '@mui/material';

/**
 * FormSkeleton - Loading skeleton for form components
 * 
 * @param {number} fields - Number of form fields (default: 5)
 * @param {boolean} showActions - Whether to show action buttons (default: true)
 * @param {string} variant - Form variant: 'default' | 'compact' | 'wizard'
 */
export default function FormSkeleton({ 
  fields = 5,
  showActions = true,
  variant = 'default'
}) {
  const fieldHeight = variant === 'compact' ? 40 : 56;
  const spacing = variant === 'compact' ? 2 : 3;

  return (
    <Paper sx={{ p: 3 }}>
      {variant === 'wizard' && (
        <Box sx={{ mb: 4 }}>
          <Skeleton variant="text" width="40%" height={32} sx={{ mb: 1 }} />
          <Skeleton variant="text" width="60%" height={20} />
        </Box>
      )}
      
      <Stack spacing={spacing}>
        {Array.from({ length: fields }).map((_, index) => (
          <Box key={`field-${index}`}>
            <Skeleton 
              variant="text" 
              width="30%" 
              height={20} 
              sx={{ mb: 0.5 }} 
            />
            <Skeleton 
              variant="rectangular" 
              height={fieldHeight} 
              sx={{ borderRadius: 1 }}
            />
          </Box>
        ))}
      </Stack>

      {showActions && (
        <Box 
          sx={{ 
            mt: 4, 
            display: 'flex', 
            gap: 2, 
            justifyContent: 'flex-end' 
          }}
        >
          <Skeleton variant="rectangular" width={100} height={36} sx={{ borderRadius: 1 }} />
          <Skeleton variant="rectangular" width={100} height={36} sx={{ borderRadius: 1 }} />
        </Box>
      )}
    </Paper>
  );
}
