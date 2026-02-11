import React from 'react';
import {
  Box,
  Container,
  Skeleton,
  Stack,
} from '@mui/material';

/**
 * PageSkeleton - Loading skeleton for full page layouts
 * 
 * @param {string} variant - Page variant: 'list' | 'detail' | 'dashboard'
 */
export default function PageSkeleton({ variant = 'list' }) {
  return (
    <Container maxWidth="xl" sx={{ mt: 4 }}>
      {/* Page header */}
      <Box sx={{ mb: 4 }}>
        <Skeleton variant="text" width="30%" height={40} sx={{ mb: 1 }} />
        <Skeleton variant="text" width="50%" height={24} />
      </Box>

      {/* Toolbar / Actions */}
      <Box 
        sx={{ 
          mb: 3, 
          display: 'flex', 
          justifyContent: 'space-between',
          alignItems: 'center'
        }}
      >
        <Skeleton variant="rectangular" width={200} height={40} sx={{ borderRadius: 1 }} />
        <Skeleton variant="rectangular" width={120} height={40} sx={{ borderRadius: 1 }} />
      </Box>

      {/* Content based on variant */}
      {variant === 'list' && (
        <Skeleton variant="rectangular" height={600} sx={{ borderRadius: 1 }} />
      )}

      {variant === 'detail' && (
        <Stack spacing={3}>
          <Skeleton variant="rectangular" height={200} sx={{ borderRadius: 1 }} />
          <Skeleton variant="rectangular" height={300} sx={{ borderRadius: 1 }} />
          <Skeleton variant="rectangular" height={150} sx={{ borderRadius: 1 }} />
        </Stack>
      )}

      {variant === 'dashboard' && (
        <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 3 }}>
          {Array.from({ length: 6 }).map((_, index) => (
            <Skeleton 
              key={`card-${index}`}
              variant="rectangular" 
              height={200} 
              sx={{ borderRadius: 1 }} 
            />
          ))}
        </Box>
      )}
    </Container>
  );
}
