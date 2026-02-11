import React from 'react';
import {
  Box,
  Card,
  CardContent,
  CardHeader,
  Skeleton,
} from '@mui/material';

/**
 * CardSkeleton - Loading skeleton for card components
 * 
 * @param {boolean} showHeader - Whether to show card header (default: true)
 * @param {boolean} showActions - Whether to show action buttons (default: false)
 * @param {number} lines - Number of content lines (default: 3)
 * @param {string} variant - Card variant: 'default' | 'compact' | 'detailed'
 */
export default function CardSkeleton({ 
  showHeader = true,
  showActions = false,
  lines = 3,
  variant = 'default'
}) {
  const getHeight = () => {
    switch (variant) {
      case 'compact':
        return 120;
      case 'detailed':
        return 280;
      default:
        return 200;
    }
  };

  return (
    <Card sx={{ height: getHeight() }}>
      {showHeader && (
        <CardHeader
          avatar={<Skeleton variant="circular" width={40} height={40} />}
          title={<Skeleton variant="text" width="60%" />}
          subheader={<Skeleton variant="text" width="40%" />}
          action={
            showActions && (
              <Skeleton variant="circular" width={32} height={32} />
            )
          }
        />
      )}
      <CardContent>
        {Array.from({ length: lines }).map((_, index) => (
          <Skeleton 
            key={`line-${index}`}
            variant="text" 
            width={`${70 + Math.random() * 25}%`}
            sx={{ mb: 1 }}
          />
        ))}
        {variant === 'detailed' && (
          <Box sx={{ mt: 2 }}>
            <Skeleton variant="rectangular" height={100} sx={{ mb: 1 }} />
            <Skeleton variant="text" width="50%" />
          </Box>
        )}
      </CardContent>
    </Card>
  );
}
