import React from 'react';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Skeleton,
} from '@mui/material';

/**
 * TableSkeleton - Loading skeleton for table components
 * 
 * @param {number} rows - Number of skeleton rows to display (default: 5)
 * @param {number} columns - Number of columns (default: 4)
 * @param {boolean} showActions - Whether to show action column (default: true)
 * @param {boolean} showCheckbox - Whether to show checkbox column (default: false)
 */
export default function TableSkeleton({ 
  rows = 5, 
  columns = 4, 
  showActions = true,
  showCheckbox = false 
}) {
  const totalColumns = columns + (showActions ? 1 : 0) + (showCheckbox ? 1 : 0);

  return (
    <TableContainer component={Paper}>
      <Table>
        <TableHead>
          <TableRow>
            {showCheckbox && (
              <TableCell padding="checkbox">
                <Skeleton variant="rectangular" width={24} height={24} />
              </TableCell>
            )}
            {Array.from({ length: columns }).map((_, index) => (
              <TableCell key={`header-${index}`}>
                <Skeleton variant="text" width="80%" />
              </TableCell>
            ))}
            {showActions && (
              <TableCell align="right">
                <Skeleton variant="text" width="60%" />
              </TableCell>
            )}
          </TableRow>
        </TableHead>
        <TableBody>
          {Array.from({ length: rows }).map((_, rowIndex) => (
            <TableRow key={`row-${rowIndex}`}>
              {showCheckbox && (
                <TableCell padding="checkbox">
                  <Skeleton variant="rectangular" width={24} height={24} />
                </TableCell>
              )}
              {Array.from({ length: columns }).map((_, colIndex) => (
                <TableCell key={`cell-${rowIndex}-${colIndex}`}>
                  <Skeleton 
                    variant="text" 
                    width={`${60 + Math.random() * 30}%`} 
                  />
                </TableCell>
              ))}
              {showActions && (
                <TableCell align="right">
                  <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
                    <Skeleton variant="circular" width={32} height={32} />
                    <Skeleton variant="circular" width={32} height={32} />
                  </Box>
                </TableCell>
              )}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  );
}
