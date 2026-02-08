/**
 * Blocking Issues Panel
 * 
 * Displays actionable blockers that prevent system readiness.
 * Only shown when blockers exist.
 */

import {
  Alert,
  AlertTitle,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Button,
  Box,
} from '@mui/material';
import { Link } from 'react-router-dom';
import WarningIcon from '@mui/icons-material/Warning';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';

/**
 * Blocking Issues Panel Component
 */
export function BlockingIssuesPanel({ blockers }) {
  if (!blockers || blockers.length === 0) {
    return null;
  }

  return (
    <Alert severity="warning" sx={{ mb: 3 }}>
      <AlertTitle>Blocking Issues</AlertTitle>
      <List dense disablePadding>
        {blockers.map((blocker) => (
          <ListItem
            key={blocker.id}
            disablePadding
            sx={{ py: 0.5 }}
          >
            <ListItemIcon sx={{ minWidth: 32 }}>
              <WarningIcon fontSize="small" color="warning" />
            </ListItemIcon>
            <ListItemText
              primary={blocker.reason}
              primaryTypographyProps={{ variant: 'body2' }}
            />
            {blocker.action && blocker.path && (
              <Button
                size="small"
                component={Link}
                to={blocker.path}
                endIcon={<ArrowForwardIcon />}
                sx={{ ml: 2 }}
              >
                {blocker.action}
              </Button>
            )}
          </ListItem>
        ))}
      </List>
    </Alert>
  );
}
