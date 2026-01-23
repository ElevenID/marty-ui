/**
 * Role Selection Card Component
 * 
 * Displays a selectable card for choosing user role (Applicant/Vendor)
 */

import React from 'react';
import {
  Card,
  CardContent,
  CardActions,
  Typography,
  Button,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import CheckCircleIcon from '@mui/icons-material/CheckCircle';

const RoleCard = ({ role, title, description, icon: Icon, selected, onSelect, features, testId }) => (
  <Card
    sx={{
      height: '100%',
      cursor: 'pointer',
      transition: 'all 0.3s ease',
      border: selected ? '2px solid' : '1px solid',
      borderColor: selected ? 'primary.main' : 'divider',
      backgroundColor: selected ? 'action.selected' : 'background.paper',
      '&:hover': {
        borderColor: 'primary.main',
        transform: 'translateY(-4px)',
        boxShadow: 4,
      },
    }}
    onClick={() => onSelect(role)}
    data-testid={testId}
  >
    <CardContent sx={{ textAlign: 'center', py: 4 }}>
      <Icon
        sx={{
          fontSize: 64,
          color: selected ? 'primary.main' : 'text.secondary',
          mb: 2,
        }}
      />
      <Typography variant="h5" gutterBottom fontWeight="bold">
        {title}
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        {description}
      </Typography>
      <Divider sx={{ my: 2 }} />
      <List dense>
        {features.map((feature, index) => (
          <ListItem key={index} sx={{ py: 0.5 }}>
            <ListItemIcon sx={{ minWidth: 32 }}>
              <CheckCircleIcon color="success" fontSize="small" />
            </ListItemIcon>
            <ListItemText primary={feature} />
          </ListItem>
        ))}
      </List>
    </CardContent>
  </Card>
);

export default RoleCard;
