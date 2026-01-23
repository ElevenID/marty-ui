/**
 * Team Page
 * 
 * Vendor-facing page for managing team members, invitations, and API keys.
 * Consolidates user management and programmatic access in one place.
 * 
 * Tabs:
 * - Members: Team roster with roles (future)
 * - Invitations: Invite and manage applicant invitations
 * - API Keys: Create and manage API keys for programmatic access
 */

import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tabs,
  Tab,
  Alert,
  Button,
} from '@mui/material';
import PeopleIcon from '@mui/icons-material/People';
import MailIcon from '@mui/icons-material/Mail';
import VpnKeyIcon from '@mui/icons-material/VpnKey';
import WebhookIcon from '@mui/icons-material/Webhook';
import PersonAddIcon from '@mui/icons-material/PersonAdd';

import InviteApplicants from './InviteApplicants';
import APIKeyManager from './APIKeyManager';
import WebhookManager from './WebhookManager';

/**
 * Tab Panel Component
 */
function TabPanel({ children, value, index, ...other }) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`team-tabpanel-${index}`}
      aria-labelledby={`team-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

/**
 * Team Main Component
 */
export default function Team() {
  const [currentTab, setCurrentTab] = useState(0);

  const handleTabChange = (event, newValue) => {
    setCurrentTab(newValue);
  };

  return (
    <Box data-testid="team-page">
      {/* Page Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <PeopleIcon fontSize="large" />
          Team
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Manage team members, send invitations, configure API keys, and set up webhooks for event notifications.
        </Typography>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={currentTab}
          onChange={handleTabChange}
          aria-label="team tabs"
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab
            icon={<PeopleIcon />}
            iconPosition="start"
            label="Members"
            id="team-tab-0"
            aria-controls="team-tabpanel-0"
          />
          <Tab
            icon={<MailIcon />}
            iconPosition="start"
            label="Invitations"
            id="team-tab-1"
            aria-controls="team-tabpanel-1"
          />
          <Tab
            icon={<VpnKeyIcon />}
            iconPosition="start"
            label="API Keys"
            id="team-tab-2"
            aria-controls="team-tabpanel-2"
          />
          <Tab
            icon={<WebhookIcon />}
            iconPosition="start"
            label="Webhooks"
            id="team-tab-3"
            aria-controls="team-tabpanel-3"
          />
        </Tabs>

        {/* Tab 0: Members */}
        <TabPanel value={currentTab} index={0}>
          <Alert severity="info" sx={{ mb: 3 }}>
            <Typography variant="body2">
              Team member management coming soon. You'll be able to add team members with different roles
              (Owner, Admin, Member, Viewer) and manage their permissions.
            </Typography>
          </Alert>

          <Paper sx={{ p: 3, bgcolor: 'grey.50', textAlign: 'center' }}>
            <PersonAddIcon sx={{ fontSize: 60, color: 'text.secondary', mb: 2 }} />
            <Typography variant="h6" gutterBottom>
              No Team Members Yet
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Invite team members to collaborate on credential issuance and application review.
            </Typography>
            <Button variant="contained" disabled>
              Invite Team Member
            </Button>
          </Paper>
        </TabPanel>

        {/* Tab 1: Invitations */}
        <TabPanel value={currentTab} index={1}>
          <InviteApplicants />
        </TabPanel>

        {/* Tab 2: API Keys */}
        <TabPanel value={currentTab} index={2}>
          <APIKeyManager />
        </TabPanel>

        {/* Tab 3: Webhooks */}
        <TabPanel value={currentTab} index={3}>
          <WebhookManager />
        </TabPanel>
      </Paper>
    </Box>
  );
}
