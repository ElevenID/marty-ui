/**
 * Issuance Page
 * 
 * Vendor-facing page for managing credential templates, issuance history,
 * and issuance settings.
 * 
 * Tabs:
 * - Templates: Credential type configuration
 * - History: Issued credential history (future)
 * - Settings: Issuance policies and preferences (future)
 */

import React, { useState } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tabs,
  Tab,
  Alert,
} from '@mui/material';
import BadgeIcon from '@mui/icons-material/Badge';
import HistoryIcon from '@mui/icons-material/History';
import SettingsIcon from '@mui/icons-material/Settings';

import CredentialConfigManager from './CredentialConfigManager';

/**
 * Tab Panel Component
 */
function TabPanel({ children, value, index, ...other }) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`issuance-tabpanel-${index}`}
      aria-labelledby={`issuance-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ py: 3 }}>{children}</Box>}
    </div>
  );
}

/**
 * Issuance Main Component
 */
export default function Issuance() {
  const [currentTab, setCurrentTab] = useState(0);

  const handleTabChange = (event, newValue) => {
    setCurrentTab(newValue);
  };

  return (
    <Box data-testid="issuance-page">
      {/* Page Header */}
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <BadgeIcon fontSize="large" />
          Issuance
        </Typography>
        <Typography variant="body1" color="text.secondary">
          Configure credential templates, review issuance history, and manage issuance policies.
        </Typography>
      </Box>

      {/* Tabs */}
      <Paper sx={{ mb: 3 }}>
        <Tabs
          value={currentTab}
          onChange={handleTabChange}
          aria-label="issuance tabs"
          sx={{ borderBottom: 1, borderColor: 'divider' }}
        >
          <Tab
            icon={<BadgeIcon />}
            iconPosition="start"
            label="Templates"
            id="issuance-tab-0"
            aria-controls="issuance-tabpanel-0"
          />
          <Tab
            icon={<HistoryIcon />}
            iconPosition="start"
            label="History"
            id="issuance-tab-1"
            aria-controls="issuance-tabpanel-1"
          />
          <Tab
            icon={<SettingsIcon />}
            iconPosition="start"
            label="Settings"
            id="issuance-tab-2"
            aria-controls="issuance-tabpanel-2"
          />
        </Tabs>

        {/* Tab 0: Templates */}
        <TabPanel value={currentTab} index={0}>
          <Typography variant="h6" gutterBottom>
            Credential Templates
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Configure the types of credentials your organization will issue. Define required fields,
            validity periods, and activation status.
          </Typography>
          
          <CredentialConfigManager />
        </TabPanel>

        {/* Tab 1: History */}
        <TabPanel value={currentTab} index={1}>
          <Typography variant="h6" gutterBottom>
            Issuance History
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            View all credentials issued by your organization, including status and revocation history.
          </Typography>

          <Alert severity="info">
            <Typography variant="body2">
              Issuance history coming soon. You'll be able to view all issued credentials, filter by status,
              and perform bulk operations.
            </Typography>
          </Alert>
        </TabPanel>

        {/* Tab 2: Settings */}
        <TabPanel value={currentTab} index={2}>
          <Typography variant="h6" gutterBottom>
            Issuance Settings
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Configure global issuance policies, approval workflows, and notification preferences.
          </Typography>

          <Alert severity="info">
            <Typography variant="body2">
              Issuance settings coming soon. You'll be able to configure automatic approval rules,
              notification templates, and credential expiration policies.
            </Typography>
          </Alert>
        </TabPanel>
      </Paper>
    </Box>
  );
}
