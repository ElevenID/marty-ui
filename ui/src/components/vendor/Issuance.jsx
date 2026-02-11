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

import { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Paper,
  Typography,
  Tabs,
  Tab,
  Alert,
  Button,
} from '@mui/material';
import BadgeIcon from '@mui/icons-material/Badge';
import HistoryIcon from '@mui/icons-material/History';
import SettingsIcon from '@mui/icons-material/Settings';
import QrCodeIcon from '@mui/icons-material/QrCode';
import AnalyticsIcon from '@mui/icons-material/Analytics';

import CredentialConfigManager from './CredentialConfigManager';
import VendorOfferList from './VendorOfferList';
import OfferAnalytics from './OfferAnalytics';
import CredentialOfferDialog from '../issuance/CredentialOfferDialog';
import { useAuth } from '../../hooks/useAuth';
import * as applicantApi from '../../services/applicantApi';
import credentialsApi from '../../services/credentialsApi';

const API_URL = import.meta.env.VITE_API_URL || '';

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
  const { organizationId } = useAuth();
  const [currentTab, setCurrentTab] = useState(0);
  const [offerDialogOpen, setOfferDialogOpen] = useState(false);
  
  // Data for credential offer dialog
  const [applicants, setApplicants] = useState([]);
  const [credentialTemplates, setCredentialTemplates] = useState([]);
  const [loadingData, setLoadingData] = useState(false);

  const handleTabChange = (event, newValue) => {
    setCurrentTab(newValue);
  };

  const handleOpenOfferDialog = async () => {
    setOfferDialogOpen(true);
    if (applicants.length === 0 || credentialTemplates.length === 0) {
      await loadDialogData();
    }
  };

  const handleCloseOfferDialog = () => {
    setOfferDialogOpen(false);
  };

  /**
   * Load applicants and credential templates for the dialog
   */
  const loadDialogData = useCallback(async () => {
    if (!organizationId) return;
    
    setLoadingData(true);
    try {
      // Fetch approved applicants
      const applicantsData = await applicantApi.listApplications({ status: 'approved', limit: 100 });
      setApplicants(applicantsData.applications || []);
      
      // Fetch credential templates
      const response = await fetch(
        `${API_URL}/api/organizations/${organizationId}/credential-types`,
        { credentials: 'include' }
      );
      if (response.ok) {
        const data = await response.json();
        setCredentialTemplates(data.credential_types || []);
      }
    } catch (error) {
      console.error('Error loading dialog data:', error);
    } finally {
      setLoadingData(false);
    }
  }, [organizationId]);

  /**
   * Generate credential offer via API
   */
  const handleGenerateOffer = async (applicantId, templateId, credentialData, options) => {
    try {
      const request = {
        applicantId,
        templateId,
        credentialData,
        expiryMinutes: options.expiryMinutes || 15,
      };
      
      const result = await credentialsApi.createCredentialOffer(request);
      return result;
    } catch (error) {
      console.error('Error generating credential offer:', error);
      throw error;
    }
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
            icon={<QrCodeIcon />}
            iconPosition="start"
            label="Active Offers"
            id="issuance-tab-1"
            aria-controls="issuance-tabpanel-1"
          />
          <Tab
            icon={<AnalyticsIcon />}
            iconPosition="start"
            label="Analytics"
            id="issuance-tab-2"
            aria-controls="issuance-tabpanel-2"
          />
          <Tab
            icon={<HistoryIcon />}
            iconPosition="start"
            label="History"
            id="issuance-tab-3"
            aria-controls="issuance-tabpanel-3"
          />
          <Tab
            icon={<SettingsIcon />}
            iconPosition="start"
            label="Settings"
            id="issuance-tab-4"
            aria-controls="issuance-tabpanel-4"
          />
        </Tabs>

        {/* Tab 0: Templates */}
        <TabPanel value={currentTab} index={0}>
          <Typography variant="h6" gutterBottom>
            Credential Templates
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Configure and manage credential templates for issuance.
          </Typography>
          
          <CredentialConfigManager />
        </TabPanel>

        {/* Tab 1: Active Offers */}
        <TabPanel value={currentTab} index={1}>
          <VendorOfferList />
        </TabPanel>

        {/* Tab 2: Analytics */}
        <TabPanel value={currentTab} index={2}>
          <OfferAnalytics />
        </TabPanel>

        {/* Tab 3: History */}
        <TabPanel value={currentTab} index={3}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Box>
              <Typography variant="h6" gutterBottom>
                Issuance History
              </Typography>
              <Typography variant="body2" color="text.secondary">
                View all credentials issued by your organization, including status and revocation history.
              </Typography>
            </Box>
            <Button
              variant="contained"
              startIcon={<QrCodeIcon />}
              onClick={handleOpenOfferDialog}
            >
              Generate Offer
            </Button>
          </Box>

          <Alert severity="info">
            <Typography variant="body2">
              Issuance history coming soon. You&apos;ll be able to view all issued credentials, filter by status,
              and review revocation history.
            </Typography>
          </Alert>
        </TabPanel>

        {/* Tab 4: Settings */}
        <TabPanel value={currentTab} index={4}>
          <Typography variant="h6" gutterBottom>
            Issuance Settings
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Configure global issuance policies, approval workflows, and notification preferences.
          </Typography>

          <Alert severity="info">
            <Typography variant="body2">
              Issuance settings coming soon. You&apos;ll be able to configure automatic approval rules,
              notification templates, and credential expiration policies.
            </Typography>
          </Alert>
        </TabPanel>
      </Paper>

      {/* Credential Offer Dialog */}
      <CredentialOfferDialog
        open={offerDialogOpen}
        onClose={handleCloseOfferDialog}
        applicants={applicants}
        credentialTemplates={credentialTemplates}
        onGenerateOffer={handleGenerateOffer}
        loading={loadingData}
      />
    </Box>
  );
}
