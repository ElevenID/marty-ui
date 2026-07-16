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
import { useTranslation } from 'react-i18next';
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
import { fetchCredentialConfigs } from '../../application/vendor';

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
export default function Issuance({ hideHeader = false }) {
  const { t } = useTranslation('vendor');
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
      const applicantsData = await applicantApi.listOrganizationApplications(
        organizationId,
        { status: 'approved', limit: 100 },
      );
      setApplicants(applicantsData.items);
      
      // Fetch credential templates
      const data = await fetchCredentialConfigs({ organizationId });
      setCredentialTemplates(data.credential_types || []);
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
      {!hideHeader && (
        /* Page Header */
        <Box sx={{ mb: 4 }}>
          <Typography variant="h4" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <BadgeIcon fontSize="large" />
            {t('issuance.title')}
          </Typography>
          <Typography variant="body1" color="text.secondary">
            {t('issuance.description')}
          </Typography>
        </Box>
      )}

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
            label={t('issuance.tabs.templates')}
            id="issuance-tab-0"
            aria-controls="issuance-tabpanel-0"
          />
          <Tab
            icon={<QrCodeIcon />}
            iconPosition="start"
            label={t('issuance.tabs.activeOffers')}
            id="issuance-tab-1"
            aria-controls="issuance-tabpanel-1"
          />
          <Tab
            icon={<AnalyticsIcon />}
            iconPosition="start"
            label={t('issuance.tabs.analytics')}
            id="issuance-tab-2"
            aria-controls="issuance-tabpanel-2"
          />
          <Tab
            icon={<HistoryIcon />}
            iconPosition="start"
            label={t('issuance.tabs.history')}
            id="issuance-tab-3"
            aria-controls="issuance-tabpanel-3"
          />
          <Tab
            icon={<SettingsIcon />}
            iconPosition="start"
            label={t('issuance.tabs.settings')}
            id="issuance-tab-4"
            aria-controls="issuance-tabpanel-4"
          />
        </Tabs>

        {/* Tab 0: Templates */}
        <TabPanel value={currentTab} index={0}>
          <Typography variant="h6" gutterBottom>
            {t('issuance.templates.title')}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            {t('issuance.templates.description')}
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
                {t('issuance.history.title')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t('issuance.history.description')}
              </Typography>
            </Box>
            <Button
              variant="contained"
              startIcon={<QrCodeIcon />}
              onClick={handleOpenOfferDialog}
            >
              {t('issuance.history.generateOfferButton')}
            </Button>
          </Box>

          <Alert severity="info">
            <Typography variant="body2">
              {t('issuance.history.comingSoon')}
            </Typography>
          </Alert>
        </TabPanel>

        {/* Tab 4: Settings */}
        <TabPanel value={currentTab} index={4}>
          <Typography variant="h6" gutterBottom>
            {t('issuance.settings.title')}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            {t('issuance.settings.description')}
          </Typography>

          <Alert severity="info">
            <Typography variant="body2">
              {t('issuance.settings.comingSoon')}
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
