import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  CircularProgress,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Typography,
} from '@mui/material';
import { getApprovedApplications } from '../../services/applicantApi';
import {
  loadApprovedApplicantOptions,
  resolveApprovedApplicantSelected,
  resolveApprovedApplicationsLoadResult,
} from '../../application/vetting';

/**
 * Component for selecting an approved applicant when issuing a document.
 * This integrates with TravelDocuments to auto-fill holder information.
 */
export function ApprovedApplicantSelector({ onSelect, disabled }) {
  const [approvedApps, setApprovedApps] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [selectedApp, setSelectedApp] = useState(null);

  useEffect(() => {
    const loadApprovedApplications = async () => {
      setLoading(true);
      try {
        const result = await loadApprovedApplicantOptions({ getApprovedApplications });
        setApprovedApps(result.approvedApps);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    loadApprovedApplications();
  }, []);

  const handleSelect = (app) => {
    setSelectedApp(app);
    onSelect?.(app);
  };

  const approvedApplicantOptions = resolveApprovedApplicationsLoadResult(approvedApps).options;

  if (loading) {
    return <CircularProgress size={24} />;
  }

  if (error) {
    return <Alert severity="error">{error}</Alert>;
  }

  if (approvedApps.length === 0) {
    return (
      <Alert severity="info">
        No approved applications available. Applicants must complete vetting before document issuance.
      </Alert>
    );
  }

  return (
    <FormControl fullWidth disabled={disabled}>
      <InputLabel>Select Approved Applicant</InputLabel>
      <Select
        value={selectedApp?.application_id || ''}
        label="Select Approved Applicant"
        onChange={(e) => {
          const { selectedApp: app } = resolveApprovedApplicantSelected(approvedApps, e.target.value);
          handleSelect(app);
        }}
      >
        {approvedApplicantOptions.map((option) => (
          <MenuItem key={option.value} value={option.value}>
            <Box>
              <Typography variant="body1">{option.primaryLabel}</Typography>
              <Typography variant="caption" color="textSecondary">
                {option.secondaryLabel}
              </Typography>
            </Box>
          </MenuItem>
        ))}
      </Select>
    </FormControl>
  );
}
