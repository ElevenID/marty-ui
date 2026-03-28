/**
 * Usage & Billing Dashboard
 * 
 * Shows current plan, usage metrics, historical trends, and upgrade CTA.
 * Fetches data from /v1/usage and /v1/usage/history endpoints.
 */

import { useState, useEffect, useCallback } from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  Grid,
  LinearProgress,
  Chip,
  Button,
  Divider,
  Paper,
  Alert,
  Skeleton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
} from '@mui/material';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import VerifiedIcon from '@mui/icons-material/Verified';
import BadgeIcon from '@mui/icons-material/Badge';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import ApiIcon from '@mui/icons-material/Api';
import UpgradeIcon from '@mui/icons-material/Upgrade';
import { useNavigate } from 'react-router-dom';
import { get } from '../../services/api';

const METRIC_CONFIG = {
  verifications: {
    label: 'Verifications',
    icon: VerifiedIcon,
    color: '#1976d2',
    limitKey: 'verifications_per_month',
  },
  issued_credentials: {
    label: 'Issued Credentials',
    icon: BadgeIcon,
    color: '#2e7d32',
    limitKey: 'issued_credentials_per_month',
  },
  active_flows: {
    label: 'Active Flows',
    icon: AccountTreeIcon,
    color: '#ed6c02',
    limitKey: 'active_flows',
  },
  api_calls: {
    label: 'API Calls',
    icon: ApiIcon,
    color: '#9c27b0',
    limitKey: null, // tracked but not billed
  },
};

const PLAN_COLORS = {
  free: 'default',
  starter: 'info',
  professional: 'primary',
  enterprise: 'secondary',
};

function UsageMetricCard({ current, limit, config }) {
  const Icon = config.icon;
  const percentage = limit ? Math.min((current / limit) * 100, 100) : 0;
  const isNearLimit = limit && percentage >= 80;
  const isAtLimit = limit && percentage >= 100;

  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
          <Icon sx={{ color: config.color }} />
          <Typography variant="subtitle2" color="text.secondary">
            {config.label}
          </Typography>
        </Box>
        <Typography variant="h4" fontWeight="bold" sx={{ mb: 1 }}>
          {current.toLocaleString()}
        </Typography>
        {limit ? (
          <>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 0.5 }}>
              <Typography variant="caption" color="text.secondary">
                {percentage.toFixed(0)}% used
              </Typography>
              <Typography variant="caption" color="text.secondary">
                {limit.toLocaleString()} limit
              </Typography>
            </Box>
            <LinearProgress
              variant="determinate"
              value={percentage}
              color={isAtLimit ? 'error' : isNearLimit ? 'warning' : 'primary'}
              sx={{ height: 8, borderRadius: 4 }}
            />
          </>
        ) : (
          <Typography variant="caption" color="text.secondary">
            Tracked for analytics (not billed)
          </Typography>
        )}
      </CardContent>
    </Card>
  );
}

function UsageDashboard() {
  const navigate = useNavigate();
  const [usage, setUsage] = useState(null);
  const [history, setHistory] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchUsage = useCallback(async () => {
    try {
      setLoading(true);
      const [usageRes, historyRes] = await Promise.all([
        get('/v1/usage'),
        get('/v1/usage/history?metric=verifications&months=6'),
      ]);
      setUsage(usageRes);
      setHistory(historyRes);
      setError(null);
    } catch (err) {
      setError('Failed to load usage data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchUsage();
  }, [fetchUsage]);

  if (loading) {
    return (
      <Box sx={{ p: 3 }}>
        <Skeleton variant="text" width={200} height={40} />
        <Grid container spacing={3} sx={{ mt: 2 }}>
          {[1, 2, 3, 4].map((i) => (
            <Grid item xs={12} sm={6} md={3} key={i}>
              <Skeleton variant="rectangular" height={140} sx={{ borderRadius: 1 }} />
            </Grid>
          ))}
        </Grid>
      </Box>
    );
  }

  if (error) {
    return (
      <Box sx={{ p: 3 }}>
        <Alert severity="error" action={<Button onClick={fetchUsage}>Retry</Button>}>
          {error}
        </Alert>
      </Box>
    );
  }

  const { plan, plan_name, plan_tagline, metrics = {}, limits = {} } = usage || {};

  return (
    <Box sx={{ p: 3 }}>
      {/* Header */}
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Box>
          <Typography variant="h5" fontWeight="bold">
            Usage & Billing
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Monitor your organization&apos;s usage and plan limits
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Box sx={{ textAlign: 'right' }}>
            <Chip
              label={plan_name || plan?.toUpperCase()}
              color={PLAN_COLORS[plan] || 'default'}
              size="medium"
              sx={{ fontWeight: 'bold' }}
            />
            {plan_tagline && (
              <Typography variant="caption" display="block" color="text.secondary" sx={{ mt: 0.5 }}>
                {plan_tagline}
              </Typography>
            )}
          </Box>
          {plan !== 'enterprise' && (
            <Button
              variant="outlined"
              startIcon={<UpgradeIcon />}
              onClick={() => navigate('/pricing')}
            >
              Upgrade Plan
            </Button>
          )}
        </Box>
      </Box>

      {/* Usage Metric Cards */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        {Object.entries(METRIC_CONFIG).map(([key, config]) => (
          <Grid item xs={12} sm={6} md={3} key={key}>
            <UsageMetricCard
              metric={key}
              current={metrics[key] || 0}
              limit={config.limitKey ? limits[config.limitKey] : null}
              config={config}
            />
          </Grid>
        ))}
      </Grid>

      {/* Limit warnings */}
      {Object.entries(METRIC_CONFIG).map(([key, config]) => {
        if (!config.limitKey) return null;
        const current = metrics[key] || 0;
        const limit = limits[config.limitKey];
        if (!limit) return null;
        const pct = (current / limit) * 100;
        if (pct >= 80 && pct < 100) {
          return (
            <Alert severity="warning" key={key} sx={{ mb: 1 }}>
              You&apos;ve used {pct.toFixed(0)}% of your monthly {config.label.toLowerCase()} ({current.toLocaleString()} / {limit.toLocaleString()}).
              Consider upgrading to avoid interruptions.
            </Alert>
          );
        }
        if (pct >= 100) {
          return (
            <Alert severity="error" key={key} sx={{ mb: 1 }}>
              Monthly {config.label.toLowerCase()} limit reached ({limit.toLocaleString()}).
              New requests will be rejected until next billing cycle.
            </Alert>
          );
        }
        return null;
      })}

      {/* Usage History */}
      {history?.history && Object.keys(history.history).length > 0 && (
        <Paper sx={{ p: 3, mt: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
            <TrendingUpIcon color="primary" />
            <Typography variant="h6" fontWeight="bold">
              Verification History (Last 6 Months)
            </Typography>
          </Box>
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Month</TableCell>
                  <TableCell align="right">Verifications</TableCell>
                  <TableCell align="right">% of Limit</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {Object.entries(history.history)
                  .sort(([a], [b]) => b.localeCompare(a))
                  .map(([month, count]) => (
                    <TableRow key={month}>
                      <TableCell>{month}</TableCell>
                      <TableCell align="right">{count.toLocaleString()}</TableCell>
                      <TableCell align="right">
                        {limits.verifications_per_month
                          ? `${((count / limits.verifications_per_month) * 100).toFixed(0)}%`
                          : 'Unlimited'}
                      </TableCell>
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}

      {/* Plan Details */}
      <Paper sx={{ p: 3, mt: 3 }}>
        <Typography variant="h6" fontWeight="bold" gutterBottom>
          Current Plan Details
        </Typography>
        <Divider sx={{ mb: 2 }} />
        <Grid container spacing={2}>
          <Grid item xs={6} md={3}>
            <Typography variant="caption" color="text.secondary">Plan</Typography>
            <Typography variant="body1" fontWeight="bold">{plan_name || plan}</Typography>
          </Grid>
          <Grid item xs={6} md={3}>
            <Typography variant="caption" color="text.secondary">Verifications/mo</Typography>
            <Typography variant="body1" fontWeight="bold">
              {limits.verifications_per_month?.toLocaleString() || 'Unlimited'}
            </Typography>
          </Grid>
          <Grid item xs={6} md={3}>
            <Typography variant="caption" color="text.secondary">Issued Credentials/mo</Typography>
            <Typography variant="body1" fontWeight="bold">
              {limits.issued_credentials_per_month?.toLocaleString() || 'Unlimited'}
            </Typography>
          </Grid>
          <Grid item xs={6} md={3}>
            <Typography variant="caption" color="text.secondary">Team Members</Typography>
            <Typography variant="body1" fontWeight="bold">
              {limits.members?.toLocaleString() || 'Unlimited'}
            </Typography>
          </Grid>
        </Grid>
      </Paper>
    </Box>
  );
}

export default UsageDashboard;
