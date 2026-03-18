import React from 'react';
import {
  Container,
  Paper,
  Typography,
  Box,
  Grid,
  Card,
  CardContent,
  LinearProgress,
  Divider
} from '@mui/material';
import {
  Timeline as TimelineIcon,
  Memory as MemoryIcon,
  Storage as StorageIcon,
  Speed as SpeedIcon
} from '@mui/icons-material';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  AreaChart,
  Area
} from 'recharts';
import {
  METRICS_VIEWER_CHART_FALLBACK,
  METRICS_VIEWER_DEFAULT_METRICS,
  getMetricsViewerRequestRateProgress,
  loadAdminMetrics,
} from '../application/admin';

const MetricsViewer = () => {
  const [metrics, setMetrics] = React.useState(METRICS_VIEWER_DEFAULT_METRICS);

  React.useEffect(() => {
    const fetchMetrics = async () => {
      const result = await loadAdminMetrics();
      setMetrics(result);
    };

    fetchMetrics();
    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <Container maxWidth="lg">
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" gutterBottom>
          <TimelineIcon sx={{ mr: 2, verticalAlign: 'middle' }} />
          System Metrics
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Performance Monitoring and Analytics
        </Typography>
      </Box>

      <Grid container spacing={3}>
        {/* Resource Usage Cards */}
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <MemoryIcon color="primary" sx={{ mr: 1 }} />
                <Typography variant="h6">CPU Usage</Typography>
              </Box>
              <Typography variant="h4" gutterBottom>{metrics.cpu_usage}%</Typography>
              <LinearProgress variant="determinate" value={metrics.cpu_usage} />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <StorageIcon color="secondary" sx={{ mr: 1 }} />
                <Typography variant="h6">Memory Usage</Typography>
              </Box>
              <Typography variant="h4" gutterBottom>{metrics.memory_usage}%</Typography>
              <LinearProgress variant="determinate" color="secondary" value={metrics.memory_usage} />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={4}>
          <Card>
            <CardContent>
              <Box display="flex" alignItems="center" mb={1}>
                <SpeedIcon color="success" sx={{ mr: 1 }} />
                <Typography variant="h6">Request Rate</Typography>
              </Box>
              <Typography variant="h4" gutterBottom>{metrics.request_rate} req/s</Typography>
              <LinearProgress
                variant="determinate"
                color="success"
                value={getMetricsViewerRequestRateProgress(metrics.request_rate)}
              />
            </CardContent>
          </Card>
        </Grid>

        {/* Charts */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Transaction Volume (24h)
            </Typography>
            <Divider sx={{ mb: 3 }} />
            <Box sx={{ height: 300 }}>
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={metrics.transaction_volume}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Area type="monotone" dataKey="issuance" stackId="1" stroke="#8884d8" fill="#8884d8" />
                  <Area type="monotone" dataKey="verification" stackId="1" stroke="#82ca9d" fill="#82ca9d" />
                </AreaChart>
              </ResponsiveContainer>
            </Box>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Latency (ms)
            </Typography>
            <Divider sx={{ mb: 3 }} />
            <Box sx={{ height: 250 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={METRICS_VIEWER_CHART_FALLBACK}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Line type="monotone" dataKey="issuance" stroke="#ff7300" name="Avg Latency" />
                </LineChart>
              </ResponsiveContainer>
            </Box>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Error Rate
            </Typography>
            <Divider sx={{ mb: 3 }} />
            <Box sx={{ height: 250 }}>
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={METRICS_VIEWER_CHART_FALLBACK}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Line type="monotone" dataKey="verification" stroke="#d32f2f" name="Errors" />
                </LineChart>
              </ResponsiveContainer>
            </Box>
          </Paper>
        </Grid>
      </Grid>
    </Container>
  );
};

export default MetricsViewer;
