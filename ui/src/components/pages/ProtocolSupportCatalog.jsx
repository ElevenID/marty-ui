import { useEffect, useState } from 'react';
import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  CircularProgress,
  Grid,
  Link,
  Stack,
  Typography,
} from '@mui/material';
import { getProtocolSupportCatalog, PROTOCOL_SUPPORT_LEVELS, PROTOCOL_SUPPORT_PATH } from '../../services/protocolSupportApi';

const STATUS_PRESENTATION = {
  implemented: { label: 'Implemented', color: 'success' },
  derived: { label: 'Derived', color: 'info' },
  partial: { label: 'Partial', color: 'warning' },
  unsupported: { label: 'Unsupported', color: 'default' },
};

export default function ProtocolSupportCatalog() {
  const [catalog, setCatalog] = useState(null);
  const [error, setError] = useState(null);
  const [requestGeneration, setRequestGeneration] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let current = true;
    setError(null);
    getProtocolSupportCatalog({ signal: controller.signal })
      .then((value) => {
        if (current) setCatalog(value);
      })
      .catch((reason) => {
        if (current && reason?.name !== 'AbortError') {
          setCatalog(null);
          setError(reason instanceof Error ? reason.message : 'Protocol support catalog is unavailable.');
        }
      });
    return () => {
      current = false;
      controller.abort();
    };
  }, [requestGeneration]);

  if (error) {
    return (
      <Alert
        severity="error"
        action={<Button color="inherit" size="small" onClick={() => setRequestGeneration((value) => value + 1)}>Retry</Button>}
      >
        Support status could not be loaded: {error}
      </Alert>
    );
  }
  if (!catalog) {
    return <Box sx={{ display: 'flex', justifyContent: 'center', py: 4 }}><CircularProgress aria-label="Loading protocol support" /></Box>;
  }

  const counts = Object.fromEntries(PROTOCOL_SUPPORT_LEVELS.map((level) => [
    level,
    catalog.entities.filter((entity) => entity.support_level === level).length,
  ]));

  return (
    <Box data-testid="protocol-support-catalog">
      <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mb: 2 }}>
        {PROTOCOL_SUPPORT_LEVELS.map((level) => (
          <Chip
            key={level}
            color={STATUS_PRESENTATION[level].color}
            label={`${STATUS_PRESENTATION[level].label}: ${counts[level]}`}
            variant={level === 'unsupported' ? 'outlined' : 'filled'}
          />
        ))}
      </Stack>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        These labels describe product consumer surfaces. Qualification is shown separately and does not imply production release readiness.
      </Typography>
      <Typography variant="caption" color="text.secondary" display="block" sx={{ mb: 3 }}>
        Protocol pin <code>{catalog.protocol_revision}</code> ·{' '}
        <Link href={PROTOCOL_SUPPORT_PATH} target="_blank" rel="noopener noreferrer">machine-readable catalog</Link>
      </Typography>
      {PROTOCOL_SUPPORT_LEVELS.map((level) => (
        <Box key={level} sx={{ mb: 4 }}>
          <Typography variant="h5" component="h3" gutterBottom>{STATUS_PRESENTATION[level].label}</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            {catalog.support_levels[level]}
          </Typography>
          <Grid container spacing={2}>
            {catalog.entities.filter((entity) => entity.support_level === level).map((entity) => (
              <Grid item xs={12} md={6} key={entity.id}>
                <Card variant="outlined" sx={{ height: '100%' }}>
                  <CardContent>
                    <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                      <Typography variant="h6" component="h4">{entity.display_name}</Typography>
                      <Chip size="small" label={entity.kind} variant="outlined" />
                    </Stack>
                    <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
                      Qualification: {entity.qualification.replaceAll('_', ' ')}
                    </Typography>
                    {entity.api_paths.length > 0 && (
                      <Typography variant="body2" sx={{ mb: 0.5 }}>
                        API: <code>{entity.api_paths[0]}</code>{entity.api_paths.length > 1 ? ` +${entity.api_paths.length - 1}` : ''}
                      </Typography>
                    )}
                    {entity.ui_paths.length > 0 && (
                      <Typography variant="body2" sx={{ mb: 0.5 }}>
                        UI: <code>{entity.ui_paths[0]}</code>{entity.ui_paths.length > 1 ? ` +${entity.ui_paths.length - 1}` : ''}
                      </Typography>
                    )}
                    {entity.limitations.map((limitation) => (
                      <Typography key={limitation} variant="body2" color="text.secondary" sx={{ mt: 1 }}>
                        {limitation}
                      </Typography>
                    ))}
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </Box>
      ))}
    </Box>
  );
}
