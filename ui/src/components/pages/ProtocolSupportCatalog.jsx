import ProtocolSupportCatalogView from './ProtocolSupportCatalogView';
import { useEffect, useState } from 'react';
import { Alert, Box, Button, CircularProgress } from '@mui/material';
import { getProtocolSupportCatalog } from '../../services/protocolSupportApi';

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

  return <ProtocolSupportCatalogView catalog={catalog} />;
}
