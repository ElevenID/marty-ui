import { Alert } from '@mui/material';
import snapshot from '../../../../contracts/protocol-support-catalog.json';
import { normalizeProtocolSupportCatalog } from '../../application/protocolSupportCatalog';
import ProtocolSupportCatalogView from './ProtocolSupportCatalogView';

const catalog = normalizeProtocolSupportCatalog(snapshot);
export default function MarketingProtocolSupportCatalog() {
  return <>
    <Alert severity="info" sx={{ mb: 2 }}>
      This is the product support snapshot included with this website. Check your deployment's live catalog before integrating.
    </Alert>
    <ProtocolSupportCatalogView catalog={catalog} />
  </>;
}
