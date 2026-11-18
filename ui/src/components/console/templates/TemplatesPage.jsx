/**
 * Templates Page
 * 
 * Main Templates section landing page.
 * Redirects to Credential Templates by default.
 */

import { Navigate } from 'react-router';

function TemplatesPage() {
  return <Navigate to="/console/org/templates/credentials" replace />;
}

export default TemplatesPage;
