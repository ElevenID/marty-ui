/**
 * Org Page
 * 
 * Main Org section landing page.
 * Redirects to Organization Settings by default.
 */

import { Navigate } from 'react-router-dom';

function OrgPage() {
  return <Navigate to="/console/org/settings" replace />;
}

export default OrgPage;
