/**
 * Trust Page
 * 
 * Main Trust section landing page.
 * Redirects to Trust Profiles by default.
 */

import { Navigate } from 'react-router';

function TrustPage() {
  return <Navigate to="/console/org/trust/profiles" replace />;
}

export default TrustPage;
