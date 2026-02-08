/**
 * Trust Page
 * 
 * Main Trust section landing page.
 * Redirects to Trust Profiles by default.
 */

import { Navigate } from 'react-router-dom';

function TrustPage() {
  return <Navigate to="/console/trust/profiles" replace />;
}

export default TrustPage;
