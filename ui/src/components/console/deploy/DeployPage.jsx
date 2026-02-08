/**
 * Deploy Page
 * 
 * Main Deploy section landing page.
 * Redirects to Deployment Profiles by default.
 */

import { Navigate } from 'react-router-dom';

function DeployPage() {
  return <Navigate to="/console/deploy/profiles" replace />;
}

export default DeployPage;
