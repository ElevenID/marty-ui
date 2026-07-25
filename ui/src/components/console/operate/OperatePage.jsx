/**
 * Operate Page
 * 
 * Main Operate section landing page.
 * Redirects to Issuance by default.
 */

import { Navigate } from 'react-router';

function OperatePage() {
  return <Navigate to="/console/org/operate/issuance" replace />;
}

export default OperatePage;
