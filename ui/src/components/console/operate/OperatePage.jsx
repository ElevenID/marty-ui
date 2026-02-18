/**
 * Operate Page
 * 
 * Main Operate section landing page.
 * Redirects to Issuance by default.
 */

import { Navigate } from 'react-router-dom';

function OperatePage() {
  return <Navigate to="/console/org/operate/issuance" replace />;
}

export default OperatePage;
