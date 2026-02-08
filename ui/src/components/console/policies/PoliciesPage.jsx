/**
 * Policies Page
 * 
 * Main Policies section landing page.
 * Redirects to Presentation Policies by default.
 */

import { Navigate } from 'react-router-dom';

function PoliciesPage() {
  return <Navigate to="/console/policies/presentation" replace />;
}

export default PoliciesPage;
