/**
 * Flows Page
 * 
 * Main Flows section landing page.
 * Redirects to Flow Definitions by default.
 */

import { Navigate } from 'react-router-dom';

function FlowsPage() {
  return <Navigate to="/console/flows/definitions" replace />;
}

export default FlowsPage;
