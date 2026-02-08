/**
 * EmptyState Component
 * 
 * Reusable empty state for list pages. Answers:
 * - "Why is this empty?"
 * - "What should I do next?"
 */

import { Box, Typography, Button, Paper } from '@mui/material';
import InboxIcon from '@mui/icons-material/Inbox';
import { Link } from 'react-router-dom';

/**
 * @param {Object} props
 * @param {React.ReactNode} [props.icon] - Icon to display (default: InboxIcon)
 * @param {string} props.title - Main message (e.g., "No templates yet")
 * @param {string} props.description - Explanation of why empty and what to do
 * @param {string} [props.actionLabel] - CTA button label
 * @param {string} [props.actionPath] - CTA button link path
 * @param {Function} [props.onAction] - CTA button click handler (alternative to path)
 * @param {string} [props.secondaryActionLabel] - Secondary action label
 * @param {string} [props.secondaryActionPath] - Secondary action path
 * @param {boolean} [props.isFiltered] - True if filters are applied (shows different message)
 */
function EmptyState({
  icon,
  title,
  description,
  actionLabel,
  actionPath,
  onAction,
  secondaryActionLabel,
  secondaryActionPath,
  isFiltered = false,
}) {
  const IconComponent = icon || InboxIcon;
  
  // Filtered state shows a simpler message
  if (isFiltered) {
    return (
      <Box 
        sx={{ 
          py: 6, 
          px: 3,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          textAlign: 'center',
        }}
      >
        <Typography color="text.secondary">
          No results match your filters. Try adjusting your search criteria.
        </Typography>
      </Box>
    );
  }

  return (
    <Paper 
      variant="outlined"
      sx={{ 
        py: 8, 
        px: 4,
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        textAlign: 'center',
        bgcolor: 'background.default',
        borderStyle: 'dashed',
      }}
    >
      <Box 
        sx={{ 
          width: 64, 
          height: 64, 
          borderRadius: '50%',
          bgcolor: 'action.hover',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          mb: 2,
        }}
      >
        {typeof IconComponent === 'function' ? (
          <IconComponent sx={{ fontSize: 32, color: 'text.secondary' }} />
        ) : (
          IconComponent
        )}
      </Box>
      
      <Typography variant="h6" gutterBottom>
        {title}
      </Typography>
      
      <Typography 
        color="text.secondary" 
        sx={{ mb: 3, maxWidth: 400 }}
      >
        {description}
      </Typography>
      
      <Box sx={{ display: 'flex', gap: 2 }}>
        {actionLabel && (actionPath || onAction) && (
          <Button
            variant="contained"
            {...(actionPath ? { component: Link, to: actionPath } : { onClick: onAction })}
          >
            {actionLabel}
          </Button>
        )}
        
        {secondaryActionLabel && secondaryActionPath && (
          <Button
            variant="outlined"
            component={Link}
            to={secondaryActionPath}
          >
            {secondaryActionLabel}
          </Button>
        )}
      </Box>
    </Paper>
  );
}

/**
 * Preset empty states for common resources
 */
export const EmptyStates = {
  templates: {
    title: 'No credential templates yet',
    description: 'Templates define the schema and format for credentials you can issue. Create your first template to start issuing credentials.',
    actionLabel: 'Create Template',
    actionPath: '/console/templates/credentials/new',
  },
  applicationTemplates: {
    title: 'No application templates yet',
    description: 'Application templates define the forms applicants fill out when requesting credentials. Create a template to collect applicant information.',
    actionLabel: 'Create Application Template',
    actionPath: '/console/templates/applications/new',
  },
  policies: {
    title: 'No presentation policies yet',
    description: 'Policies define what credentials and claims are required when verifying credentials. Create a policy to start verification flows.',
    actionLabel: 'Create Policy',
    actionPath: '/console/policies/presentation/new',
  },
  trustProfiles: {
    title: 'No trust profiles configured',
    description: 'Trust profiles define which credential formats, issuers, and validation rules to accept. Configure a profile to establish trust.',
    actionLabel: 'Create Trust Profile',
    actionPath: '/console/trust/profiles/new',
  },
  trustedIssuers: {
    title: 'No trusted issuers added',
    description: 'Trusted issuers are organizations whose credentials you accept. Add issuers manually or import from a trust registry.',
    actionLabel: 'Add Issuer',
    actionPath: '/console/trust/issuers/new',
  },
  flows: {
    title: 'No flow definitions yet',
    description: 'Flows orchestrate verification or issuance workflows. Create a flow to guide users through credential processes.',
    actionLabel: 'Create Flow',
    actionPath: '/console/flows/definitions/new',
  },
  flowInstances: {
    title: 'No flow instances yet',
    description: 'Flow instances are created when users start a verification or issuance flow. Once your flows are active and being used, instances will appear here.',
    actionLabel: 'View Flow Definitions',
    actionPath: '/console/flows/definitions',
  },
  applications: {
    title: 'No applications received',
    description: 'Applications appear here when users submit credential requests through your application templates. Share your application links to start receiving applications.',
    actionLabel: 'Manage Application Templates',
    actionPath: '/console/templates/applications',
  },
  issuance: {
    title: 'No credentials issued yet',
    description: 'Issued credentials will appear here. To issue credentials, create a credential template and approve an application.',
    actionLabel: 'View Credential Templates',
    actionPath: '/console/templates/credentials',
  },
  webhooks: {
    title: 'No webhooks configured',
    description: 'Webhooks notify your systems when events occur. Configure webhooks to integrate with your backend services.',
    actionLabel: 'Add Webhook',
    actionPath: '/console/deploy/webhooks/new',
  },
  apiKeys: {
    title: 'No API keys created',
    description: 'API keys authenticate programmatic access to your organization. Create a key to integrate with your applications.',
    actionLabel: 'Create API Key',
    actionPath: '/console/org/api-keys/new',
  },
  deploymentProfiles: {
    title: 'No deployment profiles yet',
    description: 'Deployment profiles configure how your APIs, kiosks, lanes, and devices integrate with credential flows—supporting both online and offline environments.',
    actionLabel: 'Create Profile',
    actionPath: '/console/deploy/profiles/new',
  },
  auditLogs: {
    title: 'No audit events yet',
    description: 'Audit logs track security-relevant events in your organization. Events will appear as users interact with your system.',
  },
};

export default EmptyState;
