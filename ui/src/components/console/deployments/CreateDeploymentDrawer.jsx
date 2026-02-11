import ResourceCreateDrawer from '../../common/ResourceCreateDrawer';
import { createDeploymentProfile } from '../../../services/deploymentProfilesApi';
import { useNotifications } from '../../../hooks/useNotifications';

/**
 * CreateDeploymentDrawer - Quick deployment profile creation drawer
 * 
 * Provides a streamlined form for creating deployment profiles with essential fields.
 * Links to the full DeploymentProfileWizard for advanced configuration.
 */
function CreateDeploymentDrawer({ open, onClose, onSuccess }) {
  const { showNotification } = useNotifications();

  const fields = [
    {
      name: 'name',
      label: 'Deployment Name',
      type: 'text',
      required: true,
      placeholder: 'e.g., "Mobile App Production"',
      helperText: 'A descriptive name for this deployment',
    },
    {
      name: 'environment',
      label: 'Environment',
      type: 'select',
      required: true,
      options: [
        { value: 'development', label: 'Development' },
        { value: 'staging', label: 'Staging' },
        { value: 'production', label: 'Production' },
      ],
      helperText: 'Select the deployment environment',
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      required: false,
      placeholder: 'Describe this deployment...',
      helperText: 'Optional description for documentation',
      rows: 3,
    },
  ];

  const handleSubmit = async (formData) => {
    const payload = {
      name: formData.name,
      environment: formData.environment,
      description: formData.description || '',
      // Default values for quick creation
      api_endpoints: [],
      security_settings: {
        cors_origins: [],
      },
    };

    const result = await createDeploymentProfile(payload);

    showNotification({
      message: `Deployment "${formData.name}" created successfully`,
      severity: 'success',
    });

    if (onSuccess) {
      onSuccess(result);
    }
  };

  return (
    <ResourceCreateDrawer
      open={open}
      onClose={onClose}
      onSubmit={handleSubmit}
      title="Create Deployment Profile"
      resourceType="deployment"
      advancedPath="/console/deployments/new"
      fields={fields}
      initialData={{
        name: '',
        environment: 'development',
        description: '',
      }}
    />
  );
}

export default CreateDeploymentDrawer;
