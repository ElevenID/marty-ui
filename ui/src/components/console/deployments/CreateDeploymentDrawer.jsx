import ResourceCreateDrawer from '../../common/ResourceCreateDrawer';
import { createDeploymentProfile } from '../../../services/deploymentProfilesApi';
import { useNotifications } from '../../../hooks/useNotifications';
import { useTranslation } from 'react-i18next';

/**
 * CreateDeploymentDrawer - Quick deployment profile creation drawer
 * 
 * Provides a streamlined form for creating deployment profiles with essential fields.
 * Links to the full DeploymentProfileWizard for advanced configuration.
 */
function CreateDeploymentDrawer({ open, onClose, onSuccess }) {
  const { t } = useTranslation('console');
  const { showNotification } = useNotifications();

  const fields = [
    {
      name: 'name',
      label: t('createDeploymentDrawer.deploymentName'),
      type: 'text',
      required: true,
      placeholder: t('createDeploymentDrawer.deploymentNamePlaceholder'),
      helperText: t('createDeploymentDrawer.deploymentNameHelper'),
    },
    {
      name: 'environment',
      label: t('createDeploymentDrawer.environment'),
      type: 'select',
      required: true,
      options: [
        { value: 'development', label: t('createDeploymentDrawer.environments.development') },
        { value: 'staging', label: t('createDeploymentDrawer.environments.staging') },
        { value: 'production', label: t('createDeploymentDrawer.environments.production') },
      ],
      helperText: t('createDeploymentDrawer.environmentHelper'),
    },
    {
      name: 'description',
      label: t('createDeploymentDrawer.description'),
      type: 'textarea',
      required: false,
      placeholder: t('createDeploymentDrawer.descriptionPlaceholder'),
      helperText: t('createDeploymentDrawer.descriptionHelper'),
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
      message: t('createDeploymentDrawer.successMessage', { name: formData.name }),
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
      title={t('createDeploymentDrawer.title')}
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
