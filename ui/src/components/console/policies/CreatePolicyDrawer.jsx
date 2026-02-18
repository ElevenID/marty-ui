import ResourceCreateDrawer from '../../common/ResourceCreateDrawer';
import { createPresentationPolicy } from '../../../services/presentationPolicyApi';
import { useNotifications } from '../../../hooks/useNotifications';
import { useTranslation } from 'react-i18next';

/**
 * CreatePolicyDrawer - Quick presentation policy creation drawer
 * 
 * Provides a streamlined form for creating presentation policies with essential fields.
 * Links to the full PresentationPolicyWizard for advanced configuration.
 */
function CreatePolicyDrawer({ open, onClose, onSuccess }) {
  const { t } = useTranslation('console');
  const { showNotification } = useNotifications();

  const fields = [
    {
      name: 'name',
      label: t('createPolicyDrawer.policyName'),
      type: 'text',
      required: true,
      placeholder: t('createPolicyDrawer.policyNamePlaceholder'),
      helperText: t('createPolicyDrawer.policyNameHelper'),
    },
    {
      name: 'description',
      label: t('createPolicyDrawer.description'),
      type: 'textarea',
      required: false,
      placeholder: t('createPolicyDrawer.descriptionPlaceholder'),
      helperText: t('createPolicyDrawer.descriptionHelper'),
      rows: 3,
    },
    {
      name: 'required_credentials',
      label: t('createPolicyDrawer.requiredCredentials'),
      type: 'text',
      required: false,
      placeholder: t('createPolicyDrawer.requiredCredentialsPlaceholder'),
      helperText: t('createPolicyDrawer.requiredCredentialsHelper'),
    },
  ];

  const handleSubmit = async (formData) => {
    // Parse comma-separated credential types
    const credentialTypes = formData.required_credentials
      ? formData.required_credentials.split(',').map((t) => t.trim()).filter(Boolean)
      : [];

    const payload = {
      name: formData.name,
      description: formData.description || '',
      required_credentials: credentialTypes,
      // Default values for quick creation
      rules: [],
      purpose: formData.description || 'Credential verification',
    };

    const result = await createPresentationPolicy(payload);

    showNotification({
      message: t('createPolicyDrawer.successMessage', { name: formData.name }),
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
      title={t('createPolicyDrawer.title')}
      resourceType="policy"
      advancedPath="/console/org/policies/new"
      fields={fields}
      initialData={{
        name: '',
        description: '',
        required_credentials: '',
      }}
    />
  );
}

export default CreatePolicyDrawer;
