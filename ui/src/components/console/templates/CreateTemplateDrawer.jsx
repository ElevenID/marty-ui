import ResourceCreateDrawer from '../../common/ResourceCreateDrawer';
import { createCredentialTemplate } from '../../../services/presentationPolicyApi';
import { useNotifications } from '../../../hooks/useNotifications';
import { useTranslation } from 'react-i18next';

/**
 * CreateTemplateDrawer - Quick credential template creation drawer
 * 
 * Provides a streamlined form for creating credential templates with essential fields.
 * Links to the full CredentialTemplateWizard for advanced configuration.
 */
function CreateTemplateDrawer({ open, onClose, onSuccess }) {
  const { t } = useTranslation('console');
  const { showNotification } = useNotifications();

  const fields = [
    {
      name: 'name',
      label: t('createTemplateDrawer.templateName'),
      type: 'text',
      required: true,
      placeholder: t('createTemplateDrawer.templateNamePlaceholder'),
      helperText: t('createTemplateDrawer.templateNameHelper'),
    },
    {
      name: 'credential_type',
      label: t('createTemplateDrawer.credentialType'),
      type: 'text',
      required: true,
      placeholder: t('createTemplateDrawer.credentialTypePlaceholder'),
      helperText: t('createTemplateDrawer.credentialTypeHelper'),
    },
    {
      name: 'description',
      label: t('createTemplateDrawer.description'),
      type: 'textarea',
      required: false,
      placeholder: t('createTemplateDrawer.descriptionPlaceholder'),
      helperText: t('createTemplateDrawer.descriptionHelper'),
      rows: 3,
    },
  ];

  const handleSubmit = async (formData) => {
    const payload = {
      name: formData.name,
      credential_type: formData.credential_type,
      description: formData.description || '',
      // Default values for quick creation
      schema: {
        type: 'object',
        properties: {},
        required: [],
      },
      appearance: {
        background_color: '#1976d2',
      },
    };

    const result = await createCredentialTemplate(payload);

    showNotification({
      message: t('createTemplateDrawer.successMessage', { name: formData.name }),
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
      title={t('createTemplateDrawer.title')}
      resourceType="template"
      advancedPath="/console/templates/new"
      fields={fields}
      initialData={{
        name: '',
        credential_type: '',
        description: '',
      }}
    />
  );
}

export default CreateTemplateDrawer;
