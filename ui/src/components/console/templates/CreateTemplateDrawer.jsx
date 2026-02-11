import ResourceCreateDrawer from '../../common/ResourceCreateDrawer';
import { createCredentialTemplate } from '../../../services/presentationPolicyApi';
import { useNotifications } from '../../../hooks/useNotifications';

/**
 * CreateTemplateDrawer - Quick credential template creation drawer
 * 
 * Provides a streamlined form for creating credential templates with essential fields.
 * Links to the full CredentialTemplateWizard for advanced configuration.
 */
function CreateTemplateDrawer({ open, onClose, onSuccess }) {
  const { showNotification } = useNotifications();

  const fields = [
    {
      name: 'name',
      label: 'Template Name',
      type: 'text',
      required: true,
      placeholder: 'e.g., "Employee Badge"',
      helperText: 'A descriptive name for this template',
    },
    {
      name: 'credential_type',
      label: 'Credential Type',
      type: 'text',
      required: true,
      placeholder: 'e.g., "EmployeeBadgeCredential"',
      helperText: 'The type identifier for this credential',
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      required: false,
      placeholder: 'Describe the purpose of this template...',
      helperText: 'Optional description for documentation',
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
      message: `Template "${formData.name}" created successfully`,
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
      title="Create Credential Template"
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
