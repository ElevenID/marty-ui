import ResourceCreateDrawer from '../../common/ResourceCreateDrawer';
import { createPresentationPolicy } from '../../../services/presentationPolicyApi';
import { useNotifications } from '../../../hooks/useNotifications';

/**
 * CreatePolicyDrawer - Quick presentation policy creation drawer
 * 
 * Provides a streamlined form for creating presentation policies with essential fields.
 * Links to the full PresentationPolicyWizard for advanced configuration.
 */
function CreatePolicyDrawer({ open, onClose, onSuccess }) {
  const { showNotification } = useNotifications();

  const fields = [
    {
      name: 'name',
      label: 'Policy Name',
      type: 'text',
      required: true,
      placeholder: 'e.g., "Age Verification"',
      helperText: 'A descriptive name for this policy',
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      required: false,
      placeholder: 'Describe what this policy verifies...',
      helperText: 'Optional description for documentation',
      rows: 3,
    },
    {
      name: 'required_credentials',
      label: 'Required Credentials',
      type: 'text',
      required: false,
      placeholder: 'e.g., "DriverLicense,GovernmentID"',
      helperText: 'Comma-separated list of credential types',
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
      message: `Policy "${formData.name}" created successfully`,
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
      title="Create Presentation Policy"
      resourceType="policy"
      advancedPath="/console/policies/new"
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
