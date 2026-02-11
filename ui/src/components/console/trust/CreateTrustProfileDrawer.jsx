import ResourceCreateDrawer from '../../common/ResourceCreateDrawer';
import { createTrustProfile } from '../../../services/presentationPolicyApi';
import { useNotifications } from '../../../hooks/useNotifications';

/**
 * CreateTrustProfileDrawer - Quick trust profile creation drawer
 * 
 * Provides a streamlined form for creating trust profiles with essential fields.
 * Links to the full TrustProfileWizard for advanced configuration.
 */
function CreateTrustProfileDrawer({ open, onClose, onSuccess }) {
  const { showNotification } = useNotifications();

  const fields = [
    {
      name: 'name',
      label: 'Profile Name',
      type: 'text',
      required: true,
      placeholder: 'e.g., "Government ID Verification"',
      helperText: 'A descriptive name for this trust profile',
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      required: false,
      placeholder: 'Describe the purpose of this trust profile...',
      helperText: 'Optional description for documentation',
      rows: 3,
    },
    {
      name: 'required_credential_types',
      label: 'Required Credential Types',
      type: 'text',
      required: false,
      placeholder: 'e.g., "VerifiableCredential,GovernmentIDCredential"',
      helperText: 'Comma-separated list of required credential types',
    },
  ];

  const handleSubmit = async (formData) => {
    // Parse comma-separated credential types
    const credentialTypes = formData.required_credential_types
      ? formData.required_credential_types.split(',').map((t) => t.trim()).filter(Boolean)
      : [];

    const payload = {
      name: formData.name,
      description: formData.description || '',
      required_credential_types: credentialTypes,
      // Default values for quick creation
      trust_anchors: [],
      revocation_check_enabled: true,
      signature_validation_required: true,
    };

    const result = await createTrustProfile(payload);

    showNotification({
      message: `Trust profile "${formData.name}" created successfully`,
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
      title="Create Trust Profile"
      resourceType="trust-profile"
      advancedPath="/console/trust/new"
      fields={fields}
      initialData={{
        name: '',
        description: '',
        required_credential_types: '',
      }}
    />
  );
}

export default CreateTrustProfileDrawer;
