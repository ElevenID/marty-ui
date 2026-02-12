import ResourceCreateDrawer from '../../common/ResourceCreateDrawer';
import { createTrustProfile } from '../../../services/presentationPolicyApi';
import { useNotifications } from '../../../hooks/useNotifications';
import { useTranslation } from 'react-i18next';

/**
 * CreateTrustProfileDrawer - Quick trust profile creation drawer
 * 
 * Provides a streamlined form for creating trust profiles with essential fields.
 * Links to the full TrustProfileWizard for advanced configuration.
 */
function CreateTrustProfileDrawer({ open, onClose, onSuccess }) {
  const { t } = useTranslation('console');
  const { showNotification } = useNotifications();

  const fields = [
    {
      name: 'name',
      label: t('trust.createTrustProfileDrawer.profileName'),
      type: 'text',
      required: true,
      placeholder: t('trust.createTrustProfileDrawer.profileNamePlaceholder'),
      helperText: t('trust.createTrustProfileDrawer.profileNameHelper'),
    },
    {
      name: 'description',
      label: t('trust.createTrustProfileDrawer.description'),
      type: 'textarea',
      required: false,
      placeholder: t('trust.createTrustProfileDrawer.descriptionPlaceholder'),
      helperText: t('trust.createTrustProfileDrawer.descriptionHelper'),
      rows: 3,
    },
    {
      name: 'required_credential_types',
      label: t('trust.createTrustProfileDrawer.requiredCredentialTypes'),
      type: 'text',
      required: false,
      placeholder: t('trust.createTrustProfileDrawer.requiredCredentialTypesPlaceholder'),
      helperText: t('trust.createTrustProfileDrawer.requiredCredentialTypesHelper'),
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
      message: t('trust.createTrustProfileDrawer.successMessage', { name: formData.name }),
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
      title={t('trust.createTrustProfileDrawer.title')}
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
