import ResourceCreateDrawer from '../../common/ResourceCreateDrawer';
import { addTrustProfileIssuer, createTrustProfile } from '../../../services/presentationPolicyApi';
import { useNotifications } from '../../../hooks/useNotifications';
import { useAuth } from '../../../hooks/useAuth';
import { useConsole } from '../../../contexts/ConsoleContext';
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
  const { organizationId: authOrganizationId } = useAuth();
  const { activeOrgId } = useConsole();
  const organizationId = activeOrgId;

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
      name: 'issuer_did',
      label: t('trust.createTrustProfileDrawer.issuerDid', { defaultValue: 'Trusted issuer DID' }),
      type: 'text',
      required: true,
      placeholder: t('trust.createTrustProfileDrawer.issuerDidPlaceholder', { defaultValue: 'did:web:issuer.example.com' }),
      helperText: t('trust.createTrustProfileDrawer.issuerDidHelper', { defaultValue: 'Provide one issuer DID to create a protocol-valid trust profile.' }),
    },
  ];

  const handleSubmit = async (formData) => {
    if (!organizationId) {
      throw new Error(t('trust.failedToLoad', { defaultValue: 'Organization context is required to create a trust profile.' }));
    }

    const payload = {
      organization_id: organizationId,
      name: formData.name,
      description: formData.description || '',
      supported_formats: ['sd_jwt_vc', 'mdoc'],
      trusted_issuers: [{
        did: formData.issuer_did,
        name: formData.issuer_did,
      }],
    };

    const result = await createTrustProfile(payload);
    await addTrustProfileIssuer(result.id, {
      name: formData.issuer_did,
      issuer_did: formData.issuer_did,
    });

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
      advancedPath="/console/org/trust/profiles/new"
      fields={fields}
      initialData={{
        name: '',
        description: '',
        issuer_did: '',
      }}
    />
  );
}

export default CreateTrustProfileDrawer;
