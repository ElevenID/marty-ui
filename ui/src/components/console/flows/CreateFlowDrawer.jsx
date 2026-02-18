import ResourceCreateDrawer from '../../common/ResourceCreateDrawer';
import { createFlow } from '../../../services/flowsApi';
import { useNotifications } from '../../../hooks/useNotifications';
import { useTranslation } from 'react-i18next';

/**
 * CreateFlowDrawer - Quick verification flow creation drawer
 * 
 * Provides a streamlined form for creating verification flows with essential fields.
 * Links to the full FlowDefinitionWizard for advanced configuration.
 */
function CreateFlowDrawer({ open, onClose, onSuccess }) {
  const { t } = useTranslation('console');
  const { showNotification } = useNotifications();

  const fields = [
    {
      name: 'name',
      label: t('createFlowDrawer.flowName'),
      type: 'text',
      required: true,
      placeholder: t('createFlowDrawer.flowNamePlaceholder'),
      helperText: t('createFlowDrawer.flowNameHelper'),
    },
    {
      name: 'flow_type',
      label: t('createFlowDrawer.flowType'),
      type: 'select',
      required: true,
      options: [
        { value: 'issuance', label: t('createFlowDrawer.flowTypes.issuance') },
        { value: 'verification', label: t('createFlowDrawer.flowTypes.verification') },
        { value: 'combined', label: t('createFlowDrawer.flowTypes.combined') },
      ],
      helperText: t('createFlowDrawer.flowTypeHelper'),
    },
    {
      name: 'description',
      label: t('createFlowDrawer.description'),
      type: 'textarea',
      required: false,
      placeholder: t('createFlowDrawer.descriptionPlaceholder'),
      helperText: t('createFlowDrawer.descriptionHelper'),
      rows: 3,
    },
  ];

  const handleSubmit = async (formData) => {
    const payload = {
      name: formData.name,
      flow_type: formData.flow_type,
      description: formData.description || '',
      // Default values for quick creation
      steps: [],
      configuration: {},
    };

    const result = await createFlow(payload);

    showNotification({
      message: t('createFlowDrawer.successMessage', { name: formData.name }),
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
      title={t('createFlowDrawer.title')}
      resourceType="flow"
      advancedPath="/console/org/flows/new"
      fields={fields}
      initialData={{
        name: '',
        flow_type: 'issuance',
        description: '',
      }}
    />
  );
}

export default CreateFlowDrawer;
