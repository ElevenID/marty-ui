import ResourceCreateDrawer from '../../common/ResourceCreateDrawer';
import { createFlow } from '../../../services/flowsApi';
import { useNotifications } from '../../../hooks/useNotifications';

/**
 * CreateFlowDrawer - Quick verification flow creation drawer
 * 
 * Provides a streamlined form for creating verification flows with essential fields.
 * Links to the full FlowDefinitionWizard for advanced configuration.
 */
function CreateFlowDrawer({ open, onClose, onSuccess }) {
  const { showNotification } = useNotifications();

  const fields = [
    {
      name: 'name',
      label: 'Flow Name',
      type: 'text',
      required: true,
      placeholder: 'e.g., "Employee Onboarding"',
      helperText: 'A descriptive name for this flow',
    },
    {
      name: 'flow_type',
      label: 'Flow Type',
      type: 'select',
      required: true,
      options: [
        { value: 'issuance', label: 'Credential Issuance' },
        { value: 'verification', label: 'Credential Verification' },
        { value: 'combined', label: 'Combined Flow' },
      ],
      helperText: 'Select the type of flow',
    },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      required: false,
      placeholder: 'Describe the purpose of this flow...',
      helperText: 'Optional description for documentation',
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
      message: `Flow "${formData.name}" created successfully`,
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
      title="Create Verification Flow"
      resourceType="flow"
      advancedPath="/console/flows/new"
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
