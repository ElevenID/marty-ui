import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@test/utils';

import FlowPublishDialog from '../vendor/FlowPublishDialog';
import FlowDisableDialog from '../vendor/FlowDisableDialog';

const { mockPublishFlow, mockDisableFlow } = vi.hoisted(() => ({
  mockPublishFlow: vi.fn(),
  mockDisableFlow: vi.fn(),
}));

vi.mock('react-i18next', () => ({
  useTranslation: () => ({
    t: (key: string) => key,
  }),
}));

vi.mock('../../services/flowsApi', () => ({
  default: {
    publishFlow: mockPublishFlow,
    disableFlow: mockDisableFlow,
  },
}));

describe('Flow dialogs', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: {
        ...window.location,
        origin: 'https://example.test',
      },
    });
  });

  it('publishes a flow and shows the generated url', async () => {
    mockPublishFlow.mockResolvedValue({ id: 'flow-1', name: 'Employee Flow' });
    const onPublished = vi.fn();
    const onClose = vi.fn();
    const { user } = render(
      <FlowPublishDialog
        open
        onClose={onClose}
        flow={{ id: 'flow-1', name: 'Employee Flow', flow_type: 'issuance' }}
        onPublished={onPublished}
      />
    );

    await user.type(screen.getByLabelText('flowPublishDialog.changeDescriptionLabel'), 'Release candidate');
    await user.click(screen.getByRole('button', { name: 'flowPublishDialog.publishButton' }));

    await waitFor(() => {
      expect(mockPublishFlow).toHaveBeenCalledWith('flow-1', {
        change_description: 'Release candidate',
      });
      expect(onPublished).toHaveBeenCalledWith({ id: 'flow-1', name: 'Employee Flow' });
      expect(screen.getByDisplayValue('https://example.test/apply/flow-1')).toBeInTheDocument();
    });

  });

  it('validates reason and disables a flow', async () => {
    mockDisableFlow.mockResolvedValue({ id: 'flow-1', status: 'disabled' });
    const onDisabled = vi.fn();
    const onClose = vi.fn();
    const { user } = render(
      <FlowDisableDialog
        open
        onClose={onClose}
        flow={{ id: 'flow-1', name: 'Employee Flow', status: 'published' }}
        onDisabled={onDisabled}
      />
    );

    await user.click(screen.getByRole('button', { name: 'flowDisableDialog.disableButton' }));

    await waitFor(() => {
      expect(screen.getByText('flowDisableDialog.reasonError')).toBeInTheDocument();
    });

    await user.type(screen.getByRole('textbox', { name: 'flowDisableDialog.reasonLabel' }), 'Security incident');
    await user.click(screen.getByRole('button', { name: 'flowDisableDialog.disableButton' }));

    await waitFor(() => {
      expect(mockDisableFlow).toHaveBeenCalledWith('flow-1', {
        reason: 'Security incident',
      });
      expect(onDisabled).toHaveBeenCalledWith({ id: 'flow-1', status: 'disabled' });
      expect(onClose).toHaveBeenCalled();
    });
  });
});
