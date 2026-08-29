import { describe, expect, it } from 'vitest';
import { screen } from '@testing-library/react';
import { render } from '../test/utils';
import { NotificationProvider, useNotification } from './NotificationContext';

function LifecycleNotifications() {
  const { showInfo } = useNotification();

  return (
    <button
      type="button"
      onClick={() => {
        showInfo('Lifecycle state: Suspended', { replaceKey: 'credential-lifecycle' });
        showInfo('Lifecycle state: Active', { replaceKey: 'credential-lifecycle' });
      }}
    >
      Update lifecycle
    </button>
  );
}

describe('NotificationProvider', () => {
  it('keeps one current transient notification for a replace key', async () => {
    const { user } = render(
      <NotificationProvider>
        <LifecycleNotifications />
      </NotificationProvider>,
    );

    await user.click(screen.getByRole('button', { name: 'Update lifecycle' }));

    expect(screen.getByText('Lifecycle state: Active')).toBeInTheDocument();
    expect(screen.queryByText('Lifecycle state: Suspended')).not.toBeInTheDocument();
  });
});
