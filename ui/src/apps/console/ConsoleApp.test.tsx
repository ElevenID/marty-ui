import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@test/utils';

import ConsoleApp from './ConsoleApp';

const { mockAppShell } = vi.hoisted(() => ({
  mockAppShell: vi.fn(),
}));

vi.mock('../shared/AppProviders', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div data-testid="app-providers">{children}</div>,
}));

vi.mock('../shared/AppShell', () => ({
  default: ({ children, showAppBar = true }: { children: React.ReactNode, showAppBar?: boolean }) => {
    mockAppShell({ showAppBar });
    return (
      <div data-testid="app-shell" data-show-app-bar={String(showAppBar)}>
        {children}
      </div>
    );
  },
}));

vi.mock('./ConsoleRoutes', () => ({
  default: () => <div data-testid="console-routes">Console routes</div>,
}));

describe('ConsoleApp', () => {
  it('disables the shared AppShell app bar for console routes', () => {
    render(<ConsoleApp />);

    expect(screen.getByTestId('app-providers')).toBeInTheDocument();
    expect(screen.getByTestId('app-shell')).toHaveAttribute('data-show-app-bar', 'false');
    expect(screen.getByTestId('console-routes')).toBeInTheDocument();
    expect(mockAppShell).toHaveBeenCalledWith({ showAppBar: false });
  });
});