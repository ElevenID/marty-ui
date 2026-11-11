import { describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { render, screen, waitFor } from '@test/utils';
import { server } from '@test/mocks/server';
import CheckConfigurationDialog from './CheckConfigurationDialog';

function captureCheckSave() {
  const requests: unknown[] = [];
  server.use(http.patch('*/v1/application-templates/application-template-1', async ({ request }) => {
    const body = await request.json();
    requests.push(body);
    return HttpResponse.json({ id: 'application-template-1', ...body as object });
  }));
  return requests;
}

describe('CheckConfigurationDialog', () => {
  it('saves newly added checks in one-based displayed order', async () => {
    const requests = captureCheckSave();
    const onSaved = vi.fn();
    const onClose = vi.fn();
    const { user } = render(<CheckConfigurationDialog open template={{
      id: 'application-template-1', name: 'Membership', required_checks: [],
    }} onSaved={onSaved} onClose={onClose} />);

    await user.click(screen.getByRole('button', { name: 'Add check' }));
    await user.click(screen.getByRole('button', { name: 'Add check' }));
    await user.click(screen.getAllByRole('combobox')[1]);
    await user.click(screen.getByRole('option', { name: 'Employment Verification' }));
    await user.click(screen.getByRole('button', { name: 'Save checks' }));

    const required_checks = [
      { check_type: 'identity_verification', is_required: true, order: 1 },
      { check_type: 'employment_verification', is_required: true, order: 2 },
    ];
    await waitFor(() => expect(requests).toEqual([{ required_checks }]));
    expect(onSaved).toHaveBeenCalledWith({ id: 'application-template-1', required_checks });
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it('keeps retained settings and one-based order after removing and adding checks', async () => {
    const requests = captureCheckSave();
    const retained = {
      check_type: 'employment_verification', is_required: false, order: 2,
      config: { minimum_years: 2 }, external_provider: 'employment-provider',
    };
    const onSaved = vi.fn();
    const { user } = render(<CheckConfigurationDialog open template={{
      id: 'application-template-1', name: 'Membership', required_checks: [
        { check_type: 'identity_verification', is_required: true, order: 1 },
        retained,
      ],
    }} onSaved={onSaved} onClose={vi.fn()} />);

    await user.click(screen.getAllByRole('button', { name: 'Remove check' })[0]);
    expect(screen.getByRole('switch', { name: 'Optional' })).not.toBeChecked();
    await user.click(screen.getByRole('button', { name: 'Add check' }));
    await user.click(screen.getByRole('button', { name: 'Save checks' }));

    const required_checks = [
      { ...retained, order: 1 },
      { check_type: 'identity_verification', is_required: true, order: 2 },
    ];
    await waitFor(() => expect(requests).toEqual([{ required_checks }]));
    expect(onSaved).toHaveBeenCalledWith({ id: 'application-template-1', required_checks });
  });

  it('displays stored execution order and preserves an untouched check payload', async () => {
    const requests = captureCheckSave();
    const required_checks = [
      { check_type: 'identity_verification', is_required: false, order: 20,
        config: { document_types: ['passport'] }, external_provider: 'identity-provider' },
      { check_type: 'employment_verification', is_required: true, order: 10,
        config: { minimum_years: 2 }, external_provider: 'employment-provider' },
    ];
    const { user } = render(<CheckConfigurationDialog open template={{
      id: 'application-template-1', name: 'Membership', required_checks,
    }} onSaved={vi.fn()} onClose={vi.fn()} />);

    expect(screen.getAllByRole('combobox')[0]).toHaveTextContent('Employment Verification');
    expect(screen.getAllByRole('combobox')[1]).toHaveTextContent('Identity Verification');
    await user.click(screen.getByRole('button', { name: 'Save checks' }));
    await waitFor(() => expect(requests).toEqual([{ required_checks }]));
  });

  it('normalizes stored execution order after an explicit setting edit', async () => {
    const requests = captureCheckSave();
    const identity = { check_type: 'identity_verification', is_required: false, order: 20, config: { document_types: ['passport'] } };
    const employment = { check_type: 'employment_verification', is_required: true, order: 10, config: { minimum_years: 2 } };
    const { user } = render(<CheckConfigurationDialog open template={{
      id: 'application-template-1', name: 'Membership', required_checks: [identity, employment],
    }} onSaved={vi.fn()} onClose={vi.fn()} />);

    expect(screen.getAllByRole('combobox')[0]).toHaveTextContent('Employment Verification');
    await user.click(screen.getByRole('switch', { name: 'Optional' }));
    await user.click(screen.getByRole('button', { name: 'Save checks' }));
    await waitFor(() => expect(requests).toEqual([{ required_checks: [
      { ...employment, order: 1 }, { ...identity, is_required: true, order: 2 },
    ] }]));
  });

  it('repairs legacy missing and zero orders in their displayed array order', async () => {
    const requests = captureCheckSave();
    const { user } = render(<CheckConfigurationDialog open template={{
      id: 'application-template-1', name: 'Membership', required_checks: [
        { check_type: 'identity_verification', is_required: false, order: 0 },
        { check_type: 'employment_verification', is_required: true },
      ],
    }} onSaved={vi.fn()} onClose={vi.fn()} />);

    await user.click(screen.getByRole('button', { name: 'Save checks' }));
    await waitFor(() => expect(requests).toEqual([{ required_checks: [
      { check_type: 'identity_verification', is_required: false, order: 1 },
      { check_type: 'employment_verification', is_required: true, order: 2 },
    ] }]));
  });
});
