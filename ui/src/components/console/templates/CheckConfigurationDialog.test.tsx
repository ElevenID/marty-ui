import { afterEach, describe, expect, it, vi } from 'vitest';
import { http, HttpResponse } from 'msw';
import { act, fireEvent, render, screen, waitFor } from '@test/utils';
import { server } from '@test/mocks/server';
import * as applicationTemplatesApi from '../../../services/applicationTemplatesApi';
import CheckConfigurationDialog from './CheckConfigurationDialog';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

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
  afterEach(() => vi.restoreAllMocks());

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

  it('associates each Check Type label with its own select throughout editing', async () => {
    const { user } = render(<CheckConfigurationDialog open template={{
      id: 'application-template-1', name: 'Membership', required_checks: [
        { check_type: 'identity_verification', is_required: true, order: 1 },
        { check_type: 'identity_verification', is_required: true, order: 2 },
      ],
    }} onSaved={vi.fn()} onClose={vi.fn()} />);
    const selects = screen.getAllByRole('combobox', { name: 'Check Type' });
    const labels = screen.getAllByText('Check Type', { selector: 'label' });
    const selectIds = selects.map((select) => select.id);
    const labelIds = labels.map((label) => label.id);
    expect(new Set(selectIds).size).toBe(2);
    expect(new Set(labelIds).size).toBe(2);
    labels.forEach((label, index) => {
      expect(label.id).not.toBe('');
      expect(selects[index]).toHaveAttribute('aria-labelledby', label.id);
    });

    await user.click(labels[1]);
    expect(selects[1]).toHaveFocus();
    await user.keyboard('{ArrowDown}');
    await user.click(screen.getByRole('option', { name: 'Employment Verification' }));
    expect(selects[0]).toHaveTextContent('Identity Verification');
    expect(selects[1]).toHaveTextContent('Employment Verification');
    expect(screen.getAllByRole('combobox', { name: 'Check Type' }).map((select) => select.id)).toEqual(selectIds);
    expect(screen.getAllByText('Check Type', { selector: 'label' }).map((label) => label.id)).toEqual(labelIds);
    await user.click(labels[0]);
    expect(selects[0]).toHaveFocus();
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
    expect(screen.queryByLabelText('Drag to reorder')).not.toBeInTheDocument();
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

  it('keeps the submitted checks and dialog locked until a pending save fails, then allows retry', async () => {
    const pending = deferred<unknown>();
    const save = vi.spyOn(applicationTemplatesApi, 'updateTemplateRequiredChecks').mockReturnValueOnce(pending.promise);
    const required_checks = [{
      check_type: 'custom', custom_name: 'Background check', is_required: true, order: 1,
      external_provider: 'Screening provider', webhook_url: 'https://example.com/check',
    }];
    const template = { id: 'application-template-1', name: 'Membership', required_checks };
    const onSaved = vi.fn();
    const onClose = vi.fn();
    const { user } = render(<CheckConfigurationDialog open template={template} onSaved={onSaved} onClose={onClose} />);
    const saveButton = screen.getByRole('button', { name: 'Save checks' });
    const name = screen.getByRole('textbox', { name: 'Custom check name' });
    const add = screen.getByRole('button', { name: 'Add check' });
    const remove = screen.getByRole('button', { name: 'Remove check' });
    const dialog = screen.getByRole('dialog');

    act(() => {
      fireEvent.click(saveButton);
      fireEvent.change(name, { target: { value: 'Unsubmitted change' } });
      fireEvent.click(remove);
      fireEvent.click(add);
      fireEvent.click(saveButton);
      fireEvent.keyDown(dialog, { key: 'Escape' });
      fireEvent.mouseDown(dialog.parentElement!);
      fireEvent.click(dialog.parentElement!);
    });
    expect(save).toHaveBeenCalledTimes(1);
    expect(save).toHaveBeenCalledWith(template.id, required_checks);
    expect(name).toHaveValue('Background check');
    expect(screen.getAllByRole('combobox')).toHaveLength(1);
    expect(screen.getByRole('combobox')).toHaveAttribute('aria-disabled', 'true');
    for (const control of [name, add, remove, saveButton,
      screen.getByRole('switch', { name: 'Required' }),
      screen.getByRole('textbox', { name: 'External provider name' }),
      screen.getByRole('textbox', { name: 'Webhook URL' }),
      screen.getByRole('button', { name: 'Configure external webhook' }),
      screen.getByRole('button', { name: 'Cancel' })]) {
      expect(control).toBeDisabled();
    }
    await user.keyboard('{Escape}');
    await user.click(dialog.parentElement!);
    expect(onClose).not.toHaveBeenCalled();
    expect(onSaved).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toBeInTheDocument();

    await act(async () => { pending.reject(new Error('Save temporarily unavailable')); });
    expect(screen.getByRole('alert')).toHaveTextContent('Save temporarily unavailable');
    expect(name).toBeEnabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeEnabled();
    await user.clear(name);
    await user.type(name, 'Corrected background check');
    const saved = { ...template, required_checks: [{ ...required_checks[0], custom_name: 'Corrected background check' }] };
    save.mockResolvedValueOnce(saved);
    await user.click(screen.getByRole('button', { name: 'Save checks' }));
    expect(save).toHaveBeenCalledTimes(2);
    expect(save).toHaveBeenLastCalledWith(template.id, saved.required_checks);
    expect(onSaved).toHaveBeenCalledWith(saved);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it.each(['Escape', 'backdrop', 'Cancel'])('allows %s dismissal when no save is pending', async (dismissal) => {
    const onClose = vi.fn();
    const { user } = render(<CheckConfigurationDialog open template={{
      id: 'application-template-1', name: 'Membership', required_checks: [],
    }} onSaved={vi.fn()} onClose={onClose} />);

    if (dismissal === 'Escape') await user.keyboard('{Escape}');
    else if (dismissal === 'backdrop') await user.click(screen.getByRole('dialog').parentElement!);
    else await user.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it.each(['success', 'failure'])('ignores a previous template save %s while its same-organization replacement is saving', async (outcome) => {
    const previous = deferred<unknown>();
    const current = deferred<unknown>();
    const save = vi.spyOn(applicationTemplatesApi, 'updateTemplateRequiredChecks')
      .mockReturnValueOnce(previous.promise).mockReturnValueOnce(current.promise);
    const onSaved = vi.fn();
    const onClose = vi.fn();
    const first = { id: 'application-template-1', organization_id: 'org-1', name: 'Membership', required_checks: [] };
    const replacement = { ...first, id: 'application-template-2', name: 'Employment' };
    const { user, rerender } = render(<CheckConfigurationDialog open template={first} onSaved={onSaved} onClose={onClose} />);
    await user.click(screen.getByRole('button', { name: 'Save checks' }));

    rerender(<CheckConfigurationDialog open template={replacement} onSaved={onSaved} onClose={onClose} />);
    expect(screen.getByRole('button', { name: 'Save checks' })).toBeEnabled();
    await user.click(screen.getByRole('button', { name: 'Add check' }));
    await user.click(screen.getByRole('button', { name: 'Save checks' }));
    await act(async () => {
      if (outcome === 'success') previous.resolve(first);
      else previous.reject(new Error('Late previous save failure'));
    });

    expect(screen.getByRole('dialog')).toHaveTextContent('Employment');
    expect(screen.getByRole('button', { name: 'Saving…' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Cancel' })).toBeDisabled();
    expect(screen.queryByText('Late previous save failure')).not.toBeInTheDocument();
    expect(onSaved).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
    expect(save).toHaveBeenCalledTimes(2);
    expect(save).toHaveBeenLastCalledWith(replacement.id, [{ check_type: 'identity_verification', is_required: true, order: 1 }]);

    await act(async () => { current.resolve(replacement); });
    expect(onSaved).toHaveBeenCalledExactlyOnceWith(replacement);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it.each(['success', 'failure'])('ignores a previous save %s after the same template is closed and reopened', async (outcome) => {
    const pending = deferred<unknown>();
    vi.spyOn(applicationTemplatesApi, 'updateTemplateRequiredChecks').mockReturnValueOnce(pending.promise);
    const template = { id: 'application-template-1', organization_id: 'org-1', name: 'Membership', required_checks: [] };
    const onSaved = vi.fn();
    const onClose = vi.fn();
    const { user, rerender } = render(<CheckConfigurationDialog open template={template} onSaved={onSaved} onClose={onClose} />);
    await user.click(screen.getByRole('button', { name: 'Save checks' }));
    rerender(<CheckConfigurationDialog open={false} template={template} onSaved={onSaved} onClose={onClose} />);
    rerender(<CheckConfigurationDialog open template={template} onSaved={onSaved} onClose={onClose} />);
    await user.click(screen.getByRole('button', { name: 'Add check' }));

    await act(async () => {
      if (outcome === 'success') pending.resolve(template);
      else pending.reject(new Error('Late previous save failure'));
    });
    expect(screen.getByRole('dialog')).toBeInTheDocument();
    expect(screen.getAllByRole('combobox')).toHaveLength(1);
    expect(screen.getByRole('button', { name: 'Save checks' })).toBeEnabled();
    expect(screen.queryByText('Late previous save failure')).not.toBeInTheDocument();
    expect(onSaved).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });

  it('does not call the departed scope after unmounting with a pending save', async () => {
    const pending = deferred<unknown>();
    vi.spyOn(applicationTemplatesApi, 'updateTemplateRequiredChecks').mockReturnValueOnce(pending.promise);
    const template = { id: 'application-template-1', name: 'Membership', required_checks: [] };
    const onSaved = vi.fn();
    const onClose = vi.fn();
    const { user, unmount } = render(<CheckConfigurationDialog open template={template} onSaved={onSaved} onClose={onClose} />);
    await user.click(screen.getByRole('button', { name: 'Save checks' }));
    unmount();

    await act(async () => { pending.resolve(template); });
    expect(onSaved).not.toHaveBeenCalled();
    expect(onClose).not.toHaveBeenCalled();
  });
});
