import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import DemoVideoPlayer from './DemoVideoPlayer';

const scenario = {
  slug: 'credential-lifecycle',
  scenario_revision: 1,
  title: 'Credential lifecycle',
  state: 'PUBLIC',
  youtube_id: 'abcdefghijk',
  poster: { src: '/images/demos/2026.07.0/credential-lifecycle.png', alt: 'Credential lifecycle preview' },
};

describe('DemoVideoPlayer', () => {
  it.each([
    ['DRAFT', 'Scenario in development'],
    ['VALIDATED', 'Validated demonstration'],
    ['YOUTUBE_UNLISTED', 'Recording in review'],
    ['SUPERSEDED', 'Recording unavailable'],
  ])('does not offer playback for %s even when a video ID is retained', (state, message) => {
    render(<DemoVideoPlayer scenario={{ ...scenario, state }} />);

    expect(screen.getByText(message)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /from YouTube/ })).not.toBeInTheDocument();
    expect(screen.queryByTitle('Credential lifecycle video')).not.toBeInTheDocument();
  });

  it('requires consent for public playback and retains it while seeking within the recording', async () => {
    const user = userEvent.setup();
    const { rerender } = render(<DemoVideoPlayer scenario={scenario} />);

    expect(screen.queryByTitle('Credential lifecycle video')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Load Credential lifecycle from YouTube' }));
    expect(screen.getByTitle('Credential lifecycle video')).toHaveAttribute('src', expect.stringContaining('youtube-nocookie.com/embed/abcdefghijk'));

    rerender(<DemoVideoPlayer scenario={scenario} startSeconds={42} />);
    expect(screen.getByTitle('Credential lifecycle video')).toHaveAttribute('src', expect.stringContaining('start=42'));
    expect(screen.queryByRole('button', { name: /from YouTube/ })).not.toBeInTheDocument();
  });

  it.each([
    { youtube_id: 'lmnopqrstuv' },
    { slug: 'organization-primitives' },
    { scenario_revision: 2 },
  ])('requires fresh consent when the recording binding changes: %j', async (change) => {
    const user = userEvent.setup();
    const { rerender } = render(<DemoVideoPlayer scenario={scenario} />);
    await user.click(screen.getByRole('button', { name: 'Load Credential lifecycle from YouTube' }));

    rerender(<DemoVideoPlayer scenario={{ ...scenario, ...change }} />);

    expect(screen.queryByTitle('Credential lifecycle video')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Load Credential lifecycle from YouTube' })).toBeInTheDocument();
  });

  it('unloads withdrawn media and does not reuse consent when it becomes public again', async () => {
    const user = userEvent.setup();
    const { rerender } = render(<DemoVideoPlayer scenario={scenario} />);
    await user.click(screen.getByRole('button', { name: 'Load Credential lifecycle from YouTube' }));

    rerender(<DemoVideoPlayer scenario={{ ...scenario, state: 'YOUTUBE_UNLISTED' }} />);
    expect(screen.queryByTitle('Credential lifecycle video')).not.toBeInTheDocument();
    expect(screen.getByText('Recording in review')).toBeInTheDocument();

    rerender(<DemoVideoPlayer scenario={scenario} />);
    expect(screen.queryByTitle('Credential lifecycle video')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Load Credential lifecycle from YouTube' })).toBeInTheDocument();
  });
});
