import { useMemo, useState } from 'react';
import PropTypes from 'prop-types';
import { Box, Button, Stack, Typography } from '@mui/material';
import PlayArrowRoundedIcon from '@mui/icons-material/PlayArrowRounded';
import PendingActionsRoundedIcon from '@mui/icons-material/PendingActionsRounded';

function unavailableRecordingCopy(state) {
  if (state === 'VALIDATED') {
    return {
      title: 'Validated demonstration',
      description: 'The browser run passed. A production-quality recording is being prepared; evidence, chapters, and the transcript remain available below.',
    };
  }
  if (state === 'YOUTUBE_UNLISTED') {
    return {
      title: 'Recording in review',
      description: 'The recording is completing ElevenID LLC publication review. Evidence, chapters, and the transcript remain available below.',
    };
  }
  if (state === 'DRAFT') {
    return {
      title: 'Scenario in development',
      description: 'This scenario has not been recorded yet. Its planned coverage, chapters, and acceptance criteria are available below.',
    };
  }
  return {
    title: 'Recording unavailable',
    description: 'Evidence, chapters, and the transcript remain available below.',
  };
}

function DemoVideoPlayer({ scenario, startSeconds = 0 }) {
  const [consented, setConsented] = useState(false);
  const videoKey = `${scenario.youtube_id || 'pending'}-${startSeconds}`;
  const unavailableCopy = unavailableRecordingCopy(scenario.state);
  const embedUrl = useMemo(() => {
    if (!scenario.youtube_id) return null;
    const params = new URLSearchParams({
      autoplay: '1',
      cc_load_policy: '1',
      enablejsapi: '1',
      playsinline: '1',
      rel: '0',
      start: String(startSeconds),
    });
    if (typeof window !== 'undefined') params.set('origin', window.location.origin);
    return `https://www.youtube-nocookie.com/embed/${scenario.youtube_id}?${params.toString()}`;
  }, [scenario.youtube_id, startSeconds]);

  return (
    <Box
      data-testid="demo-video-player"
      sx={{
        position: 'relative',
        width: '100%',
        aspectRatio: '16 / 9',
        overflow: 'hidden',
        bgcolor: '#111820',
        border: '1px solid',
        borderColor: 'divider',
        borderRadius: 1,
      }}
    >
      {embedUrl && consented ? (
        <Box
          key={videoKey}
          component="iframe"
          title={`${scenario.title} video`}
          src={embedUrl}
          allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
          allowFullScreen
          sx={{ width: '100%', height: '100%', border: 0, display: 'block' }}
        />
      ) : (
        <>
          <Box
            component="img"
            src={scenario.poster.src}
            alt={scenario.poster.alt}
            loading="eager"
            sx={{ width: '100%', height: '100%', objectFit: 'cover', display: 'block', opacity: 0.68 }}
          />
          <Box
            sx={{
              position: 'absolute',
              inset: 0,
              display: 'grid',
              placeItems: 'center',
              p: 2,
              bgcolor: 'rgba(8, 14, 20, 0.28)',
            }}
          >
            {embedUrl ? (
              <Button
                variant="contained"
                size="large"
                startIcon={<PlayArrowRoundedIcon />}
                onClick={() => setConsented(true)}
                aria-label={`Load ${scenario.title} from YouTube`}
                sx={{ bgcolor: '#fff', color: '#111820', '&:hover': { bgcolor: '#eef2f4' } }}
              >
                Play recording
              </Button>
            ) : (
              <Stack alignItems="center" spacing={1} sx={{ color: '#fff', textAlign: 'center', maxWidth: 440 }}>
                <PendingActionsRoundedIcon fontSize="large" />
                <Typography variant="h6" component="p" fontWeight={700}>
                  {unavailableCopy.title}
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.86)', display: { xs: 'none', sm: 'block' } }}>
                  {unavailableCopy.description}
                </Typography>
              </Stack>
            )}
          </Box>
        </>
      )}
    </Box>
  );
}

DemoVideoPlayer.propTypes = {
  scenario: PropTypes.shape({
    title: PropTypes.string.isRequired,
    state: PropTypes.string.isRequired,
    youtube_id: PropTypes.string,
    poster: PropTypes.shape({
      src: PropTypes.string.isRequired,
      alt: PropTypes.string.isRequired,
    }).isRequired,
  }).isRequired,
  startSeconds: PropTypes.number,
};

export default DemoVideoPlayer;
