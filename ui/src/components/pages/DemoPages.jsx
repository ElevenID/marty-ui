import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link as RouterLink, Navigate, useNavigate, useParams } from 'react-router-dom';
import {
  Alert,
  Box,
  Breadcrumbs,
  Button,
  Card,
  CardActionArea,
  CardContent,
  Chip,
  CircularProgress,
  Divider,
  FormControl,
  InputLabel,
  Link,
  MenuItem,
  Select,
  Stack,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
} from '@mui/material';
import ArrowBackRoundedIcon from '@mui/icons-material/ArrowBackRounded';
import ArrowForwardRoundedIcon from '@mui/icons-material/ArrowForwardRounded';
import CheckCircleRoundedIcon from '@mui/icons-material/CheckCircleRounded';
import ErrorOutlineRoundedIcon from '@mui/icons-material/ErrorOutlineRounded';
import FactCheckRoundedIcon from '@mui/icons-material/FactCheckRounded';
import PendingRoundedIcon from '@mui/icons-material/PendingRounded';
import ReplayRoundedIcon from '@mui/icons-material/ReplayRounded';
import SearchRoundedIcon from '@mui/icons-material/SearchRounded';
import YouTubeIcon from '@mui/icons-material/YouTube';

import DemoVideoPlayer from '../demos/DemoVideoPlayer';
import SEOHead from '../seo/SEOHead';
import {
  findDemoScenario,
  loadDemoIndex,
  loadDemoManifest,
} from '../../services/demoManifestService';

const AUDIENCES = ['All', 'Holder', 'Issuer', 'Verifier', 'Administrator', 'Developer'];

const stateColors = {
  DRAFT: 'default',
  VALIDATED: 'info',
  YOUTUBE_UNLISTED: 'warning',
  PUBLIC: 'success',
  SUPERSEDED: 'default',
};

function formatTimestamp(totalSeconds) {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${String(seconds).padStart(2, '0')}`;
}

function useAsyncResource(loader, dependencies) {
  const [state, setState] = useState({ status: 'loading', data: null, error: null });
  const [attempt, setAttempt] = useState(0);
  const retry = useCallback(() => setAttempt((current) => current + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    setState({ status: 'loading', data: null, error: null });
    loader(controller.signal)
      .then((data) => setState({ status: 'ready', data, error: null }))
      .catch((error) => {
        if (error.name !== 'AbortError') setState({ status: 'error', data: null, error });
      });
    return () => controller.abort();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...dependencies, attempt]);

  return { ...state, retry };
}

function LoadState({ resource, label }) {
  if (resource.status === 'loading') {
    return (
      <Stack alignItems="center" spacing={2} sx={{ py: 10 }} role="status">
        <CircularProgress size={32} />
        <Typography color="text.secondary">Loading {label}...</Typography>
      </Stack>
    );
  }
  if (resource.status === 'error') {
    return (
      <Alert
        data-demo-render-state="settled"
        severity="error"
        action={(
          <Button color="inherit" size="small" startIcon={<ReplayRoundedIcon />} onClick={resource.retry}>
            Retry
          </Button>
        )}
        sx={{ my: 6 }}
      >
        {resource.error?.message || `Unable to load ${label}.`}
      </Alert>
    );
  }
  return null;
}

function CoverageLabel({ manifest }) {
  return (
    <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" alignItems="center">
      <Chip
        size="small"
        color={manifest.coverage_state === 'COMPLETE' ? 'success' : 'warning'}
        label={`${manifest.coverage_state} coverage`}
      />
      <Chip size="small" variant="outlined" label={manifest.publication_state} />
      {!manifest.release_ready && <Chip size="small" variant="outlined" label="Preview evidence" />}
    </Stack>
  );
}

function ScenarioCard({ manifest, scenario }) {
  const passed = scenario.assertions.filter((assertion) => assertion.result === 'PASS').length;
  const recordingAvailable = scenario.state === 'PUBLIC' && Boolean(scenario.youtube_id);
  const mediaLabel = recordingAvailable
    ? 'Recording available'
    : scenario.state === 'VALIDATED'
      ? 'Validated evidence'
      : scenario.state === 'YOUTUBE_UNLISTED'
        ? 'Recording in review'
        : 'Scenario planned';
  return (
    <Card variant="outlined" sx={{ height: '100%', borderRadius: 1 }}>
      <CardActionArea
        component={RouterLink}
        to={`/demos/${manifest.stack_version}/${scenario.slug}`}
        sx={{ height: '100%', display: 'flex', flexDirection: 'column', alignItems: 'stretch' }}
      >
        <Box sx={{ width: '100%', aspectRatio: '16 / 9', overflow: 'hidden', bgcolor: 'grey.900' }}>
          <Box
            component="img"
            src={scenario.poster.src}
            alt=""
            loading="lazy"
            sx={{ display: 'block', width: '100%', height: '100%', objectFit: 'cover' }}
          />
        </Box>
        <CardContent sx={{ width: '100%', flex: 1, display: 'flex', flexDirection: 'column', gap: 1.5 }}>
          <Stack direction="row" justifyContent="space-between" alignItems="flex-start" spacing={1}>
            <Typography variant="h6" component="h2" fontWeight={750} sx={{ fontSize: '1.05rem' }}>
              {scenario.title}
            </Typography>
            <Chip size="small" color={stateColors[scenario.state]} label={scenario.state.replaceAll('_', ' ')} />
          </Stack>
          <Chip
            size="small"
            variant="outlined"
            icon={recordingAvailable ? <YouTubeIcon /> : <FactCheckRoundedIcon />}
            label={mediaLabel}
            sx={{ alignSelf: 'flex-start' }}
          />
          <Typography variant="body2" color="text.secondary" sx={{ flex: 1 }}>
            {scenario.summary}
          </Typography>
          <Stack direction="row" justifyContent="space-between" alignItems="center" spacing={1}>
            <Typography variant="caption" color="text.secondary">
              {passed}/{scenario.assertions.length} assertions passed
            </Typography>
            <ArrowForwardRoundedIcon fontSize="small" color="action" />
          </Stack>
        </CardContent>
      </CardActionArea>
    </Card>
  );
}

function ReleaseExperience({ index, manifest }) {
  const navigate = useNavigate();
  const [audience, setAudience] = useState('All');
  const [query, setQuery] = useState('');

  const visibleScenarios = useMemo(() => {
    const normalizedQuery = query.trim().toLowerCase();
    return manifest.scenarios.filter((scenario) => {
      const audienceMatches = audience === 'All' || scenario.audiences.includes(audience);
      const queryMatches = !normalizedQuery || [
        scenario.title,
        scenario.summary,
        ...scenario.capabilities,
      ].join(' ').toLowerCase().includes(normalizedQuery);
      return audienceMatches && queryMatches;
    });
  }, [audience, manifest.scenarios, query]);

  return (
    <Box component="main" data-demo-render-state="settled" sx={{ pt: { xs: 4, md: 6 } }}>
      <SEOHead
        title={`${manifest.release_name} | ElevenID LLC v${manifest.stack_version}`}
        description={`Release-bound demonstrations and evidence for the ${manifest.release_name} release of the ElevenID LLC Credential Platform, implementing MIP ${manifest.mip_version}.`}
        canonicalPath={`/demos/${manifest.stack_version}`}
        ogImage={`https://elevenidllc.com${manifest.scenarios[0].poster.src}`}
        keywords={['ElevenID LLC Credential Platform', manifest.release_name, `MIP ${manifest.mip_version}`, 'digital credential demos', 'release evidence']}
      />

      <Stack spacing={2.5} sx={{ mb: 4, maxWidth: 900 }}>
        <Typography variant="overline" color="text.secondary" fontWeight={700}>
          ElevenID LLC Credential Platform
        </Typography>
        <Typography variant="h2" component="h1" fontWeight={800} sx={{ fontSize: { xs: '2rem', md: '3rem' } }}>
          {manifest.release_name}
        </Typography>
        <Typography variant="h6" component="p" color="text.secondary" fontWeight={500}>
          Version v{manifest.stack_version}
        </Typography>
        <Typography variant="body1" component="p" color="text.secondary" fontWeight={600}>
          Implements MIP {manifest.mip_version}
        </Typography>
        <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 760 }}>
          Follow credential journeys by role, inspect the exact release binding, and see at a glance which scenarios have recordings, validated evidence, or planned coverage.
        </Typography>
        <Stack direction="row" spacing={1.5} useFlexGap flexWrap="wrap" alignItems="center">
          <CoverageLabel manifest={manifest} />
          {manifest.video_distribution.status === 'CONFIGURED' && (
            <Button
              component="a"
              href={manifest.video_distribution.playlist_url}
              target="_blank"
              rel="noopener noreferrer"
              size="small"
              variant="outlined"
              startIcon={<YouTubeIcon />}
            >
              Watch release playlist
            </Button>
          )}
        </Stack>
      </Stack>

      {!manifest.public_demo_ready && (
        <Alert severity="info" icon={<FactCheckRoundedIcon />} sx={{ mb: 4 }}>
          This release evidence is a publication preview. Independent-wallet qualification and ElevenID LLC publication review are still required for complete public coverage.
        </Alert>
      )}

      <Alert severity="info" sx={{ mb: 4 }}>
        <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 0.5 }}>
          Independent wallet demonstrations
        </Typography>
        <Typography variant="body2">
          Third-party wallet names and limited interface footage are used to document interoperability, compatibility, and user experience. They do not imply affiliation or endorsement, and vendor approval is not a publication requirement. Wallet providers may{' '}
          <Link href="mailto:sales@elevenidllc.com?subject=Demo%20review%20or%20removal%20request">
            request review or removal
          </Link>.
        </Typography>
      </Alert>

      <Box
        component="section"
        aria-label="Demo filters"
        sx={{ py: 3, mb: 4, borderTop: '1px solid', borderBottom: '1px solid', borderColor: 'divider' }}
      >
        <Stack spacing={2}>
          <Stack direction={{ xs: 'column', md: 'row' }} spacing={2} alignItems={{ md: 'center' }}>
            <FormControl size="small" sx={{ minWidth: { xs: '100%', sm: 250 } }}>
              <InputLabel id="stack-release-label">Platform version</InputLabel>
              <Select
                labelId="stack-release-label"
                value={manifest.stack_version}
                label="Platform version"
                onChange={(event) => navigate(`/demos/${event.target.value}`)}
              >
                {index.releases.map((release) => (
                  <MenuItem key={release.stack_version} value={release.stack_version}>
                    v{release.stack_version} / {release.release_name}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <TextField
              size="small"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              label="Filter scenarios"
              placeholder="Badge, verifier, Canvas..."
              InputProps={{ startAdornment: <SearchRoundedIcon color="action" sx={{ mr: 1 }} /> }}
              sx={{ flex: 1, minWidth: 0 }}
            />
          </Stack>
          <Box sx={{ overflowX: 'auto', pb: 0.5 }}>
            <ToggleButtonGroup
              exclusive
              size="small"
              value={audience}
              onChange={(_event, nextAudience) => nextAudience && setAudience(nextAudience)}
              aria-label="Audience"
              sx={{ minWidth: 'max-content' }}
            >
              {AUDIENCES.map((item) => <ToggleButton key={item} value={item}>{item}</ToggleButton>)}
            </ToggleButtonGroup>
          </Box>
        </Stack>
      </Box>

      <Box component="section" aria-labelledby="scenario-heading">
        <Stack direction="row" justifyContent="space-between" alignItems="baseline" spacing={2} sx={{ mb: 2 }}>
          <Typography id="scenario-heading" variant="h5" component="h2" fontWeight={750}>
            Scenarios
          </Typography>
          <Typography variant="body2" color="text.secondary">
            {visibleScenarios.length} of {manifest.scenarios.length}
          </Typography>
        </Stack>
        {visibleScenarios.length > 0 ? (
          <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, minmax(0, 1fr))', lg: 'repeat(3, minmax(0, 1fr))' }, gap: 2 }}>
            {visibleScenarios.map((scenario) => (
              <ScenarioCard key={scenario.slug} manifest={manifest} scenario={scenario} />
            ))}
          </Box>
        ) : (
          <Alert severity="info">No scenarios match these filters.</Alert>
        )}
      </Box>

      <Box component="section" aria-labelledby="release-differences" sx={{ mt: 7 }}>
        <Typography id="release-differences" variant="h5" component="h2" fontWeight={750} sx={{ mb: 2 }}>
          Release features
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: -1, mb: 2 }}>
          Changes since ElevenID LLC v{manifest.release_differences.previous_stack_version}
        </Typography>
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' }, columnGap: 5, rowGap: 3 }}>
          {Object.entries(manifest.release_differences)
            .filter(([key]) => key !== 'previous_stack_version')
            .map(([category, changes]) => (
              <Box key={category}>
                <Typography variant="subtitle1" fontWeight={700} textTransform="capitalize" sx={{ mb: 1 }}>
                  {category}
                </Typography>
                <Stack spacing={1}>
                  {changes.map((change) => (
                    <Stack key={change} direction="row" spacing={1} alignItems="flex-start">
                      <CheckCircleRoundedIcon color="success" sx={{ fontSize: 18, mt: '2px' }} />
                      <Typography variant="body2" color="text.secondary">{change}</Typography>
                    </Stack>
                  ))}
                </Stack>
              </Box>
            ))}
        </Box>
      </Box>

      <Box component="section" aria-labelledby="release-binding" sx={{ mt: 7 }}>
        <Typography id="release-binding" variant="h5" component="h2" fontWeight={750} sx={{ mb: 2 }}>
          Release binding
        </Typography>
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'repeat(3, minmax(0, 1fr))' }, gap: 2 }}>
          <Box>
            <Typography variant="overline" color="text.secondary">Deployment marker</Typography>
            <Typography variant="body2" sx={{ overflowWrap: 'anywhere' }}>{manifest.deployment_release_marker}</Typography>
          </Box>
          <Box>
            <Typography variant="overline" color="text.secondary">Components</Typography>
            <Typography variant="body2">{manifest.component_revisions.length} exact source revisions</Typography>
          </Box>
          <Box>
            <Typography variant="overline" color="text.secondary">Container images</Typography>
            <Typography variant="body2">{manifest.image_digests.length} immutable digests</Typography>
          </Box>
        </Box>
        <Box sx={{ mt: 3 }}>
          <Typography variant="overline" color="text.secondary">Protected evidence hashes</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
            Recorded {new Date(manifest.release_evidence.recorded_at).toLocaleString()} / displayed offers invalidated {new Date(manifest.release_evidence.displayed_offers_invalidated_at).toLocaleString()}
          </Typography>
          <Stack spacing={1}>
            {manifest.release_evidence.artifacts.map((artifact) => (
              <Box key={artifact.sha256}>
                <Typography variant="body2" fontWeight={700}>{artifact.label} / {artifact.visibility}</Typography>
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', overflowWrap: 'anywhere' }}>sha256:{artifact.sha256}</Typography>
              </Box>
            ))}
          </Stack>
        </Box>
        <Box component="details" sx={{ mt: 3, '& > summary': { cursor: 'pointer', fontWeight: 700 } }}>
          <Box component="summary">Inspect exact release revisions</Box>
          <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'repeat(2, minmax(0, 1fr))' }, gap: 3, mt: 2 }}>
            <Box>
              <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 1 }}>Source revisions</Typography>
              {manifest.component_revisions.map((component) => (
                <Typography key={component.component} variant="caption" display="block" sx={{ overflowWrap: 'anywhere', mb: 0.75 }}>
                  {component.component}: {component.revision}
                </Typography>
              ))}
            </Box>
            <Box>
              <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 1 }}>Container image digests</Typography>
              {manifest.image_digests.map((image) => (
                <Typography key={image.component} variant="caption" display="block" sx={{ overflowWrap: 'anywhere', mb: 0.75 }}>
                  {image.component}: {image.digest}
                </Typography>
              ))}
            </Box>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

export function DemoCatalogPage() {
  const indexResource = useAsyncResource((signal) => loadDemoIndex({ signal }), []);
  const version = indexResource.data?.latest_approved_stack_version || indexResource.data?.latest_available_stack_version;
  const manifestResource = useAsyncResource(
    (signal) => (version ? loadDemoManifest(version, { signal }) : Promise.reject(new Error('No ElevenID LLC release is available.'))),
    [version],
  );
  const pending = <LoadState resource={indexResource.status === 'ready' ? manifestResource : indexResource} label="ElevenID LLC demonstrations" />;
  if (indexResource.status !== 'ready' || manifestResource.status !== 'ready') return pending;
  return <ReleaseExperience index={indexResource.data} manifest={manifestResource.data} />;
}

export function DemoReleasePage() {
  const { stackVersion } = useParams();
  const indexResource = useAsyncResource((signal) => loadDemoIndex({ signal }), []);
  const manifestResource = useAsyncResource((signal) => loadDemoManifest(stackVersion, { signal }), [stackVersion]);
  if (indexResource.status !== 'ready') return <LoadState resource={indexResource} label="ElevenID LLC releases" />;
  if (manifestResource.status !== 'ready') return <LoadState resource={manifestResource} label={`ElevenID LLC v${stackVersion}`} />;
  return <ReleaseExperience index={indexResource.data} manifest={manifestResource.data} />;
}

function AssertionIcon({ result }) {
  if (result === 'PASS') return <CheckCircleRoundedIcon color="success" />;
  if (result === 'FAIL') return <ErrorOutlineRoundedIcon color="error" />;
  return <PendingRoundedIcon color="action" />;
}

export function DemoScenarioPage() {
  const { stackVersion, scenario: scenarioSlug } = useParams();
  const manifestResource = useAsyncResource((signal) => loadDemoManifest(stackVersion, { signal }), [stackVersion]);
  const [startSeconds, setStartSeconds] = useState(0);
  if (manifestResource.status !== 'ready') return <LoadState resource={manifestResource} label="scenario evidence" />;

  const manifest = manifestResource.data;
  const scenario = findDemoScenario(manifest, scenarioSlug);
  if (!scenario) {
    return (
      <Alert severity="warning" data-demo-render-state="settled" sx={{ my: 6 }}>
        This scenario is not part of ElevenID LLC v{stackVersion}. <Link component={RouterLink} to={`/demos/${stackVersion}`}>View this release</Link>.
      </Alert>
    );
  }

  const isPublicVideo = scenario.state === 'PUBLIC' && Boolean(scenario.youtube_id);
  const structuredData = isPublicVideo ? {
    '@context': 'https://schema.org',
    '@type': 'VideoObject',
    name: `${scenario.title} - ${manifest.release_name} - ElevenID LLC v${manifest.stack_version}`,
    description: scenario.summary,
    thumbnailUrl: [`https://elevenidllc.com${scenario.poster.src}`],
    uploadDate: scenario.published_at,
    embedUrl: `https://www.youtube-nocookie.com/embed/${scenario.youtube_id}`,
  } : null;

  return (
    <Box component="main" data-demo-render-state="settled" sx={{ pt: { xs: 3, md: 5 } }}>
      <SEOHead
        title={`${scenario.title} | ${manifest.release_name} | ElevenID LLC v${manifest.stack_version}`}
        description={scenario.summary}
        canonicalPath={`/demos/${manifest.stack_version}/${scenario.slug}`}
        ogImage={`https://elevenidllc.com${scenario.poster.src}`}
        ogType={isPublicVideo ? 'video.other' : 'website'}
        structuredData={structuredData}
      />
      <Breadcrumbs aria-label="Demo navigation" sx={{ mb: 3 }}>
        <Link component={RouterLink} to="/demos" underline="hover" color="inherit">Demos</Link>
        <Link component={RouterLink} to={`/demos/${manifest.stack_version}`} underline="hover" color="inherit">v{manifest.stack_version}</Link>
        <Typography color="text.primary">{scenario.title}</Typography>
      </Breadcrumbs>

      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: 'minmax(0, 2fr) minmax(260px, 0.8fr)' }, gap: { xs: 3, lg: 4 }, alignItems: 'start' }}>
        <Stack spacing={3} sx={{ minWidth: 0 }}>
          <Box>
            <Stack direction="row" spacing={1} useFlexGap flexWrap="wrap" sx={{ mb: 1.5 }}>
              <Chip size="small" color={stateColors[scenario.state]} label={scenario.state.replaceAll('_', ' ')} />
              <Chip size="small" variant="outlined" label={`Revision ${scenario.scenario_revision}`} />
              <Chip size="small" variant="outlined" label={scenario.recording_classification.replaceAll('_', ' ')} />
            </Stack>
            <Typography variant="h3" component="h1" fontWeight={800} sx={{ fontSize: { xs: '1.8rem', md: '2.5rem' }, mb: 1.5 }}>
              {scenario.title}
            </Typography>
            <Typography variant="body1" color="text.secondary">{scenario.summary}</Typography>
          </Box>

          <DemoVideoPlayer scenario={scenario} startSeconds={startSeconds} />

          <Box component="section" aria-labelledby="chapters-heading">
            <Typography id="chapters-heading" variant="h5" component="h2" fontWeight={750} sx={{ mb: 1.5 }}>Chapters</Typography>
            <Stack divider={<Divider flexItem />}>
              {scenario.chapters.map((chapter) => (
                <Button
                  key={`${chapter.start_seconds}-${chapter.title}`}
                  color="inherit"
                  onClick={() => setStartSeconds(chapter.start_seconds)}
                  sx={{ justifyContent: 'flex-start', textAlign: 'left', px: 0, py: 1.5, borderRadius: 0 }}
                >
                  <Typography component="span" variant="body2" fontWeight={700} sx={{ width: 54, flexShrink: 0 }}>
                    {formatTimestamp(chapter.start_seconds)}
                  </Typography>
                  <Box component="span" sx={{ minWidth: 0 }}>
                    <Typography component="span" display="block" variant="body2" fontWeight={700}>{chapter.title}</Typography>
                    <Typography component="span" display="block" variant="caption" color="text.secondary">{chapter.role} / {chapter.standards.join(', ')}</Typography>
                  </Box>
                </Button>
              ))}
            </Stack>
          </Box>

          <Box component="section" aria-labelledby="transcript-heading">
            <Typography id="transcript-heading" variant="h5" component="h2" fontWeight={750} sx={{ mb: 1.5 }}>Transcript</Typography>
            <Stack spacing={2}>
              {scenario.transcript.segments.map((segment) => (
                <Box key={`${segment.start_seconds}-${segment.text}`} sx={{ display: 'grid', gridTemplateColumns: '52px minmax(0, 1fr)', gap: 1.5 }}>
                  <Button
                    size="small"
                    color="inherit"
                    onClick={() => setStartSeconds(segment.start_seconds)}
                    sx={{ minWidth: 0, p: 0, alignSelf: 'start', justifyContent: 'flex-start' }}
                  >
                    {formatTimestamp(segment.start_seconds)}
                  </Button>
                  <Box>
                    <Typography variant="caption" fontWeight={700}>{segment.speaker}</Typography>
                    <Typography variant="body2" color="text.secondary">{segment.text}</Typography>
                  </Box>
                </Box>
              ))}
            </Stack>
          </Box>
        </Stack>

        <Stack component="aside" spacing={3} sx={{ minWidth: 0 }}>
          <Box>
            <Typography variant="overline" color="text.secondary">Release</Typography>
            <Typography variant="subtitle1" fontWeight={750}>{manifest.release_name}</Typography>
            <Typography variant="body2" color="text.secondary">ElevenID LLC Credential Platform v{manifest.stack_version}</Typography>
            <Typography variant="body2" color="text.secondary">Implements MIP {manifest.mip_version}</Typography>
          </Box>
          <Divider />
          <Box>
            <Typography variant="overline" color="text.secondary">For</Typography>
            <Stack direction="row" spacing={0.75} useFlexGap flexWrap="wrap" sx={{ mt: 0.5 }}>
              {scenario.audiences.map((audience) => <Chip key={audience} size="small" variant="outlined" label={audience} />)}
            </Stack>
          </Box>
          <Box>
            <Typography variant="overline" color="text.secondary">Final protocol profile</Typography>
            <Stack spacing={0.5} sx={{ mt: 0.5 }}>
              {scenario.protocols.map((protocol) => <Typography key={protocol} variant="body2" sx={{ overflowWrap: 'anywhere' }}>{protocol}</Typography>)}
            </Stack>
          </Box>
          <Divider />
          <Box>
            <Typography variant="subtitle2" fontWeight={750} sx={{ mb: 1 }}>Evidence assertions</Typography>
            <Stack spacing={1.5}>
              {scenario.assertions.map((assertion) => (
                <Stack key={assertion.id} direction="row" spacing={1} alignItems="flex-start">
                  <AssertionIcon result={assertion.result} />
                  <Box sx={{ minWidth: 0 }}>
                    <Typography variant="body2">{assertion.label}</Typography>
                    <Typography variant="caption" color="text.secondary">{assertion.result.replaceAll('_', ' ')}</Typography>
                    {assertion.evidence_sha256 && (
                      <Typography variant="caption" color="text.secondary" display="block" sx={{ overflowWrap: 'anywhere' }}>
                        Evidence sha256:{assertion.evidence_sha256}
                      </Typography>
                    )}
                  </Box>
                </Stack>
              ))}
            </Stack>
          </Box>
          {scenario.publication_attestation && (
            <Box>
              <Typography variant="subtitle2" fontWeight={750} sx={{ mb: 0.5 }}>Automated publication verification</Typography>
              <Typography variant="caption" color="text.secondary" display="block">
                Published {new Date(scenario.publication_attestation.published_at).toLocaleString()}
              </Typography>
              <Typography variant="caption" color="text.secondary" display="block" sx={{ overflowWrap: 'anywhere' }}>
                Result sha256:{scenario.publication_attestation.result_sha256}
              </Typography>
            </Box>
          )}
          {scenario.revision_history.length > 0 && (
            <Box>
              <Typography variant="subtitle2" fontWeight={750} sx={{ mb: 0.5 }}>Earlier evidence revisions</Typography>
              {scenario.revision_history.map((revision) => (
                <Typography key={revision.scenario_revision} variant="caption" color="text.secondary" display="block">
                  Revision {revision.scenario_revision}: {revision.recording_classification.replaceAll('_', ' ')} / {revision.state.replaceAll('_', ' ')}
                </Typography>
              ))}
            </Box>
          )}
          {scenario.media_evidence && (
            <Box>
              <Typography variant="subtitle2" fontWeight={750} sx={{ mb: 0.5 }}>Media integrity</Typography>
              <Typography variant="caption" color="text.secondary" display="block" sx={{ overflowWrap: 'anywhere' }}>
                Video sha256:{scenario.media_evidence.video_sha256}
              </Typography>
              <Typography variant="caption" color="text.secondary" display="block" sx={{ overflowWrap: 'anywhere' }}>
                Captions sha256:{scenario.media_evidence.captions_sha256}
              </Typography>
            </Box>
          )}
          {scenario.wallets.length > 0 && (
            <Box>
              <Typography variant="subtitle2" fontWeight={750} sx={{ mb: 1 }}>Wallet evidence</Typography>
              <Stack spacing={1.5}>
                {scenario.wallets.map((wallet) => (
                  <Box key={`${wallet.implementation}-${wallet.build}`}>
                    <Typography variant="body2" fontWeight={700}>{wallet.implementation}</Typography>
                    <Typography variant="caption" color="text.secondary" display="block">{wallet.classification.replaceAll('_', ' ')} / {wallet.result}</Typography>
                    <Typography variant="caption" color="text.secondary" display="block" sx={{ overflowWrap: 'anywhere' }}>Build {wallet.build}</Typography>
                  </Box>
                ))}
              </Stack>
            </Box>
          )}
          {scenario.limitations.length > 0 && (
            <Alert severity="warning" icon={<PendingRoundedIcon />}>
              <Typography variant="subtitle2" fontWeight={700} sx={{ mb: 0.5 }}>Limitations</Typography>
              {scenario.limitations.map((limitation) => <Typography key={limitation} variant="body2" sx={{ mb: 0.5 }}>{limitation}</Typography>)}
            </Alert>
          )}
        </Stack>
      </Box>

      <Button component={RouterLink} to={`/demos/${manifest.stack_version}`} startIcon={<ArrowBackRoundedIcon />} sx={{ mt: 6 }}>
        All {manifest.release_name} scenarios
      </Button>
    </Box>
  );
}

export function DemoLatestScenarioRedirect() {
  const { scenario } = useParams();
  const indexResource = useAsyncResource((signal) => loadDemoIndex({ signal }), []);
  if (indexResource.status !== 'ready') return <LoadState resource={indexResource} label="latest approved release" />;
  const latest = indexResource.data.latest_approved_stack_version;
  if (latest) return <Navigate to={`/demos/${latest}/${scenario}`} replace />;
  return (
    <Alert severity="info" data-demo-render-state="settled" sx={{ my: 6 }}>
      No ElevenID LLC release has completed public approval yet.{' '}
      <Link component={RouterLink} to={`/demos/${indexResource.data.latest_available_stack_version}/${scenario}`}>
        View the current evidence preview
      </Link>.
    </Alert>
  );
}
