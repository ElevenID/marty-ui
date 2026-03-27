/**
 * Interactive Protocol Map
 *
 * SVG-based interactive diagram showing the Marty Protocol architecture.
 * Features:
 *   - Four core primitives connected in a diamond
 *   - Three identity actors (Issuer, Holder, Verifier) across the top
 *   - Surrounding ecosystem standards with connections
 *   - Hover tooltips with descriptions
 *   - Click-to-navigate to guide articles
 *   - Concept / Implementation view toggle
 *   - Highlighted active node when rendered from a guide page
 *   - Mobile stacked layout
 */

import { useState, useCallback, useRef, useEffect } from 'react';
import {
  Box,
  Typography,
  Paper,
  Tooltip,
  Button,
  ButtonGroup,
  Chip,
  useMediaQuery,
  useTheme,
  Fade,
} from '@mui/material';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import DescriptionIcon from '@mui/icons-material/Description';
import PolicyIcon from '@mui/icons-material/Policy';
import CloudUploadIcon from '@mui/icons-material/CloudUpload';
import AccountTreeIcon from '@mui/icons-material/AccountTree';
import PersonIcon from '@mui/icons-material/Person';
import BusinessIcon from '@mui/icons-material/Business';
import SecurityIcon from '@mui/icons-material/Security';
import SchoolIcon from '@mui/icons-material/School';
import CodeIcon from '@mui/icons-material/Code';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import { useNavigate } from 'react-router-dom';

// ── Node definitions ───────────────────────────────────────────────────────────

const ACTORS = [
  {
    id: 'issuer',
    label: 'Issuer',
    description: 'Creates and signs verifiable credentials.',
    icon: 'Business',
    slug: 'issuance-flows',
    color: '#1565c0',
  },
  {
    id: 'holder',
    label: 'Holder',
    description: 'Stores credentials in a wallet and controls disclosure.',
    icon: 'Person',
    slug: 'foundations-credentials',
    color: '#6a1b9a',
  },
  {
    id: 'verifier',
    label: 'Verifier',
    description: 'Validates proofs and makes access decisions.',
    icon: 'Security',
    slug: 'foundations-verification',
    color: '#2e7d32',
  },
];

const PRIMITIVES = [
  {
    id: 'trust-profile',
    label: 'Trust Profiles',
    shortLabel: 'Trust',
    description: 'Define who is trusted to issue credentials and how to validate their signatures.',
    icon: 'VerifiedUser',
    slug: 'trust-profiles',
    color: '#1565c0',
    implLabel: 'PKI / X.509 / DID',
    deps: ['issuer', 'verifier'],
  },
  {
    id: 'credential-template',
    label: 'Credential Templates',
    shortLabel: 'Templates',
    description: 'Define what gets issued — schema, claims, validity, and disclosure rules.',
    icon: 'Description',
    slug: 'credential-templates',
    color: '#7b1fa2',
    implLabel: 'JSON-LD VC / SD-JWT',
    deps: ['issuer', 'trust-profile'],
  },
  {
    id: 'presentation-policy',
    label: 'Presentation Policies',
    shortLabel: 'Policies',
    description: 'Define what the verifier needs to see — and nothing more.',
    icon: 'Policy',
    slug: 'presentation-policies',
    color: '#00695c',
    implLabel: 'OID4VP / PE',
    deps: ['verifier', 'credential-template', 'trust-profile'],
  },
  {
    id: 'deployment-profile',
    label: 'Deployment Profiles',
    shortLabel: 'Deployments',
    description: 'Configure operational environments — online, offline, cache TTLs, and update schedules.',
    icon: 'CloudUpload',
    slug: 'deployment-profiles',
    color: '#e65100',
    implLabel: 'Runtime / Infrastructure',
    deps: ['trust-profile', 'presentation-policy'],
  },
];

const ECOSYSTEM = [
  {
    id: 'oid4vci',
    label: 'OID4VCI',
    description: 'OpenID for Verifiable Credential Issuance — standard issuance protocol.',
    slug: 'impl-oid4vci',
    color: '#0277bd',
    connects: ['credential-template', 'issuer'],
  },
  {
    id: 'oid4vp',
    label: 'OID4VP',
    description: 'OpenID for Verifiable Presentations — standard presentation protocol.',
    slug: 'impl-oid4vp',
    color: '#00838f',
    connects: ['presentation-policy', 'verifier'],
  },
  {
    id: 'mdoc',
    label: 'mDoc',
    description: 'ISO 18013-5 mobile document format for driver\'s licences and government credentials.',
    slug: 'impl-mdoc',
    color: '#4527a0',
    connects: ['deployment-profile', 'credential-template'],
  },
  {
    id: 'icao',
    label: 'ICAO DTC',
    description: 'Digital Travel Credentials for passports and border verification.',
    slug: 'impl-icao-dtc',
    color: '#283593',
    connects: ['trust-profile', 'deployment-profile'],
  },
  {
    id: 'open-badges',
    label: 'Open Badges',
    description: 'Education and workforce credentials based on Open Badges 3.0.',
    slug: 'impl-open-badges',
    color: '#ad1457',
    connects: ['credential-template', 'trust-profile'],
  },
  {
    id: 'pki',
    label: 'PKI',
    description: 'X.509 certificate chains, CSCA roots, and key management.',
    slug: 'pki-certificate-chains',
    color: '#37474f',
    connects: ['trust-profile'],
  },
];

const FLOW_NODE = {
  id: 'flow',
  label: 'Flows',
  description: 'Orchestrate issuance, presentation, and revocation across all primitives.',
  icon: 'AccountTree',
  slug: 'issuance-flows',
  color: '#00897b',
};

const ALL_NODES = [
  ...ACTORS,
  ...PRIMITIVES,
  { ...FLOW_NODE },
  ...ECOSYSTEM,
];

const NODE_MAP = Object.fromEntries(ALL_NODES.map((n) => [n.id, n]));

// ── Icons map ──────────────────────────────────────────────────────────────────

const ICON_MAP = {
  VerifiedUser: VerifiedUserIcon,
  Description: DescriptionIcon,
  Policy: PolicyIcon,
  CloudUpload: CloudUploadIcon,
  AccountTree: AccountTreeIcon,
  Person: PersonIcon,
  Business: BusinessIcon,
  Security: SecurityIcon,
};

// ── Desktop SVG Map ────────────────────────────────────────────────────────────

function DesktopProtocolMap({ hoveredId, setHoveredId, navigate, highlightSlug, viewMode }) {
  const svgRef = useRef(null);

  // Layout constants for 900×500 viewBox
  const W = 900;
  const H = 500;

  // Actors placement (top row)
  const actorPositions = {
    issuer:   { x: 150, y: 65 },
    holder:   { x: 450, y: 65 },
    verifier: { x: 750, y: 65 },
  };

  // Primitives placement (diamond in center)
  const primPositions = {
    'trust-profile':       { x: 450, y: 175 },
    'credential-template': { x: 200, y: 290 },
    'presentation-policy': { x: 700, y: 290 },
    'deployment-profile':  { x: 450, y: 400 },
  };

  // Flow in center
  const flowPos = { x: 450, y: 290 };

  // Ecosystem around the edges
  const ecoPositions = {
    oid4vci:      { x: 55,  y: 175 },
    oid4vp:       { x: 845, y: 175 },
    mdoc:         { x: 845, y: 400 },
    icao:         { x: 55,  y: 400 },
    'open-badges':{ x: 55,  y: 290 },
    pki:          { x: 845, y: 290 },
  };

  // Connection lines
  const connections = [
    // Actors to primitives
    { from: actorPositions.issuer, to: primPositions['credential-template'], dashed: false },
    { from: actorPositions.holder, to: primPositions['trust-profile'], dashed: false },
    { from: actorPositions.verifier, to: primPositions['presentation-policy'], dashed: false },
    // Diamond connections
    { from: primPositions['trust-profile'], to: primPositions['credential-template'], dashed: false },
    { from: primPositions['trust-profile'], to: primPositions['presentation-policy'], dashed: false },
    { from: primPositions['credential-template'], to: primPositions['deployment-profile'], dashed: false },
    { from: primPositions['presentation-policy'], to: primPositions['deployment-profile'], dashed: false },
    // Flow connects
    { from: primPositions['trust-profile'], to: flowPos, dashed: true },
    { from: primPositions['deployment-profile'], to: flowPos, dashed: true },
    // Actor chain
    { from: actorPositions.issuer, to: actorPositions.holder, dashed: false, label: 'issues' },
    { from: actorPositions.holder, to: actorPositions.verifier, dashed: false, label: 'presents' },
  ];

  // Ecosystem connections
  const ecoConnections = ECOSYSTEM.map((eco) => ({
    from: ecoPositions[eco.id],
    to: primPositions[eco.connects[0]] || actorPositions[eco.connects[0]],
    dashed: true,
    light: true,
  }));

  // Compute which nodes should be highlighted based on hover
  const highlightSet = new Set();
  if (hoveredId) {
    highlightSet.add(hoveredId);
    const node = NODE_MAP[hoveredId];
    if (node?.deps) node.deps.forEach((d) => highlightSet.add(d));
    if (node?.connects) node.connects.forEach((c) => highlightSet.add(c));
    // Reverse deps: find nodes that depend on hovered
    PRIMITIVES.forEach((p) => { if (p.deps?.includes(hoveredId)) highlightSet.add(p.id); });
    ECOSYSTEM.forEach((e) => { if (e.connects?.includes(hoveredId)) highlightSet.add(e.id); });
  }

  // Also highlight node matching current guide article
  const activeNodeId = highlightSlug
    ? ALL_NODES.find((n) => n.slug === highlightSlug)?.id
    : null;

  const getNodeOpacity = (id) => {
    if (!hoveredId) return 1;
    return highlightSet.has(id) ? 1 : 0.2;
  };

  const renderNodeBox = (node, pos, size = 'normal') => {
    const isActive = activeNodeId === node.id;
    const opacity = getNodeOpacity(node.id);
    const isHovered = hoveredId === node.id;
    const w = size === 'small' ? 100 : size === 'actor' ? 120 : 140;
    const h = size === 'small' ? 44 : size === 'actor' ? 52 : 60;

    const IconComponent = ICON_MAP[node.icon];

    return (
      <Tooltip
        key={node.id}
        title={
          <Box sx={{ p: 0.5 }}>
            <Typography variant="body2" fontWeight={700}>{node.label}</Typography>
            <Typography variant="caption">{node.description}</Typography>
            {viewMode === 'implementation' && node.implLabel && (
              <Chip label={node.implLabel} size="small" sx={{ mt: 0.5, fontSize: '0.65rem', height: 18, bgcolor: 'rgba(255,255,255,0.15)' }} />
            )}
          </Box>
        }
        arrow
        placement="top"
      >
        <g
          style={{ cursor: 'pointer', opacity, transition: 'opacity 0.2s' }}
          onMouseEnter={() => setHoveredId(node.id)}
          onMouseLeave={() => setHoveredId(null)}
          onClick={() => navigate(`/blog/${node.slug}`)}
        >
          <rect
            x={pos.x - w / 2}
            y={pos.y - h / 2}
            width={w}
            height={h}
            rx={8}
            fill={isHovered ? node.color : 'white'}
            stroke={isActive ? '#ffd600' : node.color}
            strokeWidth={isActive ? 3 : isHovered ? 2.5 : 1.5}
          />
          {isActive && (
            <rect
              x={pos.x - w / 2 - 3}
              y={pos.y - h / 2 - 3}
              width={w + 6}
              height={h + 6}
              rx={11}
              fill="none"
              stroke="#ffd600"
              strokeWidth={2}
              strokeDasharray="4 3"
            />
          )}
          <text
            x={pos.x}
            y={pos.y + (size === 'small' ? 1 : 3)}
            textAnchor="middle"
            dominantBaseline="middle"
            fill={isHovered ? 'white' : node.color}
            fontSize={size === 'small' ? 11 : size === 'actor' ? 13 : 13}
            fontWeight={700}
            fontFamily="system-ui, -apple-system, sans-serif"
          >
            {node.shortLabel || node.label}
          </text>
          {viewMode === 'implementation' && node.implLabel && !isHovered && (
            <text
              x={pos.x}
              y={pos.y + h / 2 + 13}
              textAnchor="middle"
              dominantBaseline="middle"
              fill="#666"
              fontSize={9}
              fontFamily="monospace"
            >
              {node.implLabel}
            </text>
          )}
        </g>
      </Tooltip>
    );
  };

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${W} ${H}`}
      style={{ width: '100%', height: 'auto', maxHeight: 520 }}
    >
      {/* Connections */}
      <g>
        {[...connections, ...ecoConnections].map((conn, i) => (
          <line
            key={i}
            x1={conn.from.x}
            y1={conn.from.y}
            x2={conn.to.x}
            y2={conn.to.y}
            stroke={conn.light ? '#e0e0e0' : '#bdbdbd'}
            strokeWidth={conn.light ? 1 : 1.5}
            strokeDasharray={conn.dashed ? '5 4' : undefined}
            opacity={hoveredId ? 0.3 : 0.6}
          />
        ))}
        {/* Actor chain labels */}
        {connections.filter((c) => c.label).map((conn, i) => {
          const mx = (conn.from.x + conn.to.x) / 2;
          const my = (conn.from.y + conn.to.y) / 2 - 8;
          return (
            <text
              key={`label-${i}`}
              x={mx}
              y={my}
              textAnchor="middle"
              fill="#9e9e9e"
              fontSize={10}
              fontStyle="italic"
              fontFamily="system-ui, sans-serif"
            >
              {conn.label}
            </text>
          );
        })}
      </g>

      {/* Actors */}
      {ACTORS.map((a) => renderNodeBox(a, actorPositions[a.id], 'actor'))}

      {/* Primitives */}
      {PRIMITIVES.map((p) => renderNodeBox(p, primPositions[p.id]))}

      {/* Flow */}
      {renderNodeBox(FLOW_NODE, flowPos, 'small')}

      {/* Ecosystem */}
      {ECOSYSTEM.map((e) => renderNodeBox(e, ecoPositions[e.id], 'small'))}
    </svg>
  );
}

// ── Mobile stacked layout ──────────────────────────────────────────────────────

function MobileProtocolMap({ navigate, highlightSlug }) {
  const sections = [
    { title: 'Identity Actors', nodes: ACTORS },
    { title: 'Core Primitives', nodes: PRIMITIVES },
    { title: 'Flows', nodes: [FLOW_NODE] },
    { title: 'Ecosystem Standards', nodes: ECOSYSTEM },
  ];

  const activeSlug = highlightSlug || null;

  return (
    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
      {sections.map((section) => (
        <Box key={section.title}>
          <Typography
            variant="caption"
            fontWeight={700}
            color="text.secondary"
            sx={{ textTransform: 'uppercase', letterSpacing: '0.07em', mb: 1, display: 'block' }}
          >
            {section.title}
          </Typography>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            {section.nodes.map((node) => {
              const isActive = node.slug === activeSlug;
              return (
                <Paper
                  key={node.id}
                  variant={isActive ? 'elevation' : 'outlined'}
                  elevation={isActive ? 3 : 0}
                  onClick={() => navigate(`/blog/${node.slug}`)}
                  sx={{
                    p: 2,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 1.5,
                    cursor: 'pointer',
                    borderLeft: `4px solid ${node.color}`,
                    borderColor: isActive ? '#ffd600' : undefined,
                    bgcolor: isActive ? 'primary.50' : 'background.paper',
                    transition: 'all 0.2s',
                    '&:hover': { bgcolor: 'grey.50', transform: 'translateX(4px)' },
                  }}
                >
                  <Box sx={{ flexGrow: 1 }}>
                    <Typography variant="body2" fontWeight={700}>
                      {node.label}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">
                      {node.description}
                    </Typography>
                  </Box>
                  <ArrowForwardIcon sx={{ fontSize: 16, color: 'text.disabled' }} />
                </Paper>
              );
            })}
          </Box>
          {/* Connector arrow between sections */}
          {section.title !== 'Ecosystem Standards' && (
            <Box sx={{ textAlign: 'center', py: 0.5 }}>
              <Typography variant="caption" color="text.disabled">▼</Typography>
            </Box>
          )}
        </Box>
      ))}
    </Box>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────────

function InteractiveProtocolMap({ highlightSlug = null, compact = false }) {
  const [hoveredId, setHoveredId] = useState(null);
  const [viewMode, setViewMode] = useState('concept');
  const navigate = useNavigate();
  const theme = useTheme();
  const isMd = useMediaQuery(theme.breakpoints.up('md'));

  return (
    <Box>
      {/* Header + view toggle */}
      {!compact && (
        <Box
          sx={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            mb: 2,
            flexWrap: 'wrap',
            gap: 1,
          }}
        >
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <SchoolIcon color="primary" fontSize="small" />
            <Typography variant="subtitle2" fontWeight={700} color="primary">
              Interactive Protocol Map
            </Typography>
            <Typography variant="caption" color="text.secondary">
              — click any node to read its guide
            </Typography>
          </Box>
          <ButtonGroup size="small" variant="outlined">
            <Button
              onClick={() => setViewMode('concept')}
              variant={viewMode === 'concept' ? 'contained' : 'outlined'}
            >
              Concept View
            </Button>
            <Button
              onClick={() => setViewMode('implementation')}
              variant={viewMode === 'implementation' ? 'contained' : 'outlined'}
            >
              Implementation View
            </Button>
          </ButtonGroup>
        </Box>
      )}

      {/* Map */}
      <Paper
        variant="outlined"
        sx={{
          p: { xs: 2, md: 3 },
          borderRadius: 2,
          bgcolor: 'grey.50',
          overflow: 'hidden',
        }}
      >
        {isMd ? (
          <DesktopProtocolMap
            hoveredId={hoveredId}
            setHoveredId={setHoveredId}
            navigate={navigate}
            highlightSlug={highlightSlug}
            viewMode={viewMode}
          />
        ) : (
          <MobileProtocolMap
            navigate={navigate}
            highlightSlug={highlightSlug}
          />
        )}
      </Paper>

      {/* Legend / hint (non-compact) */}
      {!compact && (
        <Box sx={{ display: 'flex', gap: 2, mt: 1.5, flexWrap: 'wrap', justifyContent: 'center' }}>
          {[
            { label: 'Core Primitive', color: '#1565c0' },
            { label: 'Identity Actor', color: '#6a1b9a' },
            { label: 'Standard', color: '#00695c' },
          ].map((item) => (
            <Box key={item.label} sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
              <Box sx={{ width: 10, height: 10, borderRadius: '50%', bgcolor: item.color }} />
              <Typography variant="caption" color="text.secondary">
                {item.label}
              </Typography>
            </Box>
          ))}
        </Box>
      )}
    </Box>
  );
}

export default InteractiveProtocolMap;
