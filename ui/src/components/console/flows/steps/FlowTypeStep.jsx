/**
 * Flow Type Selection Step
 * 
 * Choose between Verification, Issuance, or Combined flow types
 */

import {
  Box,
  Typography,
  Card,
  CardContent,
  CardActionArea,
  Grid,
} from '@mui/material';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import BadgeIcon from '@mui/icons-material/Badge';
import AccountTreeIcon from '@mui/icons-material/AccountTree';

const FLOW_TYPES = [
  {
    value: 'verification',
    icon: <VerifiedUserIcon sx={{ fontSize: 48 }} />,
    name: 'Verification Flow',
    description: 'Request and verify credentials from holders (OID4VP)',
    emoji: '🔍',
    examples: ['Age verification', 'Identity check', 'Access control'],
  },
  {
    value: 'issuance',
    icon: <BadgeIcon sx={{ fontSize: 48 }} />,
    name: 'Issuance Flow',
    description: 'Issue new credentials to holders (OID4VCI)',
    emoji: '📄',
    examples: ['Driver\'s license issuance', 'Employee badge', 'Proof of vaccination'],
  },
  {
    value: 'combined',
    icon: <AccountTreeIcon sx={{ fontSize: 48 }} />,
    name: 'Combined Flow',
    description: 'Verify existing credentials, then issue new ones',
    emoji: '🔄',
    examples: ['Upgrade license', 'Renewal with verification', 'Progressive disclosure'],
  },
];

const FlowTypeStep = ({ selectedType, onSelectType }) => {
  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        Select Flow Type
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        Choose the type of flow based on your use case
      </Typography>

      <Grid container spacing={3}>
        {FLOW_TYPES.map((type) => (
          <Grid item xs={12} md={4} key={type.value}>
            <Card
              sx={{
                height: '100%',
                border: 2,
                borderColor: selectedType === type.value ? 'primary.main' : 'transparent',
                transition: 'all 0.2s',
                '&:hover': {
                  borderColor: 'primary.light',
                  boxShadow: 4,
                },
              }}
            >
              <CardActionArea
                onClick={() => onSelectType(type.value)}
                sx={{ height: '100%', p: 2 }}
              >
                <CardContent>
                  {/* Icon & Emoji */}
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <Typography variant="h2" component="span" sx={{ mr: 2 }}>
                      {type.emoji}
                    </Typography>
                    <Box sx={{ color: 'primary.main' }}>
                      {type.icon}
                    </Box>
                  </Box>

                  {/* Title */}
                  <Typography variant="h6" gutterBottom>
                    {type.name}
                  </Typography>

                  {/* Description */}
                  <Typography variant="body2" color="text.secondary" paragraph>
                    {type.description}
                  </Typography>

                  {/* Examples */}
                  <Typography variant="caption" color="text.secondary" sx={{ fontStyle: 'italic' }}>
                    Examples:
                  </Typography>
                  <Box component="ul" sx={{ pl: 2, mt: 0.5 }}>
                    {type.examples.map((example, idx) => (
                      <Typography
                        key={idx}
                        component="li"
                        variant="caption"
                        color="text.secondary"
                      >
                        {example}
                      </Typography>
                    ))}
                  </Box>
                </CardContent>
              </CardActionArea>
            </Card>
          </Grid>
        ))}
      </Grid>
    </Box>
  );
};

export default FlowTypeStep;
