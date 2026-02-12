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
import { useTranslation } from 'react-i18next';

const getFlowTypes = (t) => [
  {
    value: 'verification',
    icon: <VerifiedUserIcon sx={{ fontSize: 48 }} />,
    name: t('wizards.flowDefinition.flowTypeStep.types.verification.name'),
    description: t('wizards.flowDefinition.flowTypeStep.types.verification.description'),
    emoji: '🔍',
    examples: [
      t('wizards.flowDefinition.flowTypeStep.types.verification.example1'),
      t('wizards.flowDefinition.flowTypeStep.types.verification.example2'),
      t('wizards.flowDefinition.flowTypeStep.types.verification.example3'),
    ],
  },
  {
    value: 'issuance',
    icon: <BadgeIcon sx={{ fontSize: 48 }} />,
    name: t('wizards.flowDefinition.flowTypeStep.types.issuance.name'),
    description: t('wizards.flowDefinition.flowTypeStep.types.issuance.description'),
    emoji: '📄',
    examples: [
      t('wizards.flowDefinition.flowTypeStep.types.issuance.example1'),
      t('wizards.flowDefinition.flowTypeStep.types.issuance.example2'),
      t('wizards.flowDefinition.flowTypeStep.types.issuance.example3'),
    ],
  },
  {
    value: 'issuance_oid4vci',
    icon: <BadgeIcon sx={{ fontSize: 48 }} />,
    name: t('wizards.flowDefinition.flowTypeStep.types.issuance_oid4vci.name'),
    description: t('wizards.flowDefinition.flowTypeStep.types.issuance_oid4vci.description'),
    emoji: '📱',
    examples: [
      t('wizards.flowDefinition.flowTypeStep.types.issuance_oid4vci.example1'),
      t('wizards.flowDefinition.flowTypeStep.types.issuance_oid4vci.example2'),
      t('wizards.flowDefinition.flowTypeStep.types.issuance_oid4vci.example3'),
    ],
  },
  {
    value: 'combined',
    icon: <AccountTreeIcon sx={{ fontSize: 48 }} />,
    name: t('wizards.flowDefinition.flowTypeStep.types.combined.name'),
    description: t('wizards.flowDefinition.flowTypeStep.types.combined.description'),
    emoji: '🔄',
    examples: [
      t('wizards.flowDefinition.flowTypeStep.types.combined.example1'),
      t('wizards.flowDefinition.flowTypeStep.types.combined.example2'),
      t('wizards.flowDefinition.flowTypeStep.types.combined.example3'),
    ],
  },
];

const FlowTypeStep = ({ selectedType, onSelectType }) => {
  const { t } = useTranslation('console');

  return (
    <Box>
      <Typography variant="h6" gutterBottom>
        {t('wizards.flowDefinition.flowTypeStep.title')}
      </Typography>
      
      <Typography color="text.secondary" paragraph>
        {t('wizards.flowDefinition.flowTypeStep.description')}
      </Typography>

      <Grid container spacing={3}>
        {getFlowTypes(t).map((type) => (
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
              data-testid={`flow-type-${type.value}`}
            >
              <CardActionArea
                onClick={() => onSelectType(type.value)}
                sx={{ height: '100%', p: 2 }}
                aria-selected={selectedType === type.value}
                role="button"
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
                    {t('wizards.flowDefinition.flowTypeStep.examples')}
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
