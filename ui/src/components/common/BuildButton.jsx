/**
 * BuildButton Component
 * 
 * Primary CTA for resource pages with Build (wizard) and New (advanced) options.
 * Follows the pattern: "Build" launches wizard, "New (Advanced)" opens raw form.
 */

import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  Button,
  ButtonGroup,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Divider,
} from '@mui/material';
import AddIcon from '@mui/icons-material/Add';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';
import CodeIcon from '@mui/icons-material/Code';
import ArrowDropDownIcon from '@mui/icons-material/ArrowDropDown';

/**
 * BuildButton Component
 * 
 * @param {string} resourceName - Display name of the resource (e.g., "Trust Profile", "Template")
 * @param {string} buildPath - Path to the wizard/build flow
 * @param {string} newPath - Path to the advanced/raw form (optional)
 * @param {function} onBuild - Callback when Build is clicked (alternative to buildPath)
 * @param {function} onNew - Callback when New is clicked (alternative to newPath)
 * @param {boolean} disabled - Disable the button
 * @param {string} size - Button size (small, medium, large)
 */
function BuildButton({
  resourceName,
  buildPath,
  newPath,
  onBuild,
  onNew,
  disabled = false,
  size = 'medium',
}) {
  const { t } = useTranslation('common');
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState(null);
  const open = Boolean(anchorEl);

  const handleMenuOpen = useCallback((event) => {
    setAnchorEl(event.currentTarget);
  }, []);

  const handleMenuClose = useCallback(() => {
    setAnchorEl(null);
  }, []);

  const handleBuild = useCallback(() => {
    handleMenuClose();
    if (onBuild) {
      onBuild();
    } else if (buildPath) {
      navigate(buildPath);
    }
  }, [buildPath, navigate, onBuild, handleMenuClose]);

  const handleNew = useCallback(() => {
    handleMenuClose();
    if (onNew) {
      onNew();
    } else if (newPath) {
      navigate(newPath);
    }
  }, [newPath, navigate, onNew, handleMenuClose]);

  // If no advanced option, show simple button
  if (!newPath && !onNew) {
    return (
      <Button
        variant="contained"
        color="primary"
        startIcon={<AutoFixHighIcon />}
        onClick={handleBuild}
        disabled={disabled}
        size={size}
      >
        {t('buildButton.build', { resourceName })}
      </Button>
    );
  }

  // Show button group with dropdown for advanced option
  return (
    <>
      <ButtonGroup
        variant="contained"
        color="primary"
        disabled={disabled}
        size={size}
        aria-label={t('buildButton.build', { resourceName })}
      >
        <Button
          startIcon={<AutoFixHighIcon />}
          onClick={handleBuild}
        >
          {t('buildButton.build', { resourceName })}
        </Button>
        <Button
          size="small"
          aria-controls={open ? 'build-menu' : undefined}
          aria-expanded={open ? 'true' : undefined}
          aria-haspopup="menu"
          onClick={handleMenuOpen}
        >
          <ArrowDropDownIcon />
        </Button>
      </ButtonGroup>
      <Menu
        id="build-menu"
        anchorEl={anchorEl}
        open={open}
        onClose={handleMenuClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
      >
        <MenuItem onClick={handleBuild}>
          <ListItemIcon>
            <AutoFixHighIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText 
            primary={t('buildButton.build', { resourceName })}
            secondary={t('buildButton.guidedWizard')}
          />
        </MenuItem>
        <Divider />
        <MenuItem onClick={handleNew}>
          <ListItemIcon>
            <CodeIcon fontSize="small" />
          </ListItemIcon>
          <ListItemText 
            primary={t('buildButton.newAdvanced')}
            secondary={t('buildButton.rawFormEditor')}
          />
        </MenuItem>
      </Menu>
    </>
  );
}

/**
 * Simple Add Button (for secondary actions)
 */
export function AddButton({ label, onClick, path, disabled = false, size = 'medium' }) {
  const navigate = useNavigate();

  const handleClick = useCallback(() => {
    if (onClick) {
      onClick();
    } else if (path) {
      navigate(path);
    }
  }, [onClick, path, navigate]);

  return (
    <Button
      variant="outlined"
      color="primary"
      startIcon={<AddIcon />}
      onClick={handleClick}
      disabled={disabled}
      size={size}
    >
      {label}
    </Button>
  );
}

export default BuildButton;
