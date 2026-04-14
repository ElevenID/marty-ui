import { Button, Tooltip } from '@mui/material';

export const DEFAULT_FUTURE_FEATURE_TOOLTIP = 'Available soon in production';

function FutureFeatureButton({
  disabled = false,
  disabledTitle = DEFAULT_FUTURE_FEATURE_TOOLTIP,
  disabledSx = {},
  sx,
  component,
  href,
  to,
  onClick,
  children,
  ...props
}) {
  const buttonSx = Array.isArray(sx) ? [...sx] : [sx];

  if (disabled) {
    buttonSx.push({
      boxShadow: 'none',
      '&.Mui-disabled': {
        opacity: 1,
        boxShadow: 'none',
        pointerEvents: 'none',
        ...disabledSx,
      },
    });
  }

  const resolvedProps = {
    ...props,
    sx: buttonSx.filter(Boolean),
    component,
    href,
    to,
    onClick,
  };

  if (disabled) {
    delete resolvedProps.component;
    delete resolvedProps.href;
    delete resolvedProps.to;
    delete resolvedProps.onClick;
  }

  return (
    <Tooltip
      title={disabled ? disabledTitle : ''}
      disableFocusListener={!disabled}
      disableHoverListener={!disabled}
      disableTouchListener={!disabled}
    >
      <span>
        <Button disabled={disabled} {...resolvedProps}>
          {children}
        </Button>
      </span>
    </Tooltip>
  );
}

export default FutureFeatureButton;