/**
 * ErrorBoundary Component
 * 
 * A React error boundary that catches JavaScript errors in child components,
 * displays a fallback UI, and reports errors to the backend /api/client-errors
 * endpoint for monitoring.
 * 
 * Usage:
 *   <ErrorBoundary>
 *     <YourComponent />
 *   </ErrorBoundary>
 * 
 * Or with custom fallback:
 *   <ErrorBoundary fallback={<CustomErrorUI />}>
 *     <YourComponent />
 *   </ErrorBoundary>
 */

import React, { Component } from 'react';
import { Box, Button, Container, Paper, Typography, Alert } from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import BugReportIcon from '@mui/icons-material/BugReport';
import HomeIcon from '@mui/icons-material/Home';
import { reportClientError } from '../services/api';

/**
 * Default fallback UI shown when an error occurs.
 */
const DefaultFallback = ({ error, errorInfo, onRetry, errorId }) => (
  <Container maxWidth="sm" sx={{ py: 8 }}>
    <Paper 
      elevation={3} 
      sx={{ 
        p: 4, 
        textAlign: 'center',
        borderTop: 4,
        borderColor: 'error.main',
      }}
    >
      <BugReportIcon 
        sx={{ fontSize: 64, color: 'error.main', mb: 2 }} 
      />
      
      <Typography variant="h5" gutterBottom color="error">
        Something went wrong
      </Typography>
      
      <Typography variant="body1" color="text.secondary" paragraph>
        We encountered an unexpected error. Our team has been notified and is working on a fix.
      </Typography>
      
      {errorId && (
        <Alert severity="info" sx={{ mb: 3, textAlign: 'left' }}>
          <Typography variant="body2">
            <strong>Error ID:</strong> {errorId}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            Share this ID with support if you need assistance.
          </Typography>
        </Alert>
      )}
      
      <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', mt: 3 }}>
        <Button
          variant="contained"
          startIcon={<RefreshIcon />}
          onClick={onRetry}
        >
          Try Again
        </Button>
        
        <Button
          variant="outlined"
          startIcon={<HomeIcon />}
          onClick={() => window.location.href = '/'}
        >
          Go Home
        </Button>
      </Box>
      
      {/* Show technical details in development */}
      {process.env.NODE_ENV === 'development' && error && (
        <Box sx={{ mt: 4, textAlign: 'left' }}>
          <Typography variant="subtitle2" color="error" gutterBottom>
            Technical Details (Development Only):
          </Typography>
          <Paper 
            variant="outlined" 
            sx={{ 
              p: 2, 
              bgcolor: 'grey.100',
              maxHeight: 200,
              overflow: 'auto',
            }}
          >
            <Typography 
              variant="body2" 
              component="pre" 
              sx={{ 
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                m: 0,
              }}
            >
              {error.toString()}
              {errorInfo?.componentStack}
            </Typography>
          </Paper>
        </Box>
      )}
    </Paper>
  </Container>
);


/**
 * ErrorBoundary class component.
 * 
 * React error boundaries must be class components as there's no
 * hook equivalent for componentDidCatch yet.
 */
class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = {
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null,
      isReporting: false,
    };
  }
  
  /**
   * Update state when an error is caught.
   */
  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }
  
  /**
   * Log error and report to backend.
   */
  componentDidCatch(error, errorInfo) {
    this.setState({ errorInfo });
    this.reportError(error, errorInfo);
  }
  
  /**
   * Report error to backend /api/client-errors endpoint.
   */
  async reportError(error, errorInfo) {
    if (this.state.isReporting) return;
    
    this.setState({ isReporting: true });
    
    try {
      // Get user info from localStorage/context if available
      let userId = null;
      let sessionId = null;
      try {
        const userStr = localStorage.getItem('user');
        if (userStr) {
          const user = JSON.parse(userStr);
          userId = user.id || user.sub;
        }
        sessionId = sessionStorage.getItem('sessionId');
      } catch (e) {
        // Ignore storage errors
      }
      
      const errorReport = {
        error_code: error.name || 'Error',
        message: error.message || String(error),
        stack_trace: error.stack || null,
        component_stack: errorInfo?.componentStack || null,
        url: window.location.href,
        user_agent: navigator.userAgent,
        user_id: userId,
        session_id: sessionId,
        timestamp: Date.now() / 1000,
        context: {
          route: window.location.pathname,
          referrer: document.referrer,
          screen: {
            width: window.innerWidth,
            height: window.innerHeight,
          },
        },
      };
      
      const response = await reportClientError(errorReport);
      
      if (response?.error_id) {
        this.setState({ errorId: response.error_id });
      }
      
      // Also log to console in development
      if (process.env.NODE_ENV === 'development') {
        console.error('Error caught by ErrorBoundary:', error);
        console.error('Component stack:', errorInfo?.componentStack);
        console.error('Error ID:', response?.error_id);
      }
    } catch (reportError) {
      // Don't let reporting failure cause more problems
      console.error('Failed to report error to server:', reportError);
    } finally {
      this.setState({ isReporting: false });
    }
  }
  
  /**
   * Reset error state to allow retry.
   */
  handleRetry = () => {
    this.setState({
      hasError: false,
      error: null,
      errorInfo: null,
      errorId: null,
    });
    
    // If onRetry prop is provided, call it
    if (this.props.onRetry) {
      this.props.onRetry();
    }
  };
  
  render() {
    const { hasError, error, errorInfo, errorId } = this.state;
    const { children, fallback, FallbackComponent } = this.props;
    
    if (hasError) {
      // If a custom fallback element is provided, use it
      if (fallback) {
        return fallback;
      }
      
      // If a custom FallbackComponent is provided, render it with props
      if (FallbackComponent) {
        return (
          <FallbackComponent
            error={error}
            errorInfo={errorInfo}
            errorId={errorId}
            onRetry={this.handleRetry}
          />
        );
      }
      
      // Use default fallback
      return (
        <DefaultFallback
          error={error}
          errorInfo={errorInfo}
          errorId={errorId}
          onRetry={this.handleRetry}
        />
      );
    }
    
    return children;
  }
}


/**
 * Higher-order component to wrap a component with ErrorBoundary.
 * 
 * Usage:
 *   export default withErrorBoundary(MyComponent);
 */
export function withErrorBoundary(WrappedComponent, errorBoundaryProps = {}) {
  const displayName = WrappedComponent.displayName || WrappedComponent.name || 'Component';
  
  const ComponentWithErrorBoundary = (props) => (
    <ErrorBoundary {...errorBoundaryProps}>
      <WrappedComponent {...props} />
    </ErrorBoundary>
  );
  
  ComponentWithErrorBoundary.displayName = `withErrorBoundary(${displayName})`;
  
  return ComponentWithErrorBoundary;
}


/**
 * Hook to manually trigger error reporting without crashing the UI.
 * 
 * Usage:
 *   const reportError = useErrorReporter();
 *   try {
 *     // risky operation
 *   } catch (error) {
 *     reportError(error, { context: 'additional info' });
 *   }
 */
export function useErrorReporter() {
  return async (error, additionalContext = {}) => {
    try {
      let userId = null;
      let sessionId = null;
      try {
        const userStr = localStorage.getItem('user');
        if (userStr) {
          const user = JSON.parse(userStr);
          userId = user.id || user.sub;
        }
        sessionId = sessionStorage.getItem('sessionId');
      } catch (e) {
        // Ignore
      }
      
      const errorReport = {
        error_code: error.name || 'Error',
        message: error.message || String(error),
        stack_trace: error.stack || null,
        component_stack: null,
        url: window.location.href,
        user_agent: navigator.userAgent,
        user_id: userId,
        session_id: sessionId,
        timestamp: Date.now() / 1000,
        context: {
          route: window.location.pathname,
          ...additionalContext,
        },
      };
      
      const response = await reportClientError(errorReport);
      return response?.error_id;
    } catch (reportError) {
      console.error('Failed to report error:', reportError);
      return null;
    }
  };
}


export default ErrorBoundary;
