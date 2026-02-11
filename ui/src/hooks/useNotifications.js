import { useContext } from 'react';
import { NotificationContext } from '../contexts/NotificationContext';

/**
 * Hook to access notification context
 * 
 * @returns {Object} Notification context methods
 */
export function useNotifications() {
  const context = useContext(NotificationContext);
  
  if (!context) {
    throw new Error('useNotifications must be used within a NotificationProvider');
  }
  
  return context;
}
