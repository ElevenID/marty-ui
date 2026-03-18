import { get } from '../../services/api';
import {
  HOME_DEFAULT_STATS,
  HOME_DEFAULT_SYSTEM_STATUS,
  resolveHomeStats,
  resolveHomeSystemStatus,
} from './homeFlow';

async function defaultGetHomeHealth() {
  return get('/api/health');
}

async function defaultGetHomeStats() {
  return get('/api/admin/stats');
}

export async function loadHomeDashboard({
  getHomeHealth = defaultGetHomeHealth,
  getHomeStats = defaultGetHomeStats,
} = {}) {
  const [healthResult, statsResult] = await Promise.allSettled([
    getHomeHealth(),
    getHomeStats(),
  ]);

  return {
    systemStatus: healthResult.status === 'fulfilled'
      ? resolveHomeSystemStatus(healthResult.value, HOME_DEFAULT_SYSTEM_STATUS)
      : HOME_DEFAULT_SYSTEM_STATUS,
    stats: statsResult.status === 'fulfilled'
      ? resolveHomeStats(statsResult.value, HOME_DEFAULT_STATS)
      : HOME_DEFAULT_STATS,
  };
}