/**
 * Agents Hook
 * Fetches registered agent list with grants
 */

import { useQuery } from '@tanstack/react-query';
import { api } from '../../lib/api';
import { queryKeys } from '../../lib/query-keys';

/** Refresh agents every 30 seconds — they change infrequently */
export function useAgents() {
  return useQuery({
    queryKey: queryKeys.agents.all,
    queryFn: () => api.agents(),
    refetchInterval: 30_000,
  });
}
