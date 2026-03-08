/**
 * Stats Hook
 * Fetches dashboard statistics with configurable time window
 */

import { useQuery } from '@tanstack/react-query';
import { api } from '../../lib/api';
import { queryKeys } from '../../lib/query-keys';

/** Poll stats every 15 seconds — powers the overview stat cards */
export function useStats(since?: string) {
  return useQuery({
    queryKey: queryKeys.stats.since(since),
    queryFn: () => api.stats(since),
    refetchInterval: 15_000,
  });
}
