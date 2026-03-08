/**
 * Credentials Hook
 * Fetches vault credential metadata (never values)
 */

import { useQuery } from '@tanstack/react-query';
import { api } from '../../lib/api';
import { queryKeys } from '../../lib/query-keys';

/** Refresh credentials every 30 seconds — they change infrequently */
export function useCredentials() {
  return useQuery({
    queryKey: queryKeys.credentials.all,
    queryFn: () => api.credentials(),
    refetchInterval: 30_000,
  });
}
