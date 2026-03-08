/**
 * Users Hook
 * Fetches RBAC user list
 */

import { useQuery } from '@tanstack/react-query';
import { api } from '../../lib/api';
import { queryKeys } from '../../lib/query-keys';

/** Refresh users every 30 seconds — they change infrequently */
export function useUsers() {
  return useQuery({
    queryKey: queryKeys.users.all,
    queryFn: () => api.users(),
    refetchInterval: 30_000,
  });
}
