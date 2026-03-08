/**
 * Health Hook
 * Polls the Aegis health endpoint for connection status
 */

import { useQuery } from '@tanstack/react-query';
import { api } from '../../lib/api';
import { queryKeys } from '../../lib/query-keys';

/** Poll health every 10 seconds — powers the "Connected" indicator */
export function useHealth() {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: () => api.health(),
    refetchInterval: 10_000,
  });
}
