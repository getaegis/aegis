/**
 * Requests Hook
 * Fetches audit log entries with optional filters
 */

import { useQuery } from '@tanstack/react-query';
import { api } from '../../lib/api';
import { queryKeys } from '../../lib/query-keys';

interface UseRequestsParams {
  status?: string;
  service?: string;
  limit?: number;
  since?: string;
  /** Polling interval in ms. Set to false to disable. Default: 5000 */
  refetchInterval?: number | false;
}

/** Fetches request entries — fast-polling for the live feed, slower for filtered views */
export function useRequests(params?: UseRequestsParams) {
  const { refetchInterval = 5_000, ...queryParams } = params ?? {};

  return useQuery({
    queryKey: queryKeys.requests.list(queryParams),
    queryFn: () => api.requests(queryParams),
    refetchInterval,
  });
}
