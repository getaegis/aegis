/**
 * React Query Configuration
 * Tuned for a monitoring dashboard: frequent refetches, short stale times
 */

import { QueryClient } from '@tanstack/react-query';

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // Dashboard data goes stale quickly — 15 seconds
      staleTime: 15 * 1000,
      // Keep inactive cache for 5 minutes (for view-switching)
      gcTime: 5 * 60 * 1000,
      // Retry twice with backoff
      retry: 2,
      retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 10_000),
      // Dashboard should refetch when operator returns to tab
      refetchOnWindowFocus: true,
      refetchOnReconnect: true,
    },
  },
});
