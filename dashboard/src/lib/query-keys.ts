/**
 * Query Keys
 * Centralized query key factory for type-safe cache management.
 *
 * Conventions (same as house-app):
 * - Hierarchical keys: [entity, subtype, params...]
 * - Dynamic params included in keys for automatic cache separation
 * - 'list' for filtered/paginated, 'detail' for single items
 */

export const queryKeys = {
  health: ['health'] as const,

  stats: {
    all: ['stats'] as const,
    since: (since?: string) => ['stats', { since }] as const,
  },

  credentials: {
    all: ['credentials'] as const,
  },

  agents: {
    all: ['agents'] as const,
  },

  users: {
    all: ['users'] as const,
  },

  requests: {
    all: ['requests'] as const,
    list: (params?: { status?: string; service?: string; limit?: number; since?: string }) =>
      ['requests', 'list', params] as const,
  },
};
