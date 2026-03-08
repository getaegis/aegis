# Contributing to Aegis

Thanks for considering contributing to Aegis! This document covers the basics.

## Getting Started

```bash
# Fork and clone
git clone git@github.com:YOUR_USERNAME/aegis.git
cd aegis

# Install dependencies (always use yarn, not npm)
yarn install

# Build
yarn build

# Run tests
yarn test
```

## Development Requirements

- **Node.js** ≥ 20
- **Yarn** v4 (via Corepack: `corepack enable`)
- **TypeScript** (compiled with `yarn build`)

## Code Style

- **Biome** handles linting and formatting. Pre-commit hooks run automatically via Husky.
- **TypeScript strict mode** — no `any` types, explicit return types on all functions.
- **Native ESM** — all relative imports must use `.js` extensions.
- Use `interface` for data shapes, `type` for unions/intersections.

```bash
# Check for issues
yarn lint

# Auto-fix
yarn lint:fix

# Format
yarn format
```

## Testing

All changes must include tests. We use [Vitest](https://vitest.dev/).

```bash
# Run all tests
yarn test

# Watch mode
yarn test:watch
```

### Test Patterns

- **In-memory SQLite** (`:memory:`) for database tests — fast and isolated.
- **Arrange-Act-Assert** pattern.
- Test files live in `tests/` with a `.test.ts` suffix.
- Use `Buffer.equals()` for buffer comparisons, not `toBe`.

## Before Submitting

```bash
# Full verification
yarn build && yarn test
```

This runs TypeScript compilation, then the full test suite. Both must pass.

## Pull Request Process

1. Fork the repo and create a feature branch from `master`.
2. Make your changes with tests.
3. Run `yarn build && yarn test` — everything must pass.
4. Open a PR with a clear description of what changed and why.
5. PRs require review before merging.

## Security

This is a security product. Every change is evaluated through a security lens:

- Does this change expose credentials in any new way?
- Does this bypass the domain guard?
- Does this create an unlogged code path through Gate?
- Does this weaken encryption (algorithm, key derivation, IV reuse)?
- Does this leak information in error messages?

If you discover a security vulnerability, please report it privately. **Do not open a public issue.** See [SECURITY.md](SECURITY.md) for details.

## Project Structure

```
aegis/
├── src/                 # TypeScript source
│   ├── cli.ts           # CLI entry point (Commander.js)
│   ├── config.ts        # Configuration (YAML + env vars)
│   ├── vault/           # Encrypted credential storage
│   ├── gate/            # HTTP proxy + credential injection
│   ├── ledger/          # SQLite audit trail
│   ├── agent/           # Agent identity & tokens
│   ├── policy/          # YAML policy engine
│   ├── mcp/             # MCP server (stdio + HTTP)
│   ├── logger/          # Structured logging (pino)
│   ├── metrics/         # Prometheus metrics
│   ├── webhook/         # Event notifications
│   ├── dashboard/       # Dashboard HTTP + WebSocket server
│   └── user/            # RBAC user management
├── dashboard/           # React frontend (Vite + Tailwind)
├── tests/               # Vitest test files
└── docs/                # Documentation
```

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
