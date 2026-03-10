# ============================================================
# Stage 1: Build — compile TypeScript + dashboard
# ============================================================
FROM node:24-bookworm-slim AS build

# Native deps for better-sqlite3 compilation + dumb-init
RUN apt-get update && apt-get install -y --no-install-recommends \
    dumb-init \
    g++ \
    make \
    python3 \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Enable Corepack for Yarn 4
RUN corepack enable && corepack prepare yarn@4.12.0 --activate

# Copy dependency files first (layer cache)
COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn/ .yarn/
COPY dashboard/package.json dashboard/yarn.lock dashboard/

# Install all dependencies (including devDependencies for build)
RUN yarn install --immutable

# Install dashboard dependencies separately (independent project)
RUN cd dashboard && yarn install --immutable

# Copy source files
COPY src/ src/
COPY tsconfig.json ./

# Copy dashboard source
COPY dashboard/tsconfig.json dashboard/vite.config.ts dashboard/index.html dashboard/
COPY dashboard/src/ dashboard/src/
COPY dashboard/public/ dashboard/public/

# Build TypeScript + dashboard
RUN yarn build

# ============================================================
# Stage 2: Production dependencies only
# ============================================================
FROM node:24-bookworm-slim AS deps

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    make \
    python3 \
  && rm -rf /var/lib/apt/lists/*

RUN corepack enable && corepack prepare yarn@4.12.0 --activate

WORKDIR /app
COPY package.json yarn.lock .yarnrc.yml ./
COPY .yarn/ .yarn/

# Strip devDependencies from package.json and install production-only
RUN node -e " \
  const pkg = JSON.parse(require('fs').readFileSync('package.json','utf8')); \
  delete pkg.devDependencies; \
  delete pkg.scripts; \
  require('fs').writeFileSync('package.json', JSON.stringify(pkg, null, 2)); \
" && yarn install

# ============================================================
# Stage 3: Runtime — minimal Debian slim image
# ============================================================
FROM node:24-bookworm-slim AS runtime

# OCI image labels
LABEL org.opencontainers.image.title="Aegis" \
      org.opencontainers.image.description="Credential isolation for AI agents" \
      org.opencontainers.image.url="https://github.com/getaegis/aegis" \
      org.opencontainers.image.source="https://github.com/getaegis/aegis" \
      org.opencontainers.image.vendor="Aegis" \
      org.opencontainers.image.licenses="Apache-2.0"

# dumb-init for proper PID 1 signal handling
COPY --from=build /usr/bin/dumb-init /usr/bin/dumb-init

# Security: run as non-root user
RUN groupadd -r aegis && useradd -r -g aegis -s /bin/false aegis

WORKDIR /app

# Copy package.json (needed by version.ts at runtime)
COPY --chown=aegis:aegis --from=build /app/package.json ./

# Copy compiled output
COPY --chown=aegis:aegis --from=build /app/dist/ dist/

# Copy production node_modules
COPY --chown=aegis:aegis --from=deps /app/node_modules/ node_modules/

# Persistent data directory for vault databases
RUN mkdir -p /data/.aegis && chown -R aegis:aegis /data
VOLUME /data

# Default environment
ENV NODE_ENV=production
ENV AEGIS_DATA_DIR=/data/.aegis

# Switch to non-root user
USER aegis

# Gate proxy port
EXPOSE 3100
# Dashboard port
EXPOSE 3200
# Metrics port (when enabled)
EXPOSE 9090

# Health check — hit the gate health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://localhost:3100/_aegis/health').then(r => { if (!r.ok) process.exit(1) }).catch(() => process.exit(1))"

ENTRYPOINT ["dumb-init", "--", "node", "dist/cli.js"]
CMD ["gate", "start"]
