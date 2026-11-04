

ARG NODE_VERSION=20-alpine

# ---------- 1. Install dependencies (cached until package*.json changes) ----------
FROM node:${NODE_VERSION} AS deps
WORKDIR /repo/website
COPY website/package.json website/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci --no-audit --no-fund

# ---------- 2. Build ----------
FROM node:${NODE_VERSION} AS builder
WORKDIR /repo
# The public URL is baked into canonical links, Open Graph tags and the sitemap at build time
ARG NEXT_PUBLIC_APP_URL=http://localhost:3000
ARG NEXT_PUBLIC_REPO_URL=https://github.com/Ashukr321/Authentication-mastry
ENV NEXT_PUBLIC_APP_URL=${NEXT_PUBLIC_APP_URL} \
    NEXT_PUBLIC_REPO_URL=${NEXT_PUBLIC_REPO_URL} \
    NEXT_TELEMETRY_DISABLED=1 \
    BUILD_STANDALONE=1
COPY . .
COPY --from=deps /repo/website/node_modules ./website/node_modules
WORKDIR /repo/website
RUN npm run build
# Gather the notes the server reads at runtime (COPY with a wildcard would flatten the level folders)
RUN mkdir /content && cp -r /repo/README.md /repo/level-* /content/

# ---------- 3. Run (only the standalone server, static files and the notes) ----------
FROM node:${NODE_VERSION} AS runner
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
# Same layout as the repo: the app reads ../README.md and ../level-*/ at runtime too
WORKDIR /app/website

COPY --from=builder --chown=node:node /content /app
COPY --from=builder --chown=node:node /repo/website/.next/standalone ./
COPY --from=builder --chown=node:node /repo/website/.next/static ./.next/static
COPY --from=builder --chown=node:node /repo/website/public ./public

USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD node -e "fetch('http://127.0.0.1:3000/robots.txt').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
CMD ["node", "server.js"]
