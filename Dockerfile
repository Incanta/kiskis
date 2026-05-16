# syntax=docker/dockerfile:1.7

# ---- builder ----------------------------------------------------------
FROM node:24-alpine AS builder
WORKDIR /app

RUN corepack enable

# Install dependencies first to take advantage of layer caching.
COPY package.json yarn.lock .yarnrc.yml ./
RUN yarn install --immutable

# Sources
COPY tsconfig.base.json tsconfig.server.json tsconfig.web.json ./
COPY scripts ./scripts
COPY src ./src

RUN yarn build

# ---- runtime ----------------------------------------------------------
# kiskis has zero runtime dependencies, so the final image carries only
# the compiled JS, the static assets, and Node itself.
FROM node:24-alpine AS runtime
WORKDIR /app

ENV NODE_ENV=production \
    PORT=8787 \
    DATA_DIR=/data

COPY --from=builder /app/dist ./dist
COPY package.json ./

RUN mkdir -p /data && chown -R node:node /app /data

USER node

EXPOSE 8787
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+ (process.env.PORT||8787) +'/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "dist/server/index.js"]
