# Use lightweight, secure Node.js 22 Alpine image
FROM node:22-alpine

# ---------------------------------------------------------
# 1. Install curl for health checks and tini for signal handling
# ---------------------------------------------------------
# tini acts as PID 1 and properly forwards SIGTERM/SIGINT to Node.js
RUN apk add --no-cache curl tini

# Set working directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json first to leverage Docker layer caching
COPY package*.json ./

# Install production dependencies only 
RUN npm ci --omit=dev || npm install --omit=dev

# Copy the rest of the application source code
COPY . .

# ---------------------------------------------------------
# 2. Security: Create non-root user and setup directories
# ---------------------------------------------------------
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Create the /data directory for persistent mappings and set ownership
RUN mkdir -p /data && chown -R appuser:appgroup /data /usr/src/app

# Switch to non-root user
USER appuser

# Expose the port your server listens on
EXPOSE 3000

# ---------------------------------------------------------
# 3. Environment Defaults & Health Check
# ---------------------------------------------------------
ENV PORT=3000 \
    NODE_ENV=production \
    OLLAMA_RUNNERS=http://ollama:11434 \
    OLLAMA_DEFAULT_MODEL=gemma:2b \
    DATA_DIR=/data

# Native Docker health check (Coolify will auto-detect this)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:3000/health/live || exit 1

# Use tini as the entrypoint to ensure graceful shutdowns work perfectly
ENTRYPOINT ["/sbin/tini", "--"]

# Ensure this filename EXACTLY matches your actual main file name!
CMD ["node", "hexabiz-gateway.js"]
