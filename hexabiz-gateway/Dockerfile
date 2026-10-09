# Use lightweight, secure Node.js 20 Alpine image
FROM node:20-alpine

# Set working directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json first to leverage Docker layer caching
COPY package*.json ./

# Install production dependencies only (npm ci is faster and more deterministic than npm install)
RUN npm ci --omit=dev

# Copy the rest of the application source code
COPY . .

# Expose the port your server listens on
EXPOSE 3000

# Set environment defaults (These act as fallbacks and are safely overridden by Coolify/docker-compose)
ENV PORT=3000
ENV OLLAMA_RUNNERS=http://ollama:11434
ENV OLLAMA_DEFAULT_MODEL=gemma:2b

# ⚠️ CRITICAL: Ensure this filename exactly matches the actual file in your repository root!
# If your file is named index.js, app.js, or server.js, change "hexabiz-gateway.js" accordingly.
CMD ["node", "hexabiz-gateway.js"]
