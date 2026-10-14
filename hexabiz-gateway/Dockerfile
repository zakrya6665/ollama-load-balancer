# Use lightweight, secure Node.js 20 Alpine image
FROM node:20-alpine

# ---------------------------------------------------------
# 1. Install curl for Coolify health checks (CRITICAL)
# ---------------------------------------------------------
RUN apk add --no-cache curl

# Set working directory
WORKDIR /usr/src/app

# Copy package.json and package-lock.json first to leverage Docker layer caching
COPY package*.json ./

# Install production dependencies only 
# (Use 'npm ci' if you have a package-lock.json for faster, reproducible builds)
RUN npm ci --omit=dev || npm install --omit=dev

# Copy the rest of the application source code
COPY . .

# Expose the port your server listens on
EXPOSE 3000

# Set environment defaults (These act as fallbacks and are safely overridden by Coolify/docker-compose)
ENV PORT=3000
ENV OLLAMA_RUNNERS=http://ollama:11434
ENV OLLAMA_DEFAULT_MODEL=gemma:2b

# Ensure this filename EXACTLY matches your actual main file name!
# (e.g., index.js, app.js, or hexabiz-gateway.js)
CMD ["node", "hexabiz-gateway.js"]
