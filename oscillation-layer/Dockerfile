# Use lightweight Node image
FROM node:20-alpine

# Set working directory
WORKDIR /usr/src/app

# Copy package.json first for caching dependencies
COPY package*.json ./

# Install production dependencies only
RUN npm install --omit=dev

# Copy app source
COPY . .

# Expose the port your server listens on
EXPOSE 3000

# Set environment defaults (These are safely overridden by docker-compose.yml)
ENV PORT=3000
# CRITICAL FIX: Match the variable name your Node.js code actually reads
ENV OLLAMA_RUNNERS=http://ollama:11434
ENV OLLAMA_DEFAULT_MODEL=gemma:2b

# CRITICAL FIX: Ensure this matches your ACTUAL JavaScript filename
# If your file is named oscillation-layer.js, change it back. 
# Based on your directory tree, it should be hexabiz-gateway.js
CMD ["node", "hexabiz-gateway.js"]
