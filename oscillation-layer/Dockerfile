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

# Set environment defaults for container runtime (optional, can override in docker-compose)
ENV PORT=3000
ENV OLLAMA_HOST=http://ollama:11434
ENV OLLAMA_DEFAULT_MODEL=gemma:2b

# Start the server
CMD ["node", "oscillation-layer.js"]
