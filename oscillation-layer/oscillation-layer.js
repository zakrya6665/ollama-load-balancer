version: "3.9"

services:
  ollama:
    image: ollama/ollama:latest
    container_name: ollama
    restart: always
    ports:
      - "11434:11434"  # main serve
      - "39045:39045"  # runner 1
      - "11435:11435"  # runner 2
    volumes:
      - ./ollama:/root/.ollama
    command: serve gemma:2b --port 11434
    environment:
      OLLAMA_MAX_LOADED_MODELS: 2
      OLLAMA_CONTEXT_LENGTH: 1024
      OLLAMA_NUM_THREADS: 8
      OLLAMA_USE_MMAP: "true"
      OLLAMA_USE_MLOCK: "false"
      OLLAMA_LOW_VRAM: "false"
      OLLAMA_VULKAN: 0
      OLLAMA_GPU_OVERHEAD: 0

  oscillation-layer:
    image: node:20        # official Node image
    container_name: oscillation-layer
    restart: always
    working_dir: /usr/src/app
    ports:
      - "3000:3000"
    volumes:
      - ./:/usr/src/app   # mount all files inside this folder
    command: sh -c "npm install && node oscillation-layer.js"
    environment:
      OLLAMA_API_KEY: "my-secret-key"
    depends_on:
      - ollama
