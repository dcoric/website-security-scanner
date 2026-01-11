FROM node:20-slim

# Install system dependencies
# - clamav for malware scanning
# - chromium for Puppeteer (so we don't need to download it)
# - ca-certificates for HTTPS
RUN apt-get update && apt-get install -y \
    clamav \
    clamav-daemon \
    chromium \
    ca-certificates \
    dumb-init \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Update ClamAV definitions (this might be slow, so doing it in build time is good for quick runs, 
# but bad for freshness. Better to do it in entrypoint or scheduled volume update. 
# For simplicity, we do a basic update here, but user should mount /var/lib/clamav for persistence)
RUN freshclam || true

# Set up Puppeteer to use installed Chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install node dependencies
RUN npm install

# Copy application source
COPY . .

# Ensure permissions
RUN chmod +x run-scan.sh

# Use dumb-init to handle signals correctly
ENTRYPOINT ["/usr/bin/dumb-init", "--"]

# Default command
CMD ["./run-scan.sh"]
