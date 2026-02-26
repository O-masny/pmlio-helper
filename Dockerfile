FROM node:20-alpine AS builder
WORKDIR /app

# Install dependencies (including optional pkcs11js)
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev && npm prune --production

# Copy source code
COPY src ./src
COPY electron-builder.yml ./
COPY assets ./assets

# Expose the HTTPS port used by the helper
EXPOSE 14725

# Run the helper (use npm start script defined in package.json)
CMD ["npm", "run", "start"]
