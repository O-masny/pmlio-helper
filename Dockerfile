FROM node:20-alpine

# Install build tools for native modules (pkcs11js)
RUN apk add --no-cache python3 make g++ 

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install only production + test deps, skip electron (not needed for tests)
RUN npm install --ignore-scripts 2>/dev/null; \
    npm rebuild 2>/dev/null; \
    # Install jest and supertest explicitly for testing
    npx --yes jest --version > /dev/null 2>&1 || true

# Copy source
COPY . .

# Run in mock mode (no real token required)
ENV PMLIO_MOCK_PKCS11=true
ENV NODE_ENV=test

CMD ["npx", "jest", "--testPathPattern=integration", "--verbose", "--no-cache"]
