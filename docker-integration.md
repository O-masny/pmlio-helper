# Docker Integration Test for pmlio‑helper

This Docker image builds the **pmlio‑helper** project and runs the integration test suite in mock mode (no real USB token required).

## How to use
1. **Build the image**
   ```powershell
   cd C:\Users\masny\Desktop\portfolio\shopio\pmlio-helper
   docker build -t pmlio-helper-test .
   ```
2. **Run the container** – the container will automatically execute `npm run test:integration` and exit with the test result code.
   ```powershell
   docker run --rm pmlio-helper-test
   ```
   You should see output similar to:
   ```
   RUNS  tests/integration/server.test.js
   Test Suites: 1 passed, 1 total
   Tests:       5 passed, 5 total
   ```

## What the test does
- Starts the Express HTTPS server on a random port inside the container.
- Calls the `/health`, `/certificates`, `/sign`, and `/sign-many` endpoints.
- Uses the **mock PKCS#11 implementation** (`PMLIO_MOCK_PKCS11=true`) so no hardware token is needed.
- Verifies that the responses contain the expected fields (certificate PEM, base64 signature, etc.).

## Extending to real hardware
If you want to run the tests against a real SafeNet token, build the image without the mock flag:
```dockerfile
ENV PMLIO_MOCK_PKCS11=false
ENV PMLIO_PKCS11_PIN=YOUR_PIN
```
Then mount the USB device into the container (e.g., `--device /dev/bus/usb`).

---
*Generated automatically – keep concise.*
