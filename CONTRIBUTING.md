# Contributing to op-secret-manager

Contributions are welcome! This document provides guidelines for building, testing, and releasing the project.

---

## **Building the Code**

To build the program from source, follow these steps:

1. **Install Go**: Ensure you have Go installed (version 1.21 or later). You can download it from the [official Go website](https://golang.org/dl/).

2. **Clone the Repository**:
   ```bash
   git clone https://github.com/bexelbie/op-secret-manager.git
   cd op-secret-manager
   ```

3. **Build the Program**:
   ```bash
   go build -ldflags="-s -w" -trimpath -o op-secret-manager .
   ```

   Build flags explanation:
   - `-ldflags="-s -w"`: Strip symbol table and DWARF debug info (reduces binary size and makes reverse engineering harder)
   - `-trimpath`: Remove file system paths from the binary (prevents leaking build environment details)

   or cross-compile if needed:

   ```bash
   GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -trimpath -o op-secret-manager
   ```

4. **Set Permissions** (if needed):
   ```bash
   sudo chown op:op op-secret-manager
   sudo chmod 6755 op-secret-manager  # SUID + SGID
   ```
   
   **Important**: Replace `op:op` with your actual service account username if different.

---

## **Testing**

### **Local Testing**

To run tests locally:

```bash
go test -v ./...
```

### **GitHub Actions Testing**

Tests run on every push to any branch and on pull requests, ensuring continuous validation of code changes. The test suite includes integration tests that require 1Password credentials. To configure GitHub Actions:

1. In your GitHub repository, go to Settings > Secrets and variables > Actions
2. Add the following secrets:
   - `OP_SERVICE_ACCOUNT_TOKEN`: Your 1Password service account token
   - `SECRET_REF1`: A valid 1Password secret reference (e.g., `op://vault/item/field`)
   - `SECRET_VAL1`: The expected value for SECRET_REF1
   - `SECRET_REF_FAIL`: An invalid 1Password secret reference for testing error cases

Example secrets:

```text
OP_SERVICE_ACCOUNT_TOKEN = op.sa.xxxxxxxxxxxxxxxxxxxxxxxx
SECRET_REF1 = op://vault1/item1/field1
SECRET_VAL1 = mysecretvalue
SECRET_REF_FAIL = op://invalid/vault/item
```

### **Security Considerations**

- Never commit secrets to your repository
- Use GitHub Actions secrets for sensitive data
- Restrict access to your 1Password service account
- Use the principle of least privilege for vault access
- Rotate service account tokens regularly
- Monitor and audit secret access

### **Test Configuration**

The test workflow (`.github/workflows/test.yml`) is pre-configured to:

1. Set up Go environment
2. Run unit tests
3. Run integration tests (if secrets are configured)
4. Generate test coverage report

To modify test behavior:

```yaml
env:
  RUN_INTEGRATION_TESTS: 'true'  # Set to 'false' to skip integration tests
  TEST_TIMEOUT: '5m'             # Maximum test duration
  TEST_VERBOSE: 'true'           # Enable verbose test output
```

---

## **Production Releases**

To create a new production release:

1. **Tag a Release**:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. **Automated Build and Release**:
   - The GitHub Actions workflow (`.github/workflows/release.yml`) will automatically build the binaries and create a release when you push a tag.
   - Binaries for Linux (AMD64 and ARM64) are built automatically.

---

## **Submitting Changes**

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests locally to ensure they pass
5. Submit a pull request with a clear description of your changes

---

## **Questions or Issues**

For help or questions, open an issue on the [GitHub repository](https://github.com/bexelbie/op-secret-manager/issues).
