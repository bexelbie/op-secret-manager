# 1Password Secret Manager

[![Go](https://github.com/bexelbie/op-secret-manager/actions/workflows/test.yml/badge.svg)](https://github.com/bexelbie/op-secret-manager/actions/workflows/test.yml)
[![Release](https://github.com/bexelbie/op-secret-manager/actions/workflows/release.yml/badge.svg)](https://github.com/bexelbie/op-secret-manager/actions/workflows/release.yml)

This is a Go program that retrieves secrets from 1Password using the 1Password Go SDK and writes them to specific files based on a map file. It is designed to run on Linux and is licensed under the GNU General Public License v3.0.

---

## **Purpose**

The program is intended to securely manage and distribute secrets to users on a Linux system. It works as follows:

1. A user (e.g., `postgres`) runs the program.
2. The program is setuid and setgid to another user (`op`) to elevate permissions.
3. The program reads a service API key from `/mnt/service-1p/api`. This location is set in the configuration file.
4. It reads a map of secrets and their corresponding file locations from `/mnt/service-1p/mapfile`. This location is set in the configuration file.
5. The program retrieves each secret that belongs to the user running the program and writes them to the specified file locations in `/run/<uid>/secrets/`.

---

### **Configuration**

The program reads its configuration from `/opt/1Password/op-secret-manager.conf`. This file specifies the paths to the API key file and the map file.

#### **Configuration File Format**

The configuration file is a simple key-value file.  Ensure the file is readable by the user running the program.  Here’s an example:

```
# Path to the API key file
API_KEY_PATH=/mnt/service-1p/api

# Path to the map file
MAP_FILE_PATH=/mnt/service-1p/mapfile
```

#### **Fields**
- **`API_KEY_PATH`**: The path to the file containing the 1Password service account API key.
- **`MAP_FILE_PATH`**: The path to the map file that defines secret mappings.

---

### **Map File Format**

The `mapfile` is a plain text file with tab separated fields that maps secrets from 1Password to specific file locations. Each line in the file represents a single mapping and follows this format:

```
<username>\t<secret_reference>\t<file_path>
```

#### **Fields**
1. **`<username>`**: The username of the user who should have access to the secret.
2. **`<secret_reference>`**: The 1Password secret reference in the format `op://<vault>/<item>/<field>`.
3. **`<file_path>`**: The file path where the secret should be written. This path should be within `/run/<uid>/secrets/`, where `<uid>` is the user ID of the user running the program.

#### **Example**
Here’s an example `mapfile`:

```
postgres	op://vault1/item1/field1	/run/1001/secrets/db_password
postgres	op://vault1/item2/field2	/run/1001/secrets/api_key
```

### **Notes**
- Use tabs (`\t`) to separate the fields.
- Ensure the file paths are unique and do not conflict with other files.
- The program will only resolve secrets for the user running it, based on their username.

---

## **Getting Started**

### **Prerequisites**
- Linux system
- 1Password service account with necessary permissions
- Go 1.21+ (for building from source)

### **Getting a Built Binary**

Pre-built binaries are available on the [Releases page](https://github.com/bexelbie/op-secret-manager/releases). Download the appropriate binary for your platform:

- `op-secret-manager-linux-amd64`: Linux (64-bit)
- `op-secret-manager-linux-arm64`: Linux (ARM64)

### **Installation**

1. Download the appropriate binary for your system
2. Move the binary to `/usr/local/bin/`:
   ```bash
   sudo mv op-secret-manager-linux-amd64 /usr/local/bin/op-secret-manager
   ```
3. Set ownership and permissions:
   ```bash
   sudo chown service-1p:service-1p /usr/local/bin/op-secret-manager
   sudo chmod u+s /usr/local/bin/op-secret-manager
   ```

### **Configuration**

1. Create the configuration directory:
   ```bash
   sudo mkdir -p /opt/1Password
   sudo chmod 755 /opt/1Password
   ```

2. Create the configuration file at `/opt/1Password/op-secret-manager.conf`:
   ```bash
   sudo tee /opt/1Password/op-secret-manager.conf <<EOF
   API_KEY_PATH=/mnt/service-1p/api
   MAP_FILE_PATH=/mnt/service-1p/mapfile
   EOF
   sudo chmod 644 /opt/1Password/op-secret-manager.conf
   ```

3. Create the API key file:
   ```bash
   sudo mkdir -p /mnt/service-1p
   echo "your-service-account-token" | sudo tee /mnt/service-1p/api
   sudo chmod 600 /mnt/service-1p/api
   sudo chown service-1p:service-1p /mnt/service-1p/api
   ```

4. Create the map file:
   ```bash
   sudo tee /mnt/service-1p/mapfile <<EOF
   sleeper-postgres    op://vault1/item1/field1    /run/1001/secrets/db_password
   sleeper-postgres    op://vault1/item2/field2    /run/1001/secrets/api_key
   EOF
   sudo chmod 600 /mnt/service-1p/mapfile
   sudo chown service-1p:service-1p /mnt/service-1p/mapfile
   ```

### **Usage**

Run the program as the target user:
```bash
postgres% op-secret-manager
```

To enable verbose logging:
```bash
postgres% op-secret-manager -v
```

To clean up created files:
```bash
postgres% op-secret-manager --cleanup
```

### **Verification**

Check that secrets were written correctly:
```bash
ls -l /run/1001/secrets/
cat /run/1001/secrets/db_password
cat /run/1001/secrets/api_key
```

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
   go build -o op-secret-manager .
   ```

4. **Set Permissions** (if needed):
   ```bash
   sudo chown service-1p:service-1p op-secret-manager
   sudo chmod u+s op-secret-manager
   ```

---

## **Branching Strategy**

The repository uses the following branching strategy:

- `develop`: The main working branch where all development happens. This is the default branch for pull requests and feature development. Pushes to this branch automatically trigger beta builds.
- `main`: The stable branch used for production releases. Code is merged from `develop` to `main` when preparing a new release.

## **Build and Release Process**

All workflows (test, beta-release, and release) can be triggered manually via the GitHub Actions interface for on-demand execution when needed.

### **Beta Builds**
Pushing tags to the `develop` branch triggers beta builds. Beta builds are marked as pre-releases and follow this naming convention: `beta-N` where N is the build number. This ensures beta releases are intentional and controlled.

To create a beta release:
```bash
git checkout develop
git tag beta-1
git push origin beta-1
```

### **Production Releases**
To create a new production release:

1. **Merge to Main**:
   ```bash
   git checkout main
   git merge develop
   git push origin main
   ```

2. **Tag a Release**:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

3. **Automated Build and Release**:
   - The GitHub Actions workflow (`.github/workflows/release.yml`) will automatically build the binaries and create a release when you push a tag.
   - Binaries for Linux (AMD64 and ARM64) are built by default.

3. **Re-Enable macOS and Windows Builds**:
   - To enable macOS and Windows builds, modify the `release.yml` workflow file:
     ```yaml
     env:
       BUILD_MACOS: 'true'    # Enable macOS builds
       BUILD_WINDOWS: 'true'  # Enable Windows builds
     ```
   - Push the changes to the repository, and the next release will include macOS and Windows binaries.

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
```
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

## **License**

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

---

## **Contributing**

Contributions are welcome! Please open an issue or submit a pull request.

---

## **Support**

For help or questions, open an issue on the [GitHub repository](https://github.com/bexelbie/op-secret-manager/issues).
