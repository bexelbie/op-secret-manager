# 1Password Secret Manager

[![Go](https://github.com/bexelbie/op-secret-manager/actions/workflows/test.yml/badge.svg)](https://github.com/bexelbie/op-secret-manager/actions/workflows/test.yml)
[![Release](https://github.com/bexelbie/op-secret-manager/actions/workflows/release.yml/badge.svg)](https://github.com/bexelbie/op-secret-manager/actions/workflows/release.yml)

This is a Go program that retrieves secrets from 1Password using the 1Password Go SDK and writes them to specific files based on a map file. It is designed to run on Linux and is licensed under the GNU General Public License v3.0.

---

## **Problem Statement**

Organizations using 1Password often face challenges distributing secrets to applications and users on multi-user Linux systems. Existing solutions either require:

- **Manual secret retrieval** using the 1Password CLI (`op`), which doesn't scale for automated deployments
- **Running persistent services** like 1Password Connect, which adds infrastructure complexity
- **Cloud provider integrations** (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault), which aren't suitable for on-premise or hybrid environments
- **Full secret management software** like HashiCorp Vault, which may be overkill for simpler use cases

This tool provides a lightweight, **no-daemon alternative** that:
- Automatically distributes secrets from 1Password to individual Linux users
- Runs on-demand as a single binary (no persistent services)
- Uses SUID privilege separation for secure multi-user environments
- Works on bare Linux systems without requiring Kubernetes or cloud infrastructure
- Leverages existing 1Password infrastructure without additional complexity

## **Use Cases**

- **Database server provisioning**: Automatically provide database credentials to the `postgres` user from 1Password
- **Application deployment**: Distribute API keys and configuration secrets to application users
- **Multi-tenant systems**: Safely distribute user-specific secrets on shared Linux hosts
- **On-premise infrastructure**: Manage secrets without cloud dependencies
- **Legacy system integration**: Add modern secret management to existing Linux systems without architectural changes

## **Purpose**

The program is intended to securely manage and distribute secrets to users on a Linux system. It works as follows:

1. A user (e.g., `postgres`) runs the program.
2. The program is setuid to a service account (`op`) to elevate permissions temporarily.
3. The program reads the 1Password service API key from `/etc/op-secret-manager/api`.
4. It reads a map of secrets and their corresponding file locations from `/etc/op-secret-manager/mapfile`.
5. The program **immediately drops privileges** back to the real user.
6. The program retrieves each secret that belongs to the user running the program and writes them to the specified file locations in `/run/<uid>/secrets/`.

**Key principle**: Configuration files are read with elevated privileges, but all network operations and secret file writes happen with the user's own permissions.

### **Security Model**

The program uses a **SUID-to-service-account** design (NOT SUID-to-root) to separate privilege levels while minimizing security risk:

#### **Privilege Separation Flow**

1. **Initial State**: Binary is SUID to `op` service account (an unprivileged user)
2. **Configuration Read** (elevated): Reads API key and map file from protected locations only accessible to `op`
3. **Privilege Drop**: Immediately drops SUID privileges to the real user (caller's UID/GID)
4. **Secret Operations** (unprivileged): All 1Password API calls and file writes run as the real user

#### **Why SUID to Service Account, Not Root?**

This design protects the 1Password API key without granting root access:

- **API Key Protection**: The API key must be readable only by the `op` service account. Making it world-readable would expose it to all users. Using file groups would require adding every user to a shared group, defeating access control.
  
- **Minimal Privilege**: If the binary is exploited, an attacker only gains the privileges of the unprivileged `op` service account, not root.

- **Alternatives Considered**:
  - **Linux capabilities** (`CAP_DAC_READ_SEARCH`): Would require the binary to be owned by root and granted special capabilities. This increases risk compared to an unprivileged service account.
  - **Group-readable API key**: Would require all users to be in a shared group, allowing any user to directly read the API key.
  - **SUID root**: Far more dangerous than SUID to an unprivileged account.

The SUID-to-service-account design is the lowest-privilege solution for secure API key access on multi-user systems.

#### **User Isolation**

The program enforces strict user boundaries:

- Each user can only access secrets mapped to their username in the map file
- Secrets are written with the caller's UID/GID (after privilege drop)
- Output paths are validated to prevent directory traversal attacks
- The map file controls which users can access which secrets

#### **Root Execution Prevention**

The program **refuses to run as root** (UID 0):

- Root has direct access to the API key file and can use the 1Password CLI directly
- There is no legitimate use case for privilege-separated secret delivery to root
- Running as root would bypass the security model's privilege separation
- If executed as root, the program exits immediately with an error

#### **Threat Model**

This security design mitigates the following threats:

**Mitigated Threats:**
- **API key exposure**: Unprivileged users cannot read the API key directly
- **Cross-user secret access**: Users cannot access secrets mapped to other users
- **Directory traversal**: Path validation prevents writing outside designated directories
- **File race conditions**: Atomic writes prevent corruption from crashes or concurrent writes
- **Environment manipulation**: Dangerous environment variables (e.g., `LD_PRELOAD`, `GOCOVERDIR`) are cleared on startup
- **Privilege escalation via SUID**: Binary is SUID to unprivileged service account, not root
- **Root misuse**: Program refuses to run as root

**NOT Mitigated:**
- **Compromised service account**: If the `op` service account is compromised, the API key is exposed
- **Compromised API key**: If the API key leaks, all secrets accessible to the service account are at risk
- **Malicious administrator**: The admin who sets up the system has full control over all components
- **Map file tampering by admin**: Administrator can modify the map file to redirect any user's secrets
- **1Password service account over-scoping**: If the service account has access to more vaults than necessary, a compromised API key exposes unrelated secrets

#### **1Password Service Account Scoping**

**The shared API key is the primary security boundary.** Administrators must follow these best practices:

1. **Principle of Least Privilege**: Grant the service account access ONLY to vaults and items that will be distributed via this program.

2. **Vault Isolation**: Create separate vaults for secrets managed by this system. Don't grant access to vaults containing unrelated secrets.

3. **Regular Audits**: Periodically review what secrets the service account can access and remove unnecessary permissions.

4. **Token Rotation**: Rotate the service account token regularly (e.g., every 90 days).

5. **Monitor Access**: Use 1Password's audit logs to monitor service account usage for anomalies.

**Warning**: A compromised API key exposes ALL secrets the service account can access, regardless of which secrets are in the map file. Over-scoping the service account multiplies the impact of a security breach.

#### **Security Implications**

**Service Account Setup:**
- The `op` service account must be unprivileged (not root, no special groups)
- Only `op` should have read access to `/etc/op-secret-manager/api` and `/etc/op-secret-manager/mapfile`
- These configuration files must have restrictive permissions (600) and be owned by `op:op`

**Binary Setup:**
- Binary must be owned by `op:op` with SUID bit set (`chmod u+s`)
- Binary should be installed in a root-owned directory (e.g., `/usr/local/bin/`)
- Regular users must not have write access to the binary

**Secret Output:**
- Secrets are written to user-specific directories (`/run/<uid>/secrets/`) with 600 permissions
- Output paths are validated to prevent directory traversal
- Files are written atomically to prevent corruption

**Environment Sanitization:**
- On startup, the program clears dangerous environment variables that could be used for attacks:
  - `GOCOVERDIR`, `GOTRACEBACK`, `GODEBUG`, `GOMAXPROCS`: Could enable code coverage/debugging features
  - `LD_PRELOAD`, `LD_LIBRARY_PATH`: Could inject malicious shared libraries

**Build Security:**
- The binary is built with `-ldflags="-s -w"` (strips symbols) and `-trimpath` (removes build paths)
- This makes reverse engineering harder and prevents leaking build environment details

---

### **Configuration**

The program uses the following default paths:
- **API Key**: `/etc/op-secret-manager/api`
- **Map File**: `/etc/op-secret-manager/mapfile`

These defaults can be overridden using command-line flags or environment variables (see Configuration Overrides below).

**No configuration file is required** - the program works out-of-the-box with these defaults.

---

### **Map File Format**

The `mapfile` is a plain text file that maps secrets from 1Password to specific file locations. Each line in the file represents a single mapping and follows this format:

```
<username>  <secret_reference>  <file_path>
```

The fields can be separated by any amount of whitespace (spaces or tabs). The file supports:
- **Comments**: Lines starting with `#` (after any leading whitespace) are ignored
- **Blank lines**: Empty lines or lines with only whitespace are ignored
- **Flexible whitespace**: Use spaces, tabs, or any combination to separate fields

**Note:** Inline comments (e.g., `# comment` at the end of a data line) are not supported to avoid ambiguity.

#### **Fields**
1. **`<username>`**: The username of the user who should have access to the secret.
2. **`<secret_reference>`**: The 1Password secret reference in the format `op://<vault>/<item>/<field>`.
3. **`<file_path>`**: The file path where the secret should be written. This path should be within `/run/<uid>/secrets/`, where `<uid>` is the user ID of the user running the program.

#### **Example**
Here’s an example `mapfile`:

```
# PostgreSQL secrets
postgres   op://vault1/item1/field1   /run/1001/secrets/db_password
postgres   op://vault1/item2/field2   /run/1001/secrets/api_key

# Redis secrets
redis      op://vault1/redis/auth     /run/1002/secrets/redis_password
```

### **Notes**
- Fields must be separated by whitespace (spaces or tabs)
- Each line must have exactly 3 fields (username, secret reference, file path)
- Ensure the file paths are unique and do not conflict with other files
- The program will only resolve secrets for the user running it, based on their username

---

### **Secret Directory Scenarios**

The program writes secrets to user-specific runtime directories. There are two scenarios depending on how your services are configured:

#### **Scenario A: User Services (systemctl --user, podman quadlets)**

For services running in the user context (systemd user services, podman quadlets):

- **Directory**: `/run/user/<uid>/secrets/`
- **Created by**: systemd automatically when user has active session or lingering enabled
- **Setup required**: None - the directory exists automatically
- **Example**: `/run/user/1001/secrets/db_password`

The `secrets/` subdirectory is created automatically by `op-secret-manager` using `MkdirAll`.

#### **Scenario B: System Services Running as a User**

For system services (managed by root systemd) that run as a specific user:

- **Directory**: `/run/<uid>/secrets/` or use systemd's `RuntimeDirectory=`
- **Created by**: Must be pre-created by administrator
- **Setup required**: Choose one of these methods:

**Option 1 - Use systemd RuntimeDirectory (recommended):**
```ini
[Service]
User=postgres
RuntimeDirectory=secrets
# This creates /run/<uid>/secrets/ automatically
```

**Option 2 - Use tmpfiles.d:**
```bash
# Create /etc/tmpfiles.d/op-secrets-<username>.conf
echo "d /run/1001/secrets 0700 postgres postgres -" | sudo tee /etc/tmpfiles.d/op-secrets-postgres.conf
sudo systemd-tmpfiles --create
```

**Important**: `/run/<uid>/` does NOT exist by default for system services. You must use one of the above methods.

#### **Path Examples in Map Files**

```
# For user services (systemctl --user, quadlets)
postgres   op://vault/db/password   /run/user/1001/secrets/db_password

# For system services
postgres   op://vault/db/password   /run/1001/secrets/db_password
```

---

### **Systemd Integration Example (Podman Quadlet)**

Here's a complete example of using `op-secret-manager` with a Podman quadlet to inject secrets into a container:

**File**: `~/.config/containers/systemd/myapp.container`

```ini
[Unit]
Description=My Application Container
After=network-online.target
Wants=network-online.target

[Container]
Image=docker.io/myapp:latest
Network=pasta

# Mount secrets directory into container
Volume=/run/user/%U/secrets:/run/secrets:ro,Z

# Application reads secrets from environment variables pointing to files
Environment=DB_PASSWORD_FILE=/run/secrets/db_password
Environment=API_KEY_FILE=/run/secrets/api_key

# Fetch secrets before starting container
ExecStartPre=/usr/local/bin/op-secret-manager

# Clean up secrets after container stops
ExecStopPost=/usr/local/bin/op-secret-manager --cleanup

[Service]
# Container will auto-restart
Restart=always

[Install]
WantedBy=default.target
```

**Corresponding map file** (`/etc/op-secret-manager/mapfile`):
```
myuser   op://vault/myapp/db_password   /run/user/1001/secrets/db_password
myuser   op://vault/myapp/api_key       /run/user/1001/secrets/api_key
```

**Secret Lifecycle**:
1. `ExecStartPre` runs `op-secret-manager` to fetch secrets and write them to `/run/user/1001/secrets/`
2. Container starts with `/run/user/1001/secrets/` mounted as `/run/secrets/` (read-only)
3. Application reads `$DB_PASSWORD_FILE` and `$API_KEY_FILE` to get secret paths
4. When container stops, `ExecStopPost` runs `op-secret-manager --cleanup` to delete secret files

**Enable and start**:
```bash
systemctl --user daemon-reload
systemctl --user enable --now myapp.container
```

---

### **Notes**
- Fields must be separated by whitespace (spaces or tabs)
- Each line must have exactly 3 fields (username, secret reference, file path)
- Ensure the file paths are unique and do not conflict with other files
- The program will only resolve secrets for the user running it, based on their username

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
   sudo chown op:op /usr/local/bin/op-secret-manager
   sudo chmod u+s /usr/local/bin/op-secret-manager
   ```
   
   **Important**: Replace `op:op` with your actual service account username if different.

### **Setup**

1. Create the configuration directory:
   ```bash
   sudo mkdir -p /etc/op-secret-manager
   sudo chmod 755 /etc/op-secret-manager
   ```

2. Create the API key file:
   ```bash
   echo "your-service-account-token" | sudo tee /etc/op-secret-manager/api > /dev/null
   sudo chmod 600 /etc/op-secret-manager/api
   sudo chown op:op /etc/op-secret-manager/api
   ```
   
   **Important**: Replace `your-service-account-token` with your actual 1Password service account token. Replace `op:op` with your actual service account username if different.

3. Create the map file:
   ```bash
   sudo tee /etc/op-secret-manager/mapfile <<EOF
   postgres    op://vault1/item1/field1    /run/1001/secrets/db_password
   postgres    op://vault1/item2/field2    /run/1001/secrets/api_key
   EOF
   sudo chmod 600 /etc/op-secret-manager/mapfile
   sudo chown op:op /etc/op-secret-manager/mapfile
   ```
   
   **Important**: Update the map file with your actual secret references and target paths. Replace `op:op` with your actual service account username if different.

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

#### **Configuration Overrides**

The program supports flexible configuration through command-line flags and environment variables. Configuration values are resolved in the following order of precedence (highest to lowest):

1. **Command-line flags** (highest priority)
2. **Environment variables**
3. **Default values** (lowest priority: `/etc/op-secret-manager/api` and `/etc/op-secret-manager/mapfile`)

**Command-line flags:**
- `--api-key-path <path>`: Override the default API key file path
- `--map-file-path <path>`: Override the default map file path

**Environment variables:**
- `OP_API_KEY_PATH`: Override the default API key file path
- `OP_MAP_FILE_PATH`: Override the default map file path

**Examples:**

Using environment variables:
```bash
postgres% export OP_API_KEY_PATH=/custom/path/api
postgres% export OP_MAP_FILE_PATH=/custom/path/mapfile
postgres% op-secret-manager
```

Using command-line flags:
```bash
postgres% op-secret-manager --api-key-path /custom/api --map-file-path /custom/mapfile
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
   sudo chmod u+s op-secret-manager
   ```
   
   **Important**: Replace `op:op` with your actual service account username if different.

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
