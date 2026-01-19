# 1Password Secret Manager

[![Go](https://github.com/bexelbie/op-secret-manager/actions/workflows/test.yml/badge.svg)](https://github.com/bexelbie/op-secret-manager/actions/workflows/test.yml)
[![Release](https://github.com/bexelbie/op-secret-manager/actions/workflows/release.yml/badge.svg)](https://github.com/bexelbie/op-secret-manager/actions/workflows/release.yml)

This is a Go program that retrieves secrets from 1Password using the 1Password Go SDK and writes them to specific files based on a map file. It is designed to run on Linux and is licensed under the GNU General Public License v3.0.

---

## **Problem Statement**

Distributing secrets to applications and users on multi-user Linux systems is a challenging problem.  Not because it isn't solved, but because the existing solutions require making a choice from:

- **Manual secret retrieval** using a tool like the 1Password CLI (`op`) or literally manually copying secrets around
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
6. The program retrieves each secret that belongs to the user running the program and writes them to the specified file locations under `/run/user/<uid>/secrets/`.

**Key principle**: Configuration files are read with elevated privileges, but all network operations and secret file writes happen with the user's own permissions.

### **Security Model**

The program uses a **SUID-to-service-account** design (NOT SUID-to-root) to separate privilege levels while minimizing security risk:

#### **Privilege Separation Flow**

1. **Initial State**: Binary is SUID to `op` service account (an unprivileged user)
2. **Configuration Read** (elevated): Reads API key and map file from protected locations only accessible to `op`
3. **Privilege Drop**: Immediately drops SUID privileges to the real user (caller's UID/GID)
4. **Secret Operations** (unprivileged): All 1Password API calls and file writes run as the real user

#### **Why SUID to Service Account, Not Root?**

This design protects the 1Password API key without granting root access.  Additionally, If the binary is exploited, an attacker only gains the privileges of the unprivileged `op` service account, not root.

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

**Mitigated:** API key exposure, cross-user secret access, directory traversal, file race conditions, environment manipulation, privilege escalation via SUID, root misuse.

**NOT Mitigated:** Compromised service account or API key, malicious administrator, 1Password service account over-scoping.

#### **1Password Service Account Scoping**

**Critical:** The shared API key is the primary security boundary. A compromised API key exposes ALL secrets the service account can access.

**Best practices:** Grant least privilege access, use separate vaults, audit permissions regularly, rotate tokens every 90 days, monitor access logs.

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
- **Relative paths**: Paths without a leading `/` are automatically prepended with `/run/user/<uid>/secrets/`
- **Absolute paths**: Paths starting with `/` are used as-is (must be under `/run/user/<uid>/secrets/` for security)

**Note:** Inline comments (e.g., `# comment` at the end of a data line) are not supported to avoid ambiguity.

#### **Fields**

1. **`<username>`**: The username of the user who should have access to the secret.
2. **`<secret_reference>`**: The 1Password secret reference in the format `op://<vault>/<item>/<field>`.
3. **`<file_path>`**: The file path where the secret should be written. Can be:
   - **Relative path** (recommended): e.g., `db_password` or `api_keys/stripe` - automatically expanded to `/run/user/<uid>/secrets/<file_path>`
   - **Absolute path**: e.g., `/run/user/1001/secrets/db_password` - must be under `/run/user/<uid>/secrets/` for the user's UID

#### **Example**

Here's an example `mapfile` using **relative paths (recommended)**:

```text
# PostgreSQL secrets - using relative paths
postgres   op://vault1/item1/field1   db_password
postgres   op://vault1/item2/field2   api_key
postgres   op://vault1/item3/field3   config/connection_string

# Redis secrets
redis      op://vault1/redis/auth     redis_password
```

This is equivalent to:

```text
# PostgreSQL secrets - using absolute paths
postgres   op://vault1/item1/field1   /run/user/1001/secrets/db_password
postgres   op://vault1/item2/field2   /run/user/1001/secrets/api_key
postgres   op://vault1/item3/field3   /run/user/1001/secrets/config/connection_string

# Redis secrets  
redis      op://vault1/redis/auth     /run/user/1002/secrets/redis_password
```

**Recommendation**: Use relative paths for cleaner, more portable mapfiles. Absolute paths are supported for backward compatibility and special cases.

### **Notes**

- Fields must be separated by whitespace (spaces or tabs)
- Each line must have exactly 3 fields (username, secret reference, file path)
- **Use relative paths** (e.g., `db_password`) for simpler, more portable mapfiles
- Absolute paths are validated to ensure they're under `/run/user/<uid>/secrets/` for security
- The program will only resolve secrets for the user running it, based on their username

---

### **Secret Directory Location**

The program writes secrets **exclusively** to user-specific runtime directories at:

```text
/run/user/<uid>/secrets/
```

This path is **hardcoded** and follows the XDG Base Directory specification (`$XDG_RUNTIME_DIR/secrets`). This standardized location:

- **Is automatically created by systemd** when users have active sessions or lingering enabled
- **Provides per-user isolation** - each user's secrets are in their own directory
- **Is automatically cleaned up** when the user logs out (unless lingering is enabled)
- **Has correct permissions** (0700) set by systemd automatically
- **Works with systemd user services** and Podman quadlets seamlessly

#### **Requirements**

1. **Systemd user instance must be running**: The user must either:
   - Have an active login session, OR
   - Have lingering enabled: `sudo loginctl enable-linger <username>`

2. **Directory creation**: The `secrets/` subdirectory within `/run/user/<uid>/` is created automatically by `op-secret-manager` using `MkdirAll`.

#### **Example Paths**

```text
# User with UID 1000
/run/user/1000/secrets/db_password
/run/user/1000/secrets/api_keys/stripe

# User with UID 1001  
/run/user/1001/secrets/db_password
```

#### **Map File Examples**

```text
# Recommended: Use relative paths for cleaner, portable mapfiles
postgres   op://vault/db/password       db_password
myuser     op://vault/api/stripe        api_keys/stripe
myuser     op://vault/db/connection     db_conn

# Absolute paths also work (but relative is preferred)
postgres   op://vault/db/backup         /run/user/1001/secrets/backup_password
```

**Security Note**: The program validates all output paths to ensure they are under `/run/user/<uid>/secrets/` for the requesting user. Path traversal attempts (e.g., `..`) are rejected.

---

### **Systemd Integration Example (Podman Quadlet)**

Here's a complete example of using `op-secret-manager` with a Podman quadlet to inject secrets into a container:

**Map file** (`/etc/op-secret-manager/mapfile`):

```text
# Using relative paths (recommended)
myuser   op://vault/myapp/db_password   db_password
myuser   op://vault/myapp/api_key       api_key
```

**Quadlet file** (`~/.config/containers/systemd/myapp.container`):

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

```text
# Relative paths are expanded to /run/user/<uid>/secrets/
myuser   op://vault/myapp/db_password   db_password
myuser   op://vault/myapp/api_key       api_key
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

**Security checklist:**
- Service account `op` must be unprivileged (not root, no special groups)
- Config files must be mode 600, owned by `op:op`
- Binary must be owned by `op:op` with SUID bit set in `/usr/local/bin/`
- Grant 1Password service account least privilege access (separate vaults recommended)

**Steps:**

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
   postgres    op://vault1/item1/field1    db_password
   postgres    op://vault1/item2/field2    api_key
   EOF
   sudo chmod 600 /etc/op-secret-manager/mapfile
   sudo chown op:op /etc/op-secret-manager/mapfile
   ```
   
   **Important**: Update the map file with your actual secret references. The paths shown are relative and will be expanded to `/run/user/<uid>/secrets/`. Replace `op:op` with your actual service account username if different.

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
   - Binaries for Linux (AMD64 and ARM64) are built automatically.

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

## **License**

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

---

## **Contributing**

Contributions are welcome! Please open an issue or submit a pull request.

---

## **Support**

For help or questions, open an issue on the [GitHub repository](https://github.com/bexelbie/op-secret-manager/issues).
