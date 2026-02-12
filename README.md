# op-secret-manager

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
6. The program acquires a per-user file lock to serialize concurrent invocations (prevents WASM runtime conflicts).
7. The program retrieves each secret that belongs to the user running the program and writes them to the specified file locations under `/run/user/<uid>/secrets/`.

**Key principle**: Configuration files are read with elevated privileges, but all network operations and secret file writes happen with the user's own permissions.

### **Security Model**

The program uses a **SUID-to-service-account** design (NOT SUID-to-root) to separate privilege levels while minimizing security risk:

#### **Privilege Separation Flow**

1. **Initial State**: Binary is SUID+SGID to `op` service account (an unprivileged user)
2. **Configuration Read** (elevated): Reads API key and map file from protected locations accessible via `op` UID/GID
3. **Privilege Drop**: Immediately drops SUID and SGID privileges to the real user (caller's UID/GID)
4. **Process Lock**: Acquires an exclusive per-user file lock (`/run/user/<uid>/op-secret-manager.lock`) to serialize concurrent invocations
5. **Secret Operations** (unprivileged): All 1Password API calls and file writes run as the real user

#### **Why SUID to Service Account, Not Root?**

This design protects the 1Password API key without granting root access.  Additionally, If the binary is exploited, an attacker only gains the privileges of the unprivileged `op` service account, not root.

- **Alternatives Considered**:
  - **Linux capabilities** (`CAP_DAC_READ_SEARCH`): Would require the binary to be owned by root and granted special capabilities. This increases risk compared to an unprivileged service account.
  - **Group-readable API key**: Would require all users to be in a shared group, allowing any user to directly read the API key.
  - **SUID root**: Far more dangerous than SUID to an unprivileged account.

The SUID-to-service-account design is the lowest-privilege solution for secure API key access on multi-user systems.

#### **API Key Storage**

The 1Password service account API key is stored in plaintext at `/etc/op-secret-manager/api`. This is an intentional design choice, not an oversight.

**Why plaintext?**

This follows the same security model as `/etc/shadow`, `/etc/ssh/ssh_host_*_key`, and other system secrets on Unix systems. **File permissions ARE the protection mechanism.** The API key file is readable only by the `op` service account (mode 0400 or 0600). Any user who can read this file already has `op` service account privileges and could use the 1Password CLI directly.

**Alternatives considered:**

- **Machine-bound encryption** (TPM, encrypted file systems): The decryption key must be accessible to the same SUID binary. An attacker with code execution in the binary can trigger decryption and capture the plaintext key. This adds complexity without meaningful security improvement.
- **Password-protected keys**: Incompatible with unattended operation. SUID binaries cannot interactively prompt for passwords.
- **OS-native keystores** (Keychain, Secret Service): Would require the binary to authenticate to the keystore with credentials accessible to the `op` service account, recreating the same plaintext storage problem with additional complexity.

**The actual security boundary:** The 1Password service account's vault permissions. Limit what this API key can access in 1Password - if the key is compromised, the blast radius is contained to those specific vaults and items.

If an attacker can bypass Unix file permissions (root compromise, kernel exploit), no encryption scheme accessible to a SUID binary would provide protection. The attacker could read the decryption key, intercept the decryption process, or simply dump the binary's memory after it decrypts the key.

File permissions are the Unix-standard mechanism for protecting on-disk secrets. This tool follows that standard.

#### **User Isolation**

The program enforces strict user boundaries:

- Each user can only access secrets mapped to their username in the map file
- Secrets are written with the caller's UID/GID (after privilege drop)
- Output paths are validated to prevent directory traversal attacks
- The map file controls which users can access which secrets

#### **Root Execution**

The program **allows root execution** (UID 0) only when the mapfile meets strict security requirements:

- The mapfile must be **owned by root** (UID 0)
- The mapfile must **not be writable by group or others** (mode must not have bits 0022 set)

This prevents an attacker from poisoning the mapfile to make root write secrets to dangerous locations. If an attacker can create a root-owned, properly-permissioned file, they already have root access and don't need this tool.

**Rationale**: While root can read the API key directly and use the 1Password CLI, requiring manual secret pulls for root is operationally painful. The mapfile ownership check provides a reasonable security boundary - root is essentially authorizing itself by ensuring the mapfile is properly secured.

**Recommended setup for shared mapfile (root + non-root entries):**

Using SGID allows a single mapfile to serve both root and non-root users:
- Binary is SUID+SGID to `op:op` (mode 6755)
- Mapfile is owned by `root:op` with mode 640 (owner read/write, group read)
- Root reads mapfile as owner, non-root users read via SGID group membership

```bash
# Set binary with SUID+SGID
sudo chown op:op /usr/local/bin/op-secret-manager
sudo chmod 6755 /usr/local/bin/op-secret-manager  # SUID + SGID

# Create mapfile with root ownership, group op readable
sudo touch /etc/op-secret-manager/mapfile
sudo chown root:op /etc/op-secret-manager/mapfile
sudo chmod 640 /etc/op-secret-manager/mapfile  # rw-r-----
```

#### **Threat Model**

**Mitigated:** API key exposure, cross-user secret access, directory traversal, file race conditions, environment manipulation, privilege escalation via SUID, mapfile poisoning (for root execution), concurrent invocation conflicts (per-user flock serialization).

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

The `mapfile` maps 1Password secrets to file locations. Each line follows this format:

```text
<username>  <secret_reference>  <file_path>
```

#### **Format Rules**

- **Fields**: Separate with whitespace (spaces or tabs). Must have exactly 3 fields per line.
- **Comments**: Lines starting with `#` (after leading whitespace) are ignored
- **Blank lines**: Empty lines or whitespace-only lines are ignored
- **No inline comments**: Comments at the end of data lines are not supported

#### **Fields**

1. **`<username>`**: User who should have access to the secret
2. **`<secret_reference>`**: 1Password reference in format `op://<vault>/<item>/<field>`
3. **`<file_path>`**: Where to write the secret:
   - **Relative path** (recommended): e.g., `db_password` → `/run/user/<uid>/secrets/db_password`
   - **Absolute path**: e.g., `/home/user/.docker/config.json` (writes anywhere user has permission)

#### **Output Directory**

Secrets are written to `/run/user/<uid>/secrets/` by default. This follows the XDG Base Directory specification (`$XDG_RUNTIME_DIR/secrets`) and:

- Is automatically created by systemd for active sessions or lingering-enabled users
- Provides per-user isolation (each user has their own directory)
- Is automatically cleaned up on logout (unless lingering is enabled)
- Has correct permissions (0700) set by systemd
- Works seamlessly with systemd user services and Podman quadlets

**Requirements**: User must have an active session or lingering enabled (`sudo loginctl enable-linger <username>`)

#### **Example Map File**

```text
# PostgreSQL secrets - relative paths (recommended)
postgres   op://vault/db/password         db_password
postgres   op://vault/db/connection       db_conn

# Redis
redis      op://vault/redis/auth          redis_password

# Absolute paths - persistent config files
myuser     op://vault/docker/config       /home/myuser/.docker/config.json
postgres   op://vault/pg/cert             /var/lib/postgresql/.postgresql/client-cert.pem
```

**Security**: After privilege drop, the program runs as the real user. Filesystem permissions control access. Path traversal (`..`) is blocked.

**Integration Examples**: See [EXAMPLES.md](EXAMPLES.md) for complete systemd, Podman quadlet, and Docker Compose examples

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
   sudo chmod 6755 /usr/local/bin/op-secret-manager  # SUID + SGID
   ```
   
   **Note**: Mode `6755` sets both SUID and SGID bits, allowing the binary to run with `op` user and group privileges. This enables reading a shared mapfile owned by `root:op` with mode `640`, supporting both root and non-root users with a single mapfile.
   
   **Important**: Replace `op:op` with your actual service account username if different.

### **Setup**

**Security checklist:**
- Service account `op` must be unprivileged (not root, no special groups)
- API key file must be mode 600, owned by `op:op`
- Binary must be owned by `op:op` with SUID+SGID bits set (mode 6755) in `/usr/local/bin/`
- Mapfile should be owned by `root:op` with mode 640 for shared use (both root and non-root entries)
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
   # Root user entries
   root        op://vault1/rootdb/password    db_password
   
   # Non-root user entries
   postgres    op://vault1/item1/field1       db_password
   postgres    op://vault1/item2/field2       api_key
   EOF
   sudo chmod 640 /etc/op-secret-manager/mapfile
   sudo chown root:op /etc/op-secret-manager/mapfile
   ```
   
   **Note**: The recommended setup uses `root:op` ownership with mode `640`. This allows:
   - Root to read the mapfile as the owner
   - Non-root users to read via SGID group membership to `op`
   - A single mapfile to contain entries for both root and non-root users
   
   **Important**: Update the map file with your actual secret references. The paths shown are relative and will be expanded to `/run/user/<uid>/secrets/`.

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

## **License**

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

---

## **Contributing**

Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on building, testing, and releasing the project.

---

## **Support**

For help or questions, open an issue on the [GitHub repository](https://github.com/bexelbie/op-secret-manager/issues).
