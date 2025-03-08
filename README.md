# 1Password Secret Manager

[![Go](https://github.com/bexelbie/op-secret-manager/actions/workflows/test.yml/badge.svg)](https://github.com/bexelbie/op-secret-manager/actions/workflows/test.yml)
[![Release](https://github.com/bexelbie/op-secret-manager/actions/workflows/release.yml/badge.svg)](https://github.com/bexelbie/op-secret-manager/actions/workflows/release.yml)

This is a Go program that retrieves secrets from 1Password using the 1Password Go SDK and writes them to specific files based on a map file. It is designed to run on Linux and is licensed under the GNU General Public License v3.0.

---

## **Purpose**

The program is intended to securely manage and distribute secrets to users on a Linux system. It works as follows:

1. A user (e.g., `sleeper-postgres`) runs the program.
2. The program is setuid to another user (`service-1p`) to elevate permissions.
3. The program reads a service API key from `/mnt/service-1p/api`.
4. It reads a map of secrets and their corresponding file locations from `/mnt/service-1p/mapfile`.
5. The program retrieves each secret that belongs to the user running the program and writes them to the specified file locations in `/run/<uid>/secrets/`.

Here’s the section describing the `mapfile` format. You can add this to your `README.md`:

---

### **Configuration**

The program reads its configuration from `/opt/1Password/op-secret-manager.conf`. This file specifies the paths to the API key file and the map file.

#### **Configuration File Format**

The configuration file is a simple key-value file. Here’s an example:

```
# Path to the API key file
API_KEY_PATH=/mnt/service-1p/api

# Path to the map file
MAP_FILE_PATH=/mnt/service-1p/mapfile
```

#### **Fields**
- **`API_KEY_PATH`**: The path to the file containing the 1Password service account API key.
- **`MAP_FILE_PATH`**: The path to the map file that defines secret mappings.

#### **Example Configuration**

Create the configuration file at `/opt/1Password/op-secret-manager.conf` with the following content:

```
API_KEY_PATH=/mnt/service-1p/api
MAP_FILE_PATH=/mnt/service-1p/mapfile
```

Ensure the file is readable by the user running the program.

---

### **Map File Format**

The `mapfile` is a plain text file that maps secrets from 1Password to specific file locations. Each line in the file represents a single mapping and follows this format:

```
<username>    <secret_reference>    <file_path>
```

#### **Fields**
1. **`<username>`**: The username of the user who should have access to the secret.
2. **`<secret_reference>`**: The 1Password secret reference in the format `op://<vault>/<item>/<field>`.
3. **`<file_path>`**: The file path where the secret should be written. This path should be within `/run/<uid>/secrets/`, where `<uid>` is the user ID of the user running the program.

#### **Example**
Here’s an example `mapfile`:

```
sleeper-postgres    op://vault1/item1/field1    /run/1001/secrets/db_password
sleeper-postgres    op://vault1/item2/field2    /run/1001/secrets/api_key
```

### **Notes**
- Use tabs (`\t`) to separate the fields.
- Ensure the file paths are unique and do not conflict with other files.
- The program will only resolve secrets for the user running it, based on their username.

---

## **Getting a Built Binary**

Pre-built binaries are available on the [Releases page](https://github.com/bexelbie/op-secret-manager/releases). Download the appropriate binary for your platform:

- `op-secret-manager-linux-amd64`: Linux (64-bit)
- `op-secret-manager-linux-arm64`: Linux (ARM64)

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

## **Pushing New Releases**

To create a new release:

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

The project includes a test suite that verifies the functionality of the 1Password secret resolution. Tests are run automatically on every push and pull request using GitHub Actions.

To run tests locally:
```bash
go test -v ./...
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
