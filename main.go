package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/1password/onepassword-sdk-go"
)

// Configuration constants
const (
	// configFilePath is the default location of the configuration file
	// that contains API key and map file paths. This path is hardcoded
	// for security reasons to prevent arbitrary file access.
	configFilePath = "/opt/1Password/op-secret-manager.conf"

	// opTimeout is the default timeout for 1Password operations.
	// This timeout is used for API calls and file operations to prevent
	// indefinite hangs. Adjust this value based on network conditions
	// and expected operation times.
	opTimeout = 10 * time.Second
)

// fileWriter defines the interface for file system operations.
// This interface is used to abstract file system interactions
// for better testability and to enable mocking in unit tests.
// Implementations must ensure atomic writes where possible and
// maintain proper file permissions and ownership.
type fileWriter interface {
	// WriteFile writes data to a file with specified permissions.
	// Implementations should ensure atomic writes to prevent
	// partial file corruption in case of failures.
	WriteFile(filename string, data []byte, perm os.FileMode) error

	// MkdirAll creates a directory and all necessary parent directories
	// with the specified permissions. Similar to os.MkdirAll but with
	// consistent permission handling.
	MkdirAll(path string, perm os.FileMode) error

	// Chown changes the ownership of a file or directory.
	// Implementations must handle both files and directories
	// and verify ownership changes were successful.
	Chown(name string, uid, gid int) error
}

// osFileWriter implements fileWriter using the os package.
type osFileWriter struct{}

func (osFileWriter) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return os.WriteFile(filename, data, perm)
}

func (osFileWriter) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (osFileWriter) Chown(name string, uid, gid int) error {
	return os.Chown(name, uid, gid)
}

// logVerbose prints verbose log messages.
func logVerbose(verbose bool, format string, args ...interface{}) {
	if verbose {
		redactedArgs := make([]interface{}, len(args))
		for i, arg := range args {
			switch v := arg.(type) {
			case string:
				// Redact secret values in the format op://vault/item/field
				if strings.HasPrefix(v, "op://") {
					parts := strings.Split(v, "/")
					if len(parts) >= 3 {
						// Redact middle parts
						for i := 1; i < len(parts)-1; i++ {
							if len(parts[i]) > 3 {
								parts[i] = parts[i][:3] + "..."
							}
						}
						// Redact last part
						if len(parts[len(parts)-1]) > 3 {
							parts[len(parts)-1] = parts[len(parts)-1][:3] + "..."
						}
					}
					redactedArgs[i] = strings.Join(parts, "/")
				} else {
					redactedArgs[i] = v
				}
			default:
				redactedArgs[i] = v
			}
		}
		fmt.Printf("[VERBOSE] "+format+"\n", redactedArgs...)
	}
}

// SecretResolver defines the interface for resolving secrets.
type SecretResolver interface {
	Resolve(ctx context.Context, secretRef string) (string, error)
}

// OPClient defines the interface our client must satisfy.
type OPClient interface {
	Secrets() SecretResolver
}

// onePasswordClientAdapter wraps the real 1Password client so it satisfies OPClient.
type onePasswordClientAdapter struct {
	client *onepassword.Client
}

func (a *onePasswordClientAdapter) Secrets() SecretResolver {
	return &onepasswordSecretsAdapter{secrets: a.client.Secrets()}
}

type onepasswordSecretsAdapter struct {
	secrets onepassword.SecretsAPI
}

func (o *onepasswordSecretsAdapter) Resolve(ctx context.Context, secretRef string) (string, error) {
	return o.secrets.Resolve(ctx, secretRef)
}

// readConfig reads the configuration file.
func readConfig(verbose bool, configFilePath string) (string, string, error) {
	logVerbose(verbose, "Reading configuration file: %s", configFilePath)
	file, err := os.Open(configFilePath)
	if err != nil {
		return "", "", fmt.Errorf("readConfig: failed to open config file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	config := make(map[string]string)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("readConfig: invalid config line: %s", line)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		config[key] = value
		logVerbose(verbose, "Config entry: %s = %s", key, value)
	}

	if err := scanner.Err(); err != nil {
		return "", "", fmt.Errorf("readConfig: error reading config file: %w", err)
	}

	apiKeyPath, ok := config["API_KEY_PATH"]
	if !ok {
		return "", "", fmt.Errorf("readConfig: API_KEY_PATH not found in config file")
	}
	mapFilePath, ok := config["MAP_FILE_PATH"]
	if !ok {
		return "", "", fmt.Errorf("readConfig: MAP_FILE_PATH not found in config file")
	}

	logVerbose(verbose, "API key path: %s", apiKeyPath)
	logVerbose(verbose, "Map file path: %s", mapFilePath)
	return apiKeyPath, mapFilePath, nil
}


// dropSUID drops SUID privileges by switching to the current user.
// This function is not unit tested due to its reliance on system calls
// that require root privileges and specific system setup.
//
//gocov:ignore
func dropSUID(verbose bool, username string) error {
	logVerbose(verbose, "Dropping SUID privileges, switching to user: %s", username)
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("dropSUID: failed to lookup user %s: %w", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("dropSUID: invalid UID for user %s: %w", username, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("dropSUID: invalid GID for user %s: %w", username, err)
	}

	// Skip supplementary groups since they're not needed for our use case
	logVerbose(verbose, "Skipping supplementary groups for user: %s", username)

	// Set GID
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("dropSUID: failed to set GID: %w", err)
	}

	// Verify GID change
	if syscall.Getgid() != gid || syscall.Getegid() != gid {
		return fmt.Errorf("dropSUID: GID change verification failed")
	}

	// Set UID
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("dropSUID: failed to set UID: %w", err)
	}

	// Verify UID change
	if syscall.Getuid() != uid || syscall.Geteuid() != uid {
		return fmt.Errorf("dropSUID: UID change verification failed")
	}

	logVerbose(verbose, "Successfully switched to user: %s", username)
	return nil
}

// processMapFile processes the map file and writes secrets with proper resource cleanup.
func processMapFile(ctx context.Context, client OPClient, mapFilePath string, currentUser *user.User, verbose bool, fw fileWriter) error {
	logVerbose(verbose, "Processing map file: %s", mapFilePath)
	mapFile, err := os.Open(mapFilePath)
	if err != nil {
		return fmt.Errorf("processMapFile: failed to open map file: %w", err)
	}
	defer mapFile.Close()

	scanner := bufio.NewScanner(mapFile)
	lineNumber := 0

	// Track directories and files we create
	createdDirs := make(map[string]bool)
	createdFiles := make(map[string]bool)

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			return fmt.Errorf("processMapFile: invalid map file entry at line %d: %s", lineNumber, line)
		}
		username := parts[0]
		secretRef := parts[1]
		filePath := parts[2]

		// Process only entries for the current user.
		if username != currentUser.Username {
			if verbose {
				logVerbose(verbose, "Skipping line %d: not for current user", lineNumber)
			}
			continue
		}

		logVerbose(verbose, "Processing entry for user: %s, secret: %s, file: %s", username, secretRef, filePath)
		logVerbose(verbose, "Resolving secret: %s", secretRef)
		secret, err := client.Secrets().Resolve(ctx, secretRef)
		if err != nil {
			return fmt.Errorf("processMapFile: failed to resolve secret %s: %w", secretRef, err)
		}
		logVerbose(verbose, "Secret resolved successfully: %s", secretRef)

		dir := filepath.Dir(filePath)
		logVerbose(verbose, "Creating directory: %s", dir)

		// Check if the directory already exists
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			// Directory does not exist, create it
			if err := fw.MkdirAll(dir, 0700); err != nil {
				return fmt.Errorf("processMapFile: failed to create directory %s: %w", dir, err)
			}
			createdDirs[dir] = true // Track that we created this directory
		}

		logVerbose(verbose, "Writing secret to file: %s", filePath)
		if err := fw.WriteFile(filePath, []byte(secret), 0600); err != nil {
			return fmt.Errorf("processMapFile: failed to write secret to %s: %w", filePath, err)
		}
		createdFiles[filePath] = true // Track that we created this file

		uid, _ := strconv.Atoi(currentUser.Uid)
		gid, _ := strconv.Atoi(currentUser.Gid)

		// Verify and set ownership for the file
		logVerbose(verbose, "Setting ownership of file: %s (UID: %d, GID: %d)", filePath, uid, gid)
		if err := fw.Chown(filePath, uid, gid); err != nil {
			return fmt.Errorf("processMapFile: failed to change ownership of file %s: %w", filePath, err)
		}

		// Verify file ownership and permissions (only if we created it)
		if createdFiles[filePath] {
			if err := verifyPermissionsAndOwnership(filePath, 0600, currentUser, verbose, fw); err != nil {
				return fmt.Errorf("processMapFile: file %s permission/ownership verification failed: %w", filePath, err)
			}
		}

		// Verify and set ownership for the directory (only if we created it)
		if createdDirs[dir] {
			logVerbose(verbose, "Setting ownership of directory: %s (UID: %d, GID: %d)", dir, uid, gid)
			if err := fw.Chown(dir, uid, gid); err != nil {
				return fmt.Errorf("processMapFile: failed to change ownership of directory %s: %w", dir, err)
			}

			if err := verifyPermissionsAndOwnership(dir, 0700, currentUser, verbose, fw); err != nil {
				return fmt.Errorf("processMapFile: directory %s permission/ownership verification failed: %w", dir, err)
			}
		}

		fmt.Printf("Successfully wrote secret to %s\n", filePath)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("processMapFile: error reading map file: %w", err)
	}
	return nil
}

// verifyPermissionsAndOwnership checks if the file or directory has the expected permissions and ownership.
func verifyPermissionsAndOwnership(path string, expectedPerm os.FileMode, currentUser *user.User, verbose bool, fw fileWriter) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("verifyPermissionsAndOwnership: failed to stat %s: %w", path, err)
	}

	// Check permissions
	if info.Mode().Perm() != expectedPerm {
		return fmt.Errorf("verifyPermissionsAndOwnership: %s has incorrect permissions: expected %o, got %o", path, expectedPerm, info.Mode().Perm())
	}

	// Check ownership
	uid, _ := strconv.Atoi(currentUser.Uid)
	gid, _ := strconv.Atoi(currentUser.Gid)
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(stat.Uid) != uid || int(stat.Gid) != gid {
			return fmt.Errorf("verifyPermissionsAndOwnership: %s has incorrect ownership: expected UID %d GID %d, got UID %d GID %d", path, uid, gid, stat.Uid, stat.Gid)
		}
	} else {
		return fmt.Errorf("verifyPermissionsAndOwnership: failed to get ownership info for %s", path)
	}

	logVerbose(verbose, "Verified permissions and ownership for %s: permissions %o, UID %d, GID %d", path, expectedPerm, uid, gid)
	return nil
}

// verifyOwnership checks if the file or directory has the expected ownership.
func verifyOwnership(path string, expectedUID, expectedGID int, verbose bool) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("verifyOwnership: failed to stat %s: %w", path, err)
	}

	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		if int(stat.Uid) != expectedUID || int(stat.Gid) != expectedGID {
			return fmt.Errorf("verifyOwnership: %s has incorrect ownership: expected UID %d GID %d, got UID %d GID %d", path, expectedUID, expectedGID, stat.Uid, stat.Gid)
		}
	} else {
		return fmt.Errorf("verifyOwnership: failed to get ownership info for %s", path)
	}

	logVerbose(verbose, "Verified ownership for %s: UID %d, GID %d", path, expectedUID, expectedGID)
	return nil
}

// readAPIKey reads the API key from the specified path.
func readAPIKey(verbose bool, apiKeyPath string) (string, error) {
	logVerbose(verbose, "Reading API key from: %s", apiKeyPath)
	apiKey, err := os.ReadFile(apiKeyPath)
	if err != nil {
		return "", fmt.Errorf("readAPIKey: failed to read API key: %w", err)
	}
	return string(apiKey), nil
}

// setupContext creates a context with a timeout and cancellation.
func setupContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// initializeClient initializes the 1Password client with enhanced context handling.
func initializeClient(ctx context.Context, apiKey string) (OPClient, error) {
	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithServiceAccountToken(strings.TrimSpace(apiKey)),
		onepassword.WithIntegrationInfo("Secret Manager", "v1.0.0"),
	)
	if err != nil {
		return nil, fmt.Errorf("initializeClient: failed to create client: %w", err)
	}
	return &onePasswordClientAdapter{client: client}, nil
}

// getTimeoutForOperation returns a timeout duration based on the operation type.
func getTimeoutForOperation(operation string) time.Duration {
	switch operation {
	case "resolveSecret":
		return 15 * time.Second
	case "writeFile":
		return 10 * time.Second
	case "createDirectory":
		return 5 * time.Second
	default:
		return 10 * time.Second
	}
}

// resolveSecretWithTimeout resolves a secret with a specific timeout.
func resolveSecretWithTimeout(ctx context.Context, client OPClient, secretRef string) (string, error) {
	timeout := getTimeoutForOperation("resolveSecret")
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return client.Secrets().Resolve(ctx, secretRef)
}

// handleSignals sets up signal handling for graceful shutdown.
// handleSignals sets up signal handling for graceful shutdown.
// It listens for SIGINT and SIGTERM signals and cancels the context when received.
// This allows for cleanup of resources before program exit.
// Logs are emitted when signals are received to aid in monitoring and debugging.
func handleSignals(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Received signal: %v, initiating graceful shutdown", sig)
		cancel()
		log.Printf("Shutdown initiated for signal: %v", sig)
	}()
}

// cleanupSecretFiles removes files that would have been created by the 1Password Secret Manager.
// It reads the map file to identify files created for the current user and safely removes them.
// Only files are removed; directories are left intact.
// Returns an error if any file cannot be removed.
func cleanupSecretFiles(mapFilePath string, currentUser *user.User, verbose bool) error {
	logVerbose(verbose, "Processing map file for cleanup: %s", mapFilePath)
	mapFile, err := os.Open(mapFilePath)
	if err != nil {
		return fmt.Errorf("cleanupSecretFiles: failed to open map file: %w", err)
	}
	defer mapFile.Close()

	scanner := bufio.NewScanner(mapFile)
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			return fmt.Errorf("cleanupSecretFiles: invalid map file entry at line %d: %s", lineNumber, line)
		}
		username := parts[0]
		filePath := parts[2]

		// Process only entries for the current user.
		if username != currentUser.Username {
			logVerbose(verbose, "Skipping line %d: file %s belongs to user %s, not current user %s", lineNumber, filePath, username, currentUser.Username)
			continue
		}

		logVerbose(verbose, "Processing cleanup for file: %s", filePath)

		// Check if the file exists.
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			logVerbose(verbose, "File does not exist, skipping: %s", filePath)
			continue
		}

		// Remove the file.
		if err := os.Remove(filePath); err != nil {
			return fmt.Errorf("cleanupSecretFiles: failed to remove file %s: %w", filePath, err)
		}

		logVerbose(verbose, "Successfully removed file: %s", filePath)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("cleanupSecretFiles: error reading map file: %w", err)
	}
	return nil
}

// main is the entry point of the program with graceful shutdown.
func main() {
	verbose := flag.Bool("v", false, "Enable verbose logging")
	cleanup := flag.Bool("cleanup", false, "Remove files created by the 1Password Secret Manager")
	flag.BoolVar(verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	logVerbose(*verbose, "Starting program with verbose logging enabled")

	// Set up context with timeout
	ctx, cancel := setupContext(opTimeout)
	defer cancel()

	// Handle signals for graceful shutdown
	handleSignals(cancel)

	// Get current user.
	currentUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	logVerbose(*verbose, "Executing user: %s (UID: %s)", currentUser.Username, currentUser.Uid)
	logVerbose(*verbose, "Running with SUID privileges (EUID: %d)", syscall.Geteuid())

	// Read configuration while still privileged
	apiKeyPath, mapFilePath, err := readConfig(*verbose, configFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Read API key while still privileged
	apiKey, err := readAPIKey(*verbose, apiKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Read map file contents while still privileged
	var mapFileContent []byte
	if *cleanup {
		mapFileContent, err = os.ReadFile(mapFilePath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}

	// Drop SUID privileges.
	if err := dropSUID(*verbose, currentUser.Username); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Initialize 1Password client.
	ctx, cancel = setupContext(opTimeout)
	defer cancel()

	client, err := initializeClient(ctx, apiKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	logVerbose(*verbose, "1Password client initialized successfully")

	// Process the map file or cleanup files.
	if *cleanup {
		// Create a temporary file with the map file contents
		tmpFile, err := os.CreateTemp("", "op-secret-manager-mapfile")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer os.Remove(tmpFile.Name())

		if _, err := tmpFile.Write(mapFileContent); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		tmpFile.Close()

		if err := cleanupSecretFiles(tmpFile.Name(), currentUser, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Cleanup completed successfully")
	} else {
		if err := processMapFile(ctx, client, mapFilePath, currentUser, *verbose, osFileWriter{}); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}
