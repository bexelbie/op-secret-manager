// ABOUTME: This program retrieves secrets from 1Password using service account credentials
// ABOUTME: and writes them to user-specific files with proper permissions and ownership
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

// version is set at build time via -ldflags="-X main.version=<version>"
var version = "dev"

// sanitizeEnvironment clears dangerous environment variables that could be exploited in SUID binaries.
// This must run before main() to prevent the Go runtime from processing these variables.
// Addresses CVE-2023-29403 and similar vulnerabilities.
func sanitizeEnvironment() {
	dangerousVars := []string{
		"GOCOVERDIR",      // Coverage directory manipulation
		"GOTRACEBACK",     // Stack trace control
		"GODEBUG",         // Runtime debugging flags
		"GOMAXPROCS",      // Threading behavior control
		"LD_PRELOAD",      // Library injection
		"LD_LIBRARY_PATH", // Library path manipulation
	}

	for _, v := range dangerousVars {
		os.Unsetenv(v)
	}
}

// init runs before main() and clears dangerous environment variables
func init() {
	sanitizeEnvironment()
}

// Configuration constants
const (
	// defaultAPIKeyPath is the default location of the API key file
	defaultAPIKeyPath = "/etc/op-secret-manager/api"

	// defaultMapFilePath is the default location of the map file
	defaultMapFilePath = "/etc/op-secret-manager/mapfile"

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
	// WriteFile writes data to a file with specified permissions atomically.
	// Implementations should ensure atomic writes to prevent
	// partial file corruption in case of failures.
	WriteFile(filename string, data []byte, perm os.FileMode) error

	// MkdirAll creates a directory and all necessary parent directories
	// with the specified permissions. Similar to os.MkdirAll but with
	// consistent permission handling.
	MkdirAll(path string, perm os.FileMode) error

	// Stat returns file information for testing and verification
	Stat(path string) (os.FileInfo, error)
}

// osFileWriter implements fileWriter using the os package.
type osFileWriter struct{}

func (osFileWriter) WriteFile(filename string, data []byte, perm os.FileMode) error {
	return atomicWriteFile(filename, data, perm)
}

func (osFileWriter) MkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

func (osFileWriter) Stat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}

// atomicWriteFile writes data to a file atomically using a temp file + rename pattern.
// This ensures that if the write fails, no partial file is left at the target path.
func atomicWriteFile(filename string, data []byte, perm os.FileMode) error {
	// Create temp file in the same directory as target (required for atomic rename)
	dir := filepath.Dir(filename)
	tmpFile, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("atomicWriteFile: failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Ensure temp file is removed on error
	defer func() {
		if tmpFile != nil {
			tmpFile.Close()
			os.Remove(tmpPath)
		}
	}()

	// Set permissions on temp file before writing
	if err := tmpFile.Chmod(perm); err != nil {
		return fmt.Errorf("atomicWriteFile: failed to set permissions on temp file: %w", err)
	}

	// Write content to temp file
	if _, err := tmpFile.Write(data); err != nil {
		return fmt.Errorf("atomicWriteFile: failed to write to temp file: %w", err)
	}

	// Sync to ensure data is written to disk
	if err := tmpFile.Sync(); err != nil {
		return fmt.Errorf("atomicWriteFile: failed to sync temp file: %w", err)
	}

	// Close the file before rename
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("atomicWriteFile: failed to close temp file: %w", err)
	}
	tmpFile = nil // Mark as closed so defer doesn't close again

	// Atomic rename (POSIX guarantees this is atomic)
	if err := os.Rename(tmpPath, filename); err != nil {
		return fmt.Errorf("atomicWriteFile: failed to rename temp file: %w", err)
	}

	return nil
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

// resolveConfigPaths resolves the API key and map file paths using the following precedence:
// 1. Command-line flags (highest priority)
// 2. Environment variables
// 3. Default paths (lowest priority)
func resolveConfigPaths(verbose bool, apiKeyPathFlag, mapFilePathFlag string) (string, string) {
	// Start with defaults
	apiKeyPath := defaultAPIKeyPath
	mapFilePath := defaultMapFilePath

	// Override with environment variables if set
	if envAPIKey := os.Getenv("OP_API_KEY_PATH"); envAPIKey != "" {
		logVerbose(verbose, "Overriding API key path with OP_API_KEY_PATH: %s", envAPIKey)
		apiKeyPath = envAPIKey
	}
	if envMapFile := os.Getenv("OP_MAP_FILE_PATH"); envMapFile != "" {
		logVerbose(verbose, "Overriding map file path with OP_MAP_FILE_PATH: %s", envMapFile)
		mapFilePath = envMapFile
	}

	// Override with command-line flags if provided
	if apiKeyPathFlag != "" {
		logVerbose(verbose, "Overriding API key path with command-line flag: %s", apiKeyPathFlag)
		apiKeyPath = apiKeyPathFlag
	}
	if mapFilePathFlag != "" {
		logVerbose(verbose, "Overriding map file path with command-line flag: %s", mapFilePathFlag)
		mapFilePath = mapFilePathFlag
	}

	logVerbose(verbose, "Resolved API key path: %s", apiKeyPath)
	logVerbose(verbose, "Resolved map file path: %s", mapFilePath)

	return apiKeyPath, mapFilePath
}

// dropSUID drops SUID privileges by switching to the current user.
// This function is not unit tested due to its reliance on system calls
// that require root privileges and specific system setup.
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

// resolveSecretPath converts a relative path to an absolute path under /run/user/<uid>/secrets/.
// Absolute paths are returned as-is. This allows mapfiles to use simple relative paths
// like "db_password" which will be expanded to "/run/user/<uid>/secrets/db_password".
func resolveSecretPath(path string, uid string) string {
	// If path is already absolute, return as-is
	if filepath.IsAbs(path) {
		return path
	}
	// For relative paths, prepend /run/user/<uid>/secrets/
	return filepath.Join("/run/user", uid, "secrets", path)
}

// parseMapFileLine parses a single line from the map file.
// Returns an error for blank lines, comments, and invalid entries (these should be skipped).
// Comments are lines that start with # (after trimming whitespace).
// Valid lines have exactly three whitespace-separated fields: username, secret-reference, file-path.
func parseMapFileLine(line string) (username, secretRef, filePath string, err error) {
	// Trim leading/trailing whitespace
	trimmed := strings.TrimSpace(line)

	// Skip blank lines
	if trimmed == "" {
		return "", "", "", fmt.Errorf("blank line")
	}

	// Skip comment lines
	if strings.HasPrefix(trimmed, "#") {
		return "", "", "", fmt.Errorf("comment line")
	}

	// Split by any whitespace
	fields := strings.Fields(trimmed)

	// Must have exactly 3 fields
	if len(fields) != 3 {
		return "", "", "", fmt.Errorf("invalid line format: expected 3 fields, got %d", len(fields))
	}

	return fields[0], fields[1], fields[2], nil
}

// processMapFile processes the map file and writes secrets with proper resource cleanup.
func processMapFile(ctx context.Context, client OPClient, mapFileContent []byte, currentUser *user.User, verbose bool, fw fileWriter) error {
	logVerbose(verbose, "Processing map file content")
	scanner := bufio.NewScanner(strings.NewReader(string(mapFileContent)))
	lineNumber := 0

	// Track directories and files we create
	createdDirs := make(map[string]bool)
	createdFiles := make(map[string]bool)

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Parse the line
		username, secretRef, filePath, err := parseMapFileLine(line)
		if err != nil {
			// Skip blank lines and comments silently
			if verbose && !strings.Contains(err.Error(), "blank line") && !strings.Contains(err.Error(), "comment line") {
				logVerbose(verbose, "Skipping line %d: %v", lineNumber, err)
			}
			continue
		}

		// Process only entries for the current user.
		if username != currentUser.Username {
			if verbose {
				logVerbose(verbose, "Skipping line %d: not for current user", lineNumber)
			}
			continue
		}

		// Resolve relative paths to absolute paths under /run/user/<uid>/secrets/
		filePath = resolveSecretPath(filePath, currentUser.Uid)
		logVerbose(verbose, "Resolved file path: %s", filePath)

		// Validate output path before any operations
		if err := validateOutputPath(filePath, currentUser.Uid); err != nil {
			return fmt.Errorf("processMapFile: invalid output path at line %d: %w", lineNumber, err)
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

		// Verify file ownership and permissions (only if we created it)
		// Note: After dropSUID, files are automatically owned by the current user
		if createdFiles[filePath] {
			if err := verifyPermissionsAndOwnership(filePath, 0600, currentUser, verbose, fw); err != nil {
				return fmt.Errorf("processMapFile: file %s permission/ownership verification failed: %w", filePath, err)
			}
		}

		// Verify directory ownership and permissions (only if we created it)
		// Note: After dropSUID, directories are automatically owned by the current user
		if createdDirs[dir] {
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
	info, err := fw.Stat(path)
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

// readAPIKey reads the API key from the specified path.
func readAPIKey(verbose bool, apiKeyPath string) (string, error) {
	logVerbose(verbose, "Reading API key from: %s", apiKeyPath)
	apiKey, err := os.ReadFile(apiKeyPath)
	if err != nil {
		return "", fmt.Errorf("readAPIKey: failed to read API key: %w", err)
	}
	return string(apiKey), nil
}

// initializeClient initializes the 1Password client with enhanced context handling.
func initializeClient(ctx context.Context, apiKey string) (OPClient, error) {
	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithServiceAccountToken(strings.TrimSpace(apiKey)),
		onepassword.WithIntegrationInfo("op-secret-manager", "v1.0.0"),
	)
	if err != nil {
		return nil, fmt.Errorf("initializeClient: failed to create client: %w", err)
	}
	return &onePasswordClientAdapter{client: client}, nil
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

// cleanupSecretFiles removes files that would have been created by op-secret-manager.
// It reads the map file to identify files created for the current user and safely removes them.
// Only files are removed; directories are left intact.
// Returns an error if any file cannot be removed.
func cleanupSecretFiles(mapFileContent []byte, currentUser *user.User, verbose bool) error {
	logVerbose(verbose, "Processing map file content for cleanup")
	scanner := bufio.NewScanner(strings.NewReader(string(mapFileContent)))
	lineNumber := 0

	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()

		// Parse the line
		username, _, filePath, err := parseMapFileLine(line)
		if err != nil {
			// Skip blank lines and comments silently
			continue
		}

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

// checkRootAllowed verifies that root execution is permitted.
// Non-root users (UID != 0) are always allowed.
// Root (UID 0) is only allowed if the mapfile is:
//   - Owned by root (UID 0)
//   - Not writable by group or others (no group-write or other-write bits)
//
// This prevents an attacker from poisoning the mapfile to make root write
// secrets to dangerous locations. If an attacker can create a root-owned
// file with restrictive permissions, they already have root access anyway.
func checkRootAllowed(currentUser *user.User, mapFilePath string) error {
	// Non-root users are always allowed
	if currentUser.Uid != "0" {
		return nil
	}

	// Root user - verify mapfile security
	info, err := os.Stat(mapFilePath)
	if err != nil {
		return fmt.Errorf("checkRootAllowed: cannot stat mapfile %s: %w", mapFilePath, err)
	}

	// Check ownership - must be owned by root (UID 0)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("checkRootAllowed: cannot determine mapfile ownership")
	}
	if stat.Uid != 0 {
		return fmt.Errorf("checkRootAllowed: mapfile must be owned by root (UID 0) when running as root, but is owned by UID %d", stat.Uid)
	}

	// Check permissions - must not be group-writable or world-writable
	perm := info.Mode().Perm()
	if perm&0022 != 0 {
		return fmt.Errorf("checkRootAllowed: mapfile must not be writable by group or others when running as root (current mode: %o)", perm)
	}

	return nil
}

// validateOutputPath ensures the output path is safe by preventing path traversal attacks.
// After dropSUID, the program runs as the real user, so OS filesystem permissions
// enforce access control. We only need to prevent path traversal attacks (e.g., ..).
// Absolute paths can write anywhere the user has permission.
// Relative paths are resolved to /run/user/<uid>/secrets/ before this validation.
func validateOutputPath(path string, uid string) error {
	// Check for .. in the original path (indicates path traversal attempt)
	if strings.Contains(path, "..") {
		return fmt.Errorf("validateOutputPath: path traversal attempt detected")
	}

	// Path must be absolute after resolution
	if !filepath.IsAbs(path) {
		return fmt.Errorf("validateOutputPath: path must be absolute (relative paths should be resolved first)")
	}

	return nil
}

// lockFilePath returns the path for the per-user process lock file.
func lockFilePath(uid string) string {
	return filepath.Join("/run/user", uid, "op-secret-manager.lock")
}

// acquireProcessLock acquires an exclusive flock on a lock file.
// It blocks until the lock is available. Returns the lock file (caller must defer Close() to release).
// The lock is automatically released if the process crashes or is killed.
func acquireProcessLock(lockPath string, verbose bool) (*os.File, error) {
	logVerbose(verbose, "Opening lock file: %s", lockPath)
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("acquireProcessLock: failed to open lock file %s: %w", lockPath, err)
	}

	logVerbose(verbose, "Waiting for exclusive lock: %s", lockPath)
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("acquireProcessLock: failed to acquire lock on %s: %w", lockPath, err)
	}

	logVerbose(verbose, "Exclusive lock acquired: %s", lockPath)
	return f, nil
}

// main is the entry point of the program with graceful shutdown.
func main() {
	verbose := flag.Bool("v", false, "Enable verbose logging")
	cleanup := flag.Bool("cleanup", false, "Remove files created by the op-secret-manager")
	apiKeyPath := flag.String("api-key-path", "", "Path to API key file (overrides OP_API_KEY_PATH env var and default)")
	mapFilePath := flag.String("map-file-path", "", "Path to map file (overrides OP_MAP_FILE_PATH env var and default)")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.BoolVar(verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	// Handle version flag
	if *versionFlag {
		fmt.Printf("op-secret-manager %s\n", version)
		os.Exit(0)
	}

	logVerbose(*verbose, "Starting program with verbose logging enabled")

	// Set up context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout)
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

	// Resolve configuration paths with precedence: CLI flags > env vars > defaults
	resolvedAPIKeyPath, resolvedMapFilePath := resolveConfigPaths(*verbose, *apiKeyPath, *mapFilePath)

	// Check if root execution is allowed (requires secure mapfile)
	if err := checkRootAllowed(currentUser, resolvedMapFilePath); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Read API key while still privileged
	apiKey, err := readAPIKey(*verbose, resolvedAPIKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Read map file contents while still privileged
	mapFileContent, err := os.ReadFile(resolvedMapFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Drop SUID privileges.
	if err := dropSUID(*verbose, currentUser.Username); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Acquire per-user process lock to serialize concurrent invocations.
	// This prevents WASM runtime conflicts when multiple containers start simultaneously.
	lockPath := lockFilePath(currentUser.Uid)
	logVerbose(*verbose, "Acquiring process lock: %s", lockPath)
	lockFile, err := acquireProcessLock(lockPath, *verbose)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer lockFile.Close()
	logVerbose(*verbose, "Process lock acquired: %s", lockPath)

	// Initialize 1Password client.
	ctx, cancel = context.WithTimeout(context.Background(), opTimeout)
	defer cancel()

	client, err := initializeClient(ctx, apiKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	logVerbose(*verbose, "1Password client initialized successfully")

	// Process the map file or cleanup files.
	if *cleanup {
		if err := cleanupSecretFiles(mapFileContent, currentUser, *verbose); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Cleanup completed successfully")
	} else {
		if err := processMapFile(ctx, client, mapFileContent, currentUser, *verbose, osFileWriter{}); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
}
