package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/1password/onepassword-sdk-go"
)

const (
	configFilePath = "/opt/1Password/op-secret-manager.conf"
	opTimeout      = 10 * time.Second // Define a named constant for the timeout value
)

var verbose bool

func logVerbose(format string, args ...interface{}) {
	if verbose {
		fmt.Printf("[VERBOSE] "+format+"\n", args...)
	}
}

// readConfig reads the configuration file and returns the API key path and map file path.
func readConfig(configFilePath string) (string, string, error) {
	logVerbose("Reading configuration file: %s", configFilePath)
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
			continue // Skip empty lines and comments
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return "", "", fmt.Errorf("readConfig: invalid config line: %s", line)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		config[key] = value
		logVerbose("Config entry: %s = %s", key, value)
	}

	apiKeyPath, ok := config["API_KEY_PATH"]
	if !ok {
		return "", "", fmt.Errorf("readConfig: API_KEY_PATH not found in config file")
	}

	mapFilePath, ok := config["MAP_FILE_PATH"]
	if !ok {
		return "", "", fmt.Errorf("readConfig: MAP_FILE_PATH not found in config file")
	}

	logVerbose("API key path: %s", apiKeyPath)
	logVerbose("Map file path: %s", mapFilePath)
	return apiKeyPath, mapFilePath, nil
}

// getSUIDUser returns the username of the SUID user.
func getSUIDUser() (string, error) {
	euid := syscall.Geteuid()
	logVerbose("Effective UID (EUID): %d", euid)
	u, err := user.LookupId(strconv.Itoa(euid))
	if err != nil {
		return "", fmt.Errorf("getSUIDUser: failed to lookup SUID user: %w", err)
	}
	logVerbose("SUID user: %s", u.Username)
	return u.Username, nil
}

// dropSUID drops SUID privileges by switching to the current user.
func dropSUID(username string) error {
	logVerbose("Dropping SUID privileges, switching to user: %s", username)
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

	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("dropSUID: failed to set GID: %w", err)
	}

	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("dropSUID: failed to set UID: %w", err)
	}

	logVerbose("Successfully switched to user: %s", username)
	return nil
}

// elevateSUID elevates to the SUID user
func elevateSUID(username string) error {
	logVerbose("Elevating to SUID privileges, switching to user: %s", username)
	u, err := user.Lookup(username)
	if err != nil {
		return fmt.Errorf("elevateSUID: failed to lookup user %s: %w", username, err)
	}

	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return fmt.Errorf("elevateSUID: invalid UID for user %s: %w", username, err)
	}

	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return fmt.Errorf("elevateSUID: invalid GID for user %s: %w", username, err)
	}

	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("elevateSUID: failed to set GID: %w", err)
	}

	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("elevateSUID: failed to set UID: %w", err)
	}

	logVerbose("Successfully switched to user: %s", username)
	return nil
}

func main() {
	// Parse command-line flags
	flag.BoolVar(&verbose, "v", false, "Enable verbose logging")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()

	logVerbose("Starting program with verbose logging enabled")

	// Step 1: Dynamically determine the SUID user
	suidUser, err := getSUIDUser()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to determine SUID user: %v\n", err)
		return
	}

	// Step 2: Get the current (executing) user
	currentUser, err := user.Current()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get current user: %v\n", err)
		return
	}
	logVerbose("Executing user: %s (UID: %s)", currentUser.Username, currentUser.Uid)

	// Step 3: Elevate to the SUID user
	if err := elevateSUID(suidUser); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to switch to SUID user: %v\n", err)
		return
	}

	// Step 4: Read the configuration file
	apiKeyPath, mapFilePath, err := readConfig(configFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config file: %v\n", err)
		return
	}

	// Step 5: Read the API key
	logVerbose("Reading API key from: %s", apiKeyPath)
	apiKey, err := os.ReadFile(apiKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read API key: %v\n", err)
		return
	}

	// Step 6: Drop SUID privileges
	if err := dropSUID(currentUser.Username); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to drop SUID privileges: %v\n", err)
		return
	}

	// Step 7: Initialize the 1Password client with a timeout
	logVerbose("Initializing 1Password client")
	ctx, cancel := context.WithTimeout(context.Background(), opTimeout) // 10-second timeout
	defer cancel()

	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithServiceAccountToken(strings.TrimSpace(string(apiKey))),
		onepassword.WithIntegrationInfo("Secret Manager", "v1.0.0"),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create 1Password client: %v\n", err)
		return
	}
	logVerbose("1Password client initialized successfully")

	// Step 8: Read the map file
	logVerbose("Reading map file: %s", mapFilePath)
	mapFile, err := os.Open(mapFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open map file: %v\n", err)
		return
	}
	defer mapFile.Close()

	// Step 9: Process the map file
	scanner := bufio.NewScanner(mapFile)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			fmt.Fprintf(os.Stderr, "Invalid map file entry: %s\n", line)
			continue
		}

		username := parts[0]
		secretRef := parts[1]
		filePath := parts[2]

		logVerbose("Processing entry for user: %s, secret: %s, file: %s", username, secretRef, filePath)

		// Step 10: Check if the entry is for the current user
		if username != currentUser.Username {
			logVerbose("Skipping entry: not for current user")
			continue
		}

		// Step 11: Resolve the secret with a timeout
		logVerbose("Resolving secret: %s", secretRef)
		secret, err := client.Secrets().Resolve(ctx, secretRef)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to resolve secret %s: %v\n", secretRef, err)
			continue
		}
		logVerbose("Secret resolved successfully: %s", secretRef)

		// Step 12: Create the directory structure with 700 permissions
		dir := filepath.Dir(filePath)
		logVerbose("Creating directory: %s", dir)
		if err := os.MkdirAll(dir, 0700); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to create directory %s: %v\n", dir, err)
			continue
		}

		// Step 13: Write the secret to the file with 600 permissions
		logVerbose("Writing secret to file: %s", filePath)
		if err := os.WriteFile(filePath, []byte(secret), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write secret to %s: %v\n", filePath, err)
			continue
		}

		// Step 14: Ensure the file and directory are owned by the executing user
		uid, _ := strconv.Atoi(currentUser.Uid)
		gid, _ := strconv.Atoi(currentUser.Gid)

		logVerbose("Setting ownership of file: %s (UID: %d, GID: %d)", filePath, uid, gid)
		if err := os.Chown(filePath, uid, gid); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to change ownership of file %s: %v\n", filePath, err)
			continue
		}

		logVerbose("Setting ownership of directory: %s (UID: %d, GID: %d)", dir, uid, gid)
		if err := os.Chown(dir, uid, gid); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to change ownership of directory %s: %v\n", dir, err)
			continue
		}

		fmt.Printf("Successfully wrote secret to %s\n", filePath)
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading map file: %v\n", err)
	}
}
