package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"strconv"

	"github.com/1password/onepassword-sdk-go"
)

const (
	configFilePath = "/opt/1Password/op-secret-manager.conf"
)

// readConfig reads the configuration file and returns the API key path and map file path.
func readConfig() (string, string, error) {
	file, err := os.Open(configFilePath)
	if err != nil {
		return "", "", fmt.Errorf("failed to open config file: %v", err)
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
			return "", "", fmt.Errorf("invalid config line: %s", line)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		config[key] = value
	}

	apiKeyPath, ok := config["API_KEY_PATH"]
	if !ok {
		return "", "", fmt.Errorf("API_KEY_PATH not found in config file")
	}

	mapFilePath, ok := config["MAP_FILE_PATH"]
	if !ok {
		return "", "", fmt.Errorf("MAP_FILE_PATH not found in config file")
	}

	return apiKeyPath, mapFilePath, nil
}

func main() {
	// Step 1: Read the configuration file
	apiKeyPath, mapFilePath, err := readConfig()
	if err != nil {
		fmt.Printf("Failed to read config file: %v\n", err)
		return
	}

	// Step 2: Read the API key
	apiKey, err := os.ReadFile(apiKeyPath)
	if err != nil {
		fmt.Printf("Failed to read API key: %v\n", err)
		return
	}

	// Step 3: Initialize the 1Password client
	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(strings.TrimSpace(string(apiKey))),
		onepassword.WithIntegrationInfo("Secret Manager", "v1.0.0"),
	)
	if err != nil {
		fmt.Printf("Failed to create 1Password client: %v\n", err)
		return
	}

	// Step 4: Get the current user
	currentUser, err := user.Current()
	if err != nil {
		fmt.Printf("Failed to get current user: %v\n", err)
		return
	}

	// Step 5: Read the map file
	mapFile, err := os.Open(mapFilePath)
	if err != nil {
		fmt.Printf("Failed to open map file: %v\n", err)
		return
	}
	defer mapFile.Close()

	scanner := bufio.NewScanner(mapFile)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			fmt.Printf("Invalid map file entry: %s\n", line)
			continue
		}

		username := parts[0]
		secretRef := parts[1]
		filePath := parts[2]

		// Step 6: Check if the entry is for the current user
		if username != currentUser.Username {
			continue
		}

		// Step 7: Resolve the secret
		secret, err := client.Secrets().Resolve(context.TODO(), secretRef)
		if err != nil {
			fmt.Printf("Failed to resolve secret %s: %v\n", secretRef, err)
			continue
		}

		// Step 8: Create the directory structure with 700 permissions
		dir := filepath.Dir(filePath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			fmt.Printf("Failed to create directory %s: %v\n", dir, err)
			continue
		}

		// Step 9: Write the secret to the file with 600 permissions
		if err := os.WriteFile(filePath, []byte(secret), 0600); err != nil {
			fmt.Printf("Failed to write secret to %s: %v\n", filePath, err)
			continue
		}

		// Step 10: Ensure the file and directory are owned by the executing user
		uid, _ := strconv.Atoi(currentUser.Uid)
		gid, _ := strconv.Atoi(currentUser.Gid)

		if err := os.Chown(filePath, uid, gid); err != nil {
			fmt.Printf("Failed to change ownership of file %s: %v\n", filePath, err)
			continue
		}

		if err := os.Chown(dir, uid, gid); err != nil {
			fmt.Printf("Failed to change ownership of directory %s: %v\n", dir, err)
			continue
		}

		fmt.Printf("Successfully wrote secret to %s\n", filePath)
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error reading map file: %v\n", err)
	}
}
