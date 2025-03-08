package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/1password/onepassword-sdk-go"
)

const (
	apiKeyPath  = "/mnt/service-1p/api"
	mapFilePath = "/mnt/service-1p/mapfile"
)

func main() {
	// Read API key
	apiKey, err := os.ReadFile(apiKeyPath)
	if err != nil {
		fmt.Printf("Failed to read API key: %v\n", err)
		return
	}

	// Initialize 1Password client
	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(strings.TrimSpace(string(apiKey))),
		onepassword.WithIntegrationInfo("Secret Manager", "v1.0.0"),
	)
	if err != nil {
		fmt.Printf("Failed to create client: %v\n", err)
		return
	}

	// Get current user
	currentUser, err := user.Current()
	if err != nil {
		fmt.Printf("Failed to get user: %v\n", err)
		return
	}

	// Process map file
	mapFile, err := os.Open(mapFilePath)
	if err != nil {
		fmt.Printf("Failed to open map: %v\n", err)
		return
	}
	defer mapFile.Close()

	scanner := bufio.NewScanner(mapFile)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, "\t")
		if len(parts) != 3 {
			fmt.Printf("Invalid line: %s\n", line)
			continue
		}

		username := parts[0]
		secretRef := parts[1]
		filePath := parts[2]

		if username != currentUser.Username {
			continue
		}

		// CORRECTED LINE: Added () to client.Secrets()
		secret, err := client.Secrets().Resolve(context.TODO(), secretRef)
		if err != nil {
			fmt.Printf("Resolve failed: %s | %v\n", secretRef, err)
			continue
		}

		dir := filepath.Dir(filePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			fmt.Printf("Mkdir failed: %s | %v\n", dir, err)
			continue
		}

		if err := os.WriteFile(filePath, []byte(secret), 0600); err != nil {
			fmt.Printf("Write failed: %s | %v\n", filePath, err)
		}

		fmt.Printf("Wrote secret to %s\n", filePath)
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Map file error: %v\n", err)
	}
}
