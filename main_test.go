package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/1password/onepassword-sdk-go"
)

// captureOutput temporarily replaces os.Stdout to capture log output
func captureOutput(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	w.Close()
	os.Stdout = old

	var buf strings.Builder
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

// TestLogVerbose tests the logVerbose function
func TestLogVerbose(t *testing.T) {
	t.Run("verbose enabled with sensitive info", func(t *testing.T) {
		output := captureOutput(func() {
			logVerbose(true, "Processing secret: %s", "op://vault/item/field")
		})

		expected := "[VERBOSE] Processing secret: op://vau.../ite.../fie...\n"
		if output != expected {
			t.Errorf("Expected output %q, got %q", expected, output)
		}
	})

	t.Run("verbose enabled with non-sensitive info", func(t *testing.T) {
		output := captureOutput(func() {
			logVerbose(true, "Processing file: %s", "/path/to/file")
		})

		expected := "[VERBOSE] Processing file: /path/to/file\n"
		if output != expected {
			t.Errorf("Expected output %q, got %q", expected, output)
		}
	})

	t.Run("verbose disabled", func(t *testing.T) {
		output := captureOutput(func() {
			logVerbose(false, "This should not appear")
		})

		if output != "" {
			t.Errorf("Expected no output, got %q", output)
		}
	})

	t.Run("verbose enabled with mixed content", func(t *testing.T) {
		output := captureOutput(func() {
			logVerbose(true, "Secret: %s, Path: %s", "op://vault/item/field", "/path/to/file")
		})

		expected := "[VERBOSE] Secret: op://vau.../ite.../fie..., Path: /path/to/file\n"
		if output != expected {
			t.Errorf("Expected output %q, got %q", expected, output)
		}
	})
}

// MockOPClient is a unified mock implementation of OPClient and SecretResolver.
type MockOPClient struct {
	ResolveSecretFunc func(ctx context.Context, secretRef string) (string, error)
}

func (m *MockOPClient) Secrets() SecretResolver {
	return m // MockOPClient implements SecretResolver directly
}

func (m *MockOPClient) Resolve(ctx context.Context, secretRef string) (string, error) {
	if m.ResolveSecretFunc != nil {
		return m.ResolveSecretFunc(ctx, secretRef)
	}
	return "", fmt.Errorf("ResolveSecretFunc not implemented")
}

// TestSecrets tests secret resolution using a live 1Password client.
func TestSecrets_SuccedingLiveCall(t *testing.T) {
	apiKey := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if apiKey == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN environment variable is not set")
	}

	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(apiKey),
		onepassword.WithIntegrationInfo("Secret Manager Tests", "v1.0.0"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Iterate over SECRET_REF* and SECRET_VAL* environment variables.
	for i := 1; ; i++ {
		secretRef := os.Getenv(fmt.Sprintf("SECRET_REF%d", i))
		expectedVal := os.Getenv(fmt.Sprintf("SECRET_VAL%d", i))
		if secretRef == "" || expectedVal == "" {
			break
		}
		actualVal, err := client.Secrets().Resolve(context.TODO(), secretRef)
		if err != nil {
			t.Errorf("Failed to resolve secret %s: %v", secretRef, err)
			continue
		}
		if actualVal != expectedVal {
			t.Errorf("Secret mismatch for %s: expected %s, got %s", secretRef, expectedVal, actualVal)
		} else {
			t.Logf("Secret %s resolved successfully", secretRef)
		}
	}
}

// TestSecrets_FailingLiveCall tests a failing live 1Password call.
func TestSecrets_FailingLiveCall(t *testing.T) {
	apiKey := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if apiKey == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN environment variable is not set")
	}

	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(apiKey),
		onepassword.WithIntegrationInfo("Secret Manager Tests", "v1.0.0"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	secretRef := os.Getenv("SECRET_REF_FAIL")
	if secretRef == "" {
		t.Skip("SECRET_REF_FAIL environment variable is not set")
	}
	_, err = client.Secrets().Resolve(context.TODO(), secretRef)
	if err == nil {
		t.Errorf("Expected error resolving invalid secret %s, but got nil", secretRef)
	} else {
		t.Logf("Successfully received error for invalid secret %s: %v", secretRef, err)
	}
}

// TestReadConfig tests the readConfig function.
func TestReadConfig(t *testing.T) {
	t.Run("valid configuration", func(t *testing.T) {
		// Create a temporary config file
		tmpFile, err := os.CreateTemp("", "testconfig")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		configContent := `API_KEY_PATH=/path/to/api/key
MAP_FILE_PATH=/path/to/map/file`
		_, err = tmpFile.WriteString(configContent)
		if err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		apiKeyPath, mapFilePath, err := readConfig(false, tmpFile.Name())
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}

		if apiKeyPath != "/path/to/api/key" {
			t.Errorf("Expected API_KEY_PATH /path/to/api/key, got %s", apiKeyPath)
		}
		if mapFilePath != "/path/to/map/file" {
			t.Errorf("Expected MAP_FILE_PATH /path/to/map/file, got %s", mapFilePath)
		}
	})

	t.Run("missing keys", func(t *testing.T) {
		// Create a temporary config file with missing keys
		tmpFile, err := os.CreateTemp("", "testconfig")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		configContent := `SOME_OTHER_KEY=value`
		_, err = tmpFile.WriteString(configContent)
		if err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		_, _, err = readConfig(false, tmpFile.Name())
		if err == nil {
			t.Fatal("Expected error for missing keys, got nil")
		}
	})

	t.Run("invalid formatting", func(t *testing.T) {
		// Create a temporary config file with invalid formatting
		tmpFile, err := os.CreateTemp("", "testconfig")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		configContent := `API_KEY_PATH /path/to/api/key
MAP_FILE_PATH=/path/to/map/file`
		_, err = tmpFile.WriteString(configContent)
		if err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		_, _, err = readConfig(false, tmpFile.Name())
		if err == nil {
			t.Fatal("Expected error for invalid formatting, got nil")
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, _, err := readConfig(false, "/non/existent/file")
		if err == nil {
			t.Fatal("Expected error for non-existent file, got nil")
		}
	})
}


// TestReadAPIKey tests the readAPIKey function.
func TestReadAPIKey(t *testing.T) {
	t.Run("valid API key file", func(t *testing.T) {
		// Create a temporary file with a valid API key
		tmpFile, err := os.CreateTemp("", "testapikey")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		apiKeyContent := "test-api-key-123"
		_, err = tmpFile.WriteString(apiKeyContent)
		if err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		key, err := readAPIKey(false, tmpFile.Name())
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if key != apiKeyContent {
			t.Errorf("Expected API key %q, got %q", apiKeyContent, key)
		}
	})

	t.Run("non-existent file", func(t *testing.T) {
		_, err := readAPIKey(false, "/non/existent/file")
		if err == nil {
			t.Fatal("Expected error for non-existent file, got nil")
		}
	})

	t.Run("file with incorrect permissions", func(t *testing.T) {
		// Create a temporary file
		tmpFile, err := os.CreateTemp("", "testapikey")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())

		// Write content
		_, err = tmpFile.WriteString("test-api-key")
		if err != nil {
			t.Fatal(err)
		}
		tmpFile.Close()

		// Change permissions to make it unreadable
		err = os.Chmod(tmpFile.Name(), 0222) // Write-only permissions
		if err != nil {
			t.Fatal(err)
		}

		_, err = readAPIKey(false, tmpFile.Name())
		if err == nil {
			t.Fatal("Expected error for unreadable file, got nil")
		}
	})
}

// TestSetupContext tests the setupContext function.
func TestSetupContext(t *testing.T) {
	t.Run("valid timeout", func(t *testing.T) {
		timeout := 100 * time.Millisecond
		ctx, cancel := setupContext(timeout)
		defer cancel()

		// Verify the context has the expected deadline
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("Expected context to have a deadline")
		}

		expectedDeadline := time.Now().Add(timeout)
		if deadline.After(expectedDeadline.Add(10*time.Millisecond)) || 
			deadline.Before(expectedDeadline.Add(-10*time.Millisecond)) {
			t.Errorf("Deadline not within expected range. Got: %v, Expected around: %v", 
				deadline, expectedDeadline)
		}

		// Verify context is not done yet
		select {
		case <-ctx.Done():
			t.Error("Context should not be done yet")
		default:
			// Expected case
		}
	})

	t.Run("cancel before timeout", func(t *testing.T) {
		timeout := 100 * time.Millisecond
		ctx, cancel := setupContext(timeout)
		
		// Cancel immediately
		cancel()

		// Verify context is done
		select {
		case <-ctx.Done():
			// Expected case
		default:
			t.Error("Context should be done after cancel")
		}

		// Verify the error is context.Canceled
		if ctx.Err() != context.Canceled {
			t.Errorf("Expected context error to be Canceled, got: %v", ctx.Err())
		}
	})
}

// TestInitializeClient tests the initializeClient function.
func TestInitializeClient(t *testing.T) {
	t.Run("valid API key", func(t *testing.T) {
		// Use environment variable for valid API key
		validAPIKey := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
		if validAPIKey == "" {
			t.Skip("OP_SERVICE_ACCOUNT_TOKEN environment variable is not set")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		client, err := initializeClient(ctx, validAPIKey)
		if err != nil {
			t.Fatalf("Expected no error with valid API key, got: %v", err)
		}

		// Verify client is not nil
		if client == nil {
			t.Error("Expected non-nil client, got nil")
		}
	})

	t.Run("invalid API key", func(t *testing.T) {
		// Use a clearly invalid API key
		invalidAPIKey := "invalid-api-key-123"

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err := initializeClient(ctx, invalidAPIKey)
		if err == nil {
			t.Fatal("Expected error with invalid API key, got nil")
		}

		// Verify the error message contains useful information
		if !strings.Contains(err.Error(), "failed to create client") {
			t.Errorf("Expected error message to contain 'failed to create client', got: %v", err)
		}
	})
}

// TestGetTimeoutForOperation tests the getTimeoutForOperation function.
func TestGetTimeoutForOperation(t *testing.T) {
	tests := []struct {
		name     string
		op       string
		expected time.Duration
	}{
		{
			name:     "resolveSecret operation",
			op:       "resolveSecret",
			expected: 15 * time.Second,
		},
		{
			name:     "writeFile operation",
			op:       "writeFile",
			expected: 10 * time.Second,
		},
		{
			name:     "createDirectory operation",
			op:       "createDirectory",
			expected: 5 * time.Second,
		},
		{
			name:     "unknown operation",
			op:       "unknownOperation",
			expected: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getTimeoutForOperation(tt.op)
			if got != tt.expected {
				t.Errorf("getTimeoutForOperation(%q) = %v, want %v", tt.op, got, tt.expected)
			}
		})
	}
}

// TestResolveSecretWithTimeout tests the resolveSecretWithTimeout function.
func TestResolveSecretWithTimeout(t *testing.T) {
	tests := []struct {
		name          string
		resolveFunc   func(ctx context.Context, secretRef string) (string, error)
		expectedValue string
		expectError   bool
	}{
		{
			name: "successful resolution within timeout",
			resolveFunc: func(ctx context.Context, secretRef string) (string, error) {
				return "secret-value", nil
			},
			expectedValue: "secret-value",
			expectError:   false,
		},
		{
			name: "timeout exceeded",
			resolveFunc: func(ctx context.Context, secretRef string) (string, error) {
				// Simulate a long-running operation that exceeds the timeout
				time.Sleep(200 * time.Millisecond)
				
				// Check if context was cancelled
				select {
				case <-ctx.Done():
					return "", ctx.Err()
				default:
					return "too-late", nil
				}
			},
			expectedValue: "",
			expectError:   true,
		},
		{
			name: "error during resolution",
			resolveFunc: func(ctx context.Context, secretRef string) (string, error) {
				return "", fmt.Errorf("resolution error")
			},
			expectedValue: "",
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockOPClient{
				ResolveSecretFunc: tt.resolveFunc,
			}

			// Use a shorter timeout for the test
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			
			value, err := resolveSecretWithTimeout(ctx, mockClient, "test-secret")

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
				if value != tt.expectedValue {
					t.Errorf("Expected value %q but got %q", tt.expectedValue, value)
				}
			}
		})
	}
}

// TestProcessMapFile tests the processMapFile function.
func TestProcessMapFile(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v", err)
	}

	// Create a temporary directory for the test
	tmpDir := t.TempDir()

	// Create a temporary map file
	mapFileContent := fmt.Sprintf(`%s	op://vault/item/field1	%s/testfile1
%s	op://vault/item/field2	%s/newdir/testfile2
otheruser	op://vault/item/field3	%s/testfile3`, currentUser.Username, tmpDir, currentUser.Username, tmpDir, tmpDir)

	tmpMapFile, err := os.CreateTemp(tmpDir, "testmap")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpMapFile.Name())
	_, err = tmpMapFile.WriteString(mapFileContent)
	if err != nil {
		t.Fatal(err)
	}
	tmpMapFile.Close()

	mockClient := &MockOPClient{
		ResolveSecretFunc: func(ctx context.Context, secretRef string) (string, error) {
			switch secretRef {
			case "op://vault/item/field1":
				return "secret1", nil
			case "op://vault/item/field2":
				return "secret2", nil
			case "op://vault/item/field3":
				return "secret3", nil
			default:
				return "", fmt.Errorf("secret not found: %s", secretRef)
			}
		},
	}

	err = processMapFile(context.TODO(), mockClient, tmpMapFile.Name(), currentUser, false, osFileWriter{})
	if err != nil {
		t.Fatalf("processMapFile failed: %v", err)
	}

	// Verify file contents
	file1Path := filepath.Join(tmpDir, "testfile1")
	file2Path := filepath.Join(tmpDir, "newdir", "testfile2")
	file3Path := filepath.Join(tmpDir, "testfile3")

	file1Content, err := os.ReadFile(file1Path)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", file1Path, err)
	}
	if string(file1Content) != "secret1" {
		t.Errorf("File %s content mismatch: expected 'secret1', got '%s'", file1Path, string(file1Content))
	}

	file2Content, err := os.ReadFile(file2Path)
	if err != nil {
		t.Fatalf("Failed to read file %s: %v", file2Path, err)
	}
	if string(file2Content) != "secret2" {
		t.Errorf("File %s content mismatch: expected 'secret2', got '%s'", file2Path, string(file2Content))
	}

	if _, err := os.Stat(file3Path); !os.IsNotExist(err) {
		t.Errorf("File %s should not have been written", file3Path)
	}

	// Verify that the new directory was created
	newDirPath := filepath.Join(tmpDir, "newdir")
	if _, err := os.Stat(newDirPath); os.IsNotExist(err) {
		t.Errorf("Directory %s was not created", newDirPath)
	}

	// Verify ownership of the files and directories
	uid, _ := strconv.Atoi(currentUser.Uid)
	gid, _ := strconv.Atoi(currentUser.Gid)

	// Use the verifyOwnership function from main.go
	if err := verifyOwnership(file1Path, uid, gid, false); err != nil {
		t.Errorf("verifyOwnership failed for %s: %v", file1Path, err)
	}
	if err := verifyOwnership(file2Path, uid, gid, false); err != nil {
		t.Errorf("verifyOwnership failed for %s: %v", file2Path, err)
	}
	if err := verifyOwnership(newDirPath, uid, gid, false); err != nil {
		t.Errorf("verifyOwnership failed for %s: %v", newDirPath, err)
	}
}
