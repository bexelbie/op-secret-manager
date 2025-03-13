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
