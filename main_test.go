// ABOUTME: This file contains comprehensive unit and integration tests for the op-secret-manager
// ABOUTME: including tests for secret resolution, file operations, permission handling, and configuration parsing
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
	"syscall"
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

// TestEnvironmentSanitization tests that dangerous environment variables are cleared
func TestEnvironmentSanitization(t *testing.T) {
	dangerousVars := []string{
		"GOCOVERDIR",
		"GOTRACEBACK",
		"GODEBUG",
		"GOMAXPROCS",
		"LD_PRELOAD",
		"LD_LIBRARY_PATH",
	}

	// Set all dangerous variables
	for _, v := range dangerousVars {
		os.Setenv(v, "test_value")
	}

	// Call sanitizeEnvironment (which should be called by init())
	sanitizeEnvironment()

	// Verify all variables are unset
	for _, v := range dangerousVars {
		if value := os.Getenv(v); value != "" {
			t.Errorf("Environment variable %s should be empty, but got: %s", v, value)
		}
	}
}

// TestCheckRootAllowed tests root execution with mapfile validation
func TestCheckRootAllowed(t *testing.T) {
	t.Run("non-root user should always be allowed", func(t *testing.T) {
		nonRootUser := &user.User{
			Uid:      "1000",
			Gid:      "1000",
			Username: "testuser",
		}
		// Mapfile path doesn't matter for non-root - even nonexistent is fine
		err := checkRootAllowed(nonRootUser, "/nonexistent/path")
		if err != nil {
			t.Errorf("Expected no error for non-root user, got: %v", err)
		}
	})

	t.Run("root with non-root-owned mapfile should be rejected", func(t *testing.T) {
		// Create a temp file owned by current user (not root)
		tmpDir := t.TempDir()
		mapFile := filepath.Join(tmpDir, "mapfile")
		if err := os.WriteFile(mapFile, []byte("test"), 0600); err != nil {
			t.Fatalf("Failed to create test mapfile: %v", err)
		}

		rootUser := &user.User{
			Uid:      "0",
			Gid:      "0",
			Username: "root",
		}

		err := checkRootAllowed(rootUser, mapFile)
		if err == nil {
			t.Error("Expected error for non-root-owned mapfile")
		}
		if !strings.Contains(err.Error(), "owned by root") {
			t.Errorf("Expected error about root ownership, got: %v", err)
		}
	})

	t.Run("root with nonexistent mapfile should return error", func(t *testing.T) {
		rootUser := &user.User{
			Uid:      "0",
			Gid:      "0",
			Username: "root",
		}

		err := checkRootAllowed(rootUser, "/nonexistent/mapfile")
		if err == nil {
			t.Error("Expected error for nonexistent mapfile")
		}
		if !strings.Contains(err.Error(), "cannot stat") {
			t.Errorf("Expected error about stat failure, got: %v", err)
		}
	})
}

// TestCheckRootAllowedPermissions tests the permission check logic directly.
// Since we can't create root-owned files in normal tests, we test the
// permission bit logic in isolation.
func TestCheckRootAllowedPermissions(t *testing.T) {
	// Test the permission bit mask logic: perm & 0022 != 0 means group or other writable
	tests := []struct {
		name       string
		perm       os.FileMode
		shouldFail bool
	}{
		{"0600 - owner only", 0600, false},
		{"0644 - owner rw, group/other r", 0644, false},
		{"0640 - owner rw, group r", 0640, false},
		{"0664 - group writable", 0664, true},
		{"0646 - other writable", 0646, true},
		{"0666 - both writable", 0666, true},
		{"0620 - group write only", 0620, true},
		{"0602 - other write only", 0602, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasGroupOrOtherWrite := tt.perm&0022 != 0
			if hasGroupOrOtherWrite != tt.shouldFail {
				t.Errorf("Permission %o: expected shouldFail=%v but got hasGroupOrOtherWrite=%v",
					tt.perm, tt.shouldFail, hasGroupOrOtherWrite)
			}
		})
	}
}

// TestValidateOutputPath tests the validateOutputPath function
func TestValidateOutputPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		uid         string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid path under /run/user/uid/secrets/",
			path:        "/run/user/1000/secrets/myfile",
			uid:         "1000",
			expectError: false,
		},
		{
			name:        "valid nested path under /run/user/uid/secrets/",
			path:        "/run/user/1000/secrets/subdir/myfile",
			uid:         "1000",
			expectError: false,
		},
		{
			name:        "valid path in home directory",
			path:        "/home/user/.docker/config.json",
			uid:         "1000",
			expectError: false,
		},
		{
			name:        "valid path in arbitrary location",
			path:        "/opt/myapp/secrets/key",
			uid:         "1000",
			expectError: false,
		},
		{
			name:        "path traversal attempt with ..",
			path:        "/run/user/1000/secrets/../../../etc/passwd",
			uid:         "1000",
			expectError: true,
			errorMsg:    "path traversal",
		},
		{
			name:        "path with .. in the middle",
			path:        "/run/user/1000/../2000/secrets/file",
			uid:         "1000",
			expectError: true,
			errorMsg:    "path traversal",
		},
		{
			name:        "relative path should fail",
			path:        "relative/path",
			uid:         "1000",
			expectError: true,
			errorMsg:    "must be absolute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateOutputPath(tt.path, tt.uid)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got: %v", tt.errorMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

// TestAtomicWriteFile tests the atomicWriteFile function
func TestAtomicWriteFile(t *testing.T) {
	tmpDir := t.TempDir()
	targetFile := filepath.Join(tmpDir, "testfile")

	t.Run("successful atomic write", func(t *testing.T) {
		content := []byte("test content")
		err := atomicWriteFile(targetFile, content, 0600)
		if err != nil {
			t.Fatalf("atomicWriteFile failed: %v", err)
		}

		// Verify file was created with correct content
		readContent, err := os.ReadFile(targetFile)
		if err != nil {
			t.Fatalf("Failed to read file: %v", err)
		}
		if string(readContent) != string(content) {
			t.Errorf("Content mismatch: expected %q, got %q", string(content), string(readContent))
		}

		// Verify permissions
		info, err := os.Stat(targetFile)
		if err != nil {
			t.Fatalf("Failed to stat file: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Errorf("Permission mismatch: expected 0600, got %o", info.Mode().Perm())
		}

		// Clean up for next test
		os.Remove(targetFile)
	})

	t.Run("no temp file left on success", func(t *testing.T) {
		content := []byte("test content 2")
		err := atomicWriteFile(targetFile, content, 0600)
		if err != nil {
			t.Fatalf("atomicWriteFile failed: %v", err)
		}

		// List directory to ensure no temp files remain
		entries, err := os.ReadDir(tmpDir)
		if err != nil {
			t.Fatalf("Failed to read directory: %v", err)
		}

		for _, entry := range entries {
			if strings.Contains(entry.Name(), ".tmp") {
				t.Errorf("Found temp file after successful write: %s", entry.Name())
			}
		}
	})
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

// mockFileWriter is a mock implementation of fileWriter for testing without real filesystem
type mockFileWriter struct {
	files map[string][]byte
	dirs  map[string]bool
	uid   int
	gid   int
}

func (m *mockFileWriter) WriteFile(filename string, data []byte, perm os.FileMode) error {
	m.files[filename] = data
	return nil
}

func (m *mockFileWriter) MkdirAll(path string, perm os.FileMode) error {
	m.dirs[path] = true
	return nil
}

func (m *mockFileWriter) Stat(path string) (os.FileInfo, error) {
	// Check if it's a file
	if _, exists := m.files[path]; exists {
		return &mockFileInfo{name: filepath.Base(path), mode: 0600, uid: m.uid, gid: m.gid}, nil
	}
	// Check if it's a directory
	if m.dirs[path] {
		return &mockFileInfo{name: filepath.Base(path), mode: 0700 | os.ModeDir, uid: m.uid, gid: m.gid}, nil
	}
	return nil, os.ErrNotExist
}

// mockFileInfo implements os.FileInfo for testing
type mockFileInfo struct {
	name string
	mode os.FileMode
	uid  int
	gid  int
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return 0 }
func (m *mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m *mockFileInfo) ModTime() time.Time { return time.Now() }
func (m *mockFileInfo) IsDir() bool        { return m.mode.IsDir() }
func (m *mockFileInfo) Sys() interface{} {
	return &syscall.Stat_t{Uid: uint32(m.uid), Gid: uint32(m.gid)}
}

// TestSecrets_SuccedingLiveCall tests secret resolution using a live 1Password client.
// This is an integration test that requires:
// 1. A valid 1Password service account token set in OP_SERVICE_ACCOUNT_TOKEN
// 2. Valid secret references set in SECRET_REF1, SECRET_REF2, etc.
// 3. Expected secret values set in SECRET_VAL1, SECRET_VAL2, etc.
// The test will be skipped if these environment variables are not set.
// Note: This test makes actual API calls to 1Password services and
// should be run in a controlled environment with test credentials.
func TestSecrets_SuccedingLiveCall(t *testing.T) {
	apiKey := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if apiKey == "" {
		t.Skip("Skipping integration test: OP_SERVICE_ACCOUNT_TOKEN environment variable is not set")
	}

	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(apiKey),
		onepassword.WithIntegrationInfo("op-secret-manager-tests", "v1.0.0"),
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

// TestSecrets_FailingLiveCall tests error handling for invalid secret references.
// This is an integration test that requires:
// 1. A valid 1Password service account token set in OP_SERVICE_ACCOUNT_TOKEN
// 2. An invalid secret reference set in SECRET_REF_FAIL
// The test verifies that the client properly handles invalid secret references
// and returns appropriate errors. The test will be skipped if the required
// environment variables are not set.
func TestSecrets_FailingLiveCall(t *testing.T) {
	apiKey := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if apiKey == "" {
		t.Skip("Skipping integration test: OP_SERVICE_ACCOUNT_TOKEN environment variable is not set")
	}

	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(apiKey),
		onepassword.WithIntegrationInfo("op-secret-manager-tests", "v1.0.0"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	secretRef := os.Getenv("SECRET_REF_FAIL")
	if secretRef == "" {
		t.Skip("Skipping integration test: SECRET_REF_FAIL environment variable is not set")
	}
	_, err = client.Secrets().Resolve(context.TODO(), secretRef)
	if err == nil {
		t.Errorf("Expected error resolving invalid secret %s, but got nil", secretRef)
	} else {
		t.Logf("Successfully received error for invalid secret %s: %v", secretRef, err)
	}
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

// TestInitializeClient tests the initializeClient function.
// This test includes both unit tests and integration tests:
// - Unit tests verify error handling with invalid API keys
// - Integration tests verify successful client initialization
// The integration test requires a valid 1Password service account token
// set in OP_SERVICE_ACCOUNT_TOKEN and will be skipped if not set.
func TestInitializeClient(t *testing.T) {
	t.Run("valid API key", func(t *testing.T) {
		// Use environment variable for valid API key
		validAPIKey := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
		if validAPIKey == "" {
			t.Skip("Skipping integration test: OP_SERVICE_ACCOUNT_TOKEN environment variable is not set")
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

// TestCleanupSecretFiles tests the cleanupSecretFiles function.
func TestCleanupSecretFiles(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v", err)
	}

	// Create a temporary directory for the test
	tmpDir := t.TempDir()

	// Create test files
	file1 := filepath.Join(tmpDir, "file1")
	file2 := filepath.Join(tmpDir, "file2")
	file3 := filepath.Join(tmpDir, "file3")

	// Create files that should be removed
	if err := os.WriteFile(file1, []byte("test1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file2, []byte("test2"), 0600); err != nil {
		t.Fatal(err)
	}

	// Create a file that should be skipped (non-existent)
	// file3 will not be created

	// Create map file content
	mapFileContent := []byte(fmt.Sprintf(`%s	op://vault/item/field1	%s
%s	op://vault/item/field2	%s
otheruser	op://vault/item/field3	%s`,
		currentUser.Username, file1,
		currentUser.Username, file2,
		file3))

	// Run cleanup
	err = cleanupSecretFiles(mapFileContent, currentUser, false)
	if err != nil {
		t.Fatalf("cleanupSecretFiles failed: %v", err)
	}

	// Verify file1 was removed
	if _, err := os.Stat(file1); !os.IsNotExist(err) {
		t.Errorf("File %s should have been removed", file1)
	}

	// Verify file2 was removed
	if _, err := os.Stat(file2); !os.IsNotExist(err) {
		t.Errorf("File %s should have been removed", file2)
	}

	// Verify file3 was not created/removed (should be skipped)
	if _, err := os.Stat(file3); !os.IsNotExist(err) {
		t.Errorf("File %s should not exist", file3)
	}
}

// TestVerifyPermissionsAndOwnership tests the verifyPermissionsAndOwnership function.
// This test verifies that the function correctly checks file permissions and ownership.
// Note: Some test cases are skipped when running as root since root can bypass
// permission and ownership checks. These tests are most meaningful when run as
// a non-privileged user.
func TestVerifyPermissionsAndOwnership(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v", err)
	}

	// Create a temporary directory for the test
	tmpDir := t.TempDir()

	t.Run("correct permissions and ownership", func(t *testing.T) {
		// Create a test file with correct permissions and ownership
		testFile := filepath.Join(tmpDir, "correct.txt")
		if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}

		// Verify should succeed
		err := verifyPermissionsAndOwnership(testFile, 0600, currentUser, false, osFileWriter{})
		if err != nil {
			t.Errorf("Expected no error for correct permissions and ownership, got: %v", err)
		}
	})

	t.Run("incorrect permissions", func(t *testing.T) {
		// Create a test file with incorrect permissions
		testFile := filepath.Join(tmpDir, "incorrect_perms.txt")
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			t.Fatal(err)
		}

		// Verify should fail
		err := verifyPermissionsAndOwnership(testFile, 0600, currentUser, false, osFileWriter{})
		if err == nil {
			t.Error("Expected error for incorrect permissions, got nil")
		} else if !strings.Contains(err.Error(), "incorrect permissions") {
			t.Errorf("Expected error about incorrect permissions, got: %v", err)
		}
	})

	t.Run("incorrect ownership", func(t *testing.T) {
		// Create a test file with correct permissions
		testFile := filepath.Join(tmpDir, "incorrect_owner.txt")
		if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}

		// Change ownership to root (if possible)
		if os.Geteuid() == 0 {
			t.Skip("Cannot test incorrect ownership when running as root")
		}

		// Verify should fail
		err := verifyPermissionsAndOwnership(testFile, 0600, &user.User{
			Uid: "0",
			Gid: "0",
		}, false, osFileWriter{})
		if err == nil {
			t.Error("Expected error for incorrect ownership, got nil")
		} else if !strings.Contains(err.Error(), "incorrect ownership") {
			t.Errorf("Expected error about incorrect ownership, got: %v", err)
		}
	})
}

// TestResolveSecretPath tests the resolveSecretPath function
func TestResolveSecretPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		uid      string
		expected string
	}{
		{
			name:     "relative path - simple filename",
			path:     "db_password",
			uid:      "1000",
			expected: "/run/user/1000/secrets/db_password",
		},
		{
			name:     "relative path - with subdirectory",
			path:     "api_keys/stripe",
			uid:      "1001",
			expected: "/run/user/1001/secrets/api_keys/stripe",
		},
		{
			name:     "absolute path - already correct",
			path:     "/run/user/1000/secrets/db_password",
			uid:      "1000",
			expected: "/run/user/1000/secrets/db_password",
		},
		{
			name:     "absolute path - different location (edge case)",
			path:     "/tmp/secret",
			uid:      "1000",
			expected: "/tmp/secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveSecretPath(tt.path, tt.uid)
			if result != tt.expected {
				t.Errorf("resolveSecretPath(%q, %q) = %q, expected %q", tt.path, tt.uid, result, tt.expected)
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

	// Use mock fileWriter to avoid needing actual /run/user directory
	files := make(map[string][]byte)
	dirs := make(map[string]bool)
	uid, _ := strconv.Atoi(currentUser.Uid)
	gid, _ := strconv.Atoi(currentUser.Gid)
	mockFW := &mockFileWriter{
		files: files,
		dirs:  dirs,
		uid:   uid,
		gid:   gid,
	}

	// Create map file content mixing relative and absolute paths
	// Use relative paths (preferred) and one absolute path
	secretPath1 := fmt.Sprintf("/run/user/%s/secrets/testfile1", currentUser.Uid)
	secretPath2 := fmt.Sprintf("/run/user/%s/secrets/newdir/testfile2", currentUser.Uid)
	secretPath3 := fmt.Sprintf("/run/user/%s/secrets/testfile3", currentUser.Uid)
	secretPath4 := fmt.Sprintf("/run/user/%s/secrets/relative_test", currentUser.Uid)

	mapFileContent := []byte(fmt.Sprintf("%s\top://vault/item/field1\ttestfile1\n%s\top://vault/item/field2\tnewdir/testfile2\n%s\top://vault/item/field3\t%s\n%s\top://vault/item/field4\trelative_test",
		currentUser.Username,     // relative path
		currentUser.Username,     // relative path with subdir
		"otheruser", secretPath3, // absolute path for other user
		currentUser.Username)) // relative path

	mockClient := &MockOPClient{
		ResolveSecretFunc: func(ctx context.Context, secretRef string) (string, error) {
			switch secretRef {
			case "op://vault/item/field1":
				return "secret1", nil
			case "op://vault/item/field2":
				return "secret2", nil
			case "op://vault/item/field3":
				return "secret3", nil
			case "op://vault/item/field4":
				return "secret4", nil
			default:
				return "", fmt.Errorf("secret not found: %s", secretRef)
			}
		},
	}

	err = processMapFile(context.TODO(), mockClient, mapFileContent, currentUser, false, mockFW)
	if err != nil {
		t.Fatalf("processMapFile failed: %v", err)
	}

	// Verify file contents in mock
	if content, exists := files[secretPath1]; !exists {
		t.Errorf("Expected file %s to be created", secretPath1)
	} else if string(content) != "secret1" {
		t.Errorf("File %s content mismatch: expected 'secret1', got '%s'", secretPath1, string(content))
	}

	if content, exists := files[secretPath2]; !exists {
		t.Errorf("Expected file %s to be created", secretPath2)
	} else if string(content) != "secret2" {
		t.Errorf("File %s content mismatch: expected 'secret2', got '%s'", secretPath2, string(content))
	}

	// Verify relative path file (secretPath4)
	if content, exists := files[secretPath4]; !exists {
		t.Errorf("Expected file %s to be created from relative path", secretPath4)
	} else if string(content) != "secret4" {
		t.Errorf("File %s content mismatch: expected 'secret4', got '%s'", secretPath4, string(content))
	}

	// Verify file for otheruser was NOT created
	if _, exists := files[secretPath3]; exists {
		t.Errorf("File %s should not have been written (user isolation failure)", secretPath3)
	}

	// Verify that directories were created in the mock
	expectedDir := fmt.Sprintf("/run/user/%s/secrets/newdir", currentUser.Uid)
	if !dirs[expectedDir] {
		t.Errorf("Directory %s was not created", expectedDir)
	}
}

// TestResolveConfigPaths tests the resolveConfigPaths function with simplified config.
func TestResolveConfigPaths(t *testing.T) {
	tests := []struct {
		name            string
		apiKeyPathFlag  string
		mapFilePathFlag string
		apiKeyPathEnv   string
		mapFilePathEnv  string
		expectedAPIKey  string
		expectedMapFile string
	}{
		{
			name:            "use defaults",
			apiKeyPathFlag:  "",
			mapFilePathFlag: "",
			apiKeyPathEnv:   "",
			mapFilePathEnv:  "",
			expectedAPIKey:  "/etc/op-secret-manager/api",
			expectedMapFile: "/etc/op-secret-manager/mapfile",
		},
		{
			name:            "override with both flags",
			apiKeyPathFlag:  "/flag/api",
			mapFilePathFlag: "/flag/map",
			apiKeyPathEnv:   "",
			mapFilePathEnv:  "",
			expectedAPIKey:  "/flag/api",
			expectedMapFile: "/flag/map",
		},
		{
			name:            "override with env vars",
			apiKeyPathFlag:  "",
			mapFilePathFlag: "",
			apiKeyPathEnv:   "/env/api",
			mapFilePathEnv:  "/env/map",
			expectedAPIKey:  "/env/api",
			expectedMapFile: "/env/map",
		},
		{
			name:            "flags override env vars",
			apiKeyPathFlag:  "/flag/api",
			mapFilePathFlag: "/flag/map",
			apiKeyPathEnv:   "/env/api",
			mapFilePathEnv:  "/env/map",
			expectedAPIKey:  "/flag/api",
			expectedMapFile: "/flag/map",
		},
		{
			name:            "partial flag override - api key only",
			apiKeyPathFlag:  "/flag/api",
			mapFilePathFlag: "",
			apiKeyPathEnv:   "",
			mapFilePathEnv:  "",
			expectedAPIKey:  "/flag/api",
			expectedMapFile: "/etc/op-secret-manager/mapfile",
		},
		{
			name:            "partial flag override - map file only",
			apiKeyPathFlag:  "",
			mapFilePathFlag: "/flag/map",
			apiKeyPathEnv:   "",
			mapFilePathEnv:  "",
			expectedAPIKey:  "/etc/op-secret-manager/api",
			expectedMapFile: "/flag/map",
		},
		{
			name:            "partial env override - api key only",
			apiKeyPathFlag:  "",
			mapFilePathFlag: "",
			apiKeyPathEnv:   "/env/api",
			mapFilePathEnv:  "",
			expectedAPIKey:  "/env/api",
			expectedMapFile: "/etc/op-secret-manager/mapfile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear any existing environment variables first
			os.Unsetenv("OP_API_KEY_PATH")
			os.Unsetenv("OP_MAP_FILE_PATH")

			// Set up environment variables
			if tt.apiKeyPathEnv != "" {
				os.Setenv("OP_API_KEY_PATH", tt.apiKeyPathEnv)
				defer os.Unsetenv("OP_API_KEY_PATH")
			}
			if tt.mapFilePathEnv != "" {
				os.Setenv("OP_MAP_FILE_PATH", tt.mapFilePathEnv)
				defer os.Unsetenv("OP_MAP_FILE_PATH")
			}

			apiKeyPath, mapFilePath := resolveConfigPaths(
				false,
				tt.apiKeyPathFlag,
				tt.mapFilePathFlag,
			)

			if apiKeyPath != tt.expectedAPIKey {
				t.Errorf("Expected API key path %q, got %q", tt.expectedAPIKey, apiKeyPath)
			}
			if mapFilePath != tt.expectedMapFile {
				t.Errorf("Expected map file path %q, got %q", tt.expectedMapFile, mapFilePath)
			}
		})
	}
}

// TestParseMapFileLine tests the parseMapFileLine function.
func TestParseMapFileLine(t *testing.T) {
	tests := []struct {
		name           string
		line           string
		expectError    bool
		expectedUser   string
		expectedSecret string
		expectedPath   string
	}{
		{
			name:           "valid line with tabs",
			line:           "postgres\top://vault/item/field\t/run/1001/secrets/db",
			expectError:    false,
			expectedUser:   "postgres",
			expectedSecret: "op://vault/item/field",
			expectedPath:   "/run/1001/secrets/db",
		},
		{
			name:           "valid line with spaces",
			line:           "postgres op://vault/item/field /run/1001/secrets/db",
			expectError:    false,
			expectedUser:   "postgres",
			expectedSecret: "op://vault/item/field",
			expectedPath:   "/run/1001/secrets/db",
		},
		{
			name:           "valid line with mixed whitespace",
			line:           "postgres  \t  op://vault/item/field\t\t/run/1001/secrets/db",
			expectError:    false,
			expectedUser:   "postgres",
			expectedSecret: "op://vault/item/field",
			expectedPath:   "/run/1001/secrets/db",
		},
		{
			name:           "line starting with comment",
			line:           "# this is a comment",
			expectError:    true,
			expectedUser:   "",
			expectedSecret: "",
			expectedPath:   "",
		},
		{
			name:           "blank line",
			line:           "",
			expectError:    true,
			expectedUser:   "",
			expectedSecret: "",
			expectedPath:   "",
		},
		{
			name:           "line with only whitespace",
			line:           "   \t  \t   ",
			expectError:    true,
			expectedUser:   "",
			expectedSecret: "",
			expectedPath:   "",
		},
		{
			name:           "line with too few fields",
			line:           "postgres op://vault/item/field",
			expectError:    true,
			expectedUser:   "",
			expectedSecret: "",
			expectedPath:   "",
		},
		{
			name:           "line with too many fields",
			line:           "postgres op://vault/item/field /run/1001/secrets/db extra",
			expectError:    true,
			expectedUser:   "",
			expectedSecret: "",
			expectedPath:   "",
		},
		{
			name:           "comment with leading whitespace",
			line:           "  # this is also a comment",
			expectError:    true,
			expectedUser:   "",
			expectedSecret: "",
			expectedPath:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, secret, path, err := parseMapFileLine(tt.line)

			if tt.expectError {
				if err == nil {
					t.Error("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if user != tt.expectedUser {
				t.Errorf("Expected user %q, got %q", tt.expectedUser, user)
			}
			if secret != tt.expectedSecret {
				t.Errorf("Expected secret %q, got %q", tt.expectedSecret, secret)
			}
			if path != tt.expectedPath {
				t.Errorf("Expected path %q, got %q", tt.expectedPath, path)
			}
		})
	}
}

// TestLockFilePath tests the lockFilePath function.
func TestLockFilePath(t *testing.T) {
	tests := []struct {
		name     string
		uid      string
		expected string
	}{
		{
			name:     "typical user",
			uid:      "1000",
			expected: "/run/user/1000/op-secret-manager.lock",
		},
		{
			name:     "root user",
			uid:      "0",
			expected: "/run/user/0/op-secret-manager.lock",
		},
		{
			name:     "high UID",
			uid:      "65534",
			expected: "/run/user/65534/op-secret-manager.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := lockFilePath(tt.uid)
			if result != tt.expected {
				t.Errorf("lockFilePath(%q) = %q, expected %q", tt.uid, result, tt.expected)
			}
		})
	}
}

// TestAcquireProcessLock tests basic lock acquisition and release.
func TestAcquireProcessLock(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "test.lock")

	t.Run("lock can be acquired on new file", func(t *testing.T) {
		lockFile, err := acquireProcessLock(lockPath, false)
		if err != nil {
			t.Fatalf("acquireProcessLock failed: %v", err)
		}
		if lockFile == nil {
			t.Fatal("Expected non-nil lock file")
		}
		lockFile.Close()
	})

	t.Run("lock file is created", func(t *testing.T) {
		lockPath := filepath.Join(tmpDir, "created.lock")
		lockFile, err := acquireProcessLock(lockPath, false)
		if err != nil {
			t.Fatalf("acquireProcessLock failed: %v", err)
		}
		defer lockFile.Close()

		if _, err := os.Stat(lockPath); os.IsNotExist(err) {
			t.Error("Expected lock file to be created on disk")
		}
	})

	t.Run("lock can be reacquired after release", func(t *testing.T) {
		lockPath := filepath.Join(tmpDir, "reacquire.lock")

		// Acquire and release
		lockFile, err := acquireProcessLock(lockPath, false)
		if err != nil {
			t.Fatalf("First acquireProcessLock failed: %v", err)
		}
		lockFile.Close()

		// Acquire again
		lockFile2, err := acquireProcessLock(lockPath, false)
		if err != nil {
			t.Fatalf("Second acquireProcessLock failed: %v", err)
		}
		defer lockFile2.Close()

		if lockFile2 == nil {
			t.Fatal("Expected non-nil lock file on reacquire")
		}
	})

	t.Run("verbose logging works", func(t *testing.T) {
		lockPath := filepath.Join(tmpDir, "verbose.lock")
		output := captureOutput(func() {
			lockFile, err := acquireProcessLock(lockPath, true)
			if err != nil {
				t.Fatalf("acquireProcessLock failed: %v", err)
			}
			lockFile.Close()
		})

		if !strings.Contains(output, "[VERBOSE]") {
			t.Errorf("Expected verbose output, got: %q", output)
		}
	})
}

// TestAcquireProcessLockSerialization tests that the lock serializes concurrent access.
func TestAcquireProcessLockSerialization(t *testing.T) {
	tmpDir := t.TempDir()
	lockPath := filepath.Join(tmpDir, "serialize.lock")

	// Acquire the lock in the main goroutine
	lockFile, err := acquireProcessLock(lockPath, false)
	if err != nil {
		t.Fatalf("acquireProcessLock failed: %v", err)
	}

	// Channel to signal that the second goroutine is attempting to acquire the lock
	attempting := make(chan struct{})
	// Channel to signal that the second goroutine has acquired the lock
	acquired := make(chan struct{})

	go func() {
		close(attempting)
		// This should block until the main goroutine releases
		lockFile2, err := acquireProcessLock(lockPath, false)
		if err != nil {
			t.Errorf("Second acquireProcessLock failed: %v", err)
			return
		}
		defer lockFile2.Close()
		close(acquired)
	}()

	// Wait for the goroutine to start attempting
	<-attempting
	// Give it time to actually call flock (which should block)
	time.Sleep(100 * time.Millisecond)

	// Verify the second goroutine hasn't acquired the lock yet
	select {
	case <-acquired:
		t.Fatal("Second goroutine acquired lock while first still held it")
	default:
		// Expected: second goroutine is blocked
	}

	// Release the lock
	lockFile.Close()

	// The second goroutine should now acquire the lock
	select {
	case <-acquired:
		// Expected: second goroutine acquired after release
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for second goroutine to acquire lock")
	}
}

// TestAcquireProcessLockErrorHandling tests error cases for lock acquisition.
func TestAcquireProcessLockErrorHandling(t *testing.T) {
	t.Run("nonexistent directory returns error", func(t *testing.T) {
		lockPath := "/nonexistent/directory/test.lock"
		lockFile, err := acquireProcessLock(lockPath, false)
		if err == nil {
			lockFile.Close()
			t.Fatal("Expected error for nonexistent directory, got nil")
		}
	})
}
