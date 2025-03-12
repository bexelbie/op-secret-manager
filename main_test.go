package main

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/1password/onepassword-sdk-go"
)

// MockFileWriter is a mock implementation of the fileWriter interface.
type MockFileWriter struct {
	WriteFileFunc func(filename string, data []byte, perm os.FileMode) error
	MkdirAllFunc  func(path string, perm os.FileMode) error
	ChownFunc     func(name string, uid, gid int) error
	FilesWritten  map[string][]byte
	DirsCreated   []string
	FilesChowned  map[string][]int
}

func (m *MockFileWriter) WriteFile(filename string, data []byte, perm os.FileMode) error {
	if m.WriteFileFunc != nil {
		return m.WriteFileFunc(filename, data, perm)
	}
	if m.FilesWritten == nil {
		m.FilesWritten = make(map[string][]byte)
	}
	m.FilesWritten[filename] = data
	return nil
}

func (m *MockFileWriter) MkdirAll(path string, perm os.FileMode) error {
	if m.MkdirAllFunc != nil {
		return m.MkdirAllFunc(path, perm)
	}
	m.DirsCreated = append(m.DirsCreated, path)
	return nil
}

func (m *MockFileWriter) Chown(name string, uid, gid int) error {
	if m.ChownFunc != nil {
		return m.ChownFunc(name, uid, gid)
	}
	if m.FilesChowned == nil {
		m.FilesChowned = make(map[string][]int)
	}
	m.FilesChowned[name] = []int{uid, gid}
	return nil
}

// Mock 1Password client
type MockOnePasswordClient struct {
	ResolveSecretFunc func(ctx context.Context, secretRef string) (string, error)
}

func (m *MockOnePasswordClient) Secrets() SecretsService {
	return &MockSecretsService{ResolveSecretFunc: m.ResolveSecretFunc}
}

type MockSecretsService struct {
	ResolveSecretFunc func(ctx context.Context, secretRef string) (string, error)
}

func (m *MockSecretsService) Resolve(ctx context.Context, secretRef string) (string, error) {
	if m.ResolveSecretFunc != nil {
		return m.ResolveSecretFunc(ctx, secretRef)
	}
	return "", fmt.Errorf("ResolveSecretFunc not implemented")
}

// TestSecrets tests the secret resolution functionality.
func TestSecrets(t *testing.T) {
	// Read API key from environment
	apiKey := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if apiKey == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN environment variable is not set")
	}

	// Initialize 1Password client
	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(apiKey),
		onepassword.WithIntegrationInfo("Secret Manager Tests", "v1.0.0"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Iterate over SECRET_REF* and SECRET_VAL* environment variables
	for i := 1; ; i++ {
		secretRef := os.Getenv(fmt.Sprintf("SECRET_REF%d", i))
		expectedVal := os.Getenv(fmt.Sprintf("SECRET_VAL%d", i))

		// Stop if no more secrets are found
		if secretRef == "" || expectedVal == "" {
			break
		}

		// Resolve the secret
		actualVal, err := client.Secrets().Resolve(context.TODO(), secretRef)
		if err != nil {
			t.Errorf("Failed to resolve secret %s: %v", secretRef, err)
			continue
		}

		// Compare resolved value to expected value
		if actualVal != expectedVal {
			t.Errorf("Secret mismatch for %s: expected %s, got %s", secretRef, expectedVal, actualVal)
		} else {
			t.Logf("Secret %s resolved successfully", secretRef)
		}
	}
}

// TestSecrets_FailingLiveCall tests a failing live 1Password call.
func TestSecrets_FailingLiveCall(t *testing.T) {
	// Read API key from environment
	apiKey := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if apiKey == "" {
		t.Skip("OP_SERVICE_ACCOUNT_TOKEN environment variable is not set")
	}

	// Initialize 1Password client
	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(apiKey),
		onepassword.WithIntegrationInfo("Secret Manager Tests", "v1.0.0"),
	)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// Resolve an invalid secret
	secretRef := "op://vault/item/invalid-field" // Replace with an intentionally invalid secret ref
	_, err = client.Secrets().Resolve(context.TODO(), secretRef)
	if err == nil {
		t.Errorf("Expected error resolving invalid secret %s, but got nil", secretRef)
	} else {
		t.Logf("Successfully received error for invalid secret %s: %v", secretRef, err)
	}
}

// TestReadConfig tests the readConfig function.
func TestReadConfig(t *testing.T) {
	// Create a temporary configuration file
	configContent := `
API_KEY_PATH = /tmp/apikey.txt
MAP_FILE_PATH = /tmp/mapfile.txt
`
	tmpConfigFile, err := os.CreateTemp("", "testconfig")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpConfigFile.Name())
	_, err = tmpConfigFile.WriteString(configContent)
	if err != nil {
		t.Fatal(err)
	}
	tmpConfigFile.Close()

	// Call readConfig
	apiKeyPath, mapFilePath, err := readConfig(tmpConfigFile.Name())
	if err != nil {
		t.Fatalf("readConfig failed: %v", err)
	}

	// Assert results
	if apiKeyPath != "/tmp/apikey.txt" {
		t.Errorf("apiKeyPath mismatch: expected /tmp/apikey.txt, got %s", apiKeyPath)
	}
	if mapFilePath != "/tmp/mapfile.txt" {
		t.Errorf("mapFilePath mismatch: expected /tmp/mapfile.txt, got %s", mapFilePath)
	}

	// Test error condition: missing API_KEY_PATH
	configContent = `MAP_FILE_PATH = /tmp/mapfile.txt`
	err = os.WriteFile(tmpConfigFile.Name(), []byte(configContent), 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = readConfig(tmpConfigFile.Name())
	if err == nil {
		t.Errorf("Expected error for missing API_KEY_PATH, but got nil")
	}

	// Test error condition: invalid config line
	configContent = `API_KEY_PATH  /tmp/apikey.txt` // Missing equals sign
	err = os.WriteFile(tmpConfigFile.Name(), []byte(configContent), 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = readConfig(tmpConfigFile.Name())
	if err == nil {
		t.Errorf("Expected error for invalid config line, but got nil")
	}
}

// TestSUIDFunctions tests the SUID functions.
func TestSUIDFunctions(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping SUID tests because not running as root")
	}

	// Get the SUID user
	suidUser, err := getSUIDUser()
	if err != nil {
		t.Fatalf("getSUIDUser failed: %v", err)
	}

	// Get the current user
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v\n", err)
	}

	// Attempt to drop and elevate SUID privileges
	err = dropSUID(currentUser.Username)
	if err != nil {
		t.Errorf("dropSUID failed: %v", err)
	}

	//Elevate back to SUID user
	err = elevateSUID(suidUser)
	if err != nil {
		t.Errorf("elevateSUID failed: %v", err)
	}
}

// TestProcessMapFile tests the processMapFile function.
func TestProcessMapFile(t *testing.T) {
	// Create a temporary map file
	mapFileContent := `testuser	op://vault/item/field1	/tmp/testfile1
testuser	op://vault/item/field2	/tmp/testfile2
otheruser	op://vault/item/field3	/tmp/testfile3` // This line should be skipped
	tmpMapFile, err := os.CreateTemp("", "testmap")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpMapFile.Name())
	_, err = tmpMapFile.WriteString(mapFileContent)
	if err != nil {
		t.Fatal(err)
	}
	tmpMapFile.Close()

	// Get the current user
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v\n", err)
	}

	// Create a mock 1Password client
	mockClient := &MockOnePasswordClient{
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

	// Create a mock file writer
	mockFileWriter := &MockFileWriter{
		FilesWritten: make(map[string][]byte),
		DirsCreated:  make([]string, 0),
		FilesChowned: make(map[string][]int),
	}

	// Set the global FileWriter to the mock
	FileWriter = mockFileWriter

	// Call processMapFile
	err = processMapFile(context.TODO(), mockClient, tmpMapFile.Name(), currentUser)
	if err != nil {
		t.Fatalf("processMapFile failed: %v", err)
	}

	// Assert that the expected files were written
	if string(mockFileWriter.FilesWritten["/tmp/testfile1"]) != "secret1" {
		t.Errorf("File /tmp/testfile1 content mismatch: expected 'secret1', got '%s'", string(mockFileWriter.FilesWritten["/tmp/testfile1"]))
	}
	if string(mockFileWriter.FilesWritten["/tmp/testfile2"]) != "secret2" {
		t.Errorf("File /tmp/testfile2 content mismatch: expected 'secret2', got '%s'", string(mockFileWriter.FilesWritten["/tmp/testfile2"]))
	}
	if _, ok := mockFileWriter.FilesWritten["/tmp/testfile3"]; ok {
		t.Errorf("File /tmp/testfile3 should not have been written")
	}

	// Assert that the expected directories were created
	expectedDirs := []string{"/tmp"}
	if len(mockFileWriter.DirsCreated) != len(expectedDirs) {
		t.Errorf("DirsCreated length mismatch: expected %d, got %d", len(expectedDirs), len(mockFileWriter.DirsCreated))
	}
	for i, dir := range expectedDirs {
		if mockFileWriter.DirsCreated[i] != dir {
			t.Errorf("DirsCreated[%d] mismatch: expected '%s', got '%s'", i, dir, mockFileWriter.DirsCreated[i])
		}
	}

	//Assert that the files were chowned
	uid, _ := strconv.Atoi(currentUser.Uid)
	gid, _ := strconv.Atoi(currentUser.Gid)

	expectedChowns := map[string][]int{
		"/tmp/testfile1": {uid, gid},
		"/tmp":          {uid, gid},
		"/tmp/testfile2": {uid, gid},
	}

	for file, expectedUidGid := range expectedChowns {
		actualUidGid, ok := mockFileWriter.FilesChowned[file]
		if !ok {
			t.Errorf("File %s was not chowned", file)
			continue
		}
		if actualUidGid[0] != expectedUidGid[0] || actualUidGid[1] != expectedUidGid[1] {
			t.Errorf("File %s chown mismatch: expected UID %d GID %d, got UID %d GID %d", file, expectedUidGid[0], expectedUidGid[1], actualUidGid[0], actualUidGid[1])
		}
	}

	// Reset the global FileWriter to the osFileWriter after the test
	FileWriter = osFileWriter{}
}
