package main

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"testing"

	"github.com/1password/onepassword-sdk-go"
)

// MockFileWriter is a mock implementation of fileWriter.
type MockFileWriter struct {
	WriteFileFunc func(filename string, data []byte, perm os.FileMode) error
	MkdirAllFunc  func(path string, perm os.FileMode) error
	ChownFunc     func(name string, uid, gid int) error
	FilesWritten  map[string][]byte // Tracks files and their content
	DirsCreated   map[string]os.FileMode // Tracks directories and their permissions
	FilesChowned  map[string][]int  // Tracks files and their ownership
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
	if m.DirsCreated == nil {
		m.DirsCreated = make(map[string]os.FileMode)
	}
	m.DirsCreated[path] = perm
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
func TestSecrets(t *testing.T) {
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

	apiKeyPath, mapFilePath, err := readConfig(false, tmpConfigFile.Name())
	if err != nil {
		t.Fatalf("readConfig failed: %v", err)
	}
	if apiKeyPath != "/tmp/apikey.txt" {
		t.Errorf("apiKeyPath mismatch: expected /tmp/apikey.txt, got %s", apiKeyPath)
	}
	if mapFilePath != "/tmp/mapfile.txt" {
		t.Errorf("mapFilePath mismatch: expected /tmp/mapfile.txt, got %s", mapFilePath)
	}

	configContent = `MAP_FILE_PATH = /tmp/mapfile.txt`
	err = os.WriteFile(tmpConfigFile.Name(), []byte(configContent), 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = readConfig(false, tmpConfigFile.Name())
	if err == nil {
		t.Errorf("Expected error for missing API_KEY_PATH, but got nil")
	}

	configContent = `API_KEY_PATH  /tmp/apikey.txt`
	err = os.WriteFile(tmpConfigFile.Name(), []byte(configContent), 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = readConfig(false, tmpConfigFile.Name())
	if err == nil {
		t.Errorf("Expected error for invalid config line, but got nil")
	}
}

// TestSUIDFunctions tests the SUID functions.
func TestSUIDFunctions(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping SUID tests because not running as root")
	}
	suidUser, err := getSUIDUser(false)
	if err != nil {
		t.Fatalf("getSUIDUser failed: %v", err)
	}
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v", err)
	}
	err = dropSUID(false, currentUser.Username)
	if err != nil {
		t.Errorf("dropSUID failed: %v", err)
	}
	err = elevateSUID(false, suidUser)
	if err != nil {
		t.Errorf("elevateSUID failed: %v", err)
	}
}

func TestProcessMapFile(t *testing.T) {
	currentUser, err := user.Current()
	if err != nil {
		t.Fatalf("Failed to get current user: %v", err)
	}

	// Update the map file content to include a new directory
	mapFileContent := fmt.Sprintf(`%s	op://vault/item/field1	/tmp/testfile1
%s	op://vault/item/field2	/tmp/newdir/testfile2
otheruser	op://vault/item/field3	/tmp/testfile3`, currentUser.Username, currentUser.Username)

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

	mockFileWriter := &MockFileWriter{
		FilesWritten: make(map[string][]byte),
		DirsCreated:  make(map[string]os.FileMode), // Correct initialization
		FilesChowned: make(map[string][]int),
	}

	err = processMapFile(context.TODO(), mockClient, tmpMapFile.Name(), currentUser, false, mockFileWriter)
	if err != nil {
		t.Fatalf("processMapFile failed: %v", err)
	}

	// Verify file contents
	if string(mockFileWriter.FilesWritten["/tmp/testfile1"]) != "secret1" {
		t.Errorf("File /tmp/testfile1 content mismatch: expected 'secret1', got '%s'", string(mockFileWriter.FilesWritten["/tmp/testfile1"]))
	}
	if string(mockFileWriter.FilesWritten["/tmp/newdir/testfile2"]) != "secret2" {
		t.Errorf("File /tmp/newdir/testfile2 content mismatch: expected 'secret2', got '%s'", string(mockFileWriter.FilesWritten["/tmp/newdir/testfile2"]))
	}
	if _, ok := mockFileWriter.FilesWritten["/tmp/testfile3"]; ok {
		t.Errorf("File /tmp/testfile3 should not have been written")
	}

	// Verify that the new directory was created
	expectedDirs := map[string]os.FileMode{
		"/tmp/newdir": 0700, // Expected directory and its permissions
	}
	for dir, expectedPerm := range expectedDirs {
		actualPerm, exists := mockFileWriter.DirsCreated[dir]
		if !exists {
			t.Errorf("Directory %s was not created", dir)
		} else if actualPerm != expectedPerm {
			t.Errorf("Directory %s permissions mismatch: expected %o, got %o", dir, expectedPerm, actualPerm)
		}
	}

	// Verify ownership of the files and directories
	uid, _ := strconv.Atoi(currentUser.Uid)
	gid, _ := strconv.Atoi(currentUser.Gid)
	expectedChowns := map[string][]int{
		"/tmp/testfile1":       {uid, gid},
		"/tmp/newdir/testfile2": {uid, gid},
		"/tmp/newdir":          {uid, gid}, // Verify directory ownership
	}

	for file, expectedUidGid := range expectedChowns {
		actualUidGid, ok := mockFileWriter.FilesChowned[file]
		if !ok {
			t.Errorf("File or directory %s was not chowned", file)
			continue
		}
		if actualUidGid[0] != expectedUidGid[0] || actualUidGid[1] != expectedUidGid[1] {
			t.Errorf("File or directory %s chown mismatch: expected UID %d GID %d, got UID %d GID %d", file, expectedUidGid[0], expectedUidGid[1], actualUidGid[0], actualUidGid[1])
		}
	}
}
