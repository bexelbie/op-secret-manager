package main

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/1password/onepassword-sdk-go"
)

func TestSecrets(t *testing.T) {
	// Read API key from environment
	apiKey := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if apiKey == "" {
		t.Fatal("OP_SERVICE_ACCOUNT_TOKEN environment variable is not set")
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
