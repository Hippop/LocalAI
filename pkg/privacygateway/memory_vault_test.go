package privacygateway

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptedMemoryVaultPutGetListDelete(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.enc")
	vault, err := NewEncryptedMemoryVault(path, "local-test-passphrase")
	if err != nil {
		t.Fatalf("failed to create vault: %v", err)
	}

	stored, err := vault.Put(VaultPutRequest{Key: "profile.email", Value: "tom@example.com", Labels: []string{"profile", "contact"}})
	if err != nil {
		t.Fatalf("put failed: %v", err)
	}
	if stored.Value != "tom@example.com" {
		t.Fatalf("unexpected stored value: %s", stored.Value)
	}

	ciphertext, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read vault file: %v", err)
	}
	if bytes.Contains(ciphertext, []byte("tom@example.com")) {
		t.Fatalf("vault file contains plaintext secret")
	}

	loaded, err := vault.Get("profile.email")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if loaded.Value != "tom@example.com" {
		t.Fatalf("unexpected loaded value: %s", loaded.Value)
	}

	listed, err := vault.List()
	if err != nil {
		t.Fatalf("list failed: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected one record, got %d", len(listed))
	}
	if listed[0].Value != "" {
		t.Fatalf("list must not expose raw value")
	}

	if err := vault.Delete("profile.email"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	_, err = vault.Get("profile.email")
	if !errors.Is(err, ErrVaultRecordNotFound) {
		t.Fatalf("expected not found after delete, got %v", err)
	}
}

func TestEncryptedMemoryVaultRequiresConfiguration(t *testing.T) {
	if _, err := NewEncryptedMemoryVault("", "passphrase"); err == nil {
		t.Fatalf("expected missing path error")
	}
	if _, err := NewEncryptedMemoryVault(filepath.Join(t.TempDir(), "vault.enc"), ""); err == nil {
		t.Fatalf("expected missing passphrase error")
	}
}
