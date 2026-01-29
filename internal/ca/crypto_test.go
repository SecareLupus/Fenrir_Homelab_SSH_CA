package ca

import (
	"bytes"
	"testing"
)

func TestCryptoHelpers(t *testing.T) {
	data := []byte("secret-key-material-to-encrypt")
	passphrase := "super-secret-passphrase"

	// 1. Encrypt
	block, err := encryptKey(data, passphrase)
	if err != nil {
		t.Fatalf("encryptKey failed: %v", err)
	}

	if block.Type != "ENCRYPTED FENRIR KEY" {
		t.Errorf("wrong block type: %s", block.Type)
	}

	// 2. Decrypt
	decrypted, err := decryptKey(block, passphrase)
	if err != nil {
		t.Fatalf("decryptKey failed: %v", err)
	}

	if !bytes.Equal(data, decrypted) {
		t.Errorf("decrypted data mismatch: got %v, want %v", decrypted, data)
	}

	// 3. Test wrong passphrase
	_, err = decryptKey(block, "wrong-passphrase")
	if err == nil {
		t.Error("decryptKey succeeded with wrong passphrase")
	}
}

func TestDeriveKey(t *testing.T) {
	passphrase := "pass"
	salt := []byte("salt")

	key1 := deriveKey(passphrase, salt)
	key2 := deriveKey(passphrase, salt)

	if !bytes.Equal(key1, key2) {
		t.Error("deriveKey is not deterministic")
	}
}
