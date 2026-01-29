package auth

import (
	"testing"
)

func TestPasswordHashing(t *testing.T) {
	password := "secure-password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if !CheckPassword(password, hash) {
		t.Errorf("CheckPassword failed to verify correct password")
	}

	if CheckPassword("wrong-password", hash) {
		t.Errorf("CheckPassword incorrectly verified wrong password")
	}
}

func TestHashAPIKey(t *testing.T) {
	key := "my-secret-key"
	secret := []byte("server-secret")

	hash1 := HashAPIKey(key, secret)
	hash2 := HashAPIKey(key, secret)
	if hash1 != hash2 {
		t.Errorf("HashAPIKey is not deterministic")
	}

	hash3 := HashAPIKey(key, []byte("different-secret"))
	if hash1 == hash3 {
		t.Errorf("HashAPIKey does not change with different secret")
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Zero(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("Zero failed at index %d: expected 0, got %v", i, v)
		}
	}

	// Should not panic on nil
	Zero(nil)
}
