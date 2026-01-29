/*
 * Copyright (c) 2026 SecareLupus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashAPIKey computes a secure HMAC of the API key using a server-side secret.
// This prevents offline rainbow table attacks if the database is leaked.
func HashAPIKey(key string, secret []byte) string {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(key))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Zero overwrites a byte slice with zeros to clear sensitive data from memory.
func Zero(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
}
