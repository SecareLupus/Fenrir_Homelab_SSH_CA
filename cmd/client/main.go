package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"ssh-ca/internal/client"
)

func main() {
	caURL := flag.String("url", "http://localhost:8080", "SSH CA Server URL")
	apiKeyFile := flag.String("key-file", "", "Path to file containing API Key (optional if already enrolled)")
	keyPath := flag.String("identity", "", "Path to SSH private key")
	keyType := flag.String("type", "ed25519", "Key type to generate (ed25519, ed25519-sk)")
	flag.Parse()

	var apiKey string
	if *apiKeyFile != "" {
		keyBytes, _ := os.ReadFile(*apiKeyFile)
		apiKey = string(keyBytes)
	}

	if *keyPath == "" {
		home, _ := os.UserHomeDir()
		suffix := "id_ed25519"
		if *keyType == "ed25519-sk" {
			suffix = "id_ed25519_sk"
		}
		*keyPath = filepath.Join(home, ".ssh", suffix)
	}

	cfg := &client.Config{
		CAURL:      *caURL,
		KeyPath:    *keyPath,
		KeyType:    *keyType,
		APIKey:     apiKey,
		AutoEnroll: true,
	}

	fmt.Printf("Requesting certificate for %s...\n", *keyPath)

	err := cfg.Sign(context.Background(), func(challenge string) {
		fmt.Println("PoP Challenge received. Touch your security key if prompted...")
	})

	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	fmt.Println("Success! Certificate saved.")
}
