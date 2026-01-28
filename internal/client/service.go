/*
 * Copyright (c) 2026 SecareLupus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type Config struct {
	CAURL      string
	KeyPath    string
	KeyType    string
	APIKey     string
	AutoEnroll bool
}

type Identity struct {
	Config      *Config
	HasCert     bool
	CertExpiry  time.Time
	Fingerprint string
}

func (c *Config) GetIdentity() (*Identity, error) {
	pubKeyPath := c.KeyPath + ".pub"
	certPath := c.KeyPath + "-cert.pub"

	id := &Identity{Config: c}

	// 1. Ensure keys exist
	if _, err := os.Stat(c.KeyPath); os.IsNotExist(err) {
		if !c.AutoEnroll {
			return nil, fmt.Errorf("local identity key not found")
		}
		// Generate
		args := []string{"-t", c.KeyType, "-f", c.KeyPath, "-N", ""}
		if err := exec.Command("ssh-keygen", args...).Run(); err != nil {
			return nil, err
		}
	}

	// 2. Read PubKey
	pubKeyBytes, err := os.ReadFile(pubKeyPath)
	if err != nil {
		return nil, err
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	id.Fingerprint = ssh.FingerprintSHA256(pubKey)

	// 3. Check Cert
	certBytes, err := os.ReadFile(certPath)
	if err == nil {
		parsed, _, _, _, err := ssh.ParseAuthorizedKey(certBytes)
		if err == nil {
			if cert, ok := parsed.(*ssh.Certificate); ok {
				id.HasCert = true
				id.CertExpiry = time.Unix(int64(cert.ValidBefore), 0)
			}
		}
	}

	return id, nil
}

// Sign handles the full enrollment or renewal flow
func (c *Config) Sign(ctx context.Context, onChallenge func(string)) error {
	if _, err := c.GetIdentity(); err != nil {
		return err
	}

	pubKeyBytes, _ := os.ReadFile(c.KeyPath + ".pub")

	send := func(headers map[string]string) (*http.Response, error) {
		form := url.Values{}
		form.Add("pubkey", string(pubKeyBytes))
		form.Add("ttl", "86400")
		req, _ := http.NewRequestWithContext(ctx, "POST", c.CAURL+"/cert/request", bytes.NewBufferString(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return http.DefaultClient.Do(req)
	}

	headers := make(map[string]string)
	if c.APIKey != "" {
		headers["X-API-Key"] = c.APIKey
	}

	resp, err := send(headers)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 && resp.Header.Get("X-SSH-Challenge") != "" {
		challenge := resp.Header.Get("X-SSH-Challenge")
		if onChallenge != nil {
			onChallenge(challenge)
		}

		signer, err := getSigner(c.KeyPath, pubKeyBytes)
		if err != nil {
			return err
		}

		sig, err := signer.Sign(nil, []byte(challenge))
		if err != nil {
			return err
		}
		sigBase64 := base64.StdEncoding.EncodeToString(ssh.Marshal(sig))

		headers["X-SSH-Challenge"] = challenge
		headers["X-SSH-Signature"] = sigBase64

		resp, err = send(headers)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("CA Error (%d): %s", resp.StatusCode, string(body))
	}

	certBytes, _ := io.ReadAll(resp.Body)
	return writeFileAtomic(c.KeyPath+"-cert.pub", certBytes, 0644)
}

func getSigner(path string, pubKeyBytes []byte) (ssh.Signer, error) {
	pubKey, _, _, _, _ := ssh.ParseAuthorizedKey(pubKeyBytes)

	// Try local file first
	privKeyBytes, err := os.ReadFile(path)
	if err == nil {
		s, err := ssh.ParsePrivateKey(privKeyBytes)
		if err == nil {
			return s, nil
		}
	}

	// Try Agent
	var conn net.Conn
	if runtime.GOOS == "windows" {
		conn, _ = net.Dial("unix", `\\.\pipe\openssh-ssh-agent`)
	} else if socket := os.Getenv("SSH_AUTH_SOCK"); socket != "" {
		conn, _ = net.Dial("unix", socket)
	}

	if conn != nil {
		defer conn.Close()
		ag := agent.NewClient(conn)
		signers, _ := ag.Signers()
		for _, s := range signers {
			if bytes.Equal(s.PublicKey().Marshal(), pubKey.Marshal()) {
				return s, nil
			}
		}
	}

	return nil, fmt.Errorf("no usable signer found")
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = os.Remove(tmpName)
	}

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(path)
		if err := os.Rename(tmpName, path); err != nil {
			cleanup()
			return err
		}
	}
	return nil
}
