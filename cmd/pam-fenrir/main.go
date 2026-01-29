/*
 * Copyright (c) 2026 SecareLupus
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

package main

/*
#cgo LDFLAGS: -lpam
#include <security/pam_modules.h>
#include <security/pam_appl.h>
*/
import "C"

import (
	"bytes"
	"crypto/rand"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const defaultCAKeyPath = "/etc/ssh/user_ca.pub"

//export go_pam_sm_authenticate
func go_pam_sm_authenticate(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	var cUser *C.char
	if C.pam_get_user(pamh, (**C.char)(unsafe.Pointer(&cUser)), nil) != C.PAM_SUCCESS || cUser == nil {
		return C.PAM_AUTH_ERR
	}
	user := C.GoString(cUser)

	// 1. Parse Arguments (e.g. allowed_groups=admin,sudo)
	allowedGroups := make(map[string]bool)
	caKeyPath := defaultCAKeyPath

	args := unsafe.Slice(argv, int(argc))
	for _, arg := range args {
		goArg := C.GoString(arg)
		if strings.HasPrefix(goArg, "allowed_groups=") {
			groups := strings.Split(strings.TrimPrefix(goArg, "allowed_groups="), ",")
			for _, g := range groups {
				allowedGroups[strings.TrimSpace(g)] = true
			}
		}
		if strings.HasPrefix(goArg, "ca_key=") {
			caKeyPath = strings.TrimPrefix(goArg, "ca_key=")
		}
	}

	// 2. Load Trusted CA Public Key
	caKeyBytes, err := os.ReadFile(caKeyPath)
	if err != nil {
		log.Printf("PAM SSH CA: Failed to read CA key at %s: %v", caKeyPath, err)
		return C.PAM_AUTH_ERR
	}
	caPubKey, _, _, _, err := ssh.ParseAuthorizedKey(caKeyBytes)
	if err != nil {
		log.Printf("PAM SSH CA: Failed to parse CA key: %v", err)
		return C.PAM_AUTH_ERR
	}

	// 3. Connect to SSH Agent
	authSock := os.Getenv("SSH_AUTH_SOCK")
	if authSock == "" {
		return C.PAM_AUTH_ERR
	}
	conn, err := net.Dial("unix", authSock)
	if err != nil {
		return C.PAM_AUTH_ERR
	}
	defer conn.Close()

	ag := agent.NewClient(conn)
	identities, err := ag.List()
	if err != nil {
		return C.PAM_AUTH_ERR
	}

	// 4. Verification Loop
	now := uint64(time.Now().Unix())
	for _, id := range identities {
		pubKey, err := ssh.ParsePublicKey(id.Blob)
		if err != nil {
			continue
		}

		cert, ok := pubKey.(*ssh.Certificate)
		if !ok {
			continue
		}

		// a. Signature check
		if cert.SignatureKey == nil || !bytes.Equal(cert.SignatureKey.Marshal(), caPubKey.Marshal()) {
			continue
		}

		// b. Expiry check
		if now < cert.ValidAfter || now > cert.ValidBefore {
			continue
		}

		// c. Identity check (user must be in principals)
		userMatch := false
		for _, p := range cert.ValidPrincipals {
			if p == user {
				userMatch = true
				break
			}
		}
		if !userMatch {
			continue
		}

		// d. Group check (if allowed_groups is set)
		if len(allowedGroups) > 0 {
			groupMatch := false
			for _, p := range cert.ValidPrincipals {
				if allowedGroups[p] {
					groupMatch = true
					break
				}
			}
			if !groupMatch {
				continue
			}
		}

		// e. Challenge-Response (PoP)
		nonce := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			continue
		}

		sig, err := ag.Sign(cert.Key, nonce)
		if err != nil {
			continue
		}

		if err := cert.Key.Verify(nonce, sig); err != nil {
			continue
		}

		log.Printf("PAM SSH CA: Successfully authenticated user %s via ssh-agent certificate", user)
		return C.PAM_SUCCESS
	}

	return C.PAM_AUTH_ERR
}

//export go_pam_sm_setcred
func go_pam_sm_setcred(pamh *C.pam_handle_t, flags C.int, argc C.int, argv **C.char) C.int {
	return C.PAM_SUCCESS
}

func main() {}
