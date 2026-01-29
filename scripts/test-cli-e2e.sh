#!/bin/bash
set -e

TYR="./tyr"
CA_URL="${CA_SERVER_URL:-http://fenrir-server:8080}"

echo "Starting CLI (Tyr) Verification..."

# 1. Version Check
echo "Checking version..."
$TYR -version

# 2. Login
echo "Testing CLI Login..."
# Using inputs for username/password prompts if flags aren't enough, 
# but main.go supports -username and -password (via flags? or prompts).
# Checking main.go: 
#   username := flag.String("username", "", ...)
#   password := flag.String("password", "", ...)
# So we can pass them as flags.
output=$($TYR -url $CA_URL -username "admin" -password "adminpassword" -key-file "" 2>&1) || { echo "Login failed: $output"; exit 1; }

# Extract key from output? 
# The main.go prints "✓ Successfully authenticated with Fenrir" but doesn't output the key to stdout unless we change it 
# OR if -key-file is not saved. 
# Wait, main.go logic:
# if username != "": loginAndGetAPIKey -> apiKey
# apiKey is then used in client.Config.
# It doesn't save it to disk automatically in main.go unless I missed it.
# It uses it for `cfg.Sign`.
# So `-username` implies "Login and then immediately Sign in one go".

# 3. Sign Certificate (Login + Sign flow)
echo "Testing CLI Sign (Login + Sign)..."
rm -f id_cli_ed25519*
# Generate a key for CLI usage
ssh-keygen -t ed25519 -N "" -f id_cli_ed25519

# Run tyr to sign
# Input: PoP challenge might be needed?
# main.go says: "PoP Challenge received. Touch your security key if prompted..."
# The server checks PoP if not authenticated, or ownership if authenticated.
# Since we are logging in as admin, and using a NEW key, it should auto-enroll (isNewKey=true in server.go).
# So no PoP challenge for *new* keys if authenticated?
# Let's check server.go handleCertRequest:
# IF authenticated:
#   CheckPublicKeyOwnership
#     If owned by another -> 403
#     If not found -> isNewKey = true
# ...
# If isNewKey -> RegisterPublicKey
# SignCertificate
#
# So correct, no challenge needed for new authenticated keys.

$TYR -url $CA_URL \
     -username "admin" \
     -password "adminpassword" \
     -identity "id_cli_ed25519" \
     -type "ed25519" || { echo "CLI Sign failed"; exit 1; }

if [ ! -f "id_cli_ed25519-cert.pub" ]; then
    echo "FAILED: CLI did not produce signed certificate"
    exit 1
fi
echo "CLI produced certificate:"
ssh-keygen -Lf id_cli_ed25519-cert.pub

echo "CLI Verification Passed!"
