#!/bin/bash
set -e

echo "Starting E2E Test Suite..."

# 1. Wait for CA Server
echo "Waiting for CA Server (http://ca-server:8080)..."
until curl -sf http://ca-server:8080/api/v1/health > /dev/null; do
    sleep 1
done
echo "CA Server is UP."

# 2. Bootstrap Admin
echo "Bootstrapping admin..."
curl -sf -c cookies.txt -d "username=admin&password=adminpassword" http://ca-server:8080/login

# 3. Generate API Key for Admin
echo "Generating API key..."
# We use curl because the client doesn't support generating API keys yet
# We need to extract the key from the response (dashboard.html has it in NewAPIKey)
# Simpler: hit the API endpoint directly if it exists, or scrape it.
# Wait, I'll just use curl to sign the cert directly for admin to save time, 
# OR I can add a dedicated API endpoint for key gen that returns JSON.
# Actually, let's just use curl to sign the cert, as that's what the client does anyway.

# 3. Generate test user SSH key
echo "Generating test user SSH key..."
ssh-keygen -t ed25519 -N "" -f id_test

# 4. Sign Certificate using Curl (acting as a client)
echo "Requesting certificate via API..."
curl -v -b cookies.txt --data-urlencode "pubkey=$(cat id_test.pub)" -d "ttl=3600" -d "principals=testuser" http://ca-server:8080/cert/request > id_test-cert.pub || { echo "Curl failed"; exit 1; }

if [ ! -s id_test-cert.pub ]; then
    echo "FAILED: Certificate issuance failed"
    exit 1
fi
echo "Certificate issued successfully."

# 5. Test SSH Connection
echo "Testing SSH connection to $TARGET_HOST..."
ssh -o StrictHostKeyChecking=no -i id_test -i id_test-cert.pub testuser@$TARGET_HOST "whoami"

if [ $? -eq 0 ]; then
    echo "SSH connection SUCCESS"
else
    echo "FAILED: SSH connection failed"
    exit 1
fi

# 6. Test Revocation
echo "Testing revocation..."
# Extract fingerprint
fp=$(ssh-keygen -l -f id_test.pub | awk '{print $2}')
echo "Revoking key $fp..."
curl -sf -b cookies.txt -d "fingerprint=$fp&reason=testing" http://ca-server:8080/admin/revoke

echo "Checking KRL..."
if curl -sf http://ca-server:8080/krl | grep -q "$(cat id_test.pub)"; then
    echo "SUCCESS: Key appeared in KRL"
else
    echo "FAILED: Key not found in KRL"
    exit 1
fi

echo "E2E Tests Passed!"
