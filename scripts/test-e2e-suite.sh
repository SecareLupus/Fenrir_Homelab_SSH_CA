#!/bin/bash
set -e

echo "Starting E2E Test Suite..."

# 1. Wait for CA Server
CA_URL="${CA_SERVER_URL:-http://fenrir-server:8080}"
echo "Waiting for CA Server ($CA_URL)..."
until curl -sf $CA_URL/api/v1/health > /dev/null; do
    sleep 1
done
echo "CA Server is UP."

# 2. Bootstrap Admin
echo "Bootstrapping admin..."
curl -sf -c cookies.txt -d "username=admin&password=adminpassword" $CA_URL/login

# 3. Generate API Key for Admin (Use CLI Login Endpoint)
echo "Generating API key..."
ADMIN_API_KEY=$(curl -sf -H "Content-Type: application/json" -d '{"username":"admin","password":"adminpassword"}' $CA_URL/api/auth/login | jq -r .api_key) || { echo "Failed to get API key"; exit 1; }
echo "Got API Key: ${ADMIN_API_KEY:0:5}..."

# 4. Generate test user SSH key
echo "Generating test user SSH key..."
rm -f id_test id_test.pub id_test-cert.pub
ssh-keygen -t ed25519 -N "" -f id_test

# 5. Sign Certificate using Curl
echo "Requesting certificate via API..."
curl -v -b cookies.txt --data-urlencode "pubkey=$(cat id_test.pub)" -d "ttl=3600" -d "principals=testuser" $CA_URL/cert/request > id_test-cert.pub || { echo "Curl failed"; exit 1; }

if [ ! -s id_test-cert.pub ]; then
    echo "FAILED: Certificate issuance failed"
    exit 1
fi
echo "Certificate issued successfully."

# 6. Test SSH Connection
echo "Testing SSH connection to $TARGET_HOST..."
nslookup $TARGET_HOST || echo "nslookup failed"

MAX_RETRIES=10
COUNT=0
until ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 -i id_test -i id_test-cert.pub testuser@$TARGET_HOST "whoami"; do
    COUNT=$((COUNT+1))
    if [ $COUNT -ge $MAX_RETRIES ]; then
        echo "FAILED: SSH connection failed after $MAX_RETRIES attempts"
        exit 1
    fi
    echo "SSH failed, retrying ($COUNT/$MAX_RETRIES)..."
    sleep 5
done

echo "SSH connection SUCCESS"

# 7. Test Revocation
echo "Testing revocation..."
fp=$(ssh-keygen -l -f id_test.pub | awk '{print $2}')
echo "Revoking key $fp with API Key..."
curl -sf -H "X-API-Key: $ADMIN_API_KEY" -d "fingerprint=$fp&reason=testing" $CA_URL/admin/revoke

echo "Checking KRL..."
curl -sf $CA_URL/krl > krl.txt
echo "--- KRL Content ---"
cat krl.txt
echo "-------------------"
echo "Looking for key content:"
cat id_test.pub

# Use grep -F for fixed string matching to avoid regex interpretation issues
if grep -Fq "$(cat id_test.pub)" krl.txt; then
    echo "SUCCESS: Key appeared in KRL"
else
    echo "FAILED: Key not found in KRL"
    exit 1
fi

echo "E2E Tests Passed!"
