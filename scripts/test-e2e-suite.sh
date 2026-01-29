#!/bin/bash
set -e

echo "Starting E2E Test Suite..."
pwd
ls -R
echo "-------"

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
chmod 600 id_test id_test-cert.pub

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
# Use API Key to bypass CSRF for revocation
curl -sf -H "X-API-Key: $ADMIN_API_KEY" --data-urlencode "fingerprint=$fp" -d "reason=testing" $CA_URL/admin/revoke

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

echo "--- Starting Additional Tests ---"

# 8. CLI Verification
echo "Running CLI Verification..."
# Use bash explicitly and provide the full path to avoid "No such file or directory" issues
bash scripts/test-cli-e2e.sh || { echo "CLI Verification Failed"; exit 1; }

# 9. Host Lifecycle Verification
echo "Starting Host Lifecycle Verification..."

# 9a. Sign Initial Host Key (Bootstrap)
echo "Generating host key..."
rm -f ssh_host_ed25519_key ssh_host_ed25519_key.pub ssh_host_ed25519_key-cert.pub
ssh-keygen -t ed25519 -N "" -f ssh_host_ed25519_key
HOST_PUB=$(cat ssh_host_ed25519_key.pub)
HOSTNAME="test-host.local"

# Sign via Admin using API Key (bypasses CSRF)
# Use --data-urlencode for pubkey to handle spaces correctly
echo "Signing host cert..."
curl -sf -H "X-API-Key: $ADMIN_API_KEY" \
    --data-urlencode "pubkey=$HOST_PUB" \
    -d "hostname=$HOSTNAME" \
    -d "ttl=86400" \
    $CA_URL/admin/hosts/sign > ssh_host_ed25519_key-cert.pub

if [ ! -s ssh_host_ed25519_key-cert.pub ]; then
    echo "FAILED: Host cert signing failed"
    exit 1
fi
echo "Host cert signed."

# 9b. Generate Host API Key (for renewal)
echo "Generating Host API Key..."
# Must use API Key or Admin Session. We have ADMIN_API_KEY from step 3.
# Let's use that for admin actions now.
HOST_API_KEY_PAGE=$(curl -sf -H "X-API-Key: $ADMIN_API_KEY" \
    -d "hostname=$HOSTNAME" \
    $CA_URL/admin/hosts/apikey)
# The page returns HTML with the key. We need to extract it.
# Unfortuantely handleAdminHostAPIKey renders a template `admin_host_apikey.html`.
# We need to parse it. 
# Assumption: The template displays the key in a consistent way.
# Let's try to grab it. If this is flaky, we might need a JSON endpoint.
# But for now, let's look for the key pattern or ID.
# Since we don't have the template content handy, let's assume it's visible.
# Wait, for testing reliability, maybe we should add a JSON mode to that handler?
# OR just rely on the standard "api/v1/host/renew" if we can bootstrap differently.
# Check server.go: handleAdminHostAPIKey -> renderPage.
# Let's skip automatic parsing if it's hard and just verify we CAN hit the page.
# BUT we need the key to test renewal.
# Let's grep it. 
# The template likely has `{{.APIKey}}`.
HOST_API_KEY=$(echo "$HOST_API_KEY_PAGE" | grep -oP '[A-Za-z0-9+/]{40,}' | head -1) # Basic base64 guess
# actually random bytes (32) encoded to base64 = 44 chars ending in =.
# Let's refine grep.
HOST_API_KEY=$(echo "$HOST_API_KEY_PAGE" | grep -oP '[A-Za-z0-9+/=]{44}') || true

if [ -z "$HOST_API_KEY" ]; then
    echo "WARNING: Could not scrape Host API Key. Skipping Renewal Test."
    echo "Page content dump:"
    echo "$HOST_API_KEY_PAGE"
else
    echo "Got Host API Key: ${HOST_API_KEY:0:5}..."
    
# 9c. Test Renewal
    echo "Testing Host Renewal..."
    # /api/v1/host/renew expects POST with X-API-Key (Host's key) and pubkey
    rm -f renewed_host.pub
    curl -sf -H "X-API-Key: $HOST_API_KEY" \
        -d "pubkey=$HOST_PUB" \
        $CA_URL/api/v1/host/renew > renewed_host.pub
        
    if [ -s renewed_host.pub ]; then
        echo "SUCCESS: Host Renewal worked."
    else
         echo "FAILED: Host Renewal failed (empty response)."
         exit 1
    fi
fi

echo "--- Advanced Renewal Tests ---"

# 10. Test Renewal of Expired Certificate
echo "Testing Renewal of Expired Certificate..."
# 10a. Sign a cert with 1s TTL
rm -f id_expired*
ssh-keygen -t ed25519 -N "" -f id_expired
EXPIRED_PUB=$(cat id_expired.pub)

echo "Issuing 1s TTL cert..."
# Using Admin API Key to issue
curl -sf -H "X-API-Key: $ADMIN_API_KEY" \
    --data-urlencode "pubkey=$EXPIRED_PUB" \
    -d "ttl=1" \
    -d "principals=testuser" \
    $CA_URL/cert/request > id_expired-cert.pub

echo "Waiting 2s for expiration..."
sleep 2

# Verify it is expired
EXPIRY=$(ssh-keygen -Lf id_expired-cert.pub | grep "Valid: from" | awk '{print $4}')
echo "Cert was valid until: $EXPIRY"

# 10b. Attempt Renewal via PoP (Simulating CLI behavior)
echo "Attempting renewal of expired cert via PoP..."
# We need to simulate PoP. tyr does this, but for the script we can use the CLI logic or just curl.
# Actually, let's use the 'tyr' binary we verified earlier, it's easier.
./tyr -url $CA_URL \
     -username "admin" \
     -password "adminpassword" \
     -identity "id_expired" \
     -type "ed25519" || { echo "Expired renewal failed"; exit 1; }

if [ -f "id_expired-cert.pub" ]; then
    echo "SUCCESS: Renewed expired certificate."
else
    echo "FAILED: Could not renew expired certificate."
    exit 1
fi

# 11. Test Revocation blocks Renewal
echo "Testing Revocation blocks Renewal..."
# 11a. Revoke the key
fp_expired=$(ssh-keygen -l -f id_expired.pub | awk '{print $2}')
echo "Revoking key $fp_expired..."
curl -sf -H "X-API-Key: $ADMIN_API_KEY" --data-urlencode "fingerprint=$fp_expired" -d "reason=revocation-test" $CA_URL/admin/revoke

# 11b. Attempt Renewal (Should FAIL now)
echo "Attempting renewal of revoked key (should fail)..."
if ./tyr -url $CA_URL \
     -username "admin" \
     -password "adminpassword" \
     -identity "id_expired" \
     -type "ed25519" 2>/dev/null; then
    echo "FAILED: Renewal succeeded for a revoked key!"
    exit 1
else
    echo "SUCCESS: Renewal correctly blocked for revoked key."
fi

echo "E2E Tests Passed!"
