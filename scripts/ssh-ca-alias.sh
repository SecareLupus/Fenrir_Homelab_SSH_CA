#!/bin/bash

# SSH CA Alias Function
# Usage: source ssh-ca-alias.sh
# Then: ssh-ca user@host

ssh-ca() {
    # Try to renew certificate (will use cached API key or prompt if needed)
    # Redirect output to stderr to keep stdout clean for piping
    echo "Checking certificate status..." >&2
    ssh-ca-client -url "${SSH_CA_URL:-http://localhost:8080}" >&2
    
    if [ $? -eq 0 ]; then
        echo "Certificate valid. Launching SSH..." >&2
        ssh "$@"
    else
        echo "Failed to obtain certificate. SSH cancelled." >&2
        return 1
    fi
}
