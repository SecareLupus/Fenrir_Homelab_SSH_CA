#!/bin/bash
set -e

# Cleanup on exit
trap "docker-compose -f docker-compose.test.yml down -v" EXIT

echo "Building and starting E2E test environment..."
docker-compose -f docker-compose.test.yml up --build -d

echo "Waiting for tests to complete..."
# Wait for test-runner to finish and capture exit code
exit_code=$(docker wait $(docker-compose -f docker-compose.test.yml ps -q test-runner))

echo "Test logs:"
docker-compose -f docker-compose.test.yml logs

if [ "$exit_code" -eq 0 ]; then
    echo "E2E Tests SUCCESS"
else
    echo "E2E Tests FAILED"
    exit 1
fi
