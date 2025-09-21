#!/bin/bash

# Test script to discover working API endpoints
BASE_URL="http://localhost:8080/api/v1"

echo "Testing Developer Utilities API endpoints..."
echo "============================================="

# Test crypto endpoints
echo "Testing crypto endpoints:"
echo "-------------------------"

echo "1. Testing crypto/hash..."
curl -s -X POST $BASE_URL/crypto/hash \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello World", "algorithm": "sha256"}' | jq .

echo -e "\n2. Testing crypto/hmac..."
curl -s -X POST $BASE_URL/crypto/hmac \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello World", "key": "secret", "algorithm": "sha256"}' | jq .

echo -e "\n3. Testing crypto/password/hash..."
curl -s -X POST $BASE_URL/crypto/password/hash \
  -H "Content-Type: application/json" \
  -d '{"password": "test123"}' | jq .

echo -e "\n4. Testing crypto/password/verify..."
# First get a hash
HASH=$(curl -s -X POST $BASE_URL/crypto/password/hash \
  -H "Content-Type: application/json" \
  -d '{"password": "test123"}' | jq -r '.data.hash')

if [ "$HASH" != "null" ] && [ "$HASH" != "" ]; then
  curl -s -X POST $BASE_URL/crypto/password/verify \
    -H "Content-Type: application/json" \
    -d "{\"password\": \"test123\", \"hash\": \"$HASH\"}" | jq .
else
  echo "Could not get hash for verification test"
fi

# Test text endpoints
echo -e "\n\nTesting text endpoints:"
echo "----------------------"

echo "1. Testing text/case..."
curl -s -X POST $BASE_URL/text/case \
  -H "Content-Type: application/json" \
  -d '{"content": "hello world", "CaseType": "camelCase"}' | jq .

echo -e "\n2. Testing text/analyze..."
curl -s -X POST $BASE_URL/text/analyze \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello world!"}' | jq .

echo -e "\n3. Testing text/stats..."
curl -s -X POST $BASE_URL/text/stats \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello world!"}' | jq .

# Test other common patterns
echo -e "\n\nTesting other endpoints:"
echo "------------------------"

echo "1. Testing id/uuid..."
curl -s -X POST $BASE_URL/id/uuid \
  -H "Content-Type: application/json" \
  -d '{"version": "v4", "count": 1}' | jq .

echo -e "\n2. Testing time/now..."
curl -s -X GET $BASE_URL/time/now | jq .

echo -e "\n3. Testing time/convert..."
curl -s -X POST $BASE_URL/time/convert \
  -H "Content-Type: application/json" \
  -d '{"time": "1640995200", "fromFormat": "unix", "toFormat": "iso8601"}' | jq .

echo -e "\n\nTest completed!"