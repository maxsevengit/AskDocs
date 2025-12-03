#!/bin/bash

# 1. Signup
echo "Signing up..."
curl -X POST http://localhost:3001/api/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123"}'

echo -e "\n\nLogging in..."
# 2. Login and get token
TOKEN=$(curl -s -X POST http://localhost:3001/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

echo -e "\nToken: $TOKEN"

if [ -z "$TOKEN" ]; then
  echo "Failed to get token"
  exit 1
fi

# 3. Create dummy PDF
echo "dummy content" > test.txt

# 4. Upload
echo -e "\nUploading..."
curl -v -X POST http://localhost:3001/api/documents/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "document=@test.txt"

rm test.txt
