#!/bin/bash

# Generate a random 256-bit (32-byte) SSE-C key for S3Broker managed encryption
#
# Usage: ./generate-sse-key.sh

set -e

echo "=========================================="
echo "  S3Broker SSE-C Key Generator"
echo "=========================================="
echo ""

# Generate 32 random bytes and base64 encode
KEY=$(openssl rand -base64 32)

echo "Your SSE-C encryption key:"
echo ""
echo "  $KEY"
echo ""
echo "=========================================="
echo "  ⚠️  IMPORTANT - READ CAREFULLY  ⚠️"
echo "=========================================="
echo ""
echo "1. Store this key in a SECURE location (e.g., password manager, secrets vault)"
echo ""
echo "2. ⚠️  YOUR DATA WILL BE PERMANENTLY LOST IF YOU LOSE THIS KEY ⚠️"
echo "   S3 does NOT store the key - only you have it."
echo ""
echo "3. Use this key in your guardrailConfig:"
echo ""
echo "   managedSse: ["
echo "     {"
echo "       pattern: '/your-bucket/encrypted/.*',"
echo "       config: { key: '$KEY' },"
echo "     },"
echo "   ],"
echo ""
echo "4. Store the key as a secret, NOT in code."
echo ""
