#!/bin/bash
set -e

# Generate random AWS-style credentials
# Access Key ID: 32 alphanumeric characters
# Secret Access Key: 64 alphanumeric characters

echo "🔑 Generating new client credentials..."

# Generate random access key ID (32 chars)
CLIENT_ACCESS_KEY_ID=$(LC_ALL=C tr -dc 'abcdef0-9' < /dev/urandom | head -c 32)

# Generate random secret access key (64 chars)
CLIENT_SECRET_ACCESS_KEY=$(LC_ALL=C tr -dc 'abcdef0-9' < /dev/urandom | head -c 64)

echo ""
echo "✅ Generated new credentials"
echo ""

# Set the secrets via wrangler
echo "📝 Setting wrangler secrets..."
echo "$CLIENT_ACCESS_KEY_ID" | wrangler secret put CLIENT_ACCESS_KEY_ID
echo "$CLIENT_SECRET_ACCESS_KEY" | wrangler secret put CLIENT_SECRET_ACCESS_KEY

echo "
✨ Done! Configure your S3 client with these credentials:
   Access Key ID: $CLIENT_ACCESS_KEY_ID
   Secret Access Key: $CLIENT_SECRET_ACCESS_KEY

   Press q to exit. You will not be able to see these credentials again.
" | less
