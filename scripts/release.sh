#!/bin/bash
# Release script for s3broker
#
# This script:
# 1. Checkouts main branch
# 2. Creates a release/<version> branch
# 3. Increments the s3broker minor version
# 4. Commits the version bump
# 5. Tags the commit with the version
# 6. Pushes to remote
#
# Usage:
#   ./scripts/release.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}🚀 Starting s3broker release process...${NC}"

# Ensure we're in the repo root
cd "$(dirname "$0")/.."

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo -e "${RED}❌ Error: You have uncommitted changes. Please commit or stash them first.${NC}"
    exit 1
fi

# Checkout main and pull latest
echo -e "${YELLOW}📥 Checking out main branch and pulling latest...${NC}"
git checkout main
git pull origin main

# Get current version from package.json
CURRENT_VERSION=$(node -p "require('./packages/s3broker/package.json').version")
echo -e "${YELLOW}📦 Current version: ${CURRENT_VERSION}${NC}"

# Parse version components
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT_VERSION"

# Increment minor version
NEW_MINOR=$((MINOR + 1))
NEW_VERSION="${MAJOR}.${NEW_MINOR}.0"

echo -e "${GREEN}📦 New version: ${NEW_VERSION}${NC}"

# Create release branch
RELEASE_BRANCH="release/${NEW_VERSION}"
echo -e "${YELLOW}🌿 Creating release branch: ${RELEASE_BRANCH}${NC}"
git checkout -b "$RELEASE_BRANCH"

# Update version in package.json using node
node -e "
const fs = require('fs');
const path = './packages/s3broker/package.json';
const pkg = JSON.parse(fs.readFileSync(path, 'utf8'));
pkg.version = '${NEW_VERSION}';
fs.writeFileSync(path, JSON.stringify(pkg, null, '\t') + '\n');
"

# Commit the version bump
echo -e "${YELLOW}📝 Committing version bump...${NC}"
git add packages/s3broker/package.json
git commit -m "release ${NEW_VERSION}"

# Create tag
TAG_NAME="${NEW_VERSION}"
echo -e "${YELLOW}🏷️  Creating tag: ${TAG_NAME}${NC}"
git tag -a "$TAG_NAME" -m "Release ${NEW_VERSION}"

# Push branch and tag to remote
echo -e "${YELLOW}📤 Pushing release branch and tag to remote...${NC}"
git push -u origin "$RELEASE_BRANCH"
git push origin "$TAG_NAME"

echo ""
echo -e "${GREEN}✅ Release ${NEW_VERSION} created successfully!${NC}"
echo ""
echo -e "Next steps:"
echo -e "  1. Create a Pull Request from ${RELEASE_BRANCH} to main"
echo -e "  2. After merging, the GitHub Actions workflow will publish to npm"
echo ""
echo -e "Tag: ${TAG_NAME}"
echo -e "Branch: ${RELEASE_BRANCH}"
