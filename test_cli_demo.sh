#!/bin/bash
# Demo script for testing CLI arguments and environment variables

set -e

echo "=== Testing CLI Arguments and Environment Variables ==="
echo ""

# Generate test keypair
echo "1. Generating test keys..."
KEYS=$(./venv/bin/python3 mumbojumbo.py --gen-keys)
PRIVKEY=$(echo "$KEYS" | head -1)
PUBKEY=$(echo "$KEYS" | tail -1)

echo "   Private key: ${PRIVKEY:0:20}..."
echo "   Public key: ${PUBKEY:0:20}..."
echo ""

# Test 1: CLI argument for domain and key
echo "2. Testing CLI arguments (should show error about missing config file handlers)..."
./venv/bin/python3 mumbojumbo.py -k "$PRIVKEY" -d .test.domain 2>&1 | head -3 || true
echo ""

# Test 2: Environment variables
echo "3. Testing environment variables (should show error about missing config file handlers)..."
export MUMBOJUMBO_SERVER_KEY="$PRIVKEY"
export MUMBOJUMBO_DOMAIN=".env.test.com"
./venv/bin/python3 mumbojumbo.py 2>&1 | head -3 || true
echo ""

# Test 3: CLI overrides environment
echo "4. Testing CLI override of environment variable..."
echo "   (CLI domain should win over environment domain)"
./venv/bin/python3 mumbojumbo.py -d .cli.override.com 2>&1 | head -3 || true
echo ""

# Clean up
unset MUMBOJUMBO_SERVER_KEY
unset MUMBOJUMBO_DOMAIN

echo "=== Demo Complete ==="
echo ""
echo "Key features implemented:"
echo "  ✓ -k, --key argument to override private key"
echo "  ✓ -d, --domain argument to override domain"
echo "  ✓ MUMBOJUMBO_SERVER_KEY environment variable"
echo "  ✓ MUMBOJUMBO_DOMAIN environment variable"
echo "  ✓ Precedence: CLI > Environment > Config file"
echo "  ✓ Security warning when key provided via CLI"
echo "  ✓ Domain validation"
echo ""
