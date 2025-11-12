#!/bin/bash
# Demo: Using environment variables for mumbojumbo server and clients

set -e

echo "=== Mumbojumbo Environment Variables Demo ==="
echo ""

# Step 1: Generate keys and domain
echo "1. Generating keys and domain..."
echo "   Command: ./venv/bin/python3 mumbojumbo.py --gen-keys"
echo ""
./venv/bin/python3 mumbojumbo.py --gen-keys
echo ""

# Step 2: Save to file and source
echo "2. Saving to file and sourcing..."
./venv/bin/python3 mumbojumbo.py --gen-keys > /tmp/mumbojumbo_env.sh
echo "   Saved to: /tmp/mumbojumbo_env.sh"
cat /tmp/mumbojumbo_env.sh
echo ""

# Step 3: Source the file
echo "3. Sourcing environment variables..."
source /tmp/mumbojumbo_env.sh
echo "   ✓ MUMBOJUMBO_SERVER_KEY=${MUMBOJUMBO_SERVER_KEY:0:25}..."
echo "   ✓ MUMBOJUMBO_CLIENT_KEY=${MUMBOJUMBO_CLIENT_KEY:0:25}..."
echo "   ✓ MUMBOJUMBO_DOMAIN=$MUMBOJUMBO_DOMAIN"
echo ""

# Step 4: Show server usage
echo "4. Server can now run with just environment variables:"
echo "   sudo ./venv/bin/python3 mumbojumbo.py"
echo "   (No config file needed! Uses env vars automatically)"
echo ""

# Step 5: Show client usage (Python example)
echo "5. Python client can use the variables:"
echo "   echo 'Hello' | ./clients/python/mumbojumbo-client.py \\"
echo "     -k \$MUMBOJUMBO_CLIENT_KEY \\"
echo "     -d \$MUMBOJUMBO_DOMAIN"
echo ""

# Step 6: Show Go client usage
echo "6. Go client can use the variables:"
echo "   echo 'Hello' | ./clients/go/mumbojumbo-client \\"
echo "     -key \$MUMBOJUMBO_CLIENT_KEY \\"
echo "     -domain \$MUMBOJUMBO_DOMAIN"
echo ""

# Step 7: Show Node.js client usage
echo "7. Node.js client can use the variables:"
echo "   echo 'Hello' | node clients/node/mumbojumbo-client.js \\"
echo "     -k \$MUMBOJUMBO_CLIENT_KEY \\"
echo "     -d \$MUMBOJUMBO_DOMAIN"
echo ""

# Step 8: Show Rust client usage
echo "8. Rust client can use the variables:"
echo "   echo 'Hello' | ./clients/rust/target/release/mumbojumbo-client \\"
echo "     --key \$MUMBOJUMBO_CLIENT_KEY \\"
echo "     --domain \$MUMBOJUMBO_DOMAIN"
echo ""

# Step 9: Show C client usage
echo "9. C client can use the variables:"
echo "   echo 'Hello' | ./clients/c/mumbojumbo-client \\"
echo "     -k \$MUMBOJUMBO_CLIENT_KEY \\"
echo "     -d \$MUMBOJUMBO_DOMAIN"
echo ""

echo "=== Complete Workflow ==="
echo ""
echo "# One-time setup:"
echo "./venv/bin/python3 mumbojumbo.py --gen-keys > ~/.mumbojumbo_env"
echo "echo 'source ~/.mumbojumbo_env' >> ~/.bashrc"
echo ""
echo "# Then in any new terminal:"
echo "sudo ./venv/bin/python3 mumbojumbo.py  # Server uses env vars"
echo "echo 'data' | ./clients/python/mumbojumbo-client.py -k \$MUMBOJUMBO_CLIENT_KEY -d \$MUMBOJUMBO_DOMAIN"
echo ""

# Cleanup
rm -f /tmp/mumbojumbo_env.sh

echo "=== Demo Complete ==="
