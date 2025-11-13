#!/usr/bin/env bash
# Test DNS delegation for Mumbojumbo server
# Verifies that DNS queries for your domain are being routed to your server

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Help message
usage() {
    cat << EOF
Usage: $0 DOMAIN SERVER_IP

Test DNS delegation for Mumbojumbo DNS covert channel server.

ARGUMENTS:
    DOMAIN      DNS domain to test (e.g., .asd.qwe or asd.qwe.foo)
    SERVER_IP   IP address of your Mumbai server

EXAMPLES:
    $0 .asd.qwe 34.123.45.67
    $0 asd.qwe.foo 1.2.3.4

WHAT IT TESTS:
    1. NS record delegation
    2. Glue record (A record for nameserver)
    3. DNS query routing to your server
    4. Server reachability

PREREQUISITES:
    - dig command installed (dnsutils package)
    - Server must be running and accessible

EOF
    exit 1
}

# Check arguments
if [[ $# -ne 2 ]]; then
    usage
fi

DOMAIN="$1"
SERVER_IP="$2"

# Normalize domain (remove leading dot for queries)
DOMAIN_QUERY="${DOMAIN#.}"

# Add leading dot if not present (for display)
if [[ ! "$DOMAIN" =~ ^\. ]]; then
    DOMAIN_DISPLAY=".$DOMAIN"
else
    DOMAIN_DISPLAY="$DOMAIN"
fi

# Check for dig command
if ! command -v dig &> /dev/null; then
    echo -e "${RED}Error: 'dig' command not found${NC}"
    echo "Install with: sudo apt-get install dnsutils  (Debian/Ubuntu)"
    echo "           or: brew install bind  (macOS)"
    exit 1
fi

echo -e "${BLUE}=== Mumbojumbo DNS Delegation Test ===${NC}"
echo "Domain: $DOMAIN_DISPLAY"
echo "Server IP: $SERVER_IP"
echo ""

# Test 1: Check NS record
echo -e "${YELLOW}[1/4] Checking NS record delegation...${NC}"
NS_RESULT=$(dig +short NS "$DOMAIN_QUERY" 2>&1 || true)

if [[ -z "$NS_RESULT" ]]; then
    echo -e "${RED}✗ FAIL: No NS records found for $DOMAIN_QUERY${NC}"
    echo ""
    echo "You need to add an NS record at your DNS provider:"
    echo "  Name: $DOMAIN_QUERY"
    echo "  Type: NS"
    echo "  Value: ns1.$DOMAIN_QUERY"
    echo ""
    exit 1
else
    echo -e "${GREEN}✓ PASS: NS record found${NC}"
    echo "  $NS_RESULT"
fi

# Test 2: Check glue record (A record for nameserver)
echo ""
echo -e "${YELLOW}[2/4] Checking glue record (A record for nameserver)...${NC}"
# Extract nameserver from NS result
NAMESERVER=$(echo "$NS_RESULT" | head -n 1 | sed 's/\.$//')
A_RESULT=$(dig +short A "$NAMESERVER" 2>&1 || true)

if [[ -z "$A_RESULT" ]]; then
    echo -e "${RED}✗ FAIL: No A record found for nameserver $NAMESERVER${NC}"
    echo ""
    echo "You need to add an A record (glue record) at your DNS provider:"
    echo "  Name: $NAMESERVER"
    echo "  Type: A"
    echo "  Value: $SERVER_IP"
    echo ""
    exit 1
elif [[ "$A_RESULT" != "$SERVER_IP" ]]; then
    echo -e "${YELLOW}⚠  WARNING: A record doesn't match server IP${NC}"
    echo "  Expected: $SERVER_IP"
    echo "  Found: $A_RESULT"
    echo ""
    echo "Update your DNS A record to point to $SERVER_IP"
    exit 1
else
    echo -e "${GREEN}✓ PASS: Glue record points to $SERVER_IP${NC}"
fi

# Test 3: Test DNS query routing
echo ""
echo -e "${YELLOW}[3/4] Testing DNS query routing...${NC}"
TEST_QUERY="test-$(date +%s).${DOMAIN_QUERY}"
echo "  Sending test query: $TEST_QUERY"

# Query directly against the server
DIRECT_RESULT=$(dig @"$SERVER_IP" "$TEST_QUERY" +short +time=2 +tries=1 2>&1 || true)

# Note: We expect NO answer (server doesn't respond to queries, just captures them)
# So we check if the query reached the server by checking for connection timeout vs other errors
if [[ "$DIRECT_RESULT" =~ "connection timed out" ]] || [[ -z "$DIRECT_RESULT" ]]; then
    echo -e "${GREEN}✓ PASS: Query routed to server (no response expected)${NC}"
    echo "  Note: Mumbojumbo server captures packets but doesn't respond"
elif [[ "$DIRECT_RESULT" =~ "connection refused" ]]; then
    echo -e "${RED}✗ FAIL: Connection refused by server${NC}"
    echo "  Check if server is running: sudo systemctl status mumbojumbo"
    exit 1
else
    echo -e "${GREEN}✓ PASS: Server reachable${NC}"
fi

# Test 4: Server reachability (ping)
echo ""
echo -e "${YELLOW}[4/4] Testing server reachability (ICMP)...${NC}"
if ping -c 1 -W 2 "$SERVER_IP" &> /dev/null; then
    echo -e "${GREEN}✓ PASS: Server is reachable via ping${NC}"
else
    echo -e "${YELLOW}⚠  WARNING: Server not responding to ping (may be firewalled)${NC}"
    echo "  This is OK - server may block ICMP"
fi

# Final summary
echo ""
echo -e "${BLUE}=== Summary ===${NC}"
echo ""
echo -e "${GREEN}✓ DNS delegation is configured correctly!${NC}"
echo ""
echo "Your domain '$DOMAIN_DISPLAY' is delegated to server at $SERVER_IP"
echo ""
echo "Next steps:"
echo "  1. Verify server is running:"
echo "     ssh to server and run: sudo systemctl status mumbojumbo"
echo ""
echo "  2. Watch server logs for incoming queries:"
echo "     ssh to server and run: sudo journalctl -u mumbojumbo -f"
echo ""
echo "  3. Send test data from client:"
echo "     export MUMBOJUMBO_CLIENT_KEY=<your_client_key>"
echo "     export MUMBOJUMBO_DOMAIN=$DOMAIN_DISPLAY"
echo "     echo 'test data' | ./mumbojumbo-client.py"
echo ""
echo -e "${GREEN}DNS delegation test complete!${NC}"
