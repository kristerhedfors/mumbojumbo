package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/nacl/box"
)

const (
	MaxFragDataLen  = 80
	DNSLabelMaxLen  = 63
	HeaderSize      = 18 // 18-byte header: u64 + u32 + u32 + u16
	SealedBoxOH     = 48 // SealedBox overhead: 32-byte ephemeral pubkey + 16-byte tag (libsodium compatible)
	PublicKeySize   = 32
	PrivateKeySize  = 32
)

// MumbojumboClient handles DNS tunneling operations
type MumbojumboClient struct {
	serverClientKey    [32]byte
	domain          string
	maxFragmentSize int
	nextPacketID    uint64
}

// NewMumbojumboClient creates a new client instance
// Accepts either a string key (mj_cli_<hex>) or raw [32]byte
func NewMumbojumboClient(serverClientKeyInput interface{}, domain string, maxFragmentSize int) (*MumbojumboClient, error) {
	var serverClientKey [32]byte

	// Handle both string and byte array inputs
	switch v := serverClientKeyInput.(type) {
	case string:
		// Parse hex format key
		parsed, err := parseKeyHex(v)
		if err != nil {
			return nil, err
		}
		serverClientKey = parsed
	case [32]byte:
		serverClientKey = v
	case []byte:
		if len(v) != 32 {
			return nil, fmt.Errorf("invalid key length: expected 32, got %d", len(v))
		}
		copy(serverClientKey[:], v)
	default:
		return nil, errors.New("serverClientKey must be string, [32]byte, or []byte")
	}

	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}

	client := &MumbojumboClient{
		serverClientKey:    serverClientKey,
		domain:          domain,
		maxFragmentSize: maxFragmentSize,
	}

	// Initialize with cryptographically random packet ID (u64)
	var randomBytes [8]byte
	rand.Read(randomBytes[:])
	client.nextPacketID = binary.BigEndian.Uint64(randomBytes[:])

	return client, nil
}

// getNextPacketID returns the next packet ID and increments counter (wraps at 2^64-1)
func (c *MumbojumboClient) getNextPacketID() uint64 {
	packetID := c.nextPacketID
	c.nextPacketID = (c.nextPacketID + 1) & 0xFFFFFFFFFFFFFFFF
	return packetID
}

// parseKeyHex parses a key in mj_cli_<hex> format (internal use)
func parseKeyHex(keyStr string) ([32]byte, error) {
	var key [32]byte

	if !strings.HasPrefix(keyStr, "mj_cli_") {
		return key, errors.New("key must start with \"mj_cli_\"")
	}

	hexKey := keyStr[7:]
	if len(hexKey) != 64 {
		return key, fmt.Errorf("invalid hex key length: expected 64, got %d", len(hexKey))
	}

	decoded, err := hex.DecodeString(hexKey)
	if err != nil {
		return key, fmt.Errorf("invalid hex characters in key: %w", err)
	}

	copy(key[:], decoded)
	return key, nil
}

// Base32Encode encodes data using base32 (lowercase, no padding)
func Base32Encode(data []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var bits, value uint
	var output strings.Builder

	for _, b := range data {
		value = (value << 8) | uint(b)
		bits += 8

		for bits >= 5 {
			output.WriteByte(alphabet[(value>>(bits-5))&31])
			bits -= 5
		}
	}

	if bits > 0 {
		output.WriteByte(alphabet[(value<<(5-bits))&31])
	}

	return strings.ToLower(output.String())
}

// SplitToLabels splits a string into DNS labels of max length
func SplitToLabels(data string, maxLen int) []string {
	if len(data) == 0 {
		return []string{}
	}

	var labels []string
	for i := 0; i < len(data); i += maxLen {
		end := i + maxLen
		if end > len(data) {
			end = len(data)
		}
		labels = append(labels, data[i:end])
	}
	return labels
}

// CreateFragment builds a fragment with 18-byte header
func CreateFragment(packetID uint64, fragIndex, fragCount uint32, fragData []byte) ([]byte, error) {
	if fragIndex >= fragCount {
		return nil, fmt.Errorf("invalid frag_index %d for frag_count %d", fragIndex, fragCount)
	}

	if len(fragData) > MaxFragDataLen {
		return nil, fmt.Errorf("fragment data too large: %d > %d", len(fragData), MaxFragDataLen)
	}

	header := make([]byte, HeaderSize)
	binary.BigEndian.PutUint64(header[0:8], packetID)
	binary.BigEndian.PutUint32(header[8:12], fragIndex)
	binary.BigEndian.PutUint32(header[12:16], fragCount)
	binary.BigEndian.PutUint16(header[16:18], uint16(len(fragData)))

	return append(header, fragData...), nil
}

// EncryptSealedBox encrypts plaintext using libsodium-compatible SealedBox
// Format: ephemeral_pubkey(32) || box(plaintext) with nonce derived from BLAKE2b
// This matches libsodium's crypto_box_seal implementation
func EncryptSealedBox(plaintext []byte, recipientPubkey *[32]byte) ([]byte, error) {
	// Generate ephemeral keypair
	ephemeralPub, ephemeralPriv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Derive nonce from BLAKE2b(ephemeral_pubkey || recipient_pubkey)
	// This is what libsodium's crypto_box_seal does
	nonce, err := deriveNonce(ephemeralPub, recipientPubkey)
	if err != nil {
		return nil, err
	}

	// Encrypt using box.Seal with derived nonce
	encrypted := box.Seal(nil, plaintext, nonce, recipientPubkey, ephemeralPriv)

	// Prepend ephemeral public key (libsodium SealedBox format)
	result := make([]byte, 0, 32+len(encrypted))
	result = append(result, ephemeralPub[:]...)
	result = append(result, encrypted...)

	return result, nil
}

// deriveNonce derives a nonce from two public keys using BLAKE2b-192
// This matches libsodium's crypto_box_seal nonce derivation
func deriveNonce(ephemeralPub, recipientPub *[32]byte) (*[24]byte, error) {
	// Concatenate ephemeral_pubkey || recipient_pubkey
	combined := make([]byte, 64)
	copy(combined[0:32], ephemeralPub[:])
	copy(combined[32:64], recipientPub[:])

	// Hash with BLAKE2b-192 (24 bytes = 192 bits)
	hash, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	hash.Write(combined)
	digest := hash.Sum(nil)

	// Convert to [24]byte array
	var nonce [24]byte
	copy(nonce[:], digest)
	return &nonce, nil
}

// CreateDNSQuery creates a DNS query name from encrypted data
func CreateDNSQuery(encrypted []byte, domain string) string {
	b32 := Base32Encode(encrypted)
	labels := SplitToLabels(b32, DNSLabelMaxLen)
	return strings.Join(labels, ".") + domain
}

// SendDNSQuery sends a DNS query using dig command
func SendDNSQuery(dnsName string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dig", "+short", dnsName)
	err := cmd.Run()
	return err == nil
}

// FragmentData splits data into fragments
func FragmentData(data []byte, maxFragmentSize int) [][]byte {
	if len(data) == 0 {
		return [][]byte{{}}
	}

	var fragments [][]byte
	for i := 0; i < len(data); i += maxFragmentSize {
		end := i + maxFragmentSize
		if end > len(data) {
			end = len(data)
		}
		fragments = append(fragments, data[i:end])
	}
	return fragments
}

// QueryResult represents the result of sending a DNS query
type QueryResult struct {
	Query   string
	Success bool
}

// generateDNSQueries generates DNS queries from data without sending them
func (c *MumbojumboClient) generateDNSQueries(data []byte) ([]string, error) {
	packetID := c.getNextPacketID()

	fragments := FragmentData(data, c.maxFragmentSize)
	fragCount := uint32(len(fragments))

	var queries []string

	for fragIndex, fragData := range fragments {
		// Create fragment with header
		plaintext, err := CreateFragment(packetID, uint32(fragIndex), fragCount, fragData)
		if err != nil {
			return nil, fmt.Errorf("failed to create fragment %d: %w", fragIndex, err)
		}

		// Encrypt with SealedBox
		encrypted, err := EncryptSealedBox(plaintext, &c.serverClientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt fragment %d: %w", fragIndex, err)
		}

		// Create DNS query name
		dnsName := CreateDNSQuery(encrypted, c.domain)
		queries = append(queries, dnsName)
	}

	return queries, nil
}

// SendData sends data via DNS queries
func (c *MumbojumboClient) SendData(data []byte) ([]QueryResult, error) {
	queries, err := c.generateDNSQueries(data)
	if err != nil {
		return nil, err
	}

	var results []QueryResult
	for _, dnsName := range queries {
		success := SendDNSQuery(dnsName)
		results = append(results, QueryResult{
			Query:   dnsName,
			Success: success,
		})
	}

	return results, nil
}

// GenerateQueries generates DNS queries without sending them
func (c *MumbojumboClient) GenerateQueries(data []byte) ([]string, error) {
	return c.generateDNSQueries(data)
}

// CLI implementation

func main() {
	var (
		key     string
		domain  string
		file    string
		verbose bool
	)

	flag.StringVar(&key, "k", "", "Server public key (mj_cli_... format)")
	flag.StringVar(&key, "key", "", "Server public key (mj_cli_... format)")
	flag.StringVar(&domain, "d", "", "DNS domain suffix (e.g., .asd.qwe)")
	flag.StringVar(&domain, "domain", "", "DNS domain suffix (e.g., .asd.qwe)")
	flag.StringVar(&file, "f", "-", "Input file path (use \"-\" for stdin)")
	flag.StringVar(&file, "file", "-", "Input file path (use \"-\" for stdin)")
	flag.BoolVar(&verbose, "v", false, "Enable verbose output to stderr")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output to stderr")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
Mumbojumbo DNS Client - Go Implementation

Usage: mumbojumbo-client -k <key> -d <domain> [options]

Required arguments:
  -k, --key <public_key>     Server public key (mj_cli_... format)
  -d, --domain <domain>      DNS domain suffix (e.g., .asd.qwe)

Optional arguments:
  -f, --file <path>          Input file path (use "-" for stdin, default: stdin)
  -v, --verbose              Enable verbose output to stderr

Examples:
  echo "Hello" | mumbojumbo-client -k mj_cli_abc123... -d .asd.qwe
  mumbojumbo-client -k mj_cli_abc123... -d .asd.qwe -f message.txt
  mumbojumbo-client -k mj_cli_abc123... -d .asd.qwe -v
`)
	}

	flag.Parse()

	if key == "" || domain == "" {
		fmt.Fprintln(os.Stderr, "Error: -k/--key and -d/--domain are required")
		fmt.Fprintln(os.Stderr, "Use --help for usage information")
		os.Exit(1)
	}

	// Validate domain
	if !strings.HasPrefix(domain, ".") {
		fmt.Fprintf(os.Stderr, "Warning: domain should start with '.', got '%s'\n", domain)
		fmt.Fprintln(os.Stderr, "         Prepending '.' automatically")
		domain = "." + domain
	}

	// Read input data
	var data []byte
	var err error
	if file == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(file)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Read %d bytes of input\n", len(data))
	}

	// Create client - key parsing happens transparently in constructor
	client, err := NewMumbojumboClient(key, domain, MaxFragDataLen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing client: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fragments := FragmentData(data, MaxFragDataLen)
		fmt.Fprintf(os.Stderr, "Split into %d fragment(s)\n", len(fragments))
		fmt.Fprintln(os.Stderr, "")
	}

	// Send data
	results, err := client.SendData(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending data: %v\n", err)
		os.Exit(1)
	}

	// Process results
	successCount := 0
	for fragIndex, result := range results {
		// Output query for inspection
		fmt.Println(result.Query)

		if result.Success {
			successCount++
		}

		if verbose {
			fragCount := len(results)
			fmt.Fprintf(os.Stderr, "Fragment %d/%d:\n", fragIndex+1, fragCount)

			// Calculate sizes for display
			fragDataLen := MaxFragDataLen
			if fragIndex == len(results)-1 && len(data)%MaxFragDataLen != 0 {
				fragDataLen = len(data) % MaxFragDataLen
			}
			plaintextLen := HeaderSize + fragDataLen
			encryptedLen := plaintextLen + SealedBoxOH

			fmt.Fprintf(os.Stderr, "  Data length: %d bytes\n", fragDataLen)
			fmt.Fprintf(os.Stderr, "  Plaintext length: %d bytes\n", plaintextLen)
			fmt.Fprintf(os.Stderr, "  Encrypted length: %d bytes\n", encryptedLen)
			fmt.Fprintf(os.Stderr, "  DNS name length: %d chars\n", len(result.Query))
			fmt.Fprintln(os.Stderr, "  Sending query...")

			if result.Success {
				fmt.Fprintln(os.Stderr, "  ✓ Sent successfully")
			} else {
				fmt.Fprintln(os.Stderr, "  ✗ Send failed (DNS query timed out or failed)")
			}

			fmt.Fprintln(os.Stderr, "")
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Sent %d/%d fragment(s) successfully\n", successCount, len(results))
	}

	if successCount != len(results) {
		os.Exit(1)
	}
}
