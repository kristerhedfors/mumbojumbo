package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/nacl/box"
)

// Test fixtures
var (
	testServerPub, testServerPriv, _ = box.GenerateKey(rand.Reader)
)

// Helper: Decrypt SealedBox
func decryptSealedBox(ciphertext []byte, recipientPub, recipientPriv *[32]byte) ([]byte, error) {
	if len(ciphertext) < 48 {
		return nil, errors.New("ciphertext too short")
	}

	// Extract ephemeral public key
	var ephemeralPub [32]byte
	copy(ephemeralPub[:], ciphertext[:32])

	// Derive nonce from BLAKE2b(ephemeral_pubkey || recipient_pubkey)
	nonce, err := deriveNonce(&ephemeralPub, recipientPub)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext, ok := box.Open(nil, ciphertext[32:], nonce, &ephemeralPub, recipientPriv)
	if !ok {
		return nil, errors.New("decryption failed")
	}

	return plaintext, nil
}

// Helper: Base32 decode
func base32Decode(encoded string) ([]byte, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	var bits, value uint
	var output []byte

	for _, char := range strings.ToUpper(encoded) {
		index := strings.IndexRune(alphabet, char)
		if index == -1 {
			continue
		}

		value = (value << 5) | uint(index)
		bits += 5

		if bits >= 8 {
			output = append(output, byte((value>>(bits-8))&0xFF))
			bits -= 8
		}
	}

	return output, nil
}

// ============================================================================
// Test: Key Parsing
// ============================================================================

func TestParseValidHexKey(t *testing.T) {
	validKey := "mj_pub_" + strings.Repeat("a", 64)
	result, err := ParseKeyHex(validKey)

	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}

	if result[0] != 0xaa {
		t.Errorf("Expected first byte 0xaa, got: 0x%x", result[0])
	}
}

func TestRejectKeyWithoutPrefix(t *testing.T) {
	_, err := ParseKeyHex(strings.Repeat("a", 64))

	if err == nil {
		t.Fatal("Expected error for missing prefix")
	}

	if !strings.Contains(err.Error(), "must start with") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestRejectKeyWithWrongLength(t *testing.T) {
	_, err := ParseKeyHex("mj_pub_" + strings.Repeat("a", 32))

	if err == nil {
		t.Fatal("Expected error for wrong length")
	}

	if !strings.Contains(err.Error(), "invalid hex key length") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestRejectKeyWithInvalidHex(t *testing.T) {
	_, err := ParseKeyHex("mj_pub_" + strings.Repeat("z", 64))

	if err == nil {
		t.Fatal("Expected error for invalid hex")
	}

	if !strings.Contains(err.Error(), "invalid hex") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// ============================================================================
// Test: Base32 Encoding
// ============================================================================

func TestBase32EncodeBasic(t *testing.T) {
	data := []byte("hello")
	encoded := Base32Encode(data)

	if encoded != "nbswy3dp" {
		t.Errorf("Expected 'nbswy3dp', got: %s", encoded)
	}
}

func TestBase32EncodeEmpty(t *testing.T) {
	encoded := Base32Encode([]byte{})

	if encoded != "" {
		t.Errorf("Expected empty string, got: %s", encoded)
	}
}

func TestBase32EncodeLowercase(t *testing.T) {
	data := []byte("TEST")
	encoded := Base32Encode(data)

	if encoded != strings.ToLower(encoded) {
		t.Errorf("Expected lowercase output, got: %s", encoded)
	}
}

func TestBase32EncodeNoPadding(t *testing.T) {
	data := []byte("hello world")
	encoded := Base32Encode(data)

	if strings.Contains(encoded, "=") {
		t.Errorf("Unexpected padding in output: %s", encoded)
	}
}

func TestBase32EncodeDecodeRoundTrip(t *testing.T) {
	original := []byte("Round trip test data!")
	encoded := Base32Encode(original)
	decoded, err := base32Decode(encoded)

	if err != nil {
		t.Fatalf("Decode error: %v", err)
	}

	if !bytes.Equal(decoded, original) {
		t.Errorf("Round-trip failed: %v != %v", decoded, original)
	}
}

// ============================================================================
// Test: DNS Label Splitting
// ============================================================================

func TestSplitToLabelsShort(t *testing.T) {
	labels := SplitToLabels("abc", DNSLabelMaxLen)

	if len(labels) != 1 || labels[0] != "abc" {
		t.Errorf("Expected ['abc'], got: %v", labels)
	}
}

func TestSplitToLabelsExact63(t *testing.T) {
	data := strings.Repeat("a", 63)
	labels := SplitToLabels(data, DNSLabelMaxLen)

	if len(labels) != 1 || labels[0] != data {
		t.Errorf("Expected single 63-char label, got: %v", labels)
	}
}

func TestSplitToLabelsLong(t *testing.T) {
	data := strings.Repeat("a", 100)
	labels := SplitToLabels(data, DNSLabelMaxLen)

	if len(labels) != 2 {
		t.Errorf("Expected 2 labels, got: %d", len(labels))
	}

	if len(labels[0]) != 63 || len(labels[1]) != 37 {
		t.Errorf("Unexpected label lengths: %d, %d", len(labels[0]), len(labels[1]))
	}
}

func TestSplitToLabelsEmpty(t *testing.T) {
	labels := SplitToLabels("", DNSLabelMaxLen)

	if len(labels) != 0 {
		t.Errorf("Expected empty slice, got: %v", labels)
	}
}

func TestSplitToLabelsCustomLen(t *testing.T) {
	labels := SplitToLabels("abcdefgh", 3)

	expected := []string{"abc", "def", "gh"}
	if len(labels) != len(expected) {
		t.Fatalf("Expected %d labels, got: %d", len(expected), len(labels))
	}

	for i, label := range labels {
		if label != expected[i] {
			t.Errorf("Label %d: expected '%s', got '%s'", i, expected[i], label)
		}
	}
}

// ============================================================================
// Test: Fragment Creation
// ============================================================================

func TestCreateBasicFragment(t *testing.T) {
	fragData := []byte("test")
	frag, err := CreateFragment(100, 0, 1, fragData)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(frag) != HeaderSize+4 {
		t.Errorf("Expected length %d, got: %d", HeaderSize+4, len(frag))
	}

	// Parse header
	packetID := binary.BigEndian.Uint16(frag[0:2])
	fragIndex := binary.BigEndian.Uint32(frag[2:6])
	fragCount := binary.BigEndian.Uint32(frag[6:10])
	dataLen := binary.BigEndian.Uint16(frag[10:12])

	if packetID != 100 {
		t.Errorf("Expected packet_id 100, got: %d", packetID)
	}

	if fragIndex != 0 {
		t.Errorf("Expected frag_index 0, got: %d", fragIndex)
	}

	if fragCount != 1 {
		t.Errorf("Expected frag_count 1, got: %d", fragCount)
	}

	if dataLen != 4 {
		t.Errorf("Expected data_len 4, got: %d", dataLen)
	}

	if !bytes.Equal(frag[HeaderSize:], fragData) {
		t.Errorf("Fragment data mismatch")
	}
}

func TestCreateMultiFragmentPacket(t *testing.T) {
	fragData := []byte("part1")
	frag, err := CreateFragment(200, 2, 5, fragData)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	fragIndex := binary.BigEndian.Uint32(frag[2:6])
	fragCount := binary.BigEndian.Uint32(frag[6:10])

	if fragIndex != 2 {
		t.Errorf("Expected frag_index 2, got: %d", fragIndex)
	}

	if fragCount != 5 {
		t.Errorf("Expected frag_count 5, got: %d", fragCount)
	}
}

func TestCreateEmptyFragment(t *testing.T) {
	frag, err := CreateFragment(1, 0, 1, []byte{})

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(frag) != HeaderSize {
		t.Errorf("Expected length %d, got: %d", HeaderSize, len(frag))
	}

	dataLen := binary.BigEndian.Uint16(frag[10:12])
	if dataLen != 0 {
		t.Errorf("Expected data_len 0, got: %d", dataLen)
	}
}

func TestRejectOversizedFragment(t *testing.T) {
	oversized := make([]byte, MaxFragDataLen+1)
	_, err := CreateFragment(1, 0, 1, oversized)

	if err == nil {
		t.Fatal("Expected error for oversized fragment")
	}

	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestRejectInvalidFragIndex(t *testing.T) {
	_, err := CreateFragment(1, 5, 5, []byte("test"))

	if err == nil {
		t.Fatal("Expected error for invalid frag_index")
	}

	if !strings.Contains(err.Error(), "invalid frag_index") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestSupportU32FragCount(t *testing.T) {
	largeCount := uint32(0xFFFFFFFF)
	frag, err := CreateFragment(1, 0, largeCount, []byte("test"))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	fragCount := binary.BigEndian.Uint32(frag[6:10])
	if fragCount != largeCount {
		t.Errorf("Expected frag_count %d, got: %d", largeCount, fragCount)
	}
}

func TestSupportU32FragIndex(t *testing.T) {
	largeIndex := uint32(1000000)
	frag, err := CreateFragment(1, largeIndex, largeIndex+1, []byte("test"))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	fragIndex := binary.BigEndian.Uint32(frag[2:6])
	if fragIndex != largeIndex {
		t.Errorf("Expected frag_index %d, got: %d", largeIndex, fragIndex)
	}
}

// ============================================================================
// Test: Data Fragmentation
// ============================================================================

func TestFragmentSmallData(t *testing.T) {
	data := []byte("small")
	fragments := FragmentData(data, MaxFragDataLen)

	if len(fragments) != 1 {
		t.Errorf("Expected 1 fragment, got: %d", len(fragments))
	}

	if !bytes.Equal(fragments[0], data) {
		t.Errorf("Fragment data mismatch")
	}
}

func TestFragmentExactMaxSize(t *testing.T) {
	data := make([]byte, MaxFragDataLen)
	fragments := FragmentData(data, MaxFragDataLen)

	if len(fragments) != 1 {
		t.Errorf("Expected 1 fragment, got: %d", len(fragments))
	}

	if len(fragments[0]) != MaxFragDataLen {
		t.Errorf("Expected length %d, got: %d", MaxFragDataLen, len(fragments[0]))
	}
}

func TestFragmentOverflow(t *testing.T) {
	data := make([]byte, MaxFragDataLen+10)
	fragments := FragmentData(data, MaxFragDataLen)

	if len(fragments) != 2 {
		t.Errorf("Expected 2 fragments, got: %d", len(fragments))
	}

	if len(fragments[0]) != MaxFragDataLen {
		t.Errorf("Expected first fragment length %d, got: %d", MaxFragDataLen, len(fragments[0]))
	}

	if len(fragments[1]) != 10 {
		t.Errorf("Expected second fragment length 10, got: %d", len(fragments[1]))
	}
}

func TestFragmentEmptyData(t *testing.T) {
	fragments := FragmentData([]byte{}, MaxFragDataLen)

	if len(fragments) != 1 {
		t.Errorf("Expected 1 fragment, got: %d", len(fragments))
	}

	if len(fragments[0]) != 0 {
		t.Errorf("Expected empty fragment, got length: %d", len(fragments[0]))
	}
}

func TestFragmentLargeData(t *testing.T) {
	data := make([]byte, 250)
	fragments := FragmentData(data, MaxFragDataLen)

	expectedCount := (250 + MaxFragDataLen - 1) / MaxFragDataLen
	if len(fragments) != expectedCount {
		t.Errorf("Expected %d fragments, got: %d", expectedCount, len(fragments))
	}
}

// ============================================================================
// Test: Encryption
// ============================================================================

func TestEncryptFragment(t *testing.T) {
	plaintext := []byte("secret data")
	encrypted, err := EncryptSealedBox(plaintext, testServerPub)

	if err != nil {
		t.Fatalf("Encryption error: %v", err)
	}

	if len(encrypted) != len(plaintext)+SealedBoxOH {
		t.Errorf("Expected length %d, got: %d", len(plaintext)+SealedBoxOH, len(encrypted))
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	plaintext := []byte("test message")

	encrypted, err := EncryptSealedBox(plaintext, testServerPub)
	if err != nil {
		t.Fatalf("Encryption error: %v", err)
	}

	decrypted, err := decryptSealedBox(encrypted, testServerPub, testServerPriv)
	if err != nil {
		t.Fatalf("Decryption error: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Round-trip failed: %v != %v", decrypted, plaintext)
	}
}

func TestEncryptEmptyData(t *testing.T) {
	encrypted, err := EncryptSealedBox([]byte{}, testServerPub)

	if err != nil {
		t.Fatalf("Encryption error: %v", err)
	}

	if len(encrypted) != SealedBoxOH {
		t.Errorf("Expected length %d, got: %d", SealedBoxOH, len(encrypted))
	}
}

func TestEncryptionProducesDifferentOutputs(t *testing.T) {
	plaintext := []byte("same data")

	enc1, _ := EncryptSealedBox(plaintext, testServerPub)
	enc2, _ := EncryptSealedBox(plaintext, testServerPub)

	if bytes.Equal(enc1, enc2) {
		t.Error("Encryption should produce different outputs due to ephemeral keys")
	}
}

// ============================================================================
// Test: DNS Query Creation
// ============================================================================

func TestCreateBasicDNSQuery(t *testing.T) {
	encrypted := []byte(strings.Repeat("a", 10))
	query := CreateDNSQuery(encrypted, ".asd.qwe")

	if !strings.HasSuffix(query, ".asd.qwe") {
		t.Errorf("Expected query to end with '.asd.qwe', got: %s", query)
	}
}

func TestCreateQuerySplitsLongBase32(t *testing.T) {
	encrypted := make([]byte, 100)
	query := CreateDNSQuery(encrypted, ".asd.qwe")

	labels := strings.Split(strings.TrimSuffix(query, ".asd.qwe"), ".")
	for _, label := range labels {
		if len(label) > DNSLabelMaxLen {
			t.Errorf("Label exceeds max length: %d > %d", len(label), DNSLabelMaxLen)
		}
	}
}

func TestCreateQueryFromEmptyData(t *testing.T) {
	query := CreateDNSQuery([]byte{}, ".asd.qwe")

	if query != ".asd.qwe" {
		t.Errorf("Expected '.asd.qwe', got: %s", query)
	}
}

// ============================================================================
// Test: MumbojumboClient Class
// ============================================================================

func TestInitializeClient(t *testing.T) {
	client := NewMumbojumboClient(*testServerPub, ".asd.qwe", MaxFragDataLen)

	if client.domain != ".asd.qwe" {
		t.Errorf("Expected domain '.asd.qwe', got: %s", client.domain)
	}

	if client.maxFragmentSize != MaxFragDataLen {
		t.Errorf("Expected maxFragmentSize %d, got: %d", MaxFragDataLen, client.maxFragmentSize)
	}
}

func TestAutoPrependDotToDomain(t *testing.T) {
	client := NewMumbojumboClient(*testServerPub, "asd.qwe", MaxFragDataLen)

	if client.domain != ".asd.qwe" {
		t.Errorf("Expected '.asd.qwe', got: %s", client.domain)
	}
}

func TestGenerateQueriesWithoutSending(t *testing.T) {
	client := NewMumbojumboClient(*testServerPub, ".asd.qwe", MaxFragDataLen)
	queries, err := client.GenerateQueries([]byte("test"))

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(queries) != 1 {
		t.Errorf("Expected 1 query, got: %d", len(queries))
	}

	if !strings.HasSuffix(queries[0], ".asd.qwe") {
		t.Errorf("Query doesn't end with domain: %s", queries[0])
	}
}

func TestSendDataDryRun(t *testing.T) {
	client := NewMumbojumboClient(*testServerPub, ".asd.qwe", MaxFragDataLen)
	results, err := client.SendData([]byte("test"), false)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(results) != 1 {
		t.Errorf("Expected 1 result, got: %d", len(results))
	}

	if !strings.HasSuffix(results[0].Query, ".asd.qwe") {
		t.Errorf("Query doesn't end with domain: %s", results[0].Query)
	}

	if !results[0].Success {
		t.Error("Expected success=true for dry run")
	}
}

func TestPacketIDIncrements(t *testing.T) {
	client := NewMumbojumboClient(*testServerPub, ".asd.qwe", MaxFragDataLen)

	queries1, _ := client.GenerateQueries([]byte("msg1"))
	queries2, _ := client.GenerateQueries([]byte("msg2"))

	if queries1[0] == queries2[0] {
		t.Error("Expected different queries for different messages")
	}
}

func TestPacketIDWrapsAt0xFFFF(t *testing.T) {
	client := NewMumbojumboClient(*testServerPub, ".asd.qwe", MaxFragDataLen)
	client.nextPacketID = 0xFFFF

	id1 := client.getNextPacketID()
	id2 := client.getNextPacketID()

	if id1 != 0xFFFF {
		t.Errorf("Expected id1=0xFFFF, got: %d", id1)
	}

	if id2 != 0 {
		t.Errorf("Expected id2=0 (wrapped), got: %d", id2)
	}
}

func TestMultiFragmentMessage(t *testing.T) {
	client := NewMumbojumboClient(*testServerPub, ".asd.qwe", MaxFragDataLen)
	largeData := make([]byte, MaxFragDataLen*3)

	queries, err := client.GenerateQueries(largeData)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(queries) != 3 {
		t.Errorf("Expected 3 queries, got: %d", len(queries))
	}
}

// ============================================================================
// Test: End-to-End Flow
// ============================================================================

func TestEncryptDecryptSingleFragment(t *testing.T) {
	client := NewMumbojumboClient(*testServerPub, ".asd.qwe", MaxFragDataLen)
	message := []byte("Hello World")

	queries, err := client.GenerateQueries(message)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(queries) != 1 {
		t.Fatalf("Expected 1 query, got: %d", len(queries))
	}

	query := queries[0]
	base32Part := strings.TrimSuffix(query, ".asd.qwe")
	base32Part = strings.ReplaceAll(base32Part, ".", "")

	encrypted, err := base32Decode(base32Part)
	if err != nil {
		t.Fatalf("Base32 decode error: %v", err)
	}

	decrypted, err := decryptSealedBox(encrypted, testServerPub, testServerPriv)
	if err != nil {
		t.Fatalf("Decryption error: %v", err)
	}

	header := decrypted[:HeaderSize]
	data := decrypted[HeaderSize:]

	dataLen := binary.BigEndian.Uint16(header[10:12])
	if dataLen != uint16(len(message)) {
		t.Errorf("Expected data_len %d, got: %d", len(message), dataLen)
	}

	if !bytes.Equal(data, message) {
		t.Errorf("Data mismatch: %v != %v", data, message)
	}
}

func TestEncryptDecryptMultiFragment(t *testing.T) {
	client := NewMumbojumboClient(*testServerPub, ".asd.qwe", MaxFragDataLen)
	message := bytes.Repeat([]byte{0x42}, MaxFragDataLen*2+10)

	queries, err := client.GenerateQueries(message)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if len(queries) != 3 {
		t.Fatalf("Expected 3 queries, got: %d", len(queries))
	}

	var fragments [][]byte

	for _, query := range queries {
		base32Part := strings.TrimSuffix(query, ".asd.qwe")
		base32Part = strings.ReplaceAll(base32Part, ".", "")

		encrypted, err := base32Decode(base32Part)
		if err != nil {
			t.Fatalf("Base32 decode error: %v", err)
		}

		decrypted, err := decryptSealedBox(encrypted, testServerPub, testServerPriv)
		if err != nil {
			t.Fatalf("Decryption error: %v", err)
		}

		header := decrypted[:HeaderSize]
		data := decrypted[HeaderSize:]

		fragIndex := binary.BigEndian.Uint32(header[2:6])
		fragCount := binary.BigEndian.Uint32(header[6:10])
		dataLen := binary.BigEndian.Uint16(header[10:12])

		if fragCount != 3 {
			t.Errorf("Expected frag_count=3, got: %d", fragCount)
		}

		fragments = append(fragments, data[:dataLen])

		_ = fragIndex // Verify ordering in production code
	}

	reassembled := bytes.Join(fragments, nil)
	if !bytes.Equal(reassembled, message) {
		t.Errorf("Reassembled data mismatch")
	}
}
