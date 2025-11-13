# Fragment Size Calculation Migration Guide

## Overview

All client implementations have been updated to **automatically calculate** the maximum fragment data size from the domain name. The `max_fragment_size` parameter has been removed from all client APIs.

## The Simple Formula

**Use this one-liner in all remaining client implementations:**

```
max_fragment_data_bytes = 83 - len(domain) / 3
```

**That's it!** This simple linear formula is:
- ✅ Within 0-2 bytes of optimal for typical domains (3-12 chars)
- ✅ Safe (slightly conservative, never exceeds DNS limits)
- ✅ One arithmetic operation (fast, simple, fool-proof)

## What Changed

### Before (Old API)
```python
# Python - manual parameter
client = MumbojumboClient(server_key, domain, max_fragment_size=80)
```

### After (New API - Automatic Calculation)
```python
# Python - auto-calculates from domain using: 83 - len(domain) / 3
client = MumbojumboClient(server_key, domain)
# For ".asd.qwe" (8 chars): 83 - 8/3 = 83 - 2 = 81 bytes
```

## Implementation Status

- ✅ **Server (mumbojumbo.py)**: Complete
- ✅ **Python Client**: Complete
- ✅ **C Client**: Complete
- ⚠️ **Rust Client**: Needs update
- ⚠️ **Go Client**: Needs update
- ⚠️ **Node.js Client**: Needs update
- ⚠️ **HTML Client**: Needs update

---

## Rust Client Update Guide

### Files to Modify
- `clients/rust/src/main.rs`

### Changes Required

#### 1. Add Calculation Function

Add after the constants near line 12:

```rust
fn calculate_safe_max_fragment_data_len(domain: &str) -> usize {
    // Simple linear formula: 83 - len(domain) / 3
    // Accurate within 0-2 bytes for typical domains (3-12 chars)
    let domain_len = domain.len();

    if domain_len > 143 {
        panic!("Domain too long: {} ({} bytes). Maximum domain length is ~143 characters.",
               domain, domain_len);
    }

    83 - domain_len / 3
}
```

#### 2. Update MumbojumboClient Struct (line ~54)

**Remove** `max_fragment_size` from `new()` parameters:

```rust
// Before
impl MumbojumboClient {
    pub fn new(server_client_key: PublicKey, domain: String, max_fragment_size: usize) -> Self {
        ...
    }
}

// After
impl MumbojumboClient {
    pub fn new(server_client_key: PublicKey, domain: String) -> Self {
        let domain = if domain.starts_with('.') {
            domain
        } else {
            format!(".{}", domain)
        };

        // Calculate max_fragment_size from domain
        let max_fragment_size = calculate_safe_max_fragment_data_len(&domain);

        let mut rng = rand::thread_rng();
        Self {
            server_client_key,
            domain,
            max_fragment_size,
            next_packet_id: rng.gen::<u64>(),
        }
    }
}
```

#### 3. Update main() Function

Remove `max_fragment_size` argument:

```rust
// Before (line ~200)
let client = MumbojumboClient::new(server_public_key, domain, MAX_FRAG_DATA_LEN);

// After
let client = MumbojumboClient::new(server_public_key, domain);
```

---

## Go Client Update Guide

### Files to Modify
- `clients/go/mumbojumbo-client.go`

### Changes Required

#### 1. Add Calculation Function

Add after constants near line 22:

```go
// calculateSafeMaxFragmentDataLen calculates the maximum safe fragment data size
// Simple linear formula: 83 - len(domain) / 3
// Accurate within 0-2 bytes for typical domains (3-12 chars)
func calculateSafeMaxFragmentDataLen(domain string) int {
	domainLen := len(domain)

	if domainLen > 143 {
		panic(fmt.Sprintf("Domain too long: %s (%d bytes). Maximum domain length is ~143 characters.",
			domain, domainLen))
	}

	return 83 - domainLen/3
}
```

#### 2. Update NewMumbojumboClient Function (line ~40)

**Remove** `maxFragmentSize` parameter:

```go
// Before
func NewMumbojumboClient(serverClientKey [32]byte, domain string, maxFragmentSize int) *MumbojumboClient {
	...
}

// After
func NewMumbojumboClient(serverClientKey [32]byte, domain string) *MumbojumboClient {
	// Ensure domain starts with dot
	if !strings.HasPrefix(domain, ".") {
		domain = "." + domain
	}

	// Calculate max fragment size from domain
	maxFragmentSize := calculateSafeMaxFragmentDataLen(domain)

	return &MumbojumboClient{
		serverClientKey:  serverClientKey,
		domain:          domain,
		maxFragmentSize: maxFragmentSize,
		nextPacketID:    rand.Uint64(),
	}
}
```

#### 3. Update main() Function

Remove `maxFragmentSize` argument from client creation:

```go
// Before (line ~350)
client := NewMumbojumboClient(serverPublicKey, *domain, MaxFragDataLen)

// After
client := NewMumbojumboClient(serverPublicKey, *domain)
```

---

## Node.js Client Update Guide

### Files to Modify
- `clients/nodejs/mumbojumbo-client.js`

### Changes Required

#### 1. Add Calculation Function

Add after constants near line 14:

```javascript
/**
 * Calculate safe maximum fragment data length based on domain.
 * Simple linear formula: 83 - len(domain) / 3
 * Accurate within 0-2 bytes for typical domains (3-12 chars)
 * @param {string} domain - Domain suffix (e.g., ".asd.qwe")
 * @returns {number} Maximum safe fragment data bytes
 */
function calculateSafeMaxFragmentDataLen(domain) {
    const domainLen = domain.length;

    if (domainLen > 143) {
        throw new Error(
            `Domain too long: ${domain} (${domainLen} bytes). ` +
            `Maximum domain length is ~143 characters.`
        );
    }

    return 83 - Math.floor(domainLen / 3);
}
```

#### 2. Update MumbojumboClient Constructor (line ~154)

**Remove** `maxFragmentSize` parameter:

```javascript
// Before
class MumbojumboClient {
    constructor(serverPublicKey, domain, maxFragmentSize = MAX_FRAG_DATA_LEN) {
        ...
    }
}

// After
class MumbojumboClient {
    constructor(serverPublicKey, domain) {
        // Parse key if string
        if (typeof serverPublicKey === 'string') {
            serverPublicKey = parseKeyHex(serverPublicKey);
        }

        // Ensure domain starts with dot
        if (!domain.startsWith('.')) {
            domain = '.' + domain;
        }

        this.serverPublicKey = serverPublicKey;
        this.domain = domain;

        // Calculate max fragment size from domain automatically
        this.maxFragmentSize = calculateSafeMaxFragmentDataLen(domain);

        // Initialize with random packet ID
        this.nextPacketId = BigInt(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));
    }
}
```

#### 3. Update main() / CLI Code

Remove `maxFragmentSize` from client instantiation (search for `new MumbojumboClient`).

---

## HTML Client Update Guide

### Files to Modify
- `clients/html/client.html`

### Changes Required

#### 1. Add Calculation Function

Add in `<script>` section after constants (around line 226):

```javascript
/**
 * Calculate safe maximum fragment data length based on domain.
 * Simple linear formula: 83 - len(domain) / 3
 * Accurate within 0-2 bytes for typical domains (3-12 chars)
 * @param {string} domain - Domain suffix (e.g., ".asd.qwe")
 * @returns {number} Maximum safe fragment data bytes
 */
function calculateSafeMaxFragmentDataLen(domain) {
    const domainLen = domain.length;

    if (domainLen > 143) {
        throw new Error(
            `Domain too long: ${domain} (${domainLen} bytes). ` +
            `Maximum domain length is ~143 characters.`
        );
    }

    return 83 - Math.floor(domainLen / 3);
}
```

#### 2. Update generateDnsQueries Function

Calculate `MAX_FRAG_DATA_LEN` from domain:

```javascript
// Before
function generateDnsQueries(message, mumbojumboPubKey, domain) {
    const maxFragDataLen = MAX_FRAG_DATA_LEN;
    ...
}

// After
function generateDnsQueries(message, mumbojumboPubKey, domain) {
    // Calculate max fragment size from domain
    const maxFragDataLen = calculateSafeMaxFragmentDataLen(domain);
    ...
}
```

---

## Testing After Migration

### Server Test
```bash
./venv/bin/pytest tests/test_packet_engine.py -v
```

### Python Client Test
```bash
./venv/bin/pytest tests/test_client_python.py -v
```

### C Client Test
```bash
cd clients/c && make clean && make && make test
```

### Rust Client Test
```bash
cd clients/rust && cargo test
```

### Go Client Test
```bash
cd clients/go && go test
```

### Node.js Client Test
```bash
cd clients/nodejs && npm test
```

### Full Integration Test
```bash
./venv/bin/pytest tests/ -v
```

---

## Benefits of This Change

1. **Fool-proof**: No more DNS name length violations
2. **Automatic**: Developers don't need to calculate fragment sizes
3. **Optimal**: Maximizes throughput for each domain
4. **Safe**: 5% safety margin prevents edge cases
5. **Simple**: One less parameter in all APIs

---

## Algorithm Reference

See [PROTOCOL.md](PROTOCOL.md#dns-fragment-sizing) for the complete algorithm documentation and examples.

---

## Backward Compatibility

⚠️ **BREAKING CHANGE**: Per project guidelines, we do NOT maintain backward compatibility.

All client code must be updated to use the new API. Remove any `max_fragment_size` arguments from client constructors.
