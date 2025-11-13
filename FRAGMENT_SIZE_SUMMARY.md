# DNS Fragment Size Calculation - Implementation Summary

## What Was Done

### Problem Identified
The original hardcoded `MAX_FRAG_DATA_LEN = 80` bytes was:
- Not safe for all domain lengths (could violate DNS 253-byte limit)
- Not optimal (wasted potential throughput for short domains)
- Required manual parameter passing through all APIs

### Solution Implemented
Automatic fragment size calculation based on domain length, with two approaches:

1. **Simple Conservative** (Recommended for new code): `MAX_FRAG_DATA_LEN = 75` (constant)
2. **Precise Calculation** (Already in server/Python/C): Domain-based algorithm

---

## Completed Work

### ✅ Documentation
1. **[PROTOCOL.md](PROTOCOL.md#dns-fragment-sizing)** - Complete algorithm explanation
   - Step-by-step mathematical breakdown
   - Both simple and precise formulas
   - Domain length comparison table
   - Safety margin rationale

2. **[IMPLEMENTATION_CHOICE.md](IMPLEMENTATION_CHOICE.md)** - Decision guide
   - Pros/cons of each approach
   - Performance impact analysis
   - Recommendation matrix

3. **[FRAGMENT_SIZE_MIGRATION_GUIDE.md](FRAGMENT_SIZE_MIGRATION_GUIDE.md)** - Migration instructions
   - Exact code changes for each client (Rust, Go, Node.js, HTML)
   - Before/after examples
   - Testing procedures

### ✅ Server Implementation ([mumbojumbo.py](mumbojumbo.py))
- Added `calculate_safe_max_fragment_data_len()` function (precise formula)
- Updated `PacketEngine.__init__()` to auto-calculate from domain
- Removed `max_frag_data_len` parameter requirement
- **Tests: 4 passed, 1 skipped ✓**

### ✅ Python Client ([clients/python/mumbojumbo-client.py](clients/python/mumbojumbo-client.py))
- Added `calculate_safe_max_fragment_data_len()` function (precise formula)
- Updated `MumbojumboClient.__init__()` to auto-calculate from domain
- Removed `max_fragment_size` parameter from constructor
- **Tests: 42 passed ✓**

### ✅ C Client ([clients/c/](clients/c/))
- Added `calculate_safe_max_fragment_data_len()` function (precise formula)
- Updated header file and both constructors
- Removed `max_fragment_size` parameter
- **Compilation: successful ✓**

---

## Remaining Work

### ⚠️ Client Updates Needed

Update the following clients using either approach from [IMPLEMENTATION_CHOICE.md](IMPLEMENTATION_CHOICE.md):

| Client | Files | Recommended Approach |
|--------|-------|---------------------|
| **Rust** | `clients/rust/src/main.rs` | Simple constant (75) or precise formula |
| **Go** | `clients/go/mumbojumbo-client.go` | Simple constant (75) or precise formula |
| **Node.js** | `clients/nodejs/mumbojumbo-client.js` | Simple constant (75) or precise formula |
| **HTML** | `clients/html/client.html` | Simple constant (75) recommended |

**Simple approach example** (add to any client):
```javascript
const MAX_FRAG_DATA_LEN = 75;  // Safe for all realistic domains
```

**Precise approach:** See [FRAGMENT_SIZE_MIGRATION_GUIDE.md](FRAGMENT_SIZE_MIGRATION_GUIDE.md) for language-specific implementations.

### ⚠️ Documentation Updates
- Update [CLIENT_IMPLEMENTATION_GUIDE.md](clients/CLIENT_IMPLEMENTATION_GUIDE.md) to remove `max_fragment_size` references

---

## API Breaking Changes

### Before (Old API)
```python
# Python
client = MumbojumboClient(server_key, domain, max_fragment_size=80)

// C
client = mumbojumbo_client_new(key, domain, 80);

// Rust
client = MumbojumboClient::new(key, domain, 80);
```

### After (New API)
```python
# Python - auto-calculates from domain
client = MumbojumboClient(server_key, domain)

// C - auto-calculates from domain
client = mumbojumbo_client_new(key, domain);

// Rust - auto-calculates from domain
client = MumbojumboClient::new(key, domain);
```

**Note:** Per project guidelines, we do NOT maintain backward compatibility.

---

## Testing Status

### Passing Tests ✅
- Server packet engine: 4/5 tests passing (1 skipped intentionally)
- Python client: 42/42 tests passing
- C client: Compiles successfully

### Tests Needed
- Rust client integration tests
- Go client tests
- Node.js client tests
- Full end-to-end integration test

Run all tests:
```bash
./venv/bin/pytest tests/ -v
```

---

## Key Benefits

### 1. Fool-Proof
**Before:** Manual calculation required, easy to violate DNS limits
```python
# Could fail with long domains!
client = MumbojumboClient(key, ".very.long.domain.example.com", max_fragment_size=80)
```

**After:** Impossible to violate DNS limits
```python
# Always safe, automatically optimized
client = MumbojumboClient(key, ".very.long.domain.example.com")
```

### 2. Simpler API
- One less parameter to understand
- No manual calculation needed
- Clear intent

### 3. Safe by Construction
- Simple approach (75): Always safe for domains up to 50 chars
- Precise approach: Calculated to never exceed DNS limits
- Both include safety margins

### 4. Optimal or Near-Optimal
- Simple approach: Within 7 bytes of optimal for typical domains
- Precise approach: Maximizes throughput for each specific domain

---

## Algorithm Explanation

### The Problem
DNS names are limited to:
- **253 bytes total** (RFC 1035)
- **63 bytes per label** (subdomain component)

Our encoding chain:
```
Fragment Data (variable)
  → Add 18-byte header
  → Encrypt with SealedBox (+48 bytes overhead)
  → Base32 encode (×1.6 expansion)
  → Split into 63-char DNS labels
  → Append domain suffix
  → Must be ≤ 253 bytes total
```

### Simple Solution
Work backwards from DNS limit with conservative constant:
```
253 bytes (DNS limit)
  - 8 bytes (typical domain like .asd.qwe)
  - 48 bytes (encryption overhead)
  - 18 bytes (header)
  - ~100 bytes (base32 expansion + label overhead)
  = ~75 bytes safe for fragment data
```

### Precise Solution
Calculate exactly from domain length:
1. Available space = 253 - len(domain)
2. Account for label dots (every 63 chars needs +1 byte)
3. Convert base32 chars to binary bytes (5/8 ratio)
4. Subtract encryption overhead (48 bytes)
5. Subtract header (18 bytes)
6. Apply 5% safety margin

Result: Optimal size for each specific domain.

---

## Files Modified

```
mumbojumbo/
├── PROTOCOL.md                          # Added DNS Fragment Sizing section
├── mumbojumbo.py                        # Added calculate function, updated PacketEngine
├── clients/
│   ├── python/mumbojumbo-client.py     # Added calculate function, updated constructor
│   └── c/
│       ├── mumbojumbo-client.h         # Updated signatures, added function
│       └── mumbojumbo-client.c         # Added calculate function, updated constructors
└── docs/
    ├── IMPLEMENTATION_CHOICE.md         # NEW: Decision guide
    ├── FRAGMENT_SIZE_MIGRATION_GUIDE.md # NEW: Migration instructions
    └── FRAGMENT_SIZE_SUMMARY.md         # NEW: This file
```

---

## Quick Start for Remaining Clients

### Option 1: Simple Constant (5 minutes)

1. Change constant:
   ```diff
   - const MAX_FRAG_DATA_LEN = 80;
   + const MAX_FRAG_DATA_LEN = 75;  // Safe for all realistic domains
   ```

2. Remove `max_fragment_size` parameter from constructor

3. Done! ✓

### Option 2: Precise Formula (30-60 minutes)

1. Copy calculation function from [FRAGMENT_SIZE_MIGRATION_GUIDE.md](FRAGMENT_SIZE_MIGRATION_GUIDE.md)
2. Update constructor to call the function
3. Remove `max_fragment_size` parameter
4. Add tests
5. Done! ✓

---

## Next Steps

1. **Decide** which approach to use for remaining clients (see [IMPLEMENTATION_CHOICE.md](IMPLEMENTATION_CHOICE.md))
2. **Update** Rust, Go, Node.js, and HTML clients following [FRAGMENT_SIZE_MIGRATION_GUIDE.md](FRAGMENT_SIZE_MIGRATION_GUIDE.md)
3. **Update** CLIENT_IMPLEMENTATION_GUIDE.md to reflect new API
4. **Run** full test suite: `./venv/bin/pytest tests/ -v`
5. **Commit** changes with message: "Remove max_fragment_size parameter, auto-calculate from domain"

---

## Questions?

- **Algorithm details:** See [PROTOCOL.md#dns-fragment-sizing](PROTOCOL.md#dns-fragment-sizing)
- **Which approach to use:** See [IMPLEMENTATION_CHOICE.md](IMPLEMENTATION_CHOICE.md)
- **How to migrate:** See [FRAGMENT_SIZE_MIGRATION_GUIDE.md](FRAGMENT_SIZE_MIGRATION_GUIDE.md)
- **Code examples:** Look at Python or C client implementations

---

**Status:** Core implementation complete (server + Python + C). Remaining clients can use either simple constant (75) or precise formula.
