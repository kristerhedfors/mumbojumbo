# Fragment Size Implementation Choice

## Two Approaches

### Option 1: Simple Linear Formula (RECOMMENDED)

**Use `83 - len(domain) / 3` for all domains.**

#### Pros:
- ✅ **Very simple**: Single arithmetic operation
- ✅ **Accurate**: Within 0-2 bytes for typical domains (3-12 chars)
- ✅ **Safe**: Slightly conservative, never exceeds DNS limits
- ✅ **Predictable**: Linear relationship

#### Cons:
- ⚠️ For very long domains (>30 chars): 5-7 bytes over optimal (wasteful but safe)

#### Implementation:
```python
# Python
def calculate_max_frag_len(domain):
    return 83 - len(domain) // 3

# C
size_t calculate_max_frag_len(const char *domain) {
    return 83 - strlen(domain) / 3;
}

// Rust
fn calculate_max_frag_len(domain: &str) -> usize {
    83 - domain.len() / 3
}

// Go
func calculateMaxFragLen(domain string) int {
    return 83 - len(domain) / 3
}

// JavaScript
function calculateMaxFragLen(domain) {
    return 83 - Math.floor(domain.length / 3);
}
```

---

### Option 2: Precise Domain-Based Calculation

**Calculate exact maximum from domain length.**

#### Pros:
- ✅ Optimizes throughput for each specific domain
- ✅ For `.xy`: 82 bytes vs 75 = +7 bytes per fragment
- ✅ Maximizes efficiency for large transfers

#### Cons:
- ⚠️ Complex: 20-40 lines of code
- ⚠️ More test surface area
- ⚠️ Potential for implementation bugs

#### Implementation:

See [PROTOCOL.md](PROTOCOL.md#dns-fragment-sizing) for the complete precise formula.

---

## Current Implementation Status

| Component | Approach | Rationale |
|-----------|----------|-----------|
| **Server (mumbojumbo.py)** | Precise formula | Already implemented, tested, working |
| **Python Client** | Precise formula | Already implemented, tested, working |
| **C Client** | Precise formula | Already implemented, compiles |
| **Rust Client** | **Your choice** | Not yet updated |
| **Go Client** | **Your choice** | Not yet updated |
| **Node.js Client** | **Your choice** | Not yet updated |
| **HTML Client** | **Your choice** | Not yet updated |

---

## Recommendation

### For New Implementations:
Use **Option 1 (simple constant 75)** unless you have a specific need for maximum throughput.

### For Server/Python/C:
Keep the precise formula since it's already implemented and tested.

### Mixed Approach (Best of Both Worlds):
- **Servers**: Use precise formula (optimize for all clients)
- **Clients**: Use simple constant (minimal code, fool-proof)
- **Result**: Server handles any fragment size ≤ its calculated max, clients use safe constant

---

## Performance Impact

### Example: Sending 10 MB file with `.asd.qwe` domain

**Simple (75 bytes/fragment):**
- Fragments: 10,485,760 / 75 = 139,810 fragments
- DNS queries: 139,810

**Precise (79 bytes/fragment):**
- Fragments: 10,485,760 / 79 = 132,730 fragments
- DNS queries: 132,730

**Difference:**
- 7,080 fewer queries (5.3% improvement)
- At 50ms/query: Saves 354 seconds (5.9 minutes)
- At 100ms/query: Saves 708 seconds (11.8 minutes)

### Verdict:
- For **small messages** (<1 MB): Negligible difference
- For **large transfers** (>10 MB): Precise formula saves meaningful time
- For **typical use** (KB-MB range): Simple constant is perfectly fine

---

## Decision Matrix

| Your Situation | Recommended Approach |
|----------------|---------------------|
| Quick prototype / demo | Simple constant (75) |
| Production with small messages | Simple constant (75) |
| High-volume large file transfers | Precise formula |
| Educational / learning project | Precise formula (learn the algorithm) |
| Minimal code / embedded systems | Simple constant (75) |
| Maximum performance required | Precise formula |

---

## Summary

**TLDR:** Use `MAX_FRAG_DATA_LEN = 75` for simplicity. It's safe, fast, and good enough for 99% of use cases. Only use the precise formula if you're optimizing large file transfers or want to learn the DNS size calculation algorithm.
