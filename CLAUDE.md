# Mumbojumbo Project Guidelines

## CRITICAL: Project Architecture Constraints

### Single-File Implementation
**mumbojumbo.py MUST remain a single file.** Do not split functionality into multiple modules or files. This is a core design principle for simplicity, portability, and ease of deployment.

### Library Dependencies
**Be VERY restrictive on adding new libraries.** Only use Python standard library unless absolutely necessary. Every new dependency:
- Increases attack surface
- Complicates deployment
- Reduces portability
- Must be strongly justified

### Code Philosophy
- **Do NOT overgeneralize** - Keep implementations specific and practical
- **Compact and effective** - Every line should have clear purpose
- **Fool-proof** - Design for reliability and error prevention
- **Robust** - Handle edge cases and failures gracefully
- **Full test coverage** - All functionality must be tested

## Domain-Key Variable

The project uses a **domain-key** concept for maximum simplicity in client configuration:

### Format
```
<server-pubkey-base64url>.<configured-domain>
```

### Purpose
This single string contains everything a client needs:
- **Server public key** (encoded as base64url, 43 characters)
- **Domain destination** (the actual domain to connect to)

### Example
```
RKoLeTKGMx9k6lvObpi1OQswh9nN9521pbb9cP7mz1k.example.com
```

Where:
- `RKoLeTKGMx9k6lvObpi1OQswh9nN9521pbb9cP7mz1k` = base64url-encoded 32-byte NaCl server public key
- `example.com` = configured domain from server config

### Implementation Details
- Uses `base64.urlsafe_b64encode` for DNS-safe encoding
- 32-byte NaCl public key → 43 characters (without padding)
- Encoding removes leading dot from domain for cleaner format
- Parsing restores leading dot (Mumbojumbo convention)
- Available functions: `encode_domain_key()` and `parse_domain_key()`
- Class method: `DnsPublicFragment.from_domain_key(domain_key, private_key)`

### Benefits
- **One copy-paste configuration** - Client only needs this single string
- **Embedded authentication** - Public key is part of the address
- **No separate key distribution** - Key and domain are unified
- **Simple UX** - Users can't misconfigure domain vs key mismatch

## Development Workflow

### Before Making Changes
1. Run `pwd` to confirm working directory
2. Read relevant tests to understand current behavior
3. Consider impact on single-file constraint

### After Making Changes
1. Run full test suite: `./venv/bin/python3 test.py`
2. Verify all tests pass (tests use unittest, not pytest)
3. Check no new dependencies added
4. Ensure code remains compact and readable

## Code Style
- Use Python standard library idioms
- Keep functions focused and testable
- Prefer explicit over implicit
- Comment only what's non-obvious
- Use type hints where they add clarity

## Testing Requirements

### Test Framework
- **Framework**: Python unittest (standard library)
- **Location**: All tests in `test.py`
- **Command**: `./venv/bin/python3 test.py`
- **Coverage**: 100% test coverage is mandatory

### Running Tests
```bash
# Run all tests
./venv/bin/python3 test.py

# Run with verbose output
./venv/bin/python3 test.py -v

# Run specific test class
./venv/bin/python3 test.py Test_DomainKey

# Run specific test method
./venv/bin/python3 test.py Test_DomainKey.test_encode_decode_round_trip
```

### Test Structure
Tests are organized into unittest.TestCase classes:
- `Test_Fragment` - Basic fragment serialization/deserialization
- `Test_PublicFragment` - Encrypted fragment operations
- `Test_PacketEngine` - Packet assembly and fragment handling
- `Test_DomainKey` - Domain-key encoding, parsing, and integration

### Test Patterns
```python
class Test_MyFeature(unittest.TestCase):
    """Test description."""

    def test_happy_path(self):
        """Test normal operation."""
        # Arrange
        input_data = b'test'

        # Act
        result = my_function(input_data)

        # Assert
        self.assertEqual(result, expected)

    def test_edge_case(self):
        """Test boundary conditions."""
        # Test with empty data
        # Test with maximum length
        # Test with special characters

    def test_error_handling(self):
        """Test error conditions."""
        with self.assertRaises(ValueError) as ctx:
            my_function(invalid_input)
        self.assertIn('expected message', str(ctx.exception))
```

### Testing Best Practices
1. **Test Coverage**: Every new function must have comprehensive tests
2. **Happy Path**: Test normal expected behavior first
3. **Edge Cases**: Test boundaries (empty, zero, max length, special chars)
4. **Error Conditions**: Test invalid inputs with `assertRaises`
5. **Integration**: Test how components work together
6. **Round-trip**: For encoders/decoders, verify encode→decode returns original
7. **Assertions**: Use specific assertions (`assertEqual`, `assertIn`, `assertIsNone`)
8. **Descriptive Names**: Test method names should describe what they test
9. **Docstrings**: Add docstrings explaining test purpose
10. **Mock Externals**: Mock network, filesystem, and external dependencies

### Example: Testing a New Feature
When adding a new feature like domain-key encoding:

```python
class Test_DomainKey(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        """Verify encoding and decoding are inverses."""
        key = nacl.public.PrivateKey.generate().public_key.encode()
        domain = '.example.com'

        domain_key = encode_domain_key(key, domain)
        decoded_key, decoded_domain = parse_domain_key(domain_key)

        self.assertEqual(key, decoded_key)
        self.assertEqual(domain, decoded_domain)

    def test_invalid_input(self):
        """Verify proper error handling."""
        with self.assertRaises(ValueError):
            parse_domain_key('invalid-format')
```

### Test Organization
- Keep tests in `test.py` (single test file)
- Group related tests in TestCase classes
- Use mixin pattern for reusable test logic (see `MyTestMixin`)
- Order tests logically: basic → complex → edge cases → errors

## Security Considerations
- Validate all inputs
- Use constant-time comparisons for crypto
- Clear sensitive data when done
- Assume hostile network environment
- Log security-relevant events

## When in Doubt
- Keep it simple
- Keep it in one file
- Keep dependencies minimal
- Keep tests comprehensive
- Keep the domain-key concept central to UX
