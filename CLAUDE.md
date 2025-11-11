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

### NO Backwards Compatibility
**We do NOT maintain backwards compatibility. EVER.**
- Always use the latest Python features and idioms
- Always use the purest, most modern implementation approach
- Remove deprecated code immediately - no compatibility shims
- Break interfaces without hesitation if it improves code quality
- Upgrade dependencies aggressively to latest versions
- Old code/configs/clients must be updated - we don't support legacy versions
- This is a cutting-edge project, not enterprise software

### Code Philosophy
- **Do NOT overgeneralize** - Keep implementations specific and practical
- **Compact and effective** - Every line should have clear purpose
- **Fool-proof** - Design for reliability and error prevention
- **Robust** - Handle edge cases and failures gracefully
- **Full test coverage** - All functionality must be tested
- **Latest and greatest** - Use modern Python features, no legacy support

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
./venv/bin/python3 test.py Test_Fragment

# Run specific test method
./venv/bin/python3 test.py Test_Fragment.test_basic
```

### Test Structure
Tests are organized into unittest.TestCase classes:
- `Test_Fragment` - Basic fragment serialization/deserialization
- `Test_PublicFragment` - Encrypted fragment operations
- `Test_PacketEngine` - Packet assembly and fragment handling

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
When adding a new feature:

```python
class Test_MyFeature(unittest.TestCase):
    def test_encode_decode_round_trip(self):
        """Verify encoding and decoding are inverses."""
        data = b'test data'

        encoded = encode_function(data)
        decoded = decode_function(encoded)

        self.assertEqual(data, decoded)

    def test_invalid_input(self):
        """Verify proper error handling."""
        with self.assertRaises(ValueError):
            decode_function('invalid-format')
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

## Running & Debugging

### Running Mumbojumbo

#### Basic Operation
```bash
# Run mumbojumbo (requires sudo for packet capture)
sudo ./venv/bin/python3 mumbojumbo.py
```

#### With Timeout
```bash
# Run with 30-second timeout
timeout 30 sudo ./venv/bin/python3 mumbojumbo.py
```

#### Verbose Mode
```bash
# Show logs to stderr in addition to stdout JSON
sudo ./venv/bin/python3 mumbojumbo.py --verbose
sudo ./venv/bin/python3 mumbojumbo.py -v
```

### Logging Behavior

Mumbojumbo uses a **simple, clean logging strategy**:

#### Default Mode (No Flags)
- **stdout**: Clean, parseable JSON for DNS events only
- **mumbojumbo.log**: All DEBUG+ logging goes here
- No log pollution in stdout - perfect for piping to other tools

#### Verbose Mode (`-v` or `--verbose`)
- **stdout**: JSON events (same as default)
- **stderr**: All DEBUG+ log messages
- **mumbojumbo.log**: All DEBUG+ logging (same as default)
- Use when troubleshooting to see logs in real-time

#### Log File Details
- **Location**: `mumbojumbo.log` in current working directory
- **Rotation**: Automatically rotates at 10MB (keeps 5 backups)
- **Format**: `YYYY-MM-DD HH:MM:SS - logger - LEVEL - message`
- **Level**: Always DEBUG (comprehensive diagnostics)

#### Viewing Logs
```bash
# Follow log file in real-time
tail -f mumbojumbo.log

# View last 50 lines
tail -50 mumbojumbo.log

# Search for errors
grep ERROR mumbojumbo.log

# Search for SMTP-related events
grep SMTP mumbojumbo.log
```

### JSON Output Format

When packets are successfully reassembled, mumbojumbo outputs JSON to stdout:

```json
{
  "timestamp": "2025-11-11T18:32:01.123456+00:00",
  "event": "packet_reassembled",
  "query": "subdomain.example.com",
  "data_length": 1234,
  "data_preview": "First 100 characters of packet data...",
  "smtp_forwarding": true
}
```

**Fields:**
- `timestamp`: ISO 8601 UTC timestamp
- `event`: Event type (`packet_reassembled`)
- `query`: DNS query name that completed the packet
- `data_length`: Size of reassembled packet in bytes
- `data_preview`: First 100 chars of data (or full data if < 100 chars)
- `smtp_forwarding`: Whether SMTP forwarding is configured

**Processing JSON:**
```bash
# Parse with jq
./mumbojumbo.py | jq '.data_preview'

# Save JSON to file
./mumbojumbo.py > events.json

# Filter by event type
./mumbojumbo.py | jq 'select(.event == "packet_reassembled")'
```

### SMTP Configuration & Error Handling

Mumbojumbo is **robust against SMTP failures** - SMTP errors will NOT crash the program.

#### Testing SMTP Configuration
```bash
# Test SMTP settings without running the full server
./venv/bin/python3 mumbojumbo.py --test-smtp
```

**Possible outcomes:**
- `SUCCESS: Test email sent successfully` - SMTP is working
- `FAILED: Could not send test email. Check mumbojumbo.log for details.` - SMTP failed, check logs

#### Common SMTP Errors

All SMTP errors are logged but **do not stop DNS packet processing**:

1. **Connection Refused** (port closed or wrong server)
   ```
   ERROR: Connection refused by SMTP server 127.0.0.1:587
   ```
   - Fix: Check server is running and port is correct

2. **Authentication Failed** (bad username/password)
   ```
   ERROR: SMTP authentication failed for user someuser
   ```
   - Fix: Verify credentials in config file

3. **DNS/Network Error** (can't resolve hostname)
   ```
   ERROR: DNS/network error connecting to SMTP server mail.example.com:587
   ```
   - Fix: Check server hostname and network connectivity

4. **Timeout** (server not responding)
   ```
   ERROR: Timeout connecting to SMTP server 127.0.0.1:587
   ```
   - Fix: Check network connectivity and server status

5. **Recipient Refused** (invalid recipient email)
   ```
   ERROR: SMTP server rejected recipient user@example.com
   ```
   - Fix: Verify recipient email address

#### SMTP Behavior During Operation

- **SMTP failures are non-fatal**: DNS processing continues even if email sending fails
- **Each failure is logged**: Check `mumbojumbo.log` for detailed error messages
- **No retries**: Failed emails are logged but not queued for retry
- **Graceful degradation**: If SMTP is misconfigured, packets are still processed and logged

### Troubleshooting Guide

#### Problem: No packets being received
1. Check `mumbojumbo.log` for DNS query events
2. Verify network interface is correct in config
3. Ensure tshark is installed and accessible
4. Run with `--verbose` to see real-time logs

#### Problem: SMTP not working
1. Run `./venv/bin/python3 mumbojumbo.py --test-smtp`
2. Check `mumbojumbo.log` for specific error
3. Verify SMTP server is running: `telnet server_address 587`
4. Check credentials and recipient addresses

#### Problem: Log file growing too large
- Logs auto-rotate at 10MB
- Check for disk space issues
- Consider cleaning old `.log.1`, `.log.2` backup files

#### Problem: Can't find log file
- Log file is created in current working directory
- Check with `ls -la | grep mumbojumbo.log`
- Run `pwd` to confirm working directory

#### Debug Checklist
1. ✅ Run tests: `./venv/bin/python3 test.py`
2. ✅ Test SMTP: `./venv/bin/python3 mumbojumbo.py --test-smtp`
3. ✅ Check logs: `tail -f mumbojumbo.log`
4. ✅ Run verbose: `sudo ./venv/bin/python3 mumbojumbo.py --verbose`
5. ✅ Verify config: Check `mumbojumbo.conf` for syntax errors

## When in Doubt
- Keep it simple
- Keep it in one file
- Keep dependencies minimal
- Keep tests comprehensive
