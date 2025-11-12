# Mumbojumbo Test Suite

This directory contains the pytest-based test suite for the mumbojumbo project.

## Structure

```
tests/
├── conftest.py                    # pytest fixtures and shared test utilities
├── test_fragment.py               # Fragment serialization tests (1 test)
├── test_packet_engine.py          # PacketEngine and encryption tests (3 tests)
├── test_key_encoding.py           # Key encoding/decoding tests (9 tests)
├── test_handlers.py               # Packet handler tests (34 tests)
├── test_handler_pipeline.py       # Handler pipeline integration tests (2 tests)
└── fixtures/
    ├── dns_utils.py               # DnsQueryWriter, DnsQueryReader utilities
    └── helpers.py                 # Test helper functions
```

**Total: 53 tests**

## Running Tests

### Basic Usage

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_fragment.py

# Run specific test class
pytest tests/test_handlers.py::TestSMTPErrorHandling

# Run specific test method
pytest tests/test_fragment.py::TestFragment::test_basic_round_trip

# Run tests matching a pattern
pytest -k "smtp"
pytest -k "handler and not smtp"
```

### Coverage

```bash
# Run with coverage report (terminal)
pytest --cov=mumbojumbo --cov-report=term-missing

# Generate HTML coverage report
pytest --cov=mumbojumbo --cov-report=html
# Open htmlcov/index.html in browser

# Generate both
pytest --cov=mumbojumbo --cov-report=term-missing --cov-report=html
```

### Advanced Options

```bash
# Stop on first failure
pytest -x

# Run last failed tests
pytest --lf

# Run last failed, then all
pytest --ff

# Show local variables in tracebacks
pytest -l

# Run in parallel (requires pytest-xdist)
pip install pytest-xdist
pytest -n auto

# Disable output capture (see print statements)
pytest -s

# Extra verbose (show test docstrings)
pytest -vv
```

## Test Organization

### test_fragment.py
Basic fragment serialization and deserialization tests.

### test_packet_engine.py
Tests for packet assembly, encryption/decryption, and fragment handling with NaCl SealedBox.

### test_key_encoding.py
Tests for key encoding/decoding with `mj_srv_` and `mj_cli_` prefixes.

### test_handlers.py
Comprehensive tests for packet handlers:
- **TestSMTPErrorHandling**: SMTP error handling robustness (7 tests)
- **TestPacketHandlers**: All handler implementations (27 tests)
  - StdoutHandler (JSON output)
  - FileHandler (hex/base64/raw formats)
  - ExecuteHandler (command execution)
  - SMTPHandler (email forwarding)

### test_handler_pipeline.py
Integration tests for running multiple handlers in sequence.

## Fixtures

Shared pytest fixtures are defined in [conftest.py](conftest.py):

- `keypair` - Generate NaCl keypair
- `serialize_deserialize` - Test round-trip serialization
- `multi_serialize_deserialize` - Test with multiple data sizes
- `public_serialize_deserialize` - Test encrypted fragments
- `multi_public_serialize_deserialize` - Test encrypted with various sizes

## Configuration

Test configuration is in [../pytest.ini](../pytest.ini):
- Verbose output by default
- Short tracebacks
- Color output enabled
- Markers for slow/integration tests

## Adding New Tests

1. Create test file matching pattern `test_*.py`
2. Create test class matching pattern `Test*`
3. Create test methods matching pattern `test_*`
4. Use pytest `assert` statements (not unittest assertions)
5. Use fixtures from conftest.py for common setup

Example:
```python
from mumbojumbo import MyClass

class TestMyFeature:
    """Test my new feature."""

    def test_basic_functionality(self):
        """Test that basic functionality works."""
        obj = MyClass()
        result = obj.do_something()
        assert result == expected_value
```

## Migration Notes

This test suite was migrated from unittest to pytest. Key changes:
- `self.assertEqual(a, b)` → `assert a == b`
- `self.assertRaises(E)` → `pytest.raises(E)`
- `setUp()` → pytest fixtures
- `MyTestMixin` → pytest fixtures in conftest.py

The original `test.py` has been archived as `test.py.bak`.
