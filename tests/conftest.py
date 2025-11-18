#!/usr/bin/env python3
"""pytest configuration and shared fixtures for mumbojumbo v2.0 protocol tests."""

import logging
import os
import secrets

import pytest

# Import from mumbojumbo - new v2.0 protocol
from mumbojumbo import derive_keys, encode_key_hex, decode_mumbojumbo_key

# Configure logging for tests
logging.basicConfig(level=logging.INFO)


@pytest.fixture
def client_key_bytes():
    """Generate a random 32-byte client key."""
    return secrets.token_bytes(32)


@pytest.fixture
def client_key_hex(client_key_bytes):
    """Generate a client key as hex string with mj_cli_ prefix."""
    return encode_key_hex(client_key_bytes, key_type='cli')


@pytest.fixture
def derived_keys(client_key_bytes):
    """Derive enc_key, auth_key, frag_key from client key."""
    return derive_keys(client_key_bytes)


@pytest.fixture
def enc_key(derived_keys):
    """Get encryption key from derived keys."""
    enc_key, auth_key, frag_key = derived_keys
    return enc_key


@pytest.fixture
def auth_key(derived_keys):
    """Get authentication key from derived keys."""
    enc_key, auth_key, frag_key = derived_keys
    return auth_key


@pytest.fixture
def frag_key(derived_keys):
    """Get fragment MAC key from derived keys."""
    enc_key, auth_key, frag_key = derived_keys
    return frag_key


@pytest.fixture
def random_data():
    """Generate random test data (100 bytes)."""
    return secrets.token_bytes(100)


@pytest.fixture
def small_message():
    """Generate small message that fits in single fragment."""
    return b'Hello, World!'


@pytest.fixture
def medium_message():
    """Generate medium message that spans multiple fragments."""
    # 28 bytes per fragment payload + 16 bytes overhead = need ~100 bytes for 3-4 fragments
    return secrets.token_bytes(100)


@pytest.fixture
def large_message():
    """Generate large message that spans many fragments."""
    return secrets.token_bytes(500)


@pytest.fixture
def test_domain():
    """Standard test domain."""
    return '.test.example.com'
