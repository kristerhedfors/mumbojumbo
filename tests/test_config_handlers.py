#!/usr/bin/env python3
"""Tests for configuration system and packet handlers in mumbojumbo v2.0.

Tests the INI-style config file format, handler pipeline, and harmonized
CLI > env > config hierarchy.
"""

import configparser
import datetime
import os
import tempfile

import pytest

from mumbojumbo import (
    StdoutHandler,
    SMTPHandler,
    FileHandler,
    ExecuteHandler,
    build_handlers,
    get_default_interface,
    __config_skel__,
    get_client_key_hex,
    validate_domain,
)


class TestConfigSkeleton:
    """Test config skeleton generation."""

    def test_config_skeleton_has_all_sections(self):
        """Config skeleton should have main, smtp, file, execute sections."""
        # Fill in placeholders
        config_content = __config_skel__.format(
            client_key='mj_cli_' + '00' * 32,
            domain='.test.example.com',
            network_interface='en0'
        )

        config = configparser.ConfigParser(allow_no_value=True)
        config.read_string(config_content)

        assert config.has_section('main')
        assert config.has_section('smtp')
        assert config.has_section('file')
        assert config.has_section('execute')

    def test_config_skeleton_main_section_has_required_fields(self):
        """Main section should have domain, handlers, client-key."""
        config_content = __config_skel__.format(
            client_key='mj_cli_' + '00' * 32,
            domain='.test.example.com',
            network_interface='en0'
        )

        config = configparser.ConfigParser(allow_no_value=True)
        config.read_string(config_content)

        assert config.has_option('main', 'domain')
        assert config.has_option('main', 'handlers')
        assert config.has_option('main', 'client-key')
        assert config.has_option('main', 'network-interface')

    def test_config_skeleton_smtp_section_fields(self):
        """SMTP section should have server, port, from, to, etc."""
        config_content = __config_skel__.format(
            client_key='mj_cli_' + '00' * 32,
            domain='.test.example.com',
            network_interface='en0'
        )

        config = configparser.ConfigParser(allow_no_value=True)
        config.read_string(config_content)

        assert config.has_option('smtp', 'server')
        assert config.has_option('smtp', 'port')
        assert config.has_option('smtp', 'username')
        assert config.has_option('smtp', 'password')
        assert config.has_option('smtp', 'from')
        assert config.has_option('smtp', 'to')

    def test_config_skeleton_file_section_fields(self):
        """File section should have path and format."""
        config_content = __config_skel__.format(
            client_key='mj_cli_' + '00' * 32,
            domain='.test.example.com',
            network_interface='en0'
        )

        config = configparser.ConfigParser(allow_no_value=True)
        config.read_string(config_content)

        assert config.has_option('file', 'path')
        assert config.has_option('file', 'format')

    def test_config_skeleton_execute_section_fields(self):
        """Execute section should have command and timeout."""
        config_content = __config_skel__.format(
            client_key='mj_cli_' + '00' * 32,
            domain='.test.example.com',
            network_interface='en0'
        )

        config = configparser.ConfigParser(allow_no_value=True)
        config.read_string(config_content)

        assert config.has_option('execute', 'command')
        assert config.has_option('execute', 'timeout')

    def test_config_skeleton_supports_starttls_flag(self):
        """Config should support start-tls flag without value."""
        config_content = __config_skel__.format(
            client_key='mj_cli_' + '00' * 32,
            domain='.test.example.com',
            network_interface='en0'
        )

        config = configparser.ConfigParser(allow_no_value=True)
        config.read_string(config_content)

        # start-tls is a flag (no value)
        assert config.has_option('smtp', 'start-tls')


class TestStdoutHandler:
    """Test StdoutHandler functionality."""

    def test_handle_returns_true_on_success(self, capsys):
        """StdoutHandler.handle should return True on success."""
        handler = StdoutHandler()
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'mykey', b'myvalue', timestamp)

        assert result is True

    def test_handle_outputs_json(self, capsys):
        """StdoutHandler should output JSON to stdout."""
        handler = StdoutHandler()
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        handler.handle(b'mykey', b'myvalue', timestamp)

        captured = capsys.readouterr()
        assert '"event": "packet_reassembled"' in captured.out
        assert '"key": "mykey"' in captured.out
        assert '"value_preview": "myvalue"' in captured.out

    def test_handle_empty_key_shows_null(self, capsys):
        """Empty key should display as null in JSON."""
        handler = StdoutHandler()
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        handler.handle(b'', b'myvalue', timestamp)

        captured = capsys.readouterr()
        assert '"key": null' in captured.out
        assert '"key_length": null' in captured.out

    def test_handle_binary_key_shows_hex(self, capsys):
        """Binary key (non-UTF-8) should show as hex."""
        handler = StdoutHandler()
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        binary_key = b'\xff\xfe\xfd'

        handler.handle(binary_key, b'myvalue', timestamp)

        captured = capsys.readouterr()
        # Should contain hex representation
        assert 'fffefd' in captured.out

    def test_handle_long_value_truncated(self, capsys):
        """Long values should be truncated to 100 chars in preview."""
        handler = StdoutHandler()
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        long_value = b'x' * 200

        handler.handle(b'key', long_value, timestamp)

        captured = capsys.readouterr()
        # Preview should be truncated
        assert '...' in captured.out
        assert '"value_length": 200' in captured.out


class TestFileHandler:
    """Test FileHandler functionality."""

    def test_init_invalid_format_raises(self):
        """FileHandler should reject invalid formats."""
        with pytest.raises(ValueError) as exc_info:
            FileHandler('/tmp/test.log', format='invalid')
        assert 'Invalid format' in str(exc_info.value)

    def test_handle_hex_format(self, tmp_path):
        """FileHandler should write hex format correctly."""
        log_file = tmp_path / 'test.log'
        handler = FileHandler(str(log_file), format='hex')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'key', b'\xde\xad\xbe\xef', timestamp)

        assert result is True
        content = log_file.read_text()
        assert 'deadbeef' in content
        assert 'format: hex' in content

    def test_handle_base64_format(self, tmp_path):
        """FileHandler should write base64 format correctly."""
        log_file = tmp_path / 'test.log'
        handler = FileHandler(str(log_file), format='base64')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'key', b'\xde\xad\xbe\xef', timestamp)

        assert result is True
        content = log_file.read_text()
        # base64 of deadbeef is 3q2+7w==
        assert '3q2+7w==' in content
        assert 'format: base64' in content

    def test_handle_raw_format(self, tmp_path):
        """FileHandler should write raw format correctly."""
        log_file = tmp_path / 'test.log'
        handler = FileHandler(str(log_file), format='raw')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'key', b'raw data', timestamp)

        assert result is True
        content = log_file.read_bytes()
        assert b'raw data' in content

    def test_handle_appends_to_file(self, tmp_path):
        """FileHandler should append to existing file."""
        log_file = tmp_path / 'test.log'
        handler = FileHandler(str(log_file), format='hex')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        handler.handle(b'key1', b'value1', timestamp)
        handler.handle(b'key2', b'value2', timestamp)

        content = log_file.read_text()
        assert 'key1' in content
        assert 'key2' in content

    def test_handle_empty_key_shows_null(self, tmp_path):
        """Empty key should display as (null)."""
        log_file = tmp_path / 'test.log'
        handler = FileHandler(str(log_file), format='hex')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        handler.handle(b'', b'value', timestamp)

        content = log_file.read_text()
        assert '(null)' in content

    def test_handle_io_error_returns_false(self):
        """FileHandler should return False on I/O error."""
        handler = FileHandler('/nonexistent/path/test.log', format='hex')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'key', b'value', timestamp)

        assert result is False


class TestExecuteHandler:
    """Test ExecuteHandler functionality."""

    def test_handle_success_returns_true(self):
        """ExecuteHandler should return True on successful command."""
        handler = ExecuteHandler('cat', timeout=5)
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'key', b'value', timestamp)

        assert result is True

    def test_handle_failure_returns_false(self):
        """ExecuteHandler should return False on failed command."""
        handler = ExecuteHandler('exit 1', timeout=5)
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'key', b'value', timestamp)

        assert result is False

    def test_handle_sets_environment_variables(self, tmp_path):
        """ExecuteHandler should set MUMBOJUMBO_* env vars."""
        script = tmp_path / 'test.sh'
        script.write_text('''#!/bin/bash
echo "KEY=$MUMBOJUMBO_KEY"
echo "KEY_LENGTH=$MUMBOJUMBO_KEY_LENGTH"
echo "VALUE_LENGTH=$MUMBOJUMBO_VALUE_LENGTH"
echo "TIMESTAMP=$MUMBOJUMBO_TIMESTAMP"
''')
        script.chmod(0o755)

        handler = ExecuteHandler(str(script), timeout=5)
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'mykey', b'myvalue', timestamp)

        assert result is True

    def test_handle_passes_value_as_stdin(self, tmp_path):
        """ExecuteHandler should pass value as stdin."""
        script = tmp_path / 'test.sh'
        output_file = tmp_path / 'output.txt'
        script.write_text(f'''#!/bin/bash
cat > {output_file}
''')
        script.chmod(0o755)

        handler = ExecuteHandler(str(script), timeout=5)
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        handler.handle(b'key', b'stdin_data', timestamp)

        assert output_file.read_bytes() == b'stdin_data'

    def test_handle_timeout_returns_false(self):
        """ExecuteHandler should return False on timeout."""
        handler = ExecuteHandler('sleep 10', timeout=1)
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'key', b'value', timestamp)

        assert result is False

    def test_handle_empty_key_sets_empty_env(self, tmp_path):
        """Empty key should set MUMBOJUMBO_KEY to empty string."""
        script = tmp_path / 'test.sh'
        script.write_text('''#!/bin/bash
[ -z "$MUMBOJUMBO_KEY" ] && exit 0 || exit 1
''')
        script.chmod(0o755)

        handler = ExecuteHandler(str(script), timeout=5)
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'', b'value', timestamp)

        assert result is True


class TestBuildHandlers:
    """Test handler pipeline building."""

    def test_build_stdout_handler(self):
        """Should build StdoutHandler from config."""
        config = configparser.ConfigParser()
        handler_names = ['stdout']

        handlers = build_handlers(config, handler_names)

        assert len(handlers) == 1
        assert isinstance(handlers[0], StdoutHandler)

    def test_build_file_handler(self, tmp_path):
        """Should build FileHandler from config."""
        config = configparser.ConfigParser()
        config.add_section('file')
        config.set('file', 'path', str(tmp_path / 'test.log'))
        config.set('file', 'format', 'hex')

        handlers = build_handlers(config, ['file'])

        assert len(handlers) == 1
        assert isinstance(handlers[0], FileHandler)

    def test_build_execute_handler(self):
        """Should build ExecuteHandler from config."""
        config = configparser.ConfigParser()
        config.add_section('execute')
        config.set('execute', 'command', '/bin/true')
        config.set('execute', 'timeout', '30')

        handlers = build_handlers(config, ['execute'])

        assert len(handlers) == 1
        assert isinstance(handlers[0], ExecuteHandler)

    def test_build_multiple_handlers(self, tmp_path):
        """Should build multiple handlers in pipeline."""
        config = configparser.ConfigParser()
        config.add_section('file')
        config.set('file', 'path', str(tmp_path / 'test.log'))
        config.set('file', 'format', 'hex')

        handlers = build_handlers(config, ['stdout', 'file'])

        assert len(handlers) == 2
        assert isinstance(handlers[0], StdoutHandler)
        assert isinstance(handlers[1], FileHandler)

    def test_build_missing_section_exits(self):
        """Should exit if required section is missing."""
        config = configparser.ConfigParser()
        # No 'file' section

        with pytest.raises(SystemExit):
            build_handlers(config, ['file'])

    def test_build_unknown_handler_exits(self):
        """Should exit for unknown handler type."""
        config = configparser.ConfigParser()

        with pytest.raises(SystemExit):
            build_handlers(config, ['unknown'])


class TestGetDefaultInterface:
    """Test platform-specific default interface detection."""

    def test_returns_string(self):
        """Should return a string interface name."""
        interface = get_default_interface()
        assert isinstance(interface, str)
        assert len(interface) > 0


class TestValidateDomain:
    """Test domain validation."""

    def test_valid_domain(self):
        """Valid domain should pass."""
        valid, msg = validate_domain('.example.com')
        assert valid is True

    def test_missing_leading_dot(self):
        """Domain without leading dot should fail."""
        valid, msg = validate_domain('example.com')
        assert valid is False
        assert 'start with dot' in msg

    def test_domain_too_short(self):
        """Domain too short should fail."""
        valid, msg = validate_domain('.a')
        assert valid is False
        assert 'too short' in msg

    def test_domain_too_long(self):
        """Domain too long should fail."""
        valid, msg = validate_domain('.' + 'a' * 254)
        assert valid is False
        assert 'too long' in msg


class TestGetClientKeyHex:
    """Test client key generation."""

    def test_generates_mj_cli_prefix(self):
        """Generated key should have mj_cli_ prefix."""
        key = get_client_key_hex()
        assert key.startswith('mj_cli_')

    def test_generates_64_hex_chars(self):
        """Generated key should have 64 hex chars after prefix."""
        key = get_client_key_hex()
        hex_part = key[7:]  # Remove 'mj_cli_'
        assert len(hex_part) == 64
        # Verify it's valid hex
        bytes.fromhex(hex_part)

    def test_generates_unique_keys(self):
        """Each call should generate unique key."""
        key1 = get_client_key_hex()
        key2 = get_client_key_hex()
        assert key1 != key2
