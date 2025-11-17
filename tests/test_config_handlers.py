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
    PacketLogHandler,
    ExecuteHandler,
    FilteredHandler,
    build_handlers,
    get_default_interface,
    __config_skel__,
    get_client_key_hex,
    validate_domain,
)


class TestConfigSkeleton:
    """Test config skeleton generation."""

    def test_config_skeleton_has_all_sections(self):
        """Config skeleton should have main, smtp, file, packetlog, execute sections."""
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
        assert config.has_section('packetlog')
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
        """File section should have output-dir."""
        config_content = __config_skel__.format(
            client_key='mj_cli_' + '00' * 32,
            domain='.test.example.com',
            network_interface='en0'
        )

        config = configparser.ConfigParser(allow_no_value=True)
        config.read_string(config_content)

        assert config.has_option('file', 'output-dir')

    def test_config_skeleton_packetlog_section_fields(self):
        """Packetlog section should have path and format."""
        config_content = __config_skel__.format(
            client_key='mj_cli_' + '00' * 32,
            domain='.test.example.com',
            network_interface='en0'
        )

        config = configparser.ConfigParser(allow_no_value=True)
        config.read_string(config_content)

        assert config.has_option('packetlog', 'path')
        assert config.has_option('packetlog', 'format')

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


class TestPacketLogHandler:
    """Test PacketLogHandler functionality."""

    def test_init_invalid_format_raises(self):
        """PacketLogHandler should reject invalid formats."""
        with pytest.raises(ValueError) as exc_info:
            PacketLogHandler('/tmp/test.log', format='invalid')
        assert 'Invalid format' in str(exc_info.value)

    def test_handle_hex_format(self, tmp_path):
        """PacketLogHandler should write hex format correctly."""
        log_file = tmp_path / 'test.log'
        handler = PacketLogHandler(str(log_file), format='hex')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'key', b'\xde\xad\xbe\xef', timestamp)

        assert result is True
        content = log_file.read_text()
        assert 'deadbeef' in content
        assert 'format: hex' in content

    def test_handle_base64_format(self, tmp_path):
        """PacketLogHandler should write base64 format correctly."""
        log_file = tmp_path / 'test.log'
        handler = PacketLogHandler(str(log_file), format='base64')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'key', b'\xde\xad\xbe\xef', timestamp)

        assert result is True
        content = log_file.read_text()
        # base64 of deadbeef is 3q2+7w==
        assert '3q2+7w==' in content
        assert 'format: base64' in content

    def test_handle_raw_format(self, tmp_path):
        """PacketLogHandler should write raw format correctly."""
        log_file = tmp_path / 'test.log'
        handler = PacketLogHandler(str(log_file), format='raw')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'key', b'raw data', timestamp)

        assert result is True
        content = log_file.read_bytes()
        assert b'raw data' in content

    def test_handle_appends_to_file(self, tmp_path):
        """PacketLogHandler should append to existing file."""
        log_file = tmp_path / 'test.log'
        handler = PacketLogHandler(str(log_file), format='hex')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        handler.handle(b'key1', b'value1', timestamp)
        handler.handle(b'key2', b'value2', timestamp)

        content = log_file.read_text()
        assert 'key1' in content
        assert 'key2' in content

    def test_handle_empty_key_shows_null(self, tmp_path):
        """Empty key should display as (null)."""
        log_file = tmp_path / 'test.log'
        handler = PacketLogHandler(str(log_file), format='hex')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        handler.handle(b'', b'value', timestamp)

        content = log_file.read_text()
        assert '(null)' in content

    def test_handle_io_error_returns_false(self):
        """PacketLogHandler should return False on I/O error."""
        handler = PacketLogHandler('/nonexistent/path/test.log', format='hex')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'key', b'value', timestamp)

        assert result is False


class TestFileHandler:
    """Test FileHandler functionality for receiving files from clients."""

    def test_init_creates_output_dir(self, tmp_path):
        """FileHandler should create output directory if it doesn't exist."""
        output_dir = tmp_path / 'new_dir'
        assert not output_dir.exists()

        handler = FileHandler(str(output_dir))

        assert output_dir.exists()
        assert output_dir.is_dir()

    def test_handle_writes_file(self, tmp_path):
        """FileHandler should write file with correct content."""
        output_dir = tmp_path / 'files'
        handler = FileHandler(str(output_dir))
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'file://test.txt', b'Hello, World!', timestamp)

        assert result is True
        written_file = output_dir / 'test.txt'
        assert written_file.exists()
        assert written_file.read_bytes() == b'Hello, World!'

    def test_handle_creates_subdirectories(self, tmp_path):
        """FileHandler should create subdirectories as needed."""
        output_dir = tmp_path / 'files'
        handler = FileHandler(str(output_dir))
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'file://subdir/nested/file.txt', b'nested content', timestamp)

        assert result is True
        written_file = output_dir / 'subdir' / 'nested' / 'file.txt'
        assert written_file.exists()
        assert written_file.read_bytes() == b'nested content'

    def test_handle_blocks_path_traversal_dotdot(self, tmp_path):
        """FileHandler should block path traversal with .. in filename."""
        output_dir = tmp_path / 'files'
        handler = FileHandler(str(output_dir))
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'file://../../../etc/passwd', b'malicious', timestamp)

        assert result is False
        # Ensure no file was created outside output_dir
        assert not (tmp_path / 'etc').exists()

    def test_handle_blocks_absolute_path(self, tmp_path):
        """FileHandler should block absolute paths."""
        output_dir = tmp_path / 'files'
        handler = FileHandler(str(output_dir))
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'file:///etc/passwd', b'malicious', timestamp)

        assert result is False

    def test_handle_rejects_non_file_prefix(self, tmp_path):
        """FileHandler should reject keys without file:// prefix."""
        output_dir = tmp_path / 'files'
        handler = FileHandler(str(output_dir))
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'data.txt', b'content', timestamp)

        assert result is False

    def test_handle_rejects_empty_filename(self, tmp_path):
        """FileHandler should reject empty filename after prefix."""
        output_dir = tmp_path / 'files'
        handler = FileHandler(str(output_dir))
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'file://', b'content', timestamp)

        assert result is False

    def test_handle_rejects_invalid_utf8_key(self, tmp_path):
        """FileHandler should reject non-UTF-8 keys."""
        output_dir = tmp_path / 'files'
        handler = FileHandler(str(output_dir))
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = handler.handle(b'\xff\xfe\xfd', b'content', timestamp)

        assert result is False

    def test_handle_binary_content(self, tmp_path):
        """FileHandler should handle binary file content."""
        output_dir = tmp_path / 'files'
        handler = FileHandler(str(output_dir))
        timestamp = datetime.datetime.now(datetime.timezone.utc)
        binary_data = bytes(range(256))

        result = handler.handle(b'file://binary.bin', binary_data, timestamp)

        assert result is True
        written_file = output_dir / 'binary.bin'
        assert written_file.read_bytes() == binary_data

    def test_handle_overwrites_existing_file(self, tmp_path):
        """FileHandler should overwrite existing files."""
        output_dir = tmp_path / 'files'
        handler = FileHandler(str(output_dir))
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        handler.handle(b'file://test.txt', b'original', timestamp)
        result = handler.handle(b'file://test.txt', b'updated', timestamp)

        assert result is True
        written_file = output_dir / 'test.txt'
        assert written_file.read_bytes() == b'updated'


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
        config.set('file', 'output-dir', str(tmp_path / 'files'))

        handlers = build_handlers(config, ['file'])

        assert len(handlers) == 1
        assert isinstance(handlers[0], FileHandler)

    def test_build_packetlog_handler(self, tmp_path):
        """Should build PacketLogHandler from config."""
        config = configparser.ConfigParser()
        config.add_section('packetlog')
        config.set('packetlog', 'path', str(tmp_path / 'test.log'))
        config.set('packetlog', 'format', 'hex')

        handlers = build_handlers(config, ['packetlog'])

        assert len(handlers) == 1
        assert isinstance(handlers[0], PacketLogHandler)

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
        config.add_section('packetlog')
        config.set('packetlog', 'path', str(tmp_path / 'test.log'))
        config.set('packetlog', 'format', 'hex')

        handlers = build_handlers(config, ['stdout', 'packetlog'])

        assert len(handlers) == 2
        assert isinstance(handlers[0], StdoutHandler)
        assert isinstance(handlers[1], PacketLogHandler)

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


class TestFilteredHandler:
    """Test FilteredHandler wrapper functionality."""

    def test_matching_key_passes_through(self, capsys):
        """Matching key should be passed to underlying handler."""
        inner_handler = StdoutHandler()
        filtered = FilteredHandler(inner_handler, 'sensor_*')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = filtered.handle(b'sensor_temperature', b'25.5', timestamp)

        assert result is True
        captured = capsys.readouterr()
        assert '"key": "sensor_temperature"' in captured.out

    def test_non_matching_key_skipped(self, capsys):
        """Non-matching key should be skipped."""
        inner_handler = StdoutHandler()
        filtered = FilteredHandler(inner_handler, 'sensor_*')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = filtered.handle(b'log_error', b'some error', timestamp)

        assert result is True  # Returns True to indicate "handled" (skipped)
        captured = capsys.readouterr()
        assert captured.out == ''  # No output

    def test_glob_star_pattern(self, capsys):
        """Test * glob pattern matches any characters."""
        inner_handler = StdoutHandler()
        filtered = FilteredHandler(inner_handler, '*debug*')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Should match
        result = filtered.handle(b'app_debug_log', b'value', timestamp)
        assert result is True
        captured = capsys.readouterr()
        assert '"key": "app_debug_log"' in captured.out

        # Should not match
        result = filtered.handle(b'app_info_log', b'value', timestamp)
        captured = capsys.readouterr()
        assert captured.out == ''

    def test_glob_question_mark_pattern(self, capsys):
        """Test ? glob pattern matches single character."""
        inner_handler = StdoutHandler()
        filtered = FilteredHandler(inner_handler, 'log_?')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Should match
        result = filtered.handle(b'log_1', b'value', timestamp)
        captured = capsys.readouterr()
        assert '"key": "log_1"' in captured.out

        # Should not match (too long)
        result = filtered.handle(b'log_12', b'value', timestamp)
        captured = capsys.readouterr()
        assert captured.out == ''

    def test_glob_bracket_pattern(self, capsys):
        """Test [seq] glob pattern matches character in sequence."""
        inner_handler = StdoutHandler()
        filtered = FilteredHandler(inner_handler, 'data_[abc]')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Should match
        result = filtered.handle(b'data_a', b'value', timestamp)
        captured = capsys.readouterr()
        assert '"key": "data_a"' in captured.out

        # Should not match
        result = filtered.handle(b'data_d', b'value', timestamp)
        captured = capsys.readouterr()
        assert captured.out == ''

    def test_glob_negated_bracket_pattern(self, capsys):
        """Test [!seq] glob pattern matches character not in sequence."""
        inner_handler = StdoutHandler()
        filtered = FilteredHandler(inner_handler, 'key_[!0-9]')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Should match (letter, not digit)
        result = filtered.handle(b'key_a', b'value', timestamp)
        captured = capsys.readouterr()
        assert '"key": "key_a"' in captured.out

        # Should not match (digit)
        result = filtered.handle(b'key_5', b'value', timestamp)
        captured = capsys.readouterr()
        assert captured.out == ''

    def test_utf8_key_decoding(self, capsys):
        """Test that UTF-8 keys are properly decoded for pattern matching."""
        inner_handler = StdoutHandler()
        filtered = FilteredHandler(inner_handler, 'café_*')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Should match UTF-8 key
        result = filtered.handle('café_order'.encode('utf-8'), b'latte', timestamp)
        captured = capsys.readouterr()
        # JSON escapes non-ASCII, so check for either form
        assert 'caf' in captured.out and 'order' in captured.out
        assert result is True

    def test_invalid_utf8_key_uses_replacement(self, capsys):
        """Test that invalid UTF-8 bytes use replacement character."""
        inner_handler = StdoutHandler()
        filtered = FilteredHandler(inner_handler, '*')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Invalid UTF-8 should still be handled (with replacement char)
        result = filtered.handle(b'\xff\xfe', b'value', timestamp)
        assert result is True
        captured = capsys.readouterr()
        assert captured.out != ''  # Should output something

    def test_empty_key_matches_empty_pattern(self, capsys):
        """Test that empty key matches empty pattern or * pattern."""
        inner_handler = StdoutHandler()
        filtered = FilteredHandler(inner_handler, '*')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = filtered.handle(b'', b'value', timestamp)
        captured = capsys.readouterr()
        assert '"key": null' in captured.out

    def test_exact_match_pattern(self, capsys):
        """Test exact match without wildcards."""
        inner_handler = StdoutHandler()
        filtered = FilteredHandler(inner_handler, 'exact_key')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Should match
        result = filtered.handle(b'exact_key', b'value', timestamp)
        captured = capsys.readouterr()
        assert '"key": "exact_key"' in captured.out

        # Should not match
        result = filtered.handle(b'exact_key_2', b'value', timestamp)
        captured = capsys.readouterr()
        assert captured.out == ''

    def test_handler_return_value_propagated(self):
        """Test that underlying handler's return value is propagated."""
        # Use ExecuteHandler that returns False on failure
        inner_handler = ExecuteHandler('exit 1', timeout=1)
        filtered = FilteredHandler(inner_handler, '*')
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        result = filtered.handle(b'key', b'value', timestamp)
        assert result is False  # Propagated from inner handler


class TestBuildHandlersWithKeyFilter:
    """Test handler pipeline building with key-filter support."""

    def test_build_stdout_with_key_filter(self):
        """Should wrap StdoutHandler with FilteredHandler when key-filter specified."""
        config = configparser.ConfigParser()
        config.add_section('stdout')
        config.set('stdout', 'key-filter', 'sensor_*')

        handlers = build_handlers(config, ['stdout'])

        assert len(handlers) == 1
        assert isinstance(handlers[0], FilteredHandler)
        assert isinstance(handlers[0]._handler, StdoutHandler)
        assert handlers[0]._pattern == 'sensor_*'

    def test_build_file_with_key_filter(self, tmp_path):
        """Should wrap FileHandler with FilteredHandler when key-filter specified."""
        config = configparser.ConfigParser()
        config.add_section('file')
        config.set('file', 'output-dir', str(tmp_path / 'files'))
        config.set('file', 'key-filter', 'file://*')

        handlers = build_handlers(config, ['file'])

        assert len(handlers) == 1
        assert isinstance(handlers[0], FilteredHandler)
        assert isinstance(handlers[0]._handler, FileHandler)
        assert handlers[0]._pattern == 'file://*'

    def test_build_packetlog_with_key_filter(self, tmp_path):
        """Should wrap PacketLogHandler with FilteredHandler when key-filter specified."""
        config = configparser.ConfigParser()
        config.add_section('packetlog')
        config.set('packetlog', 'path', str(tmp_path / 'test.log'))
        config.set('packetlog', 'format', 'hex')
        config.set('packetlog', 'key-filter', '*debug*')

        handlers = build_handlers(config, ['packetlog'])

        assert len(handlers) == 1
        assert isinstance(handlers[0], FilteredHandler)
        assert isinstance(handlers[0]._handler, PacketLogHandler)
        assert handlers[0]._pattern == '*debug*'

    def test_build_execute_with_key_filter(self):
        """Should wrap ExecuteHandler with FilteredHandler when key-filter specified."""
        config = configparser.ConfigParser()
        config.add_section('execute')
        config.set('execute', 'command', '/bin/true')
        config.set('execute', 'timeout', '30')
        config.set('execute', 'key-filter', 'alert_*')

        handlers = build_handlers(config, ['execute'])

        assert len(handlers) == 1
        assert isinstance(handlers[0], FilteredHandler)
        assert isinstance(handlers[0]._handler, ExecuteHandler)
        assert handlers[0]._pattern == 'alert_*'

    def test_build_handler_without_key_filter(self, tmp_path):
        """Handler without key-filter should not be wrapped."""
        config = configparser.ConfigParser()
        config.add_section('packetlog')
        config.set('packetlog', 'path', str(tmp_path / 'test.log'))
        config.set('packetlog', 'format', 'hex')
        # No key-filter

        handlers = build_handlers(config, ['packetlog'])

        assert len(handlers) == 1
        assert isinstance(handlers[0], PacketLogHandler)
        assert not isinstance(handlers[0], FilteredHandler)

    def test_build_multiple_handlers_with_different_filters(self, tmp_path):
        """Multiple handlers can have different key filters."""
        config = configparser.ConfigParser()
        config.add_section('stdout')
        config.set('stdout', 'key-filter', 'sensor_*')
        config.add_section('packetlog')
        config.set('packetlog', 'path', str(tmp_path / 'test.log'))
        config.set('packetlog', 'format', 'hex')
        config.set('packetlog', 'key-filter', '*debug*')
        config.add_section('execute')
        config.set('execute', 'command', '/bin/true')
        config.set('execute', 'timeout', '30')
        # No key-filter for execute

        handlers = build_handlers(config, ['stdout', 'packetlog', 'execute'])

        assert len(handlers) == 3
        # stdout - filtered
        assert isinstance(handlers[0], FilteredHandler)
        assert handlers[0]._pattern == 'sensor_*'
        # packetlog - filtered
        assert isinstance(handlers[1], FilteredHandler)
        assert handlers[1]._pattern == '*debug*'
        # execute - not filtered
        assert isinstance(handlers[2], ExecuteHandler)
        assert not isinstance(handlers[2], FilteredHandler)

    def test_functional_key_filtering(self, capsys, tmp_path):
        """Test that key filtering actually works in pipeline."""
        config = configparser.ConfigParser()
        config.add_section('stdout')
        config.set('stdout', 'key-filter', 'sensor_*')

        handlers = build_handlers(config, ['stdout'])
        timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Should be processed
        handlers[0].handle(b'sensor_temp', b'25', timestamp)
        captured = capsys.readouterr()
        assert '"key": "sensor_temp"' in captured.out

        # Should be skipped
        handlers[0].handle(b'log_error', b'err', timestamp)
        captured = capsys.readouterr()
        assert captured.out == ''
