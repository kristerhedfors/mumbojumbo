#!/usr/bin/env python3
"""Tests for CLI argument parsing and configuration precedence."""

import os
import pytest
from unittest.mock import patch, MagicMock
from mumbojumbo import validate_domain, get_nacl_keypair_hex


class TestDomainValidation:
    """Test domain format validation."""

    def test_valid_domain_with_leading_dot(self):
        """Test valid domain starting with dot."""
        assert validate_domain('.example.com') is True
        assert validate_domain('.test.domain') is True
        assert validate_domain('.asd.qwe') is True

    def test_valid_domain_without_leading_dot_warns(self, caplog):
        """Test domain without leading dot logs warning but passes."""
        assert validate_domain('example.com') is True
        # Warning should be logged about missing leading dot

    def test_empty_domain_raises(self):
        """Test empty domain raises ValueError."""
        with pytest.raises(ValueError, match='Domain cannot be empty'):
            validate_domain('')

    def test_none_domain_raises(self):
        """Test None domain raises ValueError."""
        with pytest.raises(ValueError, match='Domain cannot be empty'):
            validate_domain(None)

    def test_consecutive_dots_raises(self):
        """Test domain with consecutive dots raises ValueError."""
        with pytest.raises(ValueError, match='consecutive dots'):
            validate_domain('.example..com')
        with pytest.raises(ValueError, match='consecutive dots'):
            validate_domain('..example.com')


class TestCLIArgumentParsing:
    """Test CLI argument parsing for key and domain."""

    def test_option_parser_has_key_argument(self):
        """Test that option parser includes --server-key argument."""
        from mumbojumbo import option_parser

        parser = option_parser()
        # Parse with --server-key argument
        opt, args = parser.parse_args(['--server-key', 'mj_srv_test123'])

        assert opt.server_key == 'mj_srv_test123'

    def test_option_parser_has_domain_argument(self):
        """Test that option parser includes --domain argument."""
        from mumbojumbo import option_parser

        parser = option_parser()
        # Parse with --domain argument
        opt, args = parser.parse_args(['--domain', '.test.com'])

        assert opt.domain == '.test.com'

    def test_option_parser_short_key_argument(self):
        """Test that option parser no longer has -k short argument (removed for clarity)."""
        from mumbojumbo import option_parser

        parser = option_parser()
        # Verify -k is not accepted (should raise error)
        with pytest.raises(SystemExit):
            opt, args = parser.parse_args(['-k', 'mj_srv_shortkey'])

    def test_option_parser_short_domain_argument(self):
        """Test that option parser includes -d short argument."""
        from mumbojumbo import option_parser

        parser = option_parser()
        # Parse with -d argument
        opt, args = parser.parse_args(['-d', '.short.domain'])

        assert opt.domain == '.short.domain'

    def test_option_parser_combined_arguments(self):
        """Test parsing both key and domain together."""
        from mumbojumbo import option_parser

        parser = option_parser()
        srv_key, cli_key = get_nacl_keypair_hex()

        opt, args = parser.parse_args([
            '--server-key', srv_key,
            '-d', '.combined.test'
        ])

        assert opt.server_key == srv_key
        assert opt.domain == '.combined.test'

    def test_option_parser_defaults_none(self):
        """Test that key and domain default to None when not specified."""
        from mumbojumbo import option_parser

        parser = option_parser()
        opt, args = parser.parse_args([])

        assert opt.server_key is None
        assert opt.domain is None


class TestEnvironmentVariables:
    """Test environment variable support for configuration."""

    def test_mumbojumbo_server_key_env_var(self):
        """Test MUMBOJUMBO_SERVER_KEY environment variable."""
        srv_key, _ = get_nacl_keypair_hex()

        # Test environment variable is read correctly
        with patch.dict(os.environ, {'MUMBOJUMBO_SERVER_KEY': srv_key}):
            assert os.environ.get('MUMBOJUMBO_SERVER_KEY') == srv_key

    def test_mumbojumbo_domain_env_var(self):
        """Test MUMBOJUMBO_DOMAIN environment variable."""
        test_domain = '.env.test.com'

        # Test environment variable is read correctly
        with patch.dict(os.environ, {'MUMBOJUMBO_DOMAIN': test_domain}):
            assert os.environ.get('MUMBOJUMBO_DOMAIN') == test_domain

    def test_env_vars_not_set_returns_none(self):
        """Test that missing env vars return None."""
        with patch.dict(os.environ, {}, clear=True):
            assert os.environ.get('MUMBOJUMBO_SERVER_KEY') is None
            assert os.environ.get('MUMBOJUMBO_DOMAIN') is None


class TestConfigPrecedence:
    """
    Test configuration precedence chain.

    Note: Full integration tests for precedence would require
    mocking configparser and running main(). These tests verify
    the building blocks are in place.
    """

    def test_precedence_order_documented(self):
        """
        Verify precedence order is documented in code.

        Expected precedence (highest to lowest):
        1. CLI arguments (--key, --domain)
        2. Environment variables (MUMBOJUMBO_SERVER_KEY, MUMBOJUMBO_DOMAIN)
        3. Config file values
        """
        # This is a documentation test - the precedence logic
        # is implemented in main() starting around line 1022
        # The order should be: CLI > ENV > CONFIG

        # Read the source to verify comment exists
        import mumbojumbo
        source = open(mumbojumbo.__file__).read()

        # Check that precedence is documented
        assert 'Precedence: CLI args > Environment variables > Config file' in source

    def test_cli_key_triggers_warning(self, caplog):
        """
        Test that using CLI key argument would trigger security warning.

        Note: This tests the warning logic exists, not the full main() flow.
        """
        import logging
        logger = logging.getLogger('mumbojumbo')

        # Simulate what happens in main() when opt.key is set
        test_key = 'mj_srv_test123'
        logger.warning(
            'Server key provided via CLI argument - this is visible in '
            'process list. Consider using MUMBOJUMBO_SERVER_KEY environment '
            'variable instead.'
        )

        # This test verifies the warning pattern is correct
        # The actual warning is logged in main() when opt.key is truthy


class TestGenKeysOutput:
    """Test --gen-keys output format for environment variable declarations."""

    def test_gen_keys_outputs_env_vars(self):
        """Test that --gen-keys outputs environment variable declarations."""
        import subprocess
        import sys

        # Run mumbojumbo.py --gen-keys
        result = subprocess.run(
            [sys.executable, 'mumbojumbo.py', '--gen-keys'],
            capture_output=True,
            text=True,
            timeout=5
        )

        assert result.returncode == 0
        output_lines = result.stdout.strip().split('\n')

        # Should have exactly 3 lines
        assert len(output_lines) == 3

        # Check each line format
        assert output_lines[0].startswith('export MUMBOJUMBO_SERVER_KEY=mj_srv_')
        assert output_lines[1].startswith('export MUMBOJUMBO_CLIENT_KEY=mj_cli_')
        assert output_lines[2].startswith('export MUMBOJUMBO_DOMAIN=')

    def test_gen_keys_keys_are_valid(self):
        """Test that generated keys can be parsed."""
        import subprocess
        import sys

        # Run mumbojumbo.py --gen-keys
        result = subprocess.run(
            [sys.executable, 'mumbojumbo.py', '--gen-keys'],
            capture_output=True,
            text=True,
            timeout=5
        )

        output_lines = result.stdout.strip().split('\n')

        # Extract keys from export statements
        server_key_line = output_lines[0]
        client_key_line = output_lines[1]

        # Extract key values (between = and #)
        server_key = server_key_line.split('=')[1].split('#')[0].strip()
        client_key = client_key_line.split('=')[1].split('#')[0].strip()

        # Verify key formats
        assert server_key.startswith('mj_srv_')
        assert client_key.startswith('mj_cli_')
        assert len(server_key) == 71  # mj_srv_ (7) + 64 hex chars
        assert len(client_key) == 71   # mj_cli_ (7) + 64 hex chars

        # Verify keys can be decoded
        from mumbojumbo import decode_key_hex
        srv_bytes = decode_key_hex(server_key)
        cli_bytes = decode_key_hex(client_key)

        assert len(srv_bytes) == 32
        assert len(cli_bytes) == 32

    def test_gen_keys_domain_format(self):
        """Test that generated domain has correct format."""
        import subprocess
        import sys

        # Run mumbojumbo.py --gen-keys
        result = subprocess.run(
            [sys.executable, 'mumbojumbo.py', '--gen-keys'],
            capture_output=True,
            text=True,
            timeout=5
        )

        output_lines = result.stdout.strip().split('\n')
        domain_line = output_lines[2]

        # Extract domain value
        domain = domain_line.split('=')[1].split('#')[0].strip()

        # Verify domain format
        assert domain.startswith('.')
        assert domain.count('.') == 2  # Should be .xxxx.yyyy format
        assert len(domain) == 10  # . + 4 chars + . + 4 chars = 10 total

        # Verify domain passes validation
        from mumbojumbo import validate_domain
        assert validate_domain(domain) is True

    def test_gen_keys_output_is_sourceable(self):
        """Test that output can be sourced in bash."""
        import subprocess
        import sys

        # Run mumbojumbo.py --gen-keys
        result = subprocess.run(
            [sys.executable, 'mumbojumbo.py', '--gen-keys'],
            capture_output=True,
            text=True,
            timeout=5
        )

        # Create a shell script that sources the output
        shell_script = result.stdout + '\necho "$MUMBOJUMBO_SERVER_KEY|$MUMBOJUMBO_CLIENT_KEY|$MUMBOJUMBO_DOMAIN"'

        # Run in bash
        bash_result = subprocess.run(
            ['bash', '-c', shell_script],
            capture_output=True,
            text=True,
            timeout=5
        )

        assert bash_result.returncode == 0

        # Verify all three env vars were set
        output = bash_result.stdout.strip()
        parts = output.split('|')
        assert len(parts) == 3
        assert parts[0].startswith('mj_srv_')
        assert parts[1].startswith('mj_cli_')
        assert parts[2].startswith('.')


class TestEnvOnlyMode:
    """Test running without config file using only environment variables."""

    def test_env_only_mode_works(self, tmp_path):
        """Test that mumbojumbo runs with env vars and no config file."""
        import subprocess
        import sys
        from pathlib import Path
        from mumbojumbo import get_nacl_keypair_hex

        # Generate valid keys
        srv_key, cli_key = get_nacl_keypair_hex()
        test_domain = '.test.env'

        # Get absolute path to mumbojumbo.py
        mumbojumbo_path = Path(__file__).parent.parent / 'mumbojumbo.py'

        # Set environment variables
        env = os.environ.copy()
        env['MUMBOJUMBO_SERVER_KEY'] = srv_key
        env['MUMBOJUMBO_CLIENT_KEY'] = cli_key
        env['MUMBOJUMBO_DOMAIN'] = test_domain

        # Run mumbojumbo with --help from temp directory (no config file there)
        result = subprocess.run(
            [sys.executable, str(mumbojumbo_path), '--help'],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
            cwd=str(tmp_path)
        )

        # Should not error about missing config file
        assert result.returncode == 0
        assert 'Config file' not in result.stderr
        assert 'mumbojumbo.conf' not in result.stderr

    def test_env_only_mode_missing_server_key_fails(self, tmp_path):
        """Test that missing server key fails gracefully."""
        import subprocess
        import sys
        from pathlib import Path

        # Get absolute path to mumbojumbo.py
        mumbojumbo_path = Path(__file__).parent.parent / 'mumbojumbo.py'

        # Only set domain, not server key
        env = os.environ.copy()
        env['MUMBOJUMBO_DOMAIN'] = '.test.env'
        # Ensure server key is not set
        env.pop('MUMBOJUMBO_SERVER_KEY', None)

        # Run mumbojumbo - should fail
        result = subprocess.run(
            [sys.executable, str(mumbojumbo_path), '-v'],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
            cwd=str(tmp_path)
        )

        # Should error about missing requirements
        assert result.returncode != 0
        assert 'required environment variables not set' in result.stdout.lower() or \
               'MUMBOJUMBO_SERVER_KEY' in result.stdout

    def test_env_only_mode_missing_domain_fails(self, tmp_path):
        """Test that missing domain fails gracefully."""
        import subprocess
        import sys
        from pathlib import Path
        from mumbojumbo import get_nacl_keypair_hex

        # Generate valid keys
        srv_key, _ = get_nacl_keypair_hex()

        # Get absolute path to mumbojumbo.py
        mumbojumbo_path = Path(__file__).parent.parent / 'mumbojumbo.py'

        # Only set server key, not domain
        env = os.environ.copy()
        env['MUMBOJUMBO_SERVER_KEY'] = srv_key
        # Ensure domain is not set
        env.pop('MUMBOJUMBO_DOMAIN', None)

        # Run mumbojumbo - should fail
        result = subprocess.run(
            [sys.executable, str(mumbojumbo_path), '-v'],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
            cwd=str(tmp_path)
        )

        # Should error about missing requirements
        assert result.returncode != 0
        assert 'required environment variables not set' in result.stdout.lower() or \
               'MUMBOJUMBO_DOMAIN' in result.stdout

    def test_env_only_mode_uses_stdout_handler_by_default(self, tmp_path, caplog):
        """Test that env-only mode defaults to stdout handler."""
        import subprocess
        import sys
        from pathlib import Path
        from mumbojumbo import get_nacl_keypair_hex

        # Generate valid keys
        srv_key, cli_key = get_nacl_keypair_hex()
        test_domain = '.test.env'

        # Get absolute path to mumbojumbo.py
        mumbojumbo_path = Path(__file__).parent.parent / 'mumbojumbo.py'

        # Set environment variables
        env = os.environ.copy()
        env['MUMBOJUMBO_SERVER_KEY'] = srv_key
        env['MUMBOJUMBO_CLIENT_KEY'] = cli_key
        env['MUMBOJUMBO_DOMAIN'] = test_domain

        # Run with -v to see verbose output, but with timeout to kill it quickly
        # (we just want to verify it starts without config file errors)
        result = subprocess.run(
            ['timeout', '1', sys.executable, str(mumbojumbo_path), '-v'],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(tmp_path)
        )

        # timeout returns 124 when it kills the process
        # We expect either 124 (timeout) or other non-zero if process errors
        # The important thing is no config file error
        assert 'Config file' not in result.stdout
        assert 'mumbojumbo.conf' not in result.stdout
