#!/usr/bin/env python3
"""Test packet handlers - converted from unittest to pytest."""
import datetime
import os
import tempfile
from unittest.mock import Mock, patch

import pytest

from mumbojumbo import (
    ExecuteHandler,
    FileHandler,
    PacketHandler,
    SMTPForwarder,
    SMTPHandler,
    StdoutHandler,
)


class TestSMTPErrorHandling:
    """Test SMTP error handling to ensure robustness."""

    def test_port_type_conversion(self):
        """Test that port is converted to int."""
        forwarder = SMTPForwarder(
            server='localhost',
            port='587',  # String port
            from_='test@example.com',
            to='dest@example.com'
        )
        # SMTPForwarder now wraps SMTPHandler, check the inner handler
        assert isinstance(forwarder._handler._port, int)
        assert forwarder._handler._port == 587

    def test_connection_refused(self):
        """Test handling of connection refused errors."""
        import socket
        forwarder = SMTPForwarder(
            server='localhost',
            port=9999,  # Non-existent port
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = ConnectionRefusedError('Connection refused')
            result = forwarder.sendmail('Test', 'Test body')
            assert result is False

    def test_timeout_error(self):
        """Test handling of timeout errors."""
        import socket
        forwarder = SMTPForwarder(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = socket.timeout('Connection timed out')
            result = forwarder.sendmail('Test', 'Test body')
            assert result is False

    def test_auth_error(self):
        """Test handling of authentication errors."""
        import smtplib
        forwarder = SMTPForwarder(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com',
            username='baduser',
            password='badpass'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            mock_smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, 'Authentication failed')
            result = forwarder.sendmail('Test', 'Test body')
            assert result is False

    def test_recipient_refused(self):
        """Test handling of recipient refused errors."""
        import smtplib
        forwarder = SMTPForwarder(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='bad@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            mock_smtp.sendmail.side_effect = smtplib.SMTPRecipientsRefused({'bad@example.com': (550, 'User unknown')})
            result = forwarder.sendmail('Test', 'Test body')
            assert result is False

    def test_successful_send(self):
        """Test successful email sending."""
        forwarder = SMTPForwarder(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com',
            username='user',
            password='pass'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            result = forwarder.sendmail('Test Subject', 'Test body')
            assert result is True
            mock_smtp.sendmail.assert_called_once()
            mock_smtp.quit.assert_called()

    def test_dns_error(self):
        """Test handling of DNS resolution errors."""
        import socket
        forwarder = SMTPForwarder(
            server='nonexistent.invalid.domain.example',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = socket.gaierror('Name or service not known')
            result = forwarder.sendmail('Test', 'Test body')
            assert result is False


class TestPacketHandlers:
    """Test handler base class and concrete implementations."""

    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Set up test fixtures."""
        self.test_key = b'test_key'
        self.test_value = b'Test packet data'
        self.test_timestamp = datetime.datetime.now(datetime.timezone.utc)

    def test_handler_base_class_not_implemented(self):
        """Test that PacketHandler base class requires handle() implementation."""
        handler = PacketHandler()
        with pytest.raises(NotImplementedError):
            handler.handle(self.test_key, self.test_value, self.test_timestamp)

    def test_stdout_handler_success(self):
        """Test StdoutHandler outputs JSON successfully."""
        from io import StringIO
        import json
        import sys

        # Capture stdout
        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output

        try:
            handler = StdoutHandler()
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            # Check result
            assert result is True

            # Parse JSON output
            output = captured_output.getvalue().strip()
            data = json.loads(output)

            # Verify JSON structure
            assert data['event'] == 'packet_reassembled'
            assert data['key'] == self.test_key.decode('utf-8')
            assert data['value_length'] == len(self.test_value)
            assert 'value_preview' in data
            assert 'timestamp' in data

        finally:
            sys.stdout = original_stdout

    def test_stdout_handler_binary_data(self):
        """Test StdoutHandler handles binary data by converting to hex."""
        from io import StringIO
        import json
        import sys

        binary_data = b'\x00\x01\x02\xff'

        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output

        try:
            handler = StdoutHandler()
            result = handler.handle(self.test_key, binary_data, self.test_timestamp)

            assert result is True

            output = captured_output.getvalue().strip()
            data = json.loads(output)

            # Binary data should be hex-encoded in preview
            assert data['value_preview'] == binary_data.hex()

        finally:
            sys.stdout = original_stdout

    def test_stdout_handler_empty_data(self):
        """Test StdoutHandler handles empty data."""
        from io import StringIO
        import json
        import sys

        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output

        try:
            handler = StdoutHandler()
            result = handler.handle(b'', b'', self.test_timestamp)

            assert result is True

            output = captured_output.getvalue().strip()
            data = json.loads(output)

            assert data['value_length'] == 0
            assert data['value_preview'] == ''

        finally:
            sys.stdout = original_stdout

    def test_stdout_handler_large_data_truncation(self):
        """Test StdoutHandler truncates large data preview."""
        from io import StringIO
        import json
        import sys

        # Create data longer than 100 characters
        large_data = b'A' * 200

        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output

        try:
            handler = StdoutHandler()
            result = handler.handle(self.test_key, large_data, self.test_timestamp)

            assert result is True

            output = captured_output.getvalue().strip()
            data = json.loads(output)

            # Preview should be truncated to 100 chars + '...'
            assert len(data['value_preview']) == 103
            assert data['value_preview'].endswith('...')
            assert data['value_length'] == 200

        finally:
            sys.stdout = original_stdout

    def test_file_handler_hex_format(self):
        """Test FileHandler writes data in hex format."""
        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            handler = FileHandler(path=tmp_path, format='hex')
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is True

            # Read and verify file contents
            with open(tmp_path, 'r') as f:
                content = f.read()

            # Check header is present
            assert 'key: test_key' in content
            assert 'length: 16' in content
            assert 'format: hex' in content

            # Check data is hex-encoded
            assert self.test_value.hex() in content

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_file_handler_base64_format(self):
        """Test FileHandler writes data in base64 format."""
        import base64

        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            handler = FileHandler(path=tmp_path, format='base64')
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is True

            with open(tmp_path, 'r') as f:
                content = f.read()

            # Check data is base64-encoded
            expected_b64 = base64.b64encode(self.test_value).decode('ascii')
            assert expected_b64 in content
            assert 'format: base64' in content

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_file_handler_raw_format(self):
        """Test FileHandler writes data in raw format."""
        with tempfile.NamedTemporaryFile(mode='rb', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            handler = FileHandler(path=tmp_path, format='raw')
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is True

            with open(tmp_path, 'rb') as f:
                content = f.read()

            # Check raw data is present
            assert self.test_value in content
            # Header should also be present (as UTF-8)
            assert b'key: test_key' in content

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_file_handler_invalid_format(self):
        """Test FileHandler rejects invalid format."""
        with pytest.raises(ValueError) as exc_info:
            FileHandler(path='/tmp/test', format='invalid')
        assert 'Must be raw, hex, or base64' in str(exc_info.value)

    def test_file_handler_append_mode(self):
        """Test FileHandler appends to existing file."""
        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            handler = FileHandler(path=tmp_path, format='hex')

            # Write first packet
            handler.handle(b'key1', b'first', self.test_timestamp)

            # Write second packet
            handler.handle(b'key2', b'second', self.test_timestamp)

            # Verify both packets are in file
            with open(tmp_path, 'r') as f:
                content = f.read()

            assert 'first'.encode().hex() in content
            assert 'second'.encode().hex() in content
            assert 'key1' in content
            assert 'key2' in content

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_file_handler_empty_data(self):
        """Test FileHandler handles empty data."""
        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            handler = FileHandler(path=tmp_path, format='hex')
            result = handler.handle(b'', b'', self.test_timestamp)

            assert result is True

            with open(tmp_path, 'r') as f:
                content = f.read()

            assert 'length: 0' in content

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_file_handler_permission_error(self):
        """Test FileHandler handles file permission errors."""
        # Try to write to a read-only directory (that doesn't exist)
        handler = FileHandler(path='/nonexistent/path/file.txt', format='hex')
        result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

        assert result is False

    def test_file_handler_large_data(self):
        """Test FileHandler handles large data."""
        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Create 10MB of data
            large_data = b'X' * (10 * 1024 * 1024)

            handler = FileHandler(path=tmp_path, format='hex')
            result = handler.handle(self.test_key, large_data, self.test_timestamp)

            assert result is True

            with open(tmp_path, 'r') as f:
                content = f.read()

            assert 'length: 10485760' in content

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_execute_handler_success(self):
        """Test ExecuteHandler runs command successfully."""
        # Use a simple echo command that should work on Unix/Mac
        handler = ExecuteHandler(command='cat', timeout=5)
        result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

        assert result is True

    def test_execute_handler_with_env_vars(self):
        """Test ExecuteHandler passes environment variables."""
        # Create a script that echoes environment variables
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sh') as tmp:
            tmp.write('#!/bin/bash\n')
            tmp.write('echo "Query: $MUMBOJUMBO_QUERY"\n')
            tmp.write('echo "Length: $MUMBOJUMBO_LENGTH"\n')
            tmp.write('echo "Timestamp: $MUMBOJUMBO_TIMESTAMP"\n')
            tmp_path = tmp.name

        try:
            os.chmod(tmp_path, 0o755)

            handler = ExecuteHandler(command=tmp_path, timeout=5)
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is True

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_execute_handler_failure(self):
        """Test ExecuteHandler handles command failure."""
        # Use a command that will fail
        handler = ExecuteHandler(command='false', timeout=5)
        result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

        assert result is False

    def test_execute_handler_timeout(self):
        """Test ExecuteHandler handles timeout."""
        # Command that sleeps longer than timeout
        handler = ExecuteHandler(command='sleep 10', timeout=1)
        result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

        assert result is False

    def test_execute_handler_stdin(self):
        """Test ExecuteHandler passes data via stdin."""
        # Use a script that reads stdin
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sh') as tmp:
            tmp.write('#!/bin/bash\n')
            tmp.write('cat > /dev/null && echo "success"\n')  # Read stdin and succeed
            tmp_path = tmp.name

        try:
            os.chmod(tmp_path, 0o755)

            handler = ExecuteHandler(command=tmp_path, timeout=5)
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is True

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_execute_handler_empty_data(self):
        """Test ExecuteHandler handles empty data."""
        handler = ExecuteHandler(command='cat', timeout=5)
        result = handler.handle(b'', b'', self.test_timestamp)

        assert result is True

    def test_execute_handler_command_not_found(self):
        """Test ExecuteHandler handles command not found."""
        handler = ExecuteHandler(command='nonexistent_command_12345', timeout=5)
        result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

        assert result is False

    def test_execute_handler_large_stdin_data(self):
        """Test ExecuteHandler handles large data via stdin."""
        # Create 1MB of data
        large_data = b'Z' * (1024 * 1024)

        handler = ExecuteHandler(command='wc -c', timeout=10)
        result = handler.handle(self.test_key, large_data, self.test_timestamp)

        assert result is True

    def test_execute_handler_shell_special_chars(self):
        """Test ExecuteHandler handles shell special characters safely."""
        # Create script that echoes the data length from environment
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sh') as tmp:
            tmp.write('#!/bin/bash\n')
            tmp.write('test -n "$MUMBOJUMBO_VALUE_LENGTH" && exit 0 || exit 1\n')
            tmp_path = tmp.name

        try:
            os.chmod(tmp_path, 0o755)

            # Use data with special characters
            special_data = b'test; echo "injected"; #'

            handler = ExecuteHandler(command=tmp_path, timeout=5)
            result = handler.handle(self.test_key, special_data, self.test_timestamp)

            assert result is True

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_smtp_handler_with_mock(self):
        """Test SMTPHandler with mocked SMTP connection."""
        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com',
            starttls=True,
            username='user',
            password='pass'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp

            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is True
            mock_smtp.sendmail.assert_called_once()
            mock_smtp.quit.assert_called()

    def test_smtp_handler_connection_error(self):
        """Test SMTPHandler handles connection errors gracefully."""
        import socket

        handler = SMTPHandler(
            server='localhost',
            port=9999,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp:
            mock_smtp.side_effect = ConnectionRefusedError('Connection refused')
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is False

    def test_smtp_handler_sender_refused(self):
        """Test SMTPHandler handles sender refused errors."""
        import smtplib

        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='invalid@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            mock_smtp.sendmail.side_effect = smtplib.SMTPSenderRefused(550, 'Sender refused', 'invalid@example.com')
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is False

    def test_smtp_handler_data_error(self):
        """Test SMTPHandler handles data errors."""
        import smtplib

        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            mock_smtp.sendmail.side_effect = smtplib.SMTPDataError(550, 'Message too large')
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is False

    def test_smtp_handler_general_smtp_exception(self):
        """Test SMTPHandler handles general SMTP exceptions."""
        import smtplib

        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            mock_smtp.sendmail.side_effect = smtplib.SMTPException('General SMTP error')
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is False

    def test_smtp_handler_binary_data(self):
        """Test SMTPHandler handles binary data by converting to hex."""
        binary_data = b'\x00\x01\x02\xff'

        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            result = handler.handle(self.test_key, binary_data, self.test_timestamp)

            assert result is True
            # Verify sendmail was called with hex-encoded data
            call_args = mock_smtp.sendmail.call_args
            message_body = call_args[0][2]
            assert binary_data.hex() in message_body

    def test_smtp_handler_empty_data(self):
        """Test SMTPHandler handles empty data."""
        handler = SMTPHandler(
            server='localhost',
            port=587,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            result = handler.handle(b'', b'', self.test_timestamp)

            assert result is True
            mock_smtp.sendmail.assert_called_once()

    def test_smtp_handler_no_starttls(self):
        """Test SMTPHandler works without STARTTLS."""
        handler = SMTPHandler(
            server='localhost',
            port=25,
            from_='test@example.com',
            to='dest@example.com',
            starttls=False
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is True
            # Verify starttls was not called
            mock_smtp.starttls.assert_not_called()

    def test_smtp_handler_no_auth(self):
        """Test SMTPHandler works without authentication."""
        handler = SMTPHandler(
            server='localhost',
            port=25,
            from_='test@example.com',
            to='dest@example.com'
        )

        with patch('smtplib.SMTP') as mock_smtp_class:
            mock_smtp = Mock()
            mock_smtp_class.return_value = mock_smtp
            result = handler.handle(self.test_key, self.test_value, self.test_timestamp)

            assert result is True
            # Verify login was not called
            mock_smtp.login.assert_not_called()
