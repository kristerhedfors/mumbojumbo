#!/usr/bin/env python3
"""Test handler pipeline integration."""

import datetime
import json
import os
import sys
import tempfile
from io import StringIO

from mumbojumbo import StdoutHandler, FileHandler, ExecuteHandler


class TestHandlerPipeline:
    """Test handler pipeline integration."""

    def test_multiple_handlers_in_sequence(self):
        """Test running multiple handlers in sequence."""
        test_key = b'test_key'
        test_value = b'Pipeline test'
        test_timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Create temp file for FileHandler
        with tempfile.NamedTemporaryFile(mode='r', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Create handler pipeline
            handlers = [
                StdoutHandler(),
                FileHandler(path=tmp_path, format='hex'),
                ExecuteHandler(command='cat > /dev/null', timeout=5)
            ]

            # Capture stdout for StdoutHandler
            captured_output = StringIO()
            original_stdout = sys.stdout
            sys.stdout = captured_output

            try:
                # Run all handlers
                results = []
                for handler in handlers:
                    result = handler.handle(test_key, test_value, test_timestamp)
                    results.append(result)

                # All should succeed
                assert all(results)

                # Verify stdout handler output
                output = captured_output.getvalue().strip()
                data = json.loads(output)
                assert data['event'] == 'packet_reassembled'

                # Verify file handler wrote data
                with open(tmp_path, 'r') as f:
                    file_content = f.read()
                assert test_value.hex() in file_content

            finally:
                sys.stdout = original_stdout

        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_handler_failure_does_not_stop_pipeline(self):
        """Test that one handler failure doesn't stop other handlers."""
        test_key = b'test_key'
        test_value = b'Test data'
        test_timestamp = datetime.datetime.now(datetime.timezone.utc)

        # Create handler pipeline with a failing handler in the middle
        handlers = [
            StdoutHandler(),
            ExecuteHandler(command='false', timeout=5),  # This will fail
            ExecuteHandler(command='true', timeout=5)    # This should still run
        ]

        captured_output = StringIO()
        original_stdout = sys.stdout
        sys.stdout = captured_output

        try:
            results = []
            for handler in handlers:
                result = handler.handle(test_key, test_value, test_timestamp)
                results.append(result)

            # First should succeed, second should fail, third should succeed
            assert results[0] is True
            assert results[1] is False
            assert results[2] is True

        finally:
            sys.stdout = original_stdout
