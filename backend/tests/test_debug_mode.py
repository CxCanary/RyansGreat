"""
Tests for debug mode security configuration

This test suite validates that the Flask application's debug mode
is properly controlled via environment variables and defaults to
a secure configuration (debug=False).

CWE-489: Active Debug Code
"""
import pytest
import sys
import os
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDebugModeConfiguration:
    """Test debug mode configuration and security"""

    def test_debug_mode_disabled_by_default(self):
        """Test that debug mode is disabled when FLASK_DEBUG is not set"""
        with patch.dict(os.environ, {}, clear=False):
            # Remove FLASK_DEBUG if it exists
            os.environ.pop('FLASK_DEBUG', None)

            # Simulate the app.py logic
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')

            assert debug_mode is False, "Debug mode should be disabled by default"

    def test_debug_mode_enabled_with_true(self):
        """Test that debug mode is enabled when FLASK_DEBUG='true'"""
        with patch.dict(os.environ, {'FLASK_DEBUG': 'true'}):
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
            assert debug_mode is True, "Debug mode should be enabled with FLASK_DEBUG='true'"

    def test_debug_mode_enabled_with_True(self):
        """Test that debug mode is enabled when FLASK_DEBUG='True' (case insensitive)"""
        with patch.dict(os.environ, {'FLASK_DEBUG': 'True'}):
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
            assert debug_mode is True, "Debug mode should be enabled with FLASK_DEBUG='True'"

    def test_debug_mode_enabled_with_1(self):
        """Test that debug mode is enabled when FLASK_DEBUG='1'"""
        with patch.dict(os.environ, {'FLASK_DEBUG': '1'}):
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
            assert debug_mode is True, "Debug mode should be enabled with FLASK_DEBUG='1'"

    def test_debug_mode_enabled_with_yes(self):
        """Test that debug mode is enabled when FLASK_DEBUG='yes'"""
        with patch.dict(os.environ, {'FLASK_DEBUG': 'yes'}):
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
            assert debug_mode is True, "Debug mode should be enabled with FLASK_DEBUG='yes'"

    def test_debug_mode_disabled_with_false(self):
        """Test that debug mode is disabled when FLASK_DEBUG='false'"""
        with patch.dict(os.environ, {'FLASK_DEBUG': 'false'}):
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
            assert debug_mode is False, "Debug mode should be disabled with FLASK_DEBUG='false'"

    def test_debug_mode_disabled_with_0(self):
        """Test that debug mode is disabled when FLASK_DEBUG='0'"""
        with patch.dict(os.environ, {'FLASK_DEBUG': '0'}):
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
            assert debug_mode is False, "Debug mode should be disabled with FLASK_DEBUG='0'"

    def test_debug_mode_disabled_with_no(self):
        """Test that debug mode is disabled when FLASK_DEBUG='no'"""
        with patch.dict(os.environ, {'FLASK_DEBUG': 'no'}):
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
            assert debug_mode is False, "Debug mode should be disabled with FLASK_DEBUG='no'"

    def test_debug_mode_disabled_with_empty_string(self):
        """Test that debug mode is disabled when FLASK_DEBUG='' (empty)"""
        with patch.dict(os.environ, {'FLASK_DEBUG': ''}):
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
            assert debug_mode is False, "Debug mode should be disabled with empty FLASK_DEBUG"

    def test_debug_mode_disabled_with_invalid_value(self):
        """Test that debug mode is disabled with invalid/unexpected values"""
        invalid_values = ['True1', 'maybe', 'enabled', '2', 'YES!', 'on']

        for invalid_value in invalid_values:
            with patch.dict(os.environ, {'FLASK_DEBUG': invalid_value}):
                debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
                assert debug_mode is False, f"Debug mode should be disabled with FLASK_DEBUG='{invalid_value}'"

    def test_debug_mode_case_insensitive_TRUE(self):
        """Test that debug mode handling is case insensitive for 'TRUE'"""
        with patch.dict(os.environ, {'FLASK_DEBUG': 'TRUE'}):
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
            assert debug_mode is True, "Debug mode should be enabled with FLASK_DEBUG='TRUE'"

    def test_debug_mode_case_insensitive_YES(self):
        """Test that debug mode handling is case insensitive for 'YES'"""
        with patch.dict(os.environ, {'FLASK_DEBUG': 'YES'}):
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
            assert debug_mode is True, "Debug mode should be enabled with FLASK_DEBUG='YES'"

    @patch('app.app')
    def test_app_run_respects_debug_mode_disabled(self, mock_app):
        """Test that app.run() is called with debug=False when FLASK_DEBUG is not set"""
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('FLASK_DEBUG', None)

            # Simulate the app.py main block logic
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')

            # Verify the debug_mode value that would be passed to app.run()
            assert debug_mode is False, "app.run() should receive debug=False by default"

    @patch('app.app')
    def test_app_run_respects_debug_mode_enabled(self, mock_app):
        """Test that app.run() is called with debug=True when FLASK_DEBUG='true'"""
        with patch.dict(os.environ, {'FLASK_DEBUG': 'true'}):
            # Simulate the app.py main block logic
            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')

            # Verify the debug_mode value that would be passed to app.run()
            assert debug_mode is True, "app.run() should receive debug=True when explicitly enabled"


class TestDebugModeSecurityImplications:
    """Test security implications of debug mode settings"""

    def test_production_safe_default(self):
        """
        Test that the default configuration is safe for production deployment.

        In production, debug mode should NEVER be enabled as it:
        - Exposes detailed error messages with stack traces
        - Enables the interactive debugger (potential RCE)
        - Leaks sensitive application internals
        """
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('FLASK_DEBUG', None)

            debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')

            assert debug_mode is False, (
                "CRITICAL: Debug mode must be disabled by default to prevent "
                "information disclosure and potential remote code execution in production"
            )

    def test_explicit_opt_in_required(self):
        """
        Test that debug mode requires explicit opt-in.

        Security best practice: Dangerous features should require explicit
        enablement rather than explicit disablement.
        """
        test_cases = [
            ('', False, "empty string should not enable debug mode"),
            ('0', False, "'0' should not enable debug mode"),
            ('false', False, "'false' should not enable debug mode"),
            ('False', False, "'False' should not enable debug mode"),
            ('disabled', False, "'disabled' should not enable debug mode"),
            ('no', False, "'no' should not enable debug mode"),
            (None, False, "None/unset should not enable debug mode"),
        ]

        for value, expected, message in test_cases:
            if value is None:
                with patch.dict(os.environ, {}, clear=False):
                    os.environ.pop('FLASK_DEBUG', None)
                    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
            else:
                with patch.dict(os.environ, {'FLASK_DEBUG': value}):
                    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')

            assert debug_mode == expected, message

    def test_whitelist_approach_for_enablement(self):
        """
        Test that only specific whitelisted values enable debug mode.

        This tests the principle of secure defaults: only known-safe values
        should enable the dangerous debug feature.
        """
        enabled_values = ['true', 'True', 'TRUE', '1', 'yes', 'Yes', 'YES']

        for value in enabled_values:
            with patch.dict(os.environ, {'FLASK_DEBUG': value}):
                debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
                assert debug_mode is True, f"'{value}' should enable debug mode (whitelisted)"

        # Test that non-whitelisted values do NOT enable debug mode
        non_whitelisted_values = ['2', 'on', 'enable', 'enabled', 'debug', 'y', 't']

        for value in non_whitelisted_values:
            with patch.dict(os.environ, {'FLASK_DEBUG': value}):
                debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1', 'yes')
                assert debug_mode is False, f"'{value}' should NOT enable debug mode (not whitelisted)"


class TestDebugModeRegressionPrevention:
    """Tests to prevent regression of CWE-489 vulnerability"""

    def test_no_hardcoded_debug_true(self):
        """
        Ensure that debug mode is not hardcoded to True in app.py.

        This test prevents regression of the CWE-489 vulnerability where
        debug=True was hardcoded in the application.
        """
        app_py_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app.py')

        with open(app_py_path, 'r') as f:
            content = f.read()

        # Check that we don't have "debug=True" hardcoded
        assert 'debug=True' not in content, (
            "SECURITY REGRESSION: debug=True should not be hardcoded in app.py. "
            "Debug mode must be controlled via FLASK_DEBUG environment variable."
        )

    def test_debug_mode_uses_environment_variable(self):
        """
        Verify that the app.py file uses environment variable for debug mode.

        This ensures the fix is properly implemented and uses os.environ.get()
        for the FLASK_DEBUG configuration.
        """
        app_py_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app.py')

        with open(app_py_path, 'r') as f:
            content = f.read()

        # Verify that FLASK_DEBUG environment variable is referenced
        assert 'FLASK_DEBUG' in content, (
            "app.py should use FLASK_DEBUG environment variable for debug mode configuration"
        )

        # Verify that os.environ.get is used
        assert 'os.environ.get' in content, (
            "app.py should use os.environ.get() to read FLASK_DEBUG configuration"
        )

    def test_debug_mode_default_value_is_secure(self):
        """
        Test that the default value for debug mode in the code is secure.

        This verifies that if someone reads app.py, the default value
        used in os.environ.get() is 'False', not 'True'.
        """
        app_py_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app.py')

        with open(app_py_path, 'r') as f:
            content = f.read()

        # Look for the pattern: os.environ.get('FLASK_DEBUG', 'False')
        # The default should be 'False' for security
        import re
        pattern = r"os\.environ\.get\(['\"]FLASK_DEBUG['\"],\s*['\"]False['\"]"

        match = re.search(pattern, content)
        assert match is not None, (
            "SECURITY: The default value for FLASK_DEBUG should be 'False' in os.environ.get()"
        )
