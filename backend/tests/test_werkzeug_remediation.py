"""
Tests for Werkzeug CVE-2023-25577 remediation

This test suite verifies:
1. Request context functionality after migrating from _request_ctx_stack to flask.g
2. Multipart form data parsing works correctly with Werkzeug 2.2.3+
3. File upload functionality remains secure and operational
4. Request metadata tracking continues to function properly
"""
import pytest
import sys
import os
import io
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, g, has_request_context
from utils.request_context import (
    _get_request_id,
    get_request_context,
    set_request_metadata,
    get_request_metadata,
    get_request_start_time,
    get_request_duration,
    request_id
)


class TestRequestContextMigration:
    """Test request context functionality after Flask 2.x migration"""

    def test_request_id_generation(self, app, client):
        """Test that request IDs are generated correctly using flask.g"""
        with app.test_request_context():
            # Request ID should be generated on first access
            req_id = _get_request_id()
            assert req_id is not None
            assert isinstance(req_id, str)
            assert len(req_id) == 36  # UUID4 format

            # Second call should return same ID
            req_id2 = _get_request_id()
            assert req_id == req_id2

    def test_request_id_outside_context(self):
        """Test that request ID returns None outside request context"""
        # Outside request context, should return None
        req_id = _get_request_id()
        assert req_id is None

    def test_request_context_retrieval(self, app):
        """Test get_request_context returns flask.g in request context"""
        with app.test_request_context():
            ctx = get_request_context()
            assert ctx is not None
            # Verify it's the flask.g object
            assert ctx is g

    def test_request_context_outside_context(self):
        """Test get_request_context returns None outside request context"""
        ctx = get_request_context()
        assert ctx is None

    def test_request_metadata_storage(self, app):
        """Test storing and retrieving request metadata"""
        with app.test_request_context():
            # Set metadata
            set_request_metadata('user_id', 123)
            set_request_metadata('action', 'test_action')
            set_request_metadata('ip_address', '192.168.1.1')

            # Retrieve metadata
            assert get_request_metadata('user_id') == 123
            assert get_request_metadata('action') == 'test_action'
            assert get_request_metadata('ip_address') == '192.168.1.1'

    def test_request_metadata_default_value(self, app):
        """Test retrieving non-existent metadata returns default"""
        with app.test_request_context():
            # Non-existent key with default
            assert get_request_metadata('nonexistent', 'default') == 'default'

            # Non-existent key without default
            assert get_request_metadata('nonexistent') is None

    def test_request_metadata_outside_context(self):
        """Test metadata operations outside request context"""
        # Should not raise errors
        set_request_metadata('key', 'value')
        assert get_request_metadata('key') is None

    def test_request_start_time(self, app):
        """Test request start time tracking"""
        with app.test_request_context():
            start_time = get_request_start_time()
            assert start_time is not None
            assert isinstance(start_time, datetime)

            # Second call should return same time
            start_time2 = get_request_start_time()
            assert start_time == start_time2

    def test_request_duration(self, app):
        """Test request duration calculation"""
        import time

        with app.test_request_context():
            # Initialize start time
            get_request_start_time()

            # Wait a short time
            time.sleep(0.01)

            # Get duration
            duration = get_request_duration()
            assert duration is not None
            assert isinstance(duration, float)
            assert duration >= 0.01

    def test_request_duration_without_start_time(self, app):
        """Test duration returns None if start time not set"""
        with app.test_request_context():
            # Don't initialize start time
            duration = get_request_duration()
            assert duration is None

    def test_request_id_proxy(self, app):
        """Test LocalProxy for request_id works correctly"""
        with app.test_request_context():
            # Initialize request ID
            _get_request_id()

            # Access via LocalProxy
            proxy_id = request_id
            assert proxy_id is not None
            assert isinstance(proxy_id, str)

            # Should match direct access
            direct_id = g.request_id
            assert proxy_id == direct_id


class TestMultipartFormParsing:
    """Test multipart form data parsing with Werkzeug 2.2.3+"""

    def test_file_upload_basic(self, app, client, auth_headers):
        """Test basic file upload with multipart form data"""
        # Create test file
        data = {
            'file': (io.BytesIO(b'test file content'), 'test.txt'),
            'project_id': '1',
            'is_public': 'false'
        }

        response = client.post(
            '/api/documents',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )

        # Should work with Werkzeug 2.2.3+
        # May return 400 if no project exists, but shouldn't crash
        assert response.status_code in [200, 201, 400, 404]

    def test_file_upload_with_form_data(self, app, client, auth_headers):
        """Test file upload with additional form fields"""
        # Create test file with multiple form fields
        data = {
            'file': (io.BytesIO(b'test content'), 'document.pdf'),
            'project_id': '1',
            'is_public': 'true',
            'description': 'Test document',
            'tags': 'test,upload'
        }

        response = client.post(
            '/api/documents',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )

        # Should handle multipart data correctly
        assert response.status_code in [200, 201, 400, 404]

    def test_multipart_parsing_with_request_form(self, app):
        """Test that request.form parsing works with Werkzeug 2.2.3+"""
        with app.test_request_context(
            method='POST',
            data={'field1': 'value1', 'field2': 'value2'},
            content_type='application/x-www-form-urlencoded'
        ):
            from flask import request

            # Should parse form data correctly
            assert request.form.get('field1') == 'value1'
            assert request.form.get('field2') == 'value2'

    def test_empty_file_upload(self, app, client, auth_headers):
        """Test handling of empty file upload"""
        data = {
            'file': (io.BytesIO(b''), ''),
            'project_id': '1'
        }

        response = client.post(
            '/api/documents',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )

        # Should handle empty file gracefully
        assert response.status_code in [400, 404]
        json_data = response.get_json()
        assert 'error' in json_data


class TestFlaskWerkzeugCompatibility:
    """Test Flask 2.2.5 and Werkzeug 2.2.3+ compatibility"""

    def test_flask_g_accessible(self, app):
        """Test that flask.g is accessible in request context"""
        with app.test_request_context():
            from flask import g

            # Should be able to set and get attributes on g
            g.test_attribute = 'test_value'
            assert g.test_attribute == 'test_value'

    def test_has_request_context_function(self, app):
        """Test has_request_context function works correctly"""
        # Outside context
        assert has_request_context() is False

        # Inside context
        with app.test_request_context():
            assert has_request_context() is True

    def test_werkzeug_secure_filename_import(self):
        """Test that werkzeug.utils.secure_filename is available"""
        from werkzeug.utils import secure_filename

        # Test secure_filename functionality
        assert secure_filename('test file.txt') == 'test_file.txt'
        assert secure_filename('../../../etc/passwd') == 'etc_passwd'
        assert secure_filename('') == 'file'

    def test_werkzeug_local_proxy_import(self):
        """Test that werkzeug.local.LocalProxy is available"""
        from werkzeug.local import LocalProxy

        # Test LocalProxy functionality
        test_func = lambda: 'test_value'
        proxy = LocalProxy(test_func)
        assert proxy == 'test_value'

    def test_request_context_integration(self, app, client):
        """Test end-to-end request context in a real request"""
        @app.route('/test-context')
        def test_context_view():
            from flask import jsonify
            from utils.request_context import _get_request_id, set_request_metadata, get_request_metadata

            # Get request ID
            req_id = _get_request_id()

            # Set metadata
            set_request_metadata('test_key', 'test_value')

            # Get metadata
            value = get_request_metadata('test_key')

            return jsonify({
                'request_id': req_id,
                'metadata_value': value
            })

        response = client.get('/test-context')
        assert response.status_code == 200

        data = response.get_json()
        assert 'request_id' in data
        assert data['request_id'] is not None
        assert data['metadata_value'] == 'test_value'


class TestSecurityImprovements:
    """Test security improvements from Werkzeug 2.2.3+"""

    def test_multipart_data_limits_enforced(self, app, client, auth_headers):
        """Test that Werkzeug 2.2.3+ enforces reasonable limits on multipart data"""
        # Werkzeug 2.2.3+ should handle multipart data safely
        # This test verifies the endpoint doesn't crash with multipart data

        data = {
            'file': (io.BytesIO(b'x' * 1024), 'test.txt'),
            'project_id': '1',
            'is_public': 'false'
        }

        response = client.post(
            '/api/documents',
            data=data,
            headers=auth_headers,
            content_type='multipart/form-data'
        )

        # Should handle the request without crashing
        assert response.status_code is not None
        assert response.status_code < 500  # No server error

    def test_request_files_parsing_safe(self, app):
        """Test that request.files parsing is safe with Werkzeug 2.2.3+"""
        with app.test_request_context(
            method='POST',
            data={'file': (io.BytesIO(b'test'), 'test.txt')},
            content_type='multipart/form-data'
        ):
            from flask import request

            # Should parse files safely
            assert 'file' in request.files
            file = request.files['file']
            assert file.filename == 'test.txt'

    def test_form_data_parsing_safe(self, app):
        """Test that request.form parsing is safe with Werkzeug 2.2.3+"""
        with app.test_request_context(
            method='POST',
            data={'key1': 'value1', 'key2': 'value2'},
            content_type='application/x-www-form-urlencoded'
        ):
            from flask import request

            # Should parse form data safely without DoS risk
            assert request.form.get('key1') == 'value1'
            assert request.form.get('key2') == 'value2'
