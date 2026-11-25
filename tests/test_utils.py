"""Tests for utility functions."""

import pytest
import datetime

from bastion_citadel.utils.helpers import (
    format_bytes,
    format_timestamp,
    validate_email,
    validate_ip,
    validate_url,
    get_system_info,
    generate_report
)
from bastion_citadel.core.event import SecurityEvent, EventType, Severity


class TestFormatBytes:
    """Tests for format_bytes."""
    
    def test_bytes(self):
        assert format_bytes(500) == "500.00 B"
    
    def test_kilobytes(self):
        assert format_bytes(1024) == "1.00 KB"
    
    def test_megabytes(self):
        assert format_bytes(1024 * 1024) == "1.00 MB"
    
    def test_gigabytes(self):
        assert format_bytes(1024 * 1024 * 1024) == "1.00 GB"


class TestFormatTimestamp:
    """Tests for format_timestamp."""
    
    def test_default_timestamp(self):
        result = format_timestamp()
        assert "UTC" in result
        assert len(result) >= 20
    
    def test_custom_timestamp(self):
        dt = datetime.datetime(2023, 1, 1, 12, 0, 0)
        result = format_timestamp(dt)
        assert result == "2023-01-01 12:00:00 UTC"


class TestValidation:
    """Tests for validation functions."""
    
    def test_validate_email_valid(self):
        assert validate_email("test@example.com") is True
        assert validate_email("user.name+tag@example.co.uk") is True
    
    def test_validate_email_invalid(self):
        assert validate_email("invalid-email") is False
        assert validate_email("@example.com") is False
    
    def test_validate_ip_v4(self):
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("127.0.0.1") is True
    
    def test_validate_ip_v6(self):
        assert validate_ip("::1") is True
        assert validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
    
    def test_validate_ip_invalid(self):
        assert validate_ip("invalid") is False
        assert validate_ip("256.256.256.256") is False
    
    def test_validate_url(self):
        assert validate_url("https://example.com") is True
        assert validate_url("http://example.com/path?query=value") is True
    
    def test_validate_url_invalid(self):
        assert validate_url("example.com") is False
        assert validate_url("invalid-url") is False


class TestGetSystemInfo:
    """Tests for get_system_info."""
    
    def test_system_info_keys(self):
        info = get_system_info()
        
        assert "platform" in info
        assert "system" in info
        assert "node_name" in info
        assert "release" in info
        assert "version" in info
        assert "machine" in info
        assert "python_version" in info
        assert "hostname" in info


class TestGenerateReport:
    """Tests for generate_report."""
    
    def test_empty_report(self):
        events = []
        report = generate_report(events, "Test Report")
        
        assert report["title"] == "Test Report"
        assert report["summary"]["total_events"] == 0
        assert report["events"]["critical"] == []
    
    def test_report_with_events(self):
        events = [
            SecurityEvent(
                event_type=EventType.VULNERABILITY_DETECTED,
                severity=Severity.CRITICAL,
                title="Critical Issue",
                description="Test description",
                source="test"
            ),
            SecurityEvent(
                event_type=EventType.INFO,
                severity=Severity.INFO,
                title="Info",
                description="Info message",
                source="test"
            )
        ]
        
        report = generate_report(events, "Test Report")
        
        assert report["summary"]["total_events"] == 2
        assert report["summary"]["by_severity"]["critical"] == 1
        assert report["summary"]["by_severity"]["info"] == 1
        assert len(report["events"]["critical"]) == 1
        assert len(report["events"]["info"]) == 1
        assert "system_info" in report
