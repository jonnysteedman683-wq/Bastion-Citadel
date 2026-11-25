"""Tests for scanner plugins."""

import asyncio
import os
import tempfile
import pytest
from pathlib import Path

from bastion_citadel.core.event import EventType, Severity
from bastion_citadel.scanners.file_scanner import FileVulnerabilityScanner
from bastion_citadel.scanners.dependency_scanner import DependencyScanner


class TestFileVulnerabilityScanner:
    """Tests for FileVulnerabilityScanner."""
    
    @pytest.mark.asyncio
    async def test_scanner_initialization(self):
        """Test scanner initialization."""
        scanner = FileVulnerabilityScanner()
        result = await scanner.initialize()
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_scan_nonexistent_file(self):
        """Test scanning a non-existent file."""
        scanner = FileVulnerabilityScanner()
        await scanner.initialize()
        
        events = await scanner.execute("/nonexistent/file.txt")
        
        assert len(events) > 0
        assert events[0].event_type == EventType.ALERT
        assert events[0].severity == Severity.MEDIUM
    
    @pytest.mark.asyncio
    async def test_scan_file_with_secret(self):
        """Test scanning a file with hardcoded secret."""
        scanner = FileVulnerabilityScanner()
        await scanner.initialize()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
            f.write("api_key = 'test_api_key_1234567890abcdef'\n")
            f.write("password = 'test_password_123'\n")
            temp_path = f.name
        
        try:
            events = await scanner.execute(temp_path)
            
            # Should detect at least one secret (password or api_key)
            secret_events = [e for e in events if e.event_type == EventType.VULNERABILITY_DETECTED]
            assert len(secret_events) >= 1
            
            # Check that we detected password
            password_events = [e for e in events if "password" in e.title.lower()]
            assert len(password_events) >= 1
            
        finally:
            os.unlink(temp_path)
    
    @pytest.mark.asyncio
    async def test_scan_file_with_insecure_pattern(self):
        """Test scanning a file with insecure patterns."""
        scanner = FileVulnerabilityScanner()
        await scanner.initialize()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.py') as f:
            f.write("result = eval(user_input)\n")
            f.write("os.system('rm -rf /')\n")
            temp_path = f.name
        
        try:
            events = await scanner.execute(temp_path)
            
            # Should detect eval
            eval_events = [e for e in events if "eval" in e.title.lower()]
            assert len(eval_events) > 0
            
        finally:
            os.unlink(temp_path)
    
    @pytest.mark.asyncio
    async def test_scan_directory(self):
        """Test scanning a directory."""
        scanner = FileVulnerabilityScanner()
        await scanner.initialize()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create test files
            test_file = Path(temp_dir) / "test.py"
            test_file.write_text("password = 'secret'\n")
            
            events = await scanner.execute(temp_dir)
            
            # Should detect the password
            password_events = [e for e in events if "password" in e.title.lower()]
            assert len(password_events) > 0


class TestDependencyScanner:
    """Tests for DependencyScanner."""
    
    @pytest.mark.asyncio
    async def test_scanner_initialization(self):
        """Test scanner initialization."""
        scanner = DependencyScanner()
        result = await scanner.initialize()
        
        assert result is True
    
    @pytest.mark.asyncio
    async def test_detect_project_type_python(self):
        """Test detecting Python project."""
        scanner = DependencyScanner()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create requirements.txt
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("requests==2.28.0\n")
            
            project_type = scanner.detect_project_type(Path(temp_dir))
            assert project_type == "python"
    
    @pytest.mark.asyncio
    async def test_detect_project_type_node(self):
        """Test detecting Node.js project."""
        scanner = DependencyScanner()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create package.json
            pkg_file = Path(temp_dir) / "package.json"
            pkg_file.write_text('{"dependencies": {"lodash": "4.17.21"}}')
            
            project_type = scanner.detect_project_type(Path(temp_dir))
            assert project_type == "node"
    
    @pytest.mark.asyncio
    async def test_scan_python_project(self):
        """Test scanning a Python project."""
        scanner = DependencyScanner()
        await scanner.initialize()
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create requirements.txt with vulnerable package
            req_file = Path(temp_dir) / "requirements.txt"
            req_file.write_text("requests==2.28.0\n")
            
            events = await scanner.execute(temp_dir)
            
            # Should detect the vulnerable package
            vuln_events = [e for e in events if e.event_type == EventType.VULNERABILITY_DETECTED]
            assert len(vuln_events) > 0
    
    @pytest.mark.asyncio
    async def test_parse_requirements(self):
        """Test parsing requirements.txt."""
        scanner = DependencyScanner()
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("requests==2.28.0\n")
            f.write("flask==2.0.0\n")
            f.write("django\n")
            temp_path = f.name
        
        try:
            dependencies = await scanner.parse_requirements(Path(temp_path))
            
            assert len(dependencies) == 3
            assert ("requests", "2.28.0") in dependencies
            assert ("flask", "2.0.0") in dependencies
            
        finally:
            os.unlink(temp_path)
