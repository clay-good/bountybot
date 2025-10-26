"""
Tests for debug tools.
"""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from bountybot.debug.interactive_debugger import InteractiveDebugger
from bountybot.debug.validation_replay import ValidationReplay, ValidationSnapshot
from bountybot.debug.error_handler import EnhancedErrorHandler


class TestInteractiveDebugger:
    """Test InteractiveDebugger functionality."""
    
    def test_debugger_init(self):
        """Test debugger initialization."""
        orchestrator = Mock()
        config = {'api': {'default_provider': 'anthropic'}}
        
        debugger = InteractiveDebugger(orchestrator, config)
        
        assert debugger.orchestrator == orchestrator
        assert debugger.config == config
        assert not debugger.step_mode
        assert len(debugger.breakpoints) == 0
    
    def test_enable_step_mode(self):
        """Test enabling step mode."""
        debugger = InteractiveDebugger(Mock(), {})
        
        debugger.enable_step_mode()
        
        assert debugger.step_mode
    
    def test_add_breakpoint(self):
        """Test adding breakpoint."""
        debugger = InteractiveDebugger(Mock(), {})
        
        debugger.add_breakpoint('parsing')
        
        assert 'parsing' in debugger.breakpoints
    
    def test_remove_breakpoint(self):
        """Test removing breakpoint."""
        debugger = InteractiveDebugger(Mock(), {})
        debugger.add_breakpoint('parsing')
        
        debugger.remove_breakpoint('parsing')
        
        assert 'parsing' not in debugger.breakpoints
    
    def test_should_break_step_mode(self):
        """Test should_break in step mode."""
        debugger = InteractiveDebugger(Mock(), {})
        debugger.enable_step_mode()
        
        assert debugger.should_break('any_stage')
    
    def test_should_break_breakpoint(self):
        """Test should_break with breakpoint."""
        debugger = InteractiveDebugger(Mock(), {})
        debugger.add_breakpoint('parsing')
        
        assert debugger.should_break('parsing')
        assert not debugger.should_break('validation')


class TestValidationReplay:
    """Test ValidationReplay functionality."""
    
    def test_replay_init(self):
        """Test replay initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            replay = ValidationReplay(tmpdir)
            
            assert replay.snapshot_dir == Path(tmpdir)
            assert replay.snapshot_dir.exists()
    
    def test_save_snapshot(self):
        """Test saving snapshot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            replay = ValidationReplay(tmpdir)
            
            snapshot_id = replay.save_snapshot(
                report_path='test.json',
                config={'api': {'default_provider': 'anthropic'}},
                report_data={'id': 'test-1', 'title': 'Test Report'},
                http_requests=[],
                quality_assessment={},
                plausibility_analysis={},
                validation_result={'verdict': 'VALID', 'confidence': 0.9}
            )
            
            assert snapshot_id.startswith('snapshot_')
            assert (replay.snapshot_dir / f"{snapshot_id}.json").exists()
    
    def test_load_snapshot(self):
        """Test loading snapshot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            replay = ValidationReplay(tmpdir)
            
            # Save snapshot
            snapshot_id = replay.save_snapshot(
                report_path='test.json',
                config={'api': {'default_provider': 'anthropic'}},
                report_data={'id': 'test-1'},
                http_requests=[],
                quality_assessment={},
                plausibility_analysis={},
                validation_result={'verdict': 'VALID'}
            )
            
            # Load snapshot
            snapshot = replay.load_snapshot(snapshot_id)
            
            assert isinstance(snapshot, ValidationSnapshot)
            assert snapshot.report_path == 'test.json'
            assert snapshot.validation_result['verdict'] == 'VALID'
    
    def test_load_nonexistent_snapshot(self):
        """Test loading nonexistent snapshot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            replay = ValidationReplay(tmpdir)
            
            with pytest.raises(FileNotFoundError):
                replay.load_snapshot('nonexistent')
    
    def test_list_snapshots(self):
        """Test listing snapshots."""
        import time

        with tempfile.TemporaryDirectory() as tmpdir:
            replay = ValidationReplay(tmpdir)

            # Save multiple snapshots
            snapshot_id1 = replay.save_snapshot(
                report_path='test1.json',
                config={},
                report_data={},
                http_requests=[],
                quality_assessment={},
                plausibility_analysis={},
                validation_result={}
            )

            # Wait to ensure different timestamp
            time.sleep(1.1)

            snapshot_id2 = replay.save_snapshot(
                report_path='test2.json',
                config={},
                report_data={},
                http_requests=[],
                quality_assessment={},
                plausibility_analysis={},
                validation_result={}
            )

            # List snapshots
            snapshots = replay.list_snapshots()

            assert len(snapshots) == 2
            assert snapshot_id1 in snapshots
            assert snapshot_id2 in snapshots
    
    def test_export_snapshot(self):
        """Test exporting snapshot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            replay = ValidationReplay(tmpdir)
            
            # Save snapshot
            snapshot_id = replay.save_snapshot(
                report_path='test.json',
                config={},
                report_data={},
                http_requests=[],
                quality_assessment={},
                plausibility_analysis={},
                validation_result={}
            )
            
            # Export snapshot
            output_path = Path(tmpdir) / 'exported.json'
            replay.export_snapshot(snapshot_id, str(output_path))
            
            assert output_path.exists()
            
            # Verify exported data
            with open(output_path, 'r') as f:
                data = json.load(f)
            
            assert data['report_path'] == 'test.json'
    
    def test_import_snapshot(self):
        """Test importing snapshot."""
        with tempfile.TemporaryDirectory() as tmpdir:
            replay = ValidationReplay(tmpdir)
            
            # Create snapshot file
            snapshot_data = {
                'timestamp': '2025-01-01T00:00:00',
                'report_path': 'test.json',
                'config': {},
                'report_data': {},
                'http_requests': [],
                'quality_assessment': {},
                'plausibility_analysis': {},
                'code_analysis': None,
                'dynamic_scan': None,
                'validation_result': {},
                'performance_metrics': {},
                'errors': []
            }
            
            input_path = Path(tmpdir) / 'import.json'
            with open(input_path, 'w') as f:
                json.dump(snapshot_data, f)
            
            # Import snapshot
            snapshot_id = replay.import_snapshot(str(input_path))
            
            assert snapshot_id.endswith('_imported')
            assert (replay.snapshot_dir / f"{snapshot_id}.json").exists()


class TestEnhancedErrorHandler:
    """Test EnhancedErrorHandler functionality."""
    
    def test_error_handler_init(self):
        """Test error handler initialization."""
        handler = EnhancedErrorHandler(debug_mode=True)
        
        assert handler.debug_mode
    
    def test_error_patterns(self):
        """Test error patterns are defined."""
        handler = EnhancedErrorHandler()
        
        assert 'FileNotFoundError' in handler.ERROR_PATTERNS
        assert 'ConnectionError' in handler.ERROR_PATTERNS
        assert 'KeyError' in handler.ERROR_PATTERNS
        assert 'ImportError' in handler.ERROR_PATTERNS
    
    def test_handle_error_with_context(self):
        """Test handling error with context."""
        handler = EnhancedErrorHandler(debug_mode=False)
        
        error = FileNotFoundError("test.json not found")
        context = {'report_path': 'test.json', 'stage': 'parsing'}
        
        # Should not raise exception
        handler.handle_error(error, context, show_traceback=False)
    
    def test_handle_validation_error(self):
        """Test handling validation error."""
        handler = EnhancedErrorHandler(debug_mode=False)
        
        error = ValueError("Invalid report format")
        
        # Should not raise exception
        handler.handle_validation_error(
            error,
            report_path='test.json',
            stage='parsing',
            context={'format': 'json'}
        )
    
    def test_handle_api_error(self):
        """Test handling API error."""
        handler = EnhancedErrorHandler(debug_mode=False)
        
        error = ConnectionError("API connection failed")
        
        # Should not raise exception
        handler.handle_api_error(
            error,
            provider='anthropic',
            operation='complete',
            context={'model': 'claude-sonnet-4'}
        )
    
    def test_error_suggestions_file_not_found(self):
        """Test suggestions for FileNotFoundError."""
        handler = EnhancedErrorHandler()
        
        pattern = handler.ERROR_PATTERNS['FileNotFoundError']
        
        assert pattern['category'] == 'File System'
        assert len(pattern['suggestions']) > 0
        assert any('path' in s.lower() for s in pattern['suggestions'])
    
    def test_error_suggestions_connection_error(self):
        """Test suggestions for ConnectionError."""
        handler = EnhancedErrorHandler()
        
        pattern = handler.ERROR_PATTERNS['ConnectionError']
        
        assert pattern['category'] == 'Network'
        assert len(pattern['suggestions']) > 0
        assert any('connection' in s.lower() for s in pattern['suggestions'])
    
    def test_error_suggestions_import_error(self):
        """Test suggestions for ImportError."""
        handler = EnhancedErrorHandler()
        
        pattern = handler.ERROR_PATTERNS['ImportError']
        
        assert pattern['category'] == 'Dependencies'
        assert len(pattern['suggestions']) > 0
        assert any('pip install' in s.lower() for s in pattern['suggestions'])


if __name__ == '__main__':
    pytest.main([__file__, '-v'])

