import pytest
import sys
import os
from unittest.mock import patch, MagicMock
import numpy as np

# Add project root to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Now we can import app
from app import app

# Mock model predictions
@pytest.fixture(autouse=True)
def mock_models():
    """Mock the ML models to avoid loading actual model files"""
    with patch('app.rf_model') as mock_rf, \
         patch('app.gb_model') as mock_gb, \
         patch('app.ann_model') as mock_ann, \
         patch('capture.model') as mock_capture_model:
        
        # Configure mock models
        for mock_model in [mock_rf, mock_gb, mock_ann, mock_capture_model]:
            mock_model.predict_proba.return_value = np.array([[0.7, 0.3]])
        
        # Mock the preprocessor for categories
        mock_preprocessor = MagicMock()
        mock_preprocessor.named_transformers_ = {
            'cat': MagicMock()
        }
        mock_preprocessor.named_transformers_['cat'].categories_ = [
            ['tcp', 'udp', 'icmp'],  # protocol_types
            ['http', 'ftp', 'smtp', 'domain', 'other'],  # services
            ['SF', 'S0', 'REJ', 'RSTO', 'SH']  # flags
        ]
        mock_rf.named_steps = {'preprocessor': mock_preprocessor}
        
        yield

# Flask test client fixture
@pytest.fixture
def client():
    """Create a test client for the app"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# Sample packet data fixture
@pytest.fixture
def sample_packet():
    """Create a sample network packet for testing"""
    return {
        'timestamp': '12:00:00.000',
        'src': '192.168.1.1',
        'dst': '192.168.1.2',
        'proto': 'tcp',
        'base_proto': '6',
        'length': 100,
        'ip_version': '4',
        'ttl': '64',
        'ip_flags': 'N/A',
        'src_port': '12345',
        'dst_port': '80',
        'tcp_flags': 'SF',
        'tcp_window_size': '64240',
        'tcp_seq': '1234567890',
        'tcp_ack': 'N/A',
        'http_info': {
            'method': 'GET',
            'host': 'example.com',
            'uri': '/'
        }
    }

# Sample prediction input fixture
@pytest.fixture
def sample_prediction_input():
    """Sample input data for prediction testing"""
    return {
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'duration': 100,
        'src_bytes': 1000,
        'dst_bytes': 2000,
        'wrong_fragment': 0,
        'model_choice': 'rf'
    } 