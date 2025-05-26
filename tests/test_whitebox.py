import pytest
from app import app, interpret_prediction
import numpy as np
import pandas as pd

# White-box Testing - Model Loading
def test_model_loading():
    """Test if models are loaded correctly"""
    from app import rf_model, gb_model, ann_model
    assert rf_model is not None
    # gb_model and ann_model might be None if loading failed
    assert hasattr(rf_model, 'predict_proba')

# White-box Testing - Prediction Interpretation
def test_interpret_prediction():
    """Test prediction interpretation function"""
    # Test normal case
    assert interpret_prediction([0.7, 0.3]) == "Normal"
    assert interpret_prediction([0.3, 0.7]) == "Attack"
    
    # Test single probability case
    assert interpret_prediction([0.7]) == "Normal"
    assert interpret_prediction([0.3]) == "Attack"
    
    # Test edge cases
    assert interpret_prediction([0.5, 0.5]) == "Normal"  # Equal probabilities
    assert interpret_prediction([1.0, 0.0]) == "Normal"  # Maximum confidence
    assert interpret_prediction([0.0, 1.0]) == "Attack"  # Maximum confidence

# White-box Testing - Feature Processing
def test_feature_processing():
    """Test feature processing in predict route"""
    from app import features
    
    # Test that all required features are present
    required_features = [
        'protocol_type', 'service', 'flag',
        'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment'
    ]
    assert all(feature in features for feature in required_features)
    
    # Test that features match the expected order
    assert features == required_features

# White-box Testing - Model Categories
def test_model_categories():
    """Test model category extraction"""
    from app import protocol_types, services, flags
    
    # Test that categories are lists
    assert isinstance(protocol_types, list)
    assert isinstance(services, list)
    assert isinstance(flags, list)
    
    # Test that categories contain expected values
    assert 'tcp' in protocol_types
    assert 'http' in services
    assert 'SF' in flags

# White-box Testing - Error Handling
def test_error_handling(client):
    """Test error handling in predict route"""
    # Test with invalid input data
    response = client.post('/predict', data={})
    assert response.status_code == 200
    assert b'analyze another' in response.data.lower()
    
    # Test with missing features
    invalid_data = {
        'protocol_type': 'tcp',  # Only one feature
        'model_choice': 'rf'
    }
    response = client.post('/predict', data=invalid_data)
    assert response.status_code == 200
    assert b'analyze another' in response.data.lower()

# White-box Testing - Model Pipeline
def test_model_pipeline():
    """Test model pipeline structure"""
    from app import rf_model
    
    # Test pipeline components
    assert hasattr(rf_model, 'named_steps')
    assert 'preprocessor' in rf_model.named_steps
    
    # Test preprocessor structure
    preprocessor = rf_model.named_steps['preprocessor']
    assert hasattr(preprocessor, 'named_transformers_')
    assert 'cat' in preprocessor.named_transformers_

# White-box Testing - Data Types
def test_data_types():
    """Test data type handling in the application"""
    from app import features
    
    # Test numeric features
    numeric_features = ['duration', 'src_bytes', 'dst_bytes', 'wrong_fragment']
    for feature in numeric_features:
        assert feature in features
    
    # Test categorical features
    categorical_features = ['protocol_type', 'service', 'flag']
    for feature in categorical_features:
        assert feature in features

# White-box Testing - Model Predictions
def test_model_predictions(client):
    """Test model prediction outputs"""
    # Test RF model prediction
    data = {
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'duration': 100,
        'src_bytes': 1000,
        'dst_bytes': 2000,
        'wrong_fragment': 0,
        'model_choice': 'rf'
    }
    response = client.post('/predict', data=data)
    assert response.status_code == 200
    assert b'result' in response.data.lower()  # Check for result text
    assert b'confidence' in response.data.lower()  # Check for confidence text
    assert b'analyze another' in response.data.lower()  # Check for back button

# White-box Testing - Route Methods
def test_route_methods(client):
    """Test route method handling"""
    # Test GET method for predict
    response = client.get('/predict')
    assert response.status_code == 200
    
    # Test POST method for predict
    response = client.post('/predict', data={})
    assert response.status_code == 200
    
    # Test GET method for packets
    response = client.get('/packets')
    assert response.status_code == 200
    
    # Test GET method for packets-get
    response = client.get('/packets-get')
    assert response.status_code == 200

# White-box Testing - Template Rendering
def test_template_rendering(client):
    """Test template rendering for different routes"""
    # Test index template
    response = client.get('/')
    assert response.status_code == 200
    assert b'<!DOCTYPE html>' in response.data
    
    # Test predict template
    response = client.get('/predict')
    assert response.status_code == 200
    assert b'<!DOCTYPE html>' in response.data
    
    # Test packets template
    response = client.get('/packets')
    assert response.status_code == 200
    assert b'<!DOCTYPE html>' in response.data 