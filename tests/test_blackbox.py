import pytest
from app import app

@pytest.fixture
def sample_prediction_input():
    """Fixture providing sample prediction input data"""
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

# Black-box Testing - Functional Testing
def test_index_page(client):
    """Test if the index page loads correctly"""
    response = client.get('/')
    assert response.status_code == 200

def test_predict_page_get(client):
    """Test if the prediction form loads correctly"""
    response = client.get('/predict')
    assert response.status_code == 200
    
    # Check for form elements
    assert b'<form action="/predict" method="POST">' in response.data
    assert b'<select name="protocol_type"' in response.data
    assert b'<select name="service"' in response.data
    assert b'<select name="flag"' in response.data
    
    # Check for model options
    assert b'Random Forest' in response.data
    assert b'Gradient Boosting' in response.data
    assert b'Neural Network' in response.data
    
    # Check for protocol options
    assert b'<option value="tcp">tcp</option>' in response.data
    assert b'<option value="udp">udp</option>' in response.data
    assert b'<option value="icmp">icmp</option>' in response.data

# Black-box Testing - Input Validation
def test_predict_endpoint_valid_inputs(client, sample_prediction_input):
    """Test prediction endpoint with valid input combinations"""
    # Test with RF model
    response = client.post('/predict', data=sample_prediction_input)
    assert response.status_code == 200
    assert b'result' in response.data.lower()
    
    # Test with GB model
    sample_prediction_input['model_choice'] = 'gb'
    response = client.post('/predict', data=sample_prediction_input)
    assert response.status_code == 200
    assert b'result' in response.data.lower()
    
    # Test with ANN model
    sample_prediction_input['model_choice'] = 'ann'
    response = client.post('/predict', data=sample_prediction_input)
    assert response.status_code == 200
    assert b'result' in response.data.lower()
    
    # Test with both models
    sample_prediction_input['model_choice'] = 'both'
    response = client.post('/predict', data=sample_prediction_input)
    assert response.status_code == 200
    assert b'result' in response.data.lower()

# Black-box Testing - API Endpoints
def test_packets_endpoint(client):
    """Test packets endpoint"""
    response = client.get('/packets')
    assert response.status_code == 200

def test_packets_get_endpoint(client):
    """Test packets-get endpoint"""
    response = client.get('/packets-get')
    assert response.status_code == 200
    assert isinstance(response.json, list)

def test_dos_prediction_endpoint(client):
    """Test dos-prediction endpoint"""
    response = client.get('/dos-prediction')
    assert response.status_code == 200
    data = response.json
    assert 'is_attack' in data
    assert 'probability' in data
    assert 'status' in data
    assert 'timestamp' in data

# Black-box Testing - Error Handling
def test_predict_endpoint_invalid_data(client):
    """Test prediction endpoint with invalid data"""
    # Test with missing data
    response = client.post('/predict', data={})
    assert response.status_code == 200
    assert b'analyze another' in response.data.lower()
    
    # Test with invalid data
    invalid_data = {
        'protocol_type': 'invalid_protocol',
        'service': 'invalid_service',
        'flag': 'invalid_flag',
        'duration': 'not_a_number',
        'src_bytes': 'invalid',
        'dst_bytes': 'invalid',
        'wrong_fragment': 'invalid',
        'model_choice': 'invalid_model'
    }
    
    response = client.post('/predict', data=invalid_data)
    assert response.status_code == 200
    assert b'analyze another' in response.data.lower()

# Black-box Testing - Boundary Values
def test_predict_endpoint_boundary_values(client):
    """Test prediction endpoint with boundary values"""
    # Test with minimum values
    min_data = {
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'duration': 0,
        'src_bytes': 0,
        'dst_bytes': 0,
        'wrong_fragment': 0,
        'model_choice': 'rf'
    }
    response = client.post('/predict', data=min_data)
    assert response.status_code == 200
    
    # Test with maximum values
    max_data = {
        'protocol_type': 'tcp',
        'service': 'http',
        'flag': 'SF',
        'duration': 999999,
        'src_bytes': 999999,
        'dst_bytes': 999999,
        'wrong_fragment': 999999,
        'model_choice': 'rf'
    }
    response = client.post('/predict', data=max_data)
    assert response.status_code == 200

# Black-box Testing - Navigation
def test_navigation_links(client):
    """Test navigation links between pages"""
    # Test home to predict
    response = client.get('/')
    assert response.status_code == 200
    assert b'href="/predict"' in response.data
    
    # Test predict to home
    response = client.get('/predict')
    assert response.status_code == 200
    assert b'analyze-button' in response.data  # Check for analyze button class
    
    # Test packets page navigation
    response = client.get('/packets')
    assert response.status_code == 200
    assert b'Network Packet Monitor' in response.data  # Check for page title
    assert b'fetchPackets()' in response.data  # Check for packet fetching function

# Black-box Testing - Form Validation
def test_form_validation(client, sample_prediction_input):
    """Test form validation for different input combinations"""
    # Test with empty protocol type
    data = dict(sample_prediction_input)  # Create a new dict instead of using copy
    data['protocol_type'] = ''
    response = client.post('/predict', data=data)
    assert response.status_code == 200
    assert b'analyze another' in response.data.lower()
    
    # Test with empty service
    data = dict(sample_prediction_input)  # Create a new dict instead of using copy
    data['service'] = ''
    response = client.post('/predict', data=data)
    assert response.status_code == 200
    assert b'analyze another' in response.data.lower()
    
    # Test with empty flag
    data = dict(sample_prediction_input)  # Create a new dict instead of using copy
    data['flag'] = ''
    response = client.post('/predict', data=data)
    assert response.status_code == 200
    assert b'analyze another' in response.data.lower()

# Black-box Testing - Model Selection
def test_model_selection(client, sample_prediction_input):
    """Test different model selection combinations"""
    # Test invalid model selection
    data = dict(sample_prediction_input)  # Create a new dict instead of using copy
    data['model_choice'] = 'invalid_model'
    response = client.post('/predict', data=data)
    assert response.status_code == 200
    assert b'analyze another' in response.data.lower()
    
    # Test missing model selection
    data = dict(sample_prediction_input)  # Create a new dict instead of using copy
    data.pop('model_choice', None)
    response = client.post('/predict', data=data)
    assert response.status_code == 200
    assert b'analyze another' in response.data.lower()

# Black-box Testing - Response Headers
def test_response_headers(client):
    """Test response headers for different endpoints"""
    # Test index page headers
    response = client.get('/')
    assert response.status_code == 200
    assert 'text/html' in response.headers['Content-Type']
    
    # Test predict page headers
    response = client.get('/predict')
    assert response.status_code == 200
    assert 'text/html' in response.headers['Content-Type']
    
    # Test API endpoint headers
    response = client.get('/packets-get')
    assert response.status_code == 200
    assert 'application/json' in response.headers['Content-Type'] 