from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
import pandas as pd
from capture import start_capture, packet_data, dos_prediction, dos_probability, dos_status
from datetime import datetime
app = Flask(__name__)
start_capture()

# Load trained model pipelines
try:
    rf_model = joblib.load('rf_pipeline.pkl')
    gb_model = joblib.load('gb_pipeline.pkl')
    ann_model = joblib.load('ann_pipeline.pkl')
except Exception as e:
    print(f"❌ Failed to load model files: {e}")
    # Continue with at least the rf_model which was loaded in capture.py
    gb_model = None
    ann_model = None

# Input feature list (must match training exactly)
features = [
    'protocol_type', 'service', 'flag',
    'duration', 'src_bytes', 'dst_bytes', 'wrong_fragment'
]

# Extract categories for dropdowns from the preprocessing pipeline
try:
    preprocessor = rf_model.named_steps['preprocessor']
    protocol_types = preprocessor.named_transformers_['cat'].categories_[0].tolist()
    services = preprocessor.named_transformers_['cat'].categories_[1].tolist()
    flags = preprocessor.named_transformers_['cat'].categories_[2].tolist()
except Exception as e:
    print(f"⚠️ Could not extract categories: {e}")
    # Fallback values
    protocol_types = ['tcp', 'udp', 'icmp']
    services = ['http', 'ftp', 'smtp', 'domain', 'other']
    flags = ['SF', 'S0', 'REJ', 'RSTO', 'SH']

def interpret_prediction(probabilities):
    """Convert prediction probabilities into label."""
    if len(probabilities) == 1:
        return "Normal" if probabilities[0] > 0.5 else "Attack"
    return "Attack" if probabilities[1] > 0.5 else "Normal"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if request.method == 'POST':
        try:
            form_data = request.form.to_dict()
            selected_model = form_data.pop('model_choice', 'rf')
            
            # Ensure all expected features are present
            input_data = {k: form_data[k] for k in features if k in form_data}
            input_df = pd.DataFrame([input_data])
            
            # Results dictionary
            output = {}
            
            if selected_model in ['rf', 'both'] and rf_model is not None:
                rf_proba = rf_model.predict_proba(input_df)[0]
                output['rf_result'] = interpret_prediction(rf_proba)
                output['rf_confidence'] = round(max(rf_proba) * 100, 2)
            
            if selected_model in ['gb', 'both'] and gb_model is not None:
                gb_proba = gb_model.predict_proba(input_df)[0]
                output['gb_result'] = interpret_prediction(gb_proba)
                output['gb_confidence'] = round(max(gb_proba) * 100, 2)
            
            if selected_model in ['ann', 'both'] and ann_model is not None:
                ann_proba = ann_model.predict_proba(input_df)[0]
                output['ann_result'] = interpret_prediction(ann_proba)
                output['ann_confidence'] = round(max(ann_proba) * 100, 2)
            
            return render_template(
                'results.html',
                model_choice=selected_model,
                input_data=input_data,
                **output
            )
        except Exception as e:
            return render_template('error.html', error_message=f"Prediction failed: {e}")
    
    # GET method - render input form
    return render_template(
        'predict.html',
        protocol_types=protocol_types,
        services=services,
        flags=flags
    )

@app.route('/packets')
def packets():
    return render_template('packets.html')

@app.route('/packets-get')
def get_packets():
    return jsonify(packet_data)

@app.route('/dos-prediction')
def get_dos_prediction():
    from capture import dos_prediction, dos_probability, dos_status, last_update
    return jsonify({
        'is_attack': str(dos_prediction).lower(),
        'probability': dos_probability,
        'status': dos_status,
        'timestamp': last_update
        })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)