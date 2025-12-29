from flask import Flask, render_template, request, jsonify, Response
import pandas as pd
import numpy as np
import joblib
from collections import defaultdict
import json
import time
from datetime import datetime

app = Flask(__name__)

# Load the trained model and label encoder
try:
    rf_model = joblib.load('random_forest_model.pkl')
    le = joblib.load('label_encoder.pkl')
    print("✓ Model loaded successfully")
except:
    print("⚠ Model files not found. Please train the model first.")
    rf_model = None
    le = None

# Global state
attack_counter = defaultdict(int)
recent_detections = []
is_monitoring = False

def extract_features(traffic_df):
    """Extract features from traffic data"""
    flows = traffic_df.groupby(['src_ip','dst_ip','protocol'])
    
    features = pd.DataFrame()
    features['packet_count'] = flows.size()
    features['total_bytes'] = flows['length'].sum()
    features['avg_packet_size'] = flows['length'].mean()
    features['duration'] = flows['time'].max() - flows['time'].min()
    
    features.reset_index(inplace=True)
    features.fillna(0, inplace=True)
    
    return features

def ml_detect(row):
    """ML-based detection using trained Random Forest"""
    if rf_model is None:
        return 'benign'
    
    data = [[
        row['packet_count'],
        row['total_bytes'],
        row['avg_packet_size'],
        row['duration']
    ]]
    
    pred = rf_model.predict(data)[0]
    return le.inverse_transform([pred])[0]

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    """Get current statistics"""
    return jsonify({
        'stats': dict(attack_counter),
        'recent': recent_detections[-10:],
        'is_monitoring': is_monitoring
    })

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """Handle file upload and analysis"""
    global is_monitoring, attack_counter, recent_detections
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        # Read CSV
        traffic = pd.read_csv(
            file,
            encoding='latin1',
            on_bad_lines='skip',
            low_memory=False
        )
        
        # Clean column names
        traffic.columns = traffic.columns.str.strip()
        
        # Rename columns
        traffic = traffic.rename(columns={
            'Time': 'time',
            'Source': 'src_ip',
            'Destination': 'dst_ip',
            'Protocol': 'protocol',
            'Length': 'length'
        })
        
        # Select relevant columns
        traffic = traffic[['time','src_ip','dst_ip','protocol','length']]
        
        # Extract features
        features = extract_features(traffic)
        
        # Reset counters
        attack_counter = defaultdict(int)
        recent_detections = []
        
        # Analyze first 100 flows
        total_flows = min(len(features), 100)
        
        for i in range(total_flows):
            row = features.iloc[i]
            attack_type = ml_detect(row)
            attack_counter[attack_type] += 1
            
            recent_detections.append({
                'id': i,
                'type': attack_type,
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'packets': int(row['packet_count']),
                'avg_size': round(float(row['avg_packet_size']), 1),
                'duration': round(float(row['duration']), 2)
            })
        
        return jsonify({
            'success': True,
            'total_flows': total_flows,
            'stats': dict(attack_counter)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/monitor/start', methods=['POST'])
def start_monitoring():
    """Start real-time monitoring"""
    global is_monitoring
    is_monitoring = True
    return jsonify({'status': 'started'})

@app.route('/api/monitor/stop', methods=['POST'])
def stop_monitoring():
    """Stop real-time monitoring"""
    global is_monitoring
    is_monitoring = False
    return jsonify({'status': 'stopped'})

@app.route('/api/monitor/stream')
def monitor_stream():
    """Server-sent events for real-time updates"""
    def generate():
        while is_monitoring:
            data = {
                'stats': dict(attack_counter),
                'recent': recent_detections[-10:]
            }
            yield f"data: {json.dumps(data)}\n\n"
            time.sleep(2)
    
    return Response(generate(), mimetype='text/event-stream')

@app.route('/api/reset', methods=['POST'])
def reset_stats():
    """Reset all statistics"""
    global attack_counter, recent_detections
    attack_counter = defaultdict(int)
    recent_detections = []
    return jsonify({'status': 'reset'})

if __name__ == '__main__':
    app.run(debug=True, port=5000)