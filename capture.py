import pyshark
import threading
from datetime import datetime
import time
import joblib
import numpy as np
import pandas as pd

packet_data = []
dos_prediction = False
dos_probability = 0.0
dos_status = "Normal" 
last_update = datetime.now().strftime('%H:%M:%S')

# Load the trained model
model = joblib.load('rf_pipeline.pkl')

def capture_packets():
    # Capture packets on port 1337
    capture = pyshark.LiveCapture(interface='lo', bpf_filter='tcp port 1234')
    packet_count = 0
    batch_start_time = None
    
    for packet in capture.sniff_continuously():
        try:
            if 'IP' in packet:
                timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp))
                formatted_time = timestamp.strftime('%H:%M:%S.%f')[:-3]

                if batch_start_time is None:
                    batch_start_time = timestamp

                info = {
                    'timestamp': formatted_time,
                    'src': packet.ip.src,
                    'dst': packet.ip.dst,
                    'proto': packet.highest_layer,
                    'base_proto': packet.ip.proto,
                    'length': packet.length,
                    'ip_version': packet.ip.version,
                    'ttl': packet.ip.ttl,
                    'ip_flags': packet.ip.flags if hasattr(packet.ip, 'flags') else 'N/A',
                }

                if 'TCP' in packet:
                    info.update({
                        'src_port': packet.tcp.srcport,
                        'dst_port': packet.tcp.dstport,
                        'tcp_flags': packet.tcp.flags,
                        'tcp_window_size': packet.tcp.window_size,
                        'tcp_seq': packet.tcp.seq,
                        'tcp_ack': packet.tcp.ack if hasattr(packet.tcp, 'ack') else 'N/A',
                    })
                elif 'UDP' in packet:
                    info.update({
                        'src_port': packet.udp.srcport,
                        'dst_port': packet.udp.dstport,
                        'udp_length': packet.udp.length,
                    })
                else:
                    info.update({
                        'src_port': 'N/A',
                        'dst_port': 'N/A',
                    })

                if 'HTTP' in packet:
                    info['http_info'] = {
                        'method': packet.http.request_method if hasattr(packet.http, 'request_method') else 'N/A',
                        'host': packet.http.host if hasattr(packet.http, 'host') else 'N/A',
                        'uri': packet.http.request_uri if hasattr(packet.http, 'request_uri') else 'N/A',
                    }

                if 'DNS' in packet:
                    info['dns_info'] = {
                        'qry_name': packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else 'N/A',
                        'qry_type': packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else 'N/A',
                    }

                packet_data.append(info)
                packet_count += 1

                # Analyze batch after 10 packets or 5 seconds, whichever comes first
                if packet_count >= 10:
                    analyze_batch(packet_data[-packet_count:])
                    packet_count = 0
                    batch_start_time = None

        except AttributeError as e:
            continue

def analyze_batch(batch):
    global dos_prediction, dos_probability, dos_status, last_update
    
    if not batch:
        return

    print(batch[0])

    # Calculate duration of the batch
    first_packet_time = datetime.strptime(batch[0]['timestamp'], '%H:%M:%S.%f')
    last_packet_time = datetime.strptime(batch[-1]['timestamp'], '%H:%M:%S.%f')
    duration = (last_packet_time - first_packet_time).total_seconds()

    # Prepare features for prediction
    df = pd.DataFrame([{
        'protocol_type': pkt['proto'],
        'service': pkt['http_info']['method'] if 'http_info' in pkt and isinstance(pkt['http_info'], dict) else 'other',
        'flag': pkt['tcp_flags'] if 'tcp_flags' in pkt else 'OTH',
        'duration': duration,
        'src_bytes': int(pkt['length']),
        'dst_bytes': 0,
        'wrong_fragment': 0  # Default value
    } for pkt in batch])

    try:
        # Get probabilities for the entire batch
        probabilities = model.predict_proba(df)
        
        # Calculate average probability of attack (assuming class 1 is attack)
        if probabilities.shape[1] > 1:
            avg_prob = np.mean(probabilities[:, 1])
        else:
            avg_prob = np.mean(probabilities)
        
        # Update global variables
        dos_probability = float(avg_prob)
        dos_prediction = avg_prob > 0.5
        dos_status = "DoS Attack Detected" if dos_prediction else "Normal Traffic"
        last_update = datetime.now().strftime('%H:%M:%S')
        
        print(f"Batch analysis: {len(batch)} packets, Avg probability: {avg_prob:.2f}, Is DoS: {dos_prediction}")
        
    except Exception as e:
        print(f"Error during batch analysis: {e}")
        dos_prediction = False
        dos_probability = 0.0
        dos_status = "Analysis Error"
        last_update = datetime.now().strftime('%H:%M:%S')

def start_capture():
    print("Starting packet capture...")
    thread = threading.Thread(target=capture_packets, daemon=True)
    thread.start()