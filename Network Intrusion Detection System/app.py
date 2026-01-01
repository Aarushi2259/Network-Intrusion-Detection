import asyncio
import psutil
import threading
import collections
import time
import numpy as np
import joblib
import pyshark
from flask import Flask, render_template
from flask_socketio import SocketIO
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'nids_secret_secure_key'
socketio = SocketIO(app, cors_allowed_origins="*")

# --- CONFIGURATION ---
# IMPORTANT: Update this path to your Wireshark/tshark location
TSHARK_PATH = r'C:\Program Files\Wireshark\tshark.exe' 

# Load the model generated from your notebook
try:
    model = joblib.load('multiclass_nids.pkl')
    print("✅ Machine Learning Model loaded.")
except FileNotFoundError:
    print("❌ Critical Error: 'multiclass_nids.pkl' not found. Run your notebook first.")
    exit()

ATTACK_LABELS = {0: "Benign", 1: "Probe", 2: "DoS", 3: "R2L", 4: "U2R"}
pkt_history = collections.deque(maxlen=2000)

def get_active_interface():
    """Automatically detects the network card currently in use."""
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()
    for iface, info in stats.items():
        if info.isup and iface in addrs:
            for addr in addrs[iface]:
                if addr.family == 2 and not addr.address.startswith("127."):
                    return iface
    return None

def sniffer_worker():
    """Sniffs packets and emits AI classifications in real-time."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    interface = get_active_interface()
    if not interface:
        print("❌ Interface Detection Failed.")
        return
    
    print(f"📡 Sensor Live on: {interface}")
    
    try:
        capture = pyshark.LiveCapture(
            interface=interface, 
            bpf_filter='ip', 
            tshark_path=TSHARK_PATH
        )
        
        for pkt in capture.sniff_continuously():
            try:
                now = time.time()
                length = int(pkt.length)
                proto = 6 if 'TCP' in pkt else (17 if 'UDP' in pkt else 1)
                src_ip = pkt.ip.src
                
                # Feature Engineering: Count density
                pkt_history.append((now, src_ip))
                density = sum(1 for t, ip in pkt_history if t > now - 2 and ip == src_ip)
                
                # AI Inference
                features = np.array([[length, proto, density, density]])
                pred = int(model.predict(features)[0])
                
                socketio.emit('new_pkt', {
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "src": src_ip,
                    "dst": pkt.ip.dst,
                    "label": ATTACK_LABELS[pred],
                    "alert": bool(pred != 0)
                })
            except: continue
    except Exception as e:
        print(f"❌ Sniffer Crash: {e}")

@app.route('/')
def dashboard():
    return render_template('index.html')

if __name__ == '__main__':
    threading.Thread(target=sniffer_worker, daemon=True).start()
    socketio.run(app, debug=True, port=5000, use_reloader=False)