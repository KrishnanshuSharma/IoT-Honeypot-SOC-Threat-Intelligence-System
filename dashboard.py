import os
import json
import requests
import psutil
import time
from collections import Counter
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# --- CONFIGURATION ---
LOG_FILE = '/home/adminn/iot_project/logs/iot_attacks.json'
CSV_FILE = '/home/adminn/iot_project/dataset.csv'
ABUSE_IPDB_KEY = "ENTER YOUR API KEY HERE"

# Globals for Tracking
last_net_io = psutil.net_io_counters().bytes_recv
last_time = time.time()
ip_cache = {}

def get_geo_info(ip):
    if ip in ip_cache: return ip_cache[ip]
    if ip.startswith("192.168.") or ip == "127.0.0.1":
        return {"country": "Local Network", "flag": "🏠", "isp": "Internal VM"}
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2).json()
        if res.get("status") == "success":
            info = {"country": res.get("country"), "flag": "🌍", "isp": res.get("isp", "Unknown")}
        else:
            info = {"country": "Unknown", "flag": "❓", "isp": "Unknown"}
    except:
        info = {"country": "Unknown", "flag": "❓", "isp": "Check Connection"}
    ip_cache[ip] = info
    return info

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_ip():
    ip = request.json.get('ip')
    geo = get_geo_info(ip)
    reputation = {"abuseConfidenceScore": 0, "totalReports": 0}
    
    if not ip.startswith("192.168.") and ABUSE_IPDB_KEY:
        try:
            headers = {'Accept': 'application/json', 'Key': ABUSE_IPDB_KEY}
            params = {'ipAddress': ip, 'maxAgeInDays': '90'}
            res = requests.get('https://api.abuseipdb.com/api/v2/check', headers=headers, params=params, timeout=2)
            if res.status_code == 200:
                reputation = res.json()['data']
        except: pass

    # --- DEEP FORENSICS: SESSION RECONSTRUCTION ---
    session_history = []
    try:
        with open(LOG_FILE, 'r') as f:
            for line in reversed(f.readlines()):
                if not line.strip(): continue
                entry = json.loads(line)
                if entry.get('src_ip') == ip or entry.get('ip') == ip:
                    # Format: [Time] Port X: Payload
                    msg = f"[{entry.get('timestamp')}] Port {entry.get('port', '??')}: {entry.get('raw_data', 'No Data')}"
                    session_history.append(msg)
                    if len(session_history) >= 5: break
    except: pass

    return jsonify({
        "ip": ip, "country": geo['country'], "flag": geo['flag'], "isp": geo['isp'],
        "score": reputation.get('abuseConfidenceScore', 'N/A'),
        "reports": reputation.get('totalReports', 'N/A'),
        "session": "\n---\n".join(session_history) if session_history else "No session data."
    })

@app.route('/api/ban', methods=['POST'])
def ban_ip():
    ip = request.json.get('ip')
    if ip:
        os.system(f"sudo iptables -I INPUT -s {ip} -j DROP")
        return jsonify({"status": "success"})
    return jsonify({"status": "error"}), 400

@app.route('/api/data')
def get_data():
    global last_net_io, last_time
    recent_logs, all_ips, attack_counts = [], [], {}
    
    # 1. System & Network Health
    now_ts = time.time()
    curr_io = psutil.net_io_counters().bytes_recv
    dt = now_ts - last_time
    net_speed = (curr_io - last_net_io) / 1024 / (dt if dt > 0 else 1)
    last_net_io, last_time = curr_io, now_ts

    # 2. Timeline Logic (Last 10 Minutes)
    timeline = {}
    now_dt = datetime.now()
    for i in range(10):
        t_key = (now_dt - timedelta(minutes=i)).strftime('%H:%M')
        timeline[t_key] = 0

# 3. Parse Logs
    try:
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            for line in lines:
                if not line.strip(): continue
                data = json.loads(line)
                ip = data.get('src_ip', data.get('ip', 'UNKNOWN'))
                all_ips.append(ip)

                # --- FIX 1: BAR CHART SPIKES ---
                # Count directly from the JSON log so it captures CoAP!
                label = data.get('type', '')
                attack_counts[label] = attack_counts.get(label, 0) + 1

                # --- FIX 2: TIMELINE SPIKES ---
                # A robust time parser that handles both ISO and standard timestamps
                ts = data.get('timestamp', '')
                if 'T' in ts:
                    m_key = ts.split('T')[1][:5] # Extracts 19:34 from ISO
                elif ' ' in ts:
                    m_key = ts.split(' ')[1][:5]
                else:
                    m_key = ts[:5]
                    
                if m_key in timeline: 
                    timeline[m_key] += 1

            for line in lines[-50:]:
                data = json.loads(line)
                ip = data.get('src_ip', data.get('ip', 'UNKNOWN'))
                geo = get_geo_info(ip)
                recent_logs.append({
#                    "time": data.get("timestamp", "Just now"),
		    "time": data.get("timestamp", "Just now").replace("T", " ").split(".")[0],
                    "ip": ip, 
                    "location": f"{geo['flag']} {geo['country']}",
                    "port": data.get("port", data.get("dst_port", "Unknown")),
                    "type": data.get("type", ""), 
                    "payload": str(data.get('raw_data', ""))[0:50]
                })
    except: pass

# 4. Analytics Finalization
    sorted_timeline = sorted(timeline.items())
    
    # --- RESTORE AI CLASSIFICATIONS FROM CSV ---
    try:
        with open(CSV_FILE, 'r') as f:
            csv_lines = f.readlines()[1:] # Skip the header row
            for line in csv_lines:
                parts = line.strip().split(',')
                if len(parts) >= 7:
                    label = parts[-1]
                    attack_counts[label] = attack_counts.get(label, 0) + 1
    except: pass

    return jsonify({
        "sys_stats": {"cpu": psutil.cpu_percent(), "ram": psutil.virtual_memory().percent, "net": round(net_speed, 2)},
        "recent_logs": list(reversed(recent_logs)),
        "top_talkers": [{"ip": ip, "count": count} for ip, count in Counter(all_ips).most_common(5)],
        "attack_labels": list(attack_counts.keys()),
        "attack_counts": list(attack_counts.values()),
        "timeline_labels": [x[0] for x in sorted_timeline],
        "timeline_data": [x[1] for x in sorted_timeline],
        "total_attacks": len(all_ips)
    })

# --- ABUSEIPDB REPUTATION API ROUTE ---
@app.route('/api/reputation/<ip>')
def get_reputation(ip):
    # PASTE YOUR REAL API KEY INSIDE THESE QUOTES:
    ABUSE_IPDB_KEY = "47dfcec04fee80c2115634c703d04cf2dc68ee623b4b2feb4ea7310bee92dd693bd3e9755f6379c7" 

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': ABUSE_IPDB_KEY
    }
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }
    
    try:
        res = requests.get(url, headers=headers, params=params, timeout=5)
        res.raise_for_status()
        return res.json().get('data', {}), 200
    except Exception as e:
        print(f"[ERROR] API Request Failed: {e}")
        return {"error": str(e)}, 500

    
# --------------------------------------

# Your existing startup code should be right below this:
# if __name__ == '__main__':
#     app.run(...)
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=61234)
