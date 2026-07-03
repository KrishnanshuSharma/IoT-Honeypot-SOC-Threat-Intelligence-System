from flask import Flask, request
import json
import datetime
import logging

# Keep terminal clean from default Flask logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
LOG_FILE = '/home/adminn/iot_project/logs/iot_attacks.json'

print("==========================================")
print("[*] SMART HTTP Web Honeypot Active")
print("[*] Listening on Port 80 (Web)")
print("==========================================")

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    payload = f"USER: {username} | PASS: {password}"
    
    # --- THE DYNAMIC AI LABELING FIX ---
    if "'" in payload or "OR " in payload.upper() or "1=1" in payload:
        attack_type = "EXPLOIT_HTTP_SQLI"
    else:
        attack_type = "LOGIN_ATTEMPT"

    # Create the JSON Log Entry
    log_entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "src_ip": request.remote_addr,
        "protocol": "HTTP",
        "type": attack_type,
        "raw_data": payload
    }

    # Save to Database
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(log_entry) + '\n')
        
    print(f"[*] ALERT [HTTP]: Captured {attack_type} from {request.remote_addr}")

    # The Fake MySQL Error
    fake_error = """<br>
    <b>Warning</b>: mysql_fetch_assoc() expects parameter 1 to be resource, boolean given in <b>/var/www/html/auth.php</b> on line <b>42</b><br>
    <br>
    <div style="text-align:center; font-family:sans-serif;">
        <h3 style="color:red;">Database Query Failed.</h3>
    </div>"""
    
    return fake_error, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)
