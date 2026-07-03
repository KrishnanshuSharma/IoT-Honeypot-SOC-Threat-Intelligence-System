import socket
import json
import datetime
import threading
import os

# --- CONFIGURATION ---
BIND_IP = '0.0.0.0'
BIND_PORT = 1883
# Updated to match your username 'adminn'
LOG_FILE = '/home/adminn/iot_project/logs/iot_attacks.json'

def log_attack(ip, payload_data):
    timestamp = datetime.datetime.now().isoformat()
    
    # Try to decode payload to text, otherwise keep it raw
    try:
        payload_str = payload_data.decode('utf-8', errors='ignore')
    except:
        payload_str = str(payload_data)

    entry = {
        "timestamp": timestamp,
        "src_ip": ip,
        "protocol": "MQTT",
        "type": "PAYLOAD_CAPTURE",
        "raw_data": payload_str
    }

    try:
        # Ensure directory exists just in case
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        
        print(f"[*] ALERT: Captured attack data from {ip}")
    except Exception as e:
        print(f"[!] ERROR WRITING LOG: {e}")

def handle_hacker(client_socket, address):
    ip = address[0]
    # print(f"[+] Connection from: {ip}") # Uncomment to see every connection attempt
    
    try:
        # 1. Receive their initial Hello
        client_socket.recv(1024)
        
        # 2. THE TRICK: Send "Login Success" (ConnAck)
        client_socket.send(b'\x20\x02\x00\x00')
        
        # 3. Listen for the payload
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            # Only log if they actually send data
            if len(data) > 0:
                log_attack(ip, data)
                
    except Exception as e:
        print(f"[!] ERROR CRASH in Connection: {e}")
    finally:
        client_socket.close()

def start_trap():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Allow reusing the address (fixes "Address already in use" errors)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((BIND_IP, BIND_PORT))
    except PermissionError:
        print("[!] ERROR: You must run this with SUDO (Permission Denied for Port 1883)")
        return

    server.listen(5)
    print(f"==========================================")
    print(f"[*] IoT HONEYPOT ACTIVE. Listening on port {BIND_PORT}")
    print(f"[*] Log File: {LOG_FILE}")
    print(f"==========================================")

    while True:
        try:
            client, addr = server.accept()
            t = threading.Thread(target=handle_hacker, args=(client, addr))
            t.start()
        except KeyboardInterrupt:
            print("\n[*] Stopping Honeypot...")
            break

if __name__ == '__main__':
    start_trap()
