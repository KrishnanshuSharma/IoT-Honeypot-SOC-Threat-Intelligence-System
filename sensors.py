import socket
import threading
import json
import time

LOG_FILE = '/home/adminn/iot_project/logs/iot_attacks.json'

def start_sensor(port, service_name):
    """Opens a port, listens for attacks, and logs them to the JSON file."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # This ensures the port is freed immediately if you restart the script
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
    
    try:
        s.bind(('0.0.0.0', port))
        s.listen(5)
        print(f"[*] {service_name} Sensor ACTIVE on Port {port}")
        
        while True:
            conn, addr = s.accept()
            try:
                # Grab the payload sent by the attacker
                data = conn.recv(1024).decode('utf-8', errors='ignore').strip()
                if data:
                    log_entry = {
                        "timestamp": time.strftime("%H:%M:%S"),
                        "src_ip": addr[0],
                        "port": port,
                        "raw_data": data
                    }
                    # Write it to the log file for the dashboard to read
                    with open(LOG_FILE, 'a') as f:
                        f.write(json.dumps(log_entry) + "\n")
                    print(f"[!] {service_name} Attack Captured from {addr[0]}")
            except Exception:
                pass
            finally:
                conn.close()
    except PermissionError:
        print(f"[X] Permission Denied: Port {port}. Did you forget 'sudo'?")
    except Exception as e:
        print(f"[X] Failed to start {service_name} on Port {port}: {e}")

# Define our honeypot attack surfaces
targets = [
    (80, "HTTP/Web"),
    (22, "SSH"),
    (23, "Telnet/Mirai"),
    (1883, "MQTT/IoT")
]

print("=========================================")
print("   INITIALIZING IOT HONEYPOT SENSORS     ")
print("=========================================")

# Start a background thread for each port
for port, name in targets:
    t = threading.Thread(target=start_sensor, args=(port, name))
    t.daemon = True
    t.start()

# Keep the main script running
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[*] Shutting down sensors.")
