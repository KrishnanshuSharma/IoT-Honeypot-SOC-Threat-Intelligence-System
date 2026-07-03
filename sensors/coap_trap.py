import socket
import json
import datetime
import os

# --- 1. CONFIGURATION ---
BIND_IP = '0.0.0.0'
BIND_PORT = 5683 # Default CoAP UDP Port
LOG_FILE = '/home/adminn/iot_project/logs/iot_attacks.json'

def log_attack(ip, attack_type, payload):
    entry = {
        "timestamp": datetime.datetime.now().isoformat(),
        "src_ip": ip,
	"port": BIND_PORT,
        "protocol": "COAP (UDP)",
        "type": attack_type,
        "raw_data": payload
    }
    
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"[*] ALERT [COAP]: Captured {attack_type} from {ip}")
    except Exception as e:
        print(f"[!] Error writing to log: {e}")

# --- 2. UDP DECEPTION ENGINE ---
def start_trap():
    # SOCK_DGRAM specifies this is a UDP socket
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        server.bind((BIND_IP, BIND_PORT))
        print("==========================================")
        print("[*] SECURE COAP IoT Honeypot Active")
        print("[*] Listening on Port 5683 (UDP)")
        print("==========================================")
        
        while True:
            # UDP doesn't "accept" connections, it just receives datagrams
            data, addr = server.recvfrom(2048) 
            ip = addr[0]
            
            # CoAP payloads are often binary, so we try to decode as text, 
            # and fallback to hex representation if it's raw machine code
            try:
                payload_str = data.decode('utf-8', errors='ignore').strip()
            except:
                payload_str = data.hex()

            # --- ATTACK CLASSIFICATION ---
            
            # 1. Reconnaissance: Attackers scan for ".well-known/core" to map the device
            if ".well-known/core" in payload_str:
                attack_type = "RECON_COAP_DISCOVERY"
                # Deception: Send back a fake resource list simulating a smart thermostat
                fake_response = b'</sensors/temp>;rt="temperature-c", </sensors/light>;rt="light-lux"'
                server.sendto(fake_response, addr)
                
            # 2. DDoS Amplification Attempt: Sending unusually large payloads to UDP
            elif len(data) > 100:
                attack_type = "DOS_AMPLIFICATION_ATTEMPT"
                
            # 3. Generic/Malformed CoAP traffic
            else:
                attack_type = "COAP_MALFORMED_PAYLOAD"

            log_attack(ip, attack_type, payload_str[:250]) # Truncate to save disk space
            
    except PermissionError:
        print("[!] ERROR: Run with sudo!")
    except Exception as e:
        print(f"[!] Server error: {e}")

if __name__ == '__main__':
    start_trap()
