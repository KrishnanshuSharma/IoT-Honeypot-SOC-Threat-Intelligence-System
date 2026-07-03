import json
import random
import datetime

LOG_FILE = '/home/adminn/iot_project/logs/iot_attacks.json'

print("==========================================")
print("[*] Patching AI Database with Zero-Day Signatures...")

with open(LOG_FILE, 'a') as f:
    # 1. Inject 500 Nmap Recon Scans (Tiny, malformed garbage packets)
    for _ in range(500):
        log = {
            "timestamp": datetime.datetime.now().isoformat(),
            "src_ip": "192.168.56.4",
            "protocol": random.choice(["TELNET", "HTTP", "MQTT", "COAP"]),
            "type": "NMAP_RECON",
            "raw_data": "".join(random.choices(['\x00', '\x01', '\x02', 'A', 'B', 'C'], k=random.randint(1, 5)))
        }
        f.write(json.dumps(log) + '\n')

    # 2. Inject 500 MQTT Floods (Rapid, repetitive payloads)
    for _ in range(500):
        log = {
            "timestamp": datetime.datetime.now().isoformat(),
            "src_ip": "192.168.56.4",
            "protocol": "MQTT",
            "type": "MQTT_FLOOD",
            "raw_data": f"MALICIOUS_FLOOD_DATA_{random.randint(10000, 99999)}"
        }
        f.write(json.dumps(log) + '\n')

print("[+] Successfully injected 1,000 new Threat Signatures!")
print("==========================================")
