import json
import datetime
import time

# Tumhare log file ka exact path
LOG_FILE = '/home/adminn/iot_project/logs/iot_attacks.json'

# Real-world malicious IPs (Known scanners and botnets)
malicious_ips = [
    {"ip": "141.98.11.11", "desc": "Known SSH Bruteforcer", "type": "LOGIN_ATTEMPT", "port": 22},
    {"ip": "45.133.1.53", "desc": "Mirai Botnet Node", "type": "TELNET_BRUTE", "port": 23},
    {"ip": "194.169.175.128", "desc": "Web Vulnerability Scanner", "type": "EXPLOIT_HTTP_SQLI", "port": 80}
]

print("""
===================================================
 🌍 INITIATING GLOBAL THREAT INTEL INJECTION 🌍
===================================================
""")

try:
    with open(LOG_FILE, "a") as f:
        # Hum har IP ko 15-20 baar inject karenge taki woh "Top Threat Actors" list me upar aa jaye
        for actor in malicious_ips:
            print(f"[*] Injecting {actor['ip']} ({actor['desc']})...")
            for _ in range(15):
                entry = {
                    "timestamp": datetime.datetime.now().isoformat(),
                    "src_ip": actor["ip"],
                    "port": actor["port"],
                    "protocol": "TCP",
                    "type": actor["type"],
                    "raw_data": f"Automated Demo Payload from {actor['ip']}"
                }
                f.write(json.dumps(entry) + "\n")
            time.sleep(1) # Chota sa pause for dramatic effect
            
    print("\n[✔] THREAT INJECTION COMPLETE.")
    print(">>> Ab apna Dashboard refresh karo! <<<")
    print(">>> 'Top Threat Actors' table me dekho, AbuseIPDB API inke red scores aur country flags pull kar legi.")

except PermissionError:
    print("[!] ERROR: Sudo ke sath run karo (sudo python3 abuseipdb_demo.py)")
except Exception as e:
    print(f"[!] ERROR: {e}")
