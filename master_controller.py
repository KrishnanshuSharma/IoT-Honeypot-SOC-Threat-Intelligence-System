import json
import time
import pickle
import re
import os
import csv
import warnings

# Silence the Scikit-Learn missing feature names warning
warnings.filterwarnings("ignore", category=UserWarning)

# --- 1. CONFIGURATION ---
LOG_FILE = '/home/adminn/iot_project/logs/iot_attacks.json'
MODEL_FILE = '/home/adminn/iot_project/rf_model.pkl'
CSV_FILE = '/home/adminn/iot_project/dataset.csv'

# --- 2. LOAD THE AI BRAIN ---
print("===================================================")
print("[*] Booting AI-Driven IoT Honeypot SOC...")
try:
    with open(MODEL_FILE, 'rb') as f:
        ai_brain = pickle.load(f)
    print("[+] Artificial Intelligence Model Loaded (Random Forest)")
except FileNotFoundError:
    print(f"[!] Critical Error: Could not find {MODEL_FILE}")
    exit()
print("===================================================")
print("[*] SYSTEM ACTIVE. Monitoring network traffic in real-time...")
print("===================================================\n")

# --- 3. FEATURE EXTRACTION ---
def extract_features_for_live_packet(entry):
    raw_data = str(entry.get("raw_data", ""))
    protocol = str(entry.get("protocol", "UNKNOWN")).upper()
    
    # Feature 1: Protocol_num
    protocol_map = {"HTTP": 1, "TELNET": 2, "MQTT": 3, "COAP": 4}
    protocol_num = protocol_map.get(protocol, 0)
    
    # Feature 2: payload_length
    payload_length = len(raw_data)
    
    # Feature 3: special_char_count
    special_chars = len(re.findall(r'[\'\"\;\,\-\<\>\$\|\&]', raw_data))
    
    # Feature 4: sql_keyword_count
    sql_keywords = len(re.findall(r'(?i)(select|union|insert|update|delete|drop|or 1=1)', raw_data))
    
    # Feature 5: cmd_keyword_count
    cmd_keywords = len(re.findall(r'(?i)(wget|curl|chmod|rm|reboot)', raw_data))
    
    # Feature 6: linux_cmd_count
    linux_cmds = len(re.findall(r'(?i)(cat|cd|sh|ls|sudo|pwd)', raw_data))
    
    # Return exactly 6 features matching your training CSV
    return [[protocol_num, payload_length, special_chars, sql_keywords, cmd_keywords, linux_cmds]]

# --- 4. THE REAL-TIME WATCHDOG LOOP ---
def follow_logs():
    with open(LOG_FILE, 'r') as file:
        # Go to the end of the file to wait for NEW attacks
        file.seek(0, os.SEEK_END)
        
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue
                
            try:
                # Parse the JSON log
                packet = json.loads(line.strip())
                ip = packet.get("src_ip", "UNKNOWN")
                proto = packet.get("protocol", "UNKNOWN")
                
                # Extract the 6 features and make a prediction
                live_features = extract_features_for_live_packet(packet)
                prediction = ai_brain.predict(live_features)[0]
                
                # Feed the Web Dashboard
                with open(CSV_FILE, 'a', newline='') as csvfile:
                    writer = csv.writer(csvfile)
                    row_to_save = live_features[0] + [prediction]
                    writer.writerow(row_to_save)
                    
                # Print the Alert to the Terminal
                print(f"[!] THREAT DETECTED | IP: {ip} | Port: {proto}")
                print(f"    -> AI Classification: {prediction}")
                print("-" * 50)
                
            except Exception as e:
                # Print exact error to avoid silent failures
                print(f"[!] ERROR PROCESSING PACKET: {e}")

if __name__ == "__main__":
    follow_logs()
