import json
import csv
import re
import os

# --- CONFIGURATION ---
LOG_FILE = '/home/adminn/iot_project/logs/iot_attacks.json'
CSV_FILE = '/home/adminn/iot_project/dataset.csv'

def extract_features(entry):
    protocol = entry.get("protocol", "UNKNOWN")
    attack_type = entry.get("type", "UNKNOWN")
    raw_data = str(entry.get("raw_data", ""))
    
    # Feature 1: Protocol Encoding
    protocol_map = {"HTTP": 1, "TELNET": 2, "MQTT": 3, "COAP (UDP)": 4}
    protocol_num = protocol_map.get(protocol.upper(), 0)

    # Feature 2: Payload Length
    payload_length = len(raw_data)
    
    # Feature 3: Special Character Count (Hooks for SQLi, XSS, Command Injection)
    # Counts occurrences of: ' " ; - < > $ | &
    special_chars = len(re.findall(r'[\'";\-<>$|&]', raw_data))
    
    # Feature 4: SQL Injection Keywords
    sql_keywords = len(re.findall(r'(?i)(select|union|insert|update|delete|drop|or 1=1)', raw_data))
    
    # Feature 5: Malicious Command Keywords (Mirai / OS Injection)
    cmd_keywords = len(re.findall(r'(?i)(wget|curl|chmod|rm|reboot|cat|cd|sh)', raw_data))
    
    # The Label: This is the "Answer" we want the AI to learn to predict
    label = attack_type
    
    return [protocol_num, payload_length, special_chars, sql_keywords, cmd_keywords, label]

def process_data():
    print("==========================================")
    print("[*] Starting AI Data Preprocessing...")
    print("==========================================")
    
    if not os.path.exists(LOG_FILE):
        print(f"[!] Error: {LOG_FILE} not found. Did you run the generator?")
        return
        
    with open(LOG_FILE, 'r') as jfile, open(CSV_FILE, 'w', newline='') as cfile:
        writer = csv.writer(cfile)
        
        # Write the Column Headers for our CSV
        writer.writerow(["protocol_num", "payload_length", "special_char_count", "sql_keyword_count", "cmd_keyword_count", "label"])
        
        count = 0
        for line in jfile:
            try:
                entry = json.loads(line.strip())
                features = extract_features(entry)
                writer.writerow(features)
                count += 1
            except Exception as e:
                continue
                
    print(f"[+] Successfully engineered features for {count} attack records.")
    print(f"[+] Clean ML Dataset saved to: {CSV_FILE}")
    print("==========================================")

if __name__ == "__main__":
    process_data()
