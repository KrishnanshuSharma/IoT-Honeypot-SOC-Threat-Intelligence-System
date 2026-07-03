import pandas as pd
import os

print("==========================================")
print("[*] Loading UNSW-NB15 Open Source Dataset...")

# Load the UNSW training dataset
unsw_path = "CSV Files/Training and Testing Sets/UNSW_NB15_training-set.csv"
unsw_df = pd.read_csv(unsw_path)

print("[*] Translating Features for Honeypot AI...")
translated_df = pd.DataFrame()

# 1. Map Source Bytes to our Payload Length
translated_df['payload_length'] = unsw_df['sbytes']

# 2. Since UNSW is flow data (no raw text), we set text features to 0
translated_df['special_char_count'] = 0
translated_df['sql_keyword_count'] = 0
translated_df['linux_cmd_count'] = 0

# 3. Translate the UNSW attack categories to match our honeypot labels
def translate_label(row):
    cat = str(row['attack_cat']).strip().lower()
    if 'reconnaissance' in cat: return 'NMAP_RECON'
    if 'dos' in cat: return 'MQTT_FLOOD'
    if 'exploit' in cat: return 'EXPLOIT_HTTP_SQLI'
    if 'normal' in cat: return 'NORMAL_TRAFFIC'
    return 'UNKNOWN_ATTACK'

translated_df['label'] = unsw_df.apply(translate_label, axis=1)

# Drop the unknowns to keep the AI focused
translated_df = translated_df[translated_df['label'] != 'UNKNOWN_ATTACK']

# Take a random sample of 5,000 attacks
sampled_df = translated_df.sample(n=5000, random_state=42)

print("[*] Merging with local honeypot dataset.csv...")
local_df = pd.read_csv("dataset.csv")

# Combine them into one massive dataset
mega_dataset = pd.concat([local_df, sampled_df], ignore_index=True)

# Save the new master dataset
mega_dataset.to_csv("master_dataset.csv", index=False)
print(f"[+] Success! master_dataset.csv created with {len(mega_dataset)} total rows.")
print("==========================================")
