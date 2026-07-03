import requests
import json

def test_ip(ip):
    api_key = '47dfcec04fee80c2115634c703d04cf2dc68ee623b4b2feb4ea7310bee92dd693bd3e9755f6379c7' # Insert your Api Key here
    url = 'https://api.abuseipdb.com/api/v2/check'
    
    headers = {
        'Accept': 'application/json',
        'Key': api_key
    }
    
    params = {
        'ipAddress': ip,
        'maxAgeInDays': '90'
    }

    print(f"[*] Checking Reputation for: {ip}...")
    response = requests.get(url, headers=headers, params=params)
    
    if response.status_code == 200:
        data = response.json()['data']
        print(f"[+] Success! Score: {data['abuseConfidenceScore']}%")
        print(f"[+] Country: {data['countryCode']} | ISP: {data['isp']}")
    else:
        print(f"[-] Error: {response.status_code}")
        print(response.text)

# Test both ip types
test_ip('8.8.8.8')      # Clean IP
print("-" * 30)
test_ip('141.98.11.11') # Likely Malicious IP
