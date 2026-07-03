import socket
import json
import datetime
import threading

LOG_FILE = '/home/adminn/iot_project/logs/iot_attacks.json'

def handle_client(client_socket, addr):
    try:
        # 1. The Fake Login Sequence
        client_socket.send(b"Ubuntu 20.04 LTS\r\n")
        client_socket.send(b"iot-device login: ")
        username = client_socket.recv(1024).decode('utf-8').strip()
        
        client_socket.send(b"Password: ")
        password = client_socket.recv(1024).decode('utf-8').strip()
        
        # 2. The Hook (Pretend they successfully hacked us)
        client_socket.send(b"\r\nAuthentication successful.\r\n")
        client_socket.send(b"root@iot-device:~# ") # Fake Linux Shell Prompt
        
        # 3. Capture the Malware Payload
        payload = client_socket.recv(2048).decode('utf-8').strip()
        
        if payload:
            print(f"[*] ALERT [TELNET]: Captured malware payload from {addr[0]}")
            
            # Log the attack for the AI Watchdog
            log_entry = {
                "timestamp": datetime.datetime.now().isoformat(),
                "src_ip": addr[0],
                "protocol": "TELNET",
                "type": "MIRAI_BOTNET_ATTACK",
                "raw_data": payload
            }
            
            with open(LOG_FILE, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
                
        # 4. Drop the connection after capturing
        client_socket.send(b"Connection closed by foreign host.\r\n")
        
    except Exception as e:
        pass
    finally:
        client_socket.close()

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 23))
    server.listen(5)
    
    print("==========================================")
    print("[*] HIGH-INTERACTION Telnet Honeypot Active")
    print("[*] Listening on Port 23 (Telnet)")
    print("==========================================")
    
    while True:
        client, addr = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client, addr))
        client_handler.start()

if __name__ == "__main__":
    main()
