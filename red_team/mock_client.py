import requests
import time

SERVER_URL = "http://127.0.0.1:8080/beacon"

while True:
    try:
        payload = {"bot_id": "cachyos_victim_01", "os": "linux"}
        response = requests.post(SERVER_URL, json=payload)
        print(f"[*] Sent beacon. Server replied: {response.json()}")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
    time.sleep(3) # Nhịp beacon