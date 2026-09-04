from flask import Flask, request

app = Flask(__name__)

@app.route('/beacon', methods=['POST'])
def receive_beacon():
    data = request.json
    print(f"[+] Received beacon from bot: {data}")
    return {"status": "ok", "command": "sleep"}

if __name__ == '__main__':
    print("[*] C2 Server listening on port 8080...")
    app.run(host='0.0.0.0', port=8080)