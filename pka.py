import socket
import json
import os
import traceback

class PublicKeyAuthority:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port
        self.public_keys = {}
        self.keys_dir = 'public_keys'
        
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        # Get actual IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        print("\n" + "="*70)
        print("PUBLIC KEY AUTHORITY (PKA) SERVER")
        print("="*70)
        print(f"Server IP   : {local_ip}")
        print(f"Port        : {self.port}")
        print(f"Status      : Running")
        print("="*70)
        print("\n[INFO] Waiting for clients to register...\n")

        while True:
            conn, addr = server_socket.accept()
            
            try:
                data = conn.recv(1024).decode('utf-8')
                request = json.loads(data)
                
                if request['type'] == 'register':
                    self.register_public_key(request['username'], request['public_key'], conn, addr)
                elif request['type'] == 'get_public_key':
                    self.send_public_key(request['username'], conn, addr)
            
            except Exception as e:
                print(f"[ERROR] {e}")
                conn.send(json.dumps({"error": str(e)}).encode('utf-8'))
            
            conn.close()

    def register_public_key(self, username, public_key, conn, addr):
        try:
            with open(os.path.join(self.keys_dir, f"{username}_public_key.json"), 'w') as f:
                json.dump(public_key, f)
            
            self.public_keys[username] = public_key
            
            print("-" * 70)
            print(f"✅ [REGISTER] User: {username}")
            print(f"   From IP: {addr[0]}")
            print(f"   Public Key (e, n): ({public_key['e']}, {public_key['n']})")
            print("-" * 70 + "\n")
            
            conn.send(json.dumps({"status": "success"}).encode('utf-8'))
        except Exception as e:
            print(f"[ERROR] Registration failed: {e}")
            conn.send(json.dumps({"error": str(e)}).encode('utf-8'))

    def send_public_key(self, username, conn, addr):
        try:
            file_path = os.path.join(self.keys_dir, f"{username}_public_key.json")
            
            if not os.path.exists(file_path):
                error_response = json.dumps({
                    "error": f"Public key for {username} not found"
                })
                conn.send(error_response.encode('utf-8'))
                print(f"[WARNING] Public key for '{username}' not found (requested from {addr[0]})")
                return

            with open(file_path, 'r') as f:
                public_key = json.load(f)
            
            print(f"[INFO] Public key for '{username}' sent to {addr[0]}")
            conn.send(json.dumps(public_key).encode('utf-8'))
        except Exception as e:
            print(f"[ERROR] Key delivery failed: {e}")
            error_response = json.dumps({
                "error": f"Failed to retrieve key: {str(e)}"
            })
            conn.send(error_response.encode('utf-8'))

if __name__ == "__main__":
    print("\n⚠️  NOTE: PKA Server akan bind ke 0.0.0.0 (semua interface)")
    print("   Pastikan firewall mengizinkan port 5000\n")
    
    pka_server = PublicKeyAuthority()
    pka_server.start_server()