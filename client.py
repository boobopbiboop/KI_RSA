import socket
import json
import rsa
import des
import sys

class SecureClient:
    def __init__(self, username, pka_host='localhost', pka_port=5000):
        self.username = username
        self.pka_host = pka_host
        self.pka_port = pka_port
        
        print("\n" + "="*70)
        print("SECURE CHAT CLIENT - RSA + DES ENCRYPTION")
        print("="*70)
        print(f"Username    : {self.username}")
        print("="*70)
        
        print("\n[STEP 1] Generating RSA keypair...")
        self.generate_rsa_keys()
        
        print(f"\n[STEP 2] Registering to PKA Server at {pka_host}:{pka_port}...")
        self.register_to_pka()

    def generate_rsa_keys(self):
        p, q = 93, 89
        n = p * q
        phi_n = (p - 1) * (q - 1)
        
        e = rsa.generate_e(phi_n)
        d = rsa.mod_inverse(e, phi_n)
        
        self.public_key = {"e": e, "n": n}
        self.private_key = {"d": d, "n": n}
        
        print(f"   Public Key  : (e={e}, n={n})")
        print(f"   Private Key : (d={d}, n={n})")
        print(f"   ✅ RSA keys generated")

    def register_to_pka(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.pka_host, self.pka_port))
                
                register_request = {
                    "type": "register",
                    "username": self.username,
                    "public_key": self.public_key
                }
                
                sock.send(json.dumps(register_request).encode('utf-8'))
                response = sock.recv(1024).decode('utf-8')
                response_data = json.loads(response)
                
                if 'error' in response_data:
                    print(f"   ❌ [ERROR] Registration failed: {response_data['error']}")
                    sys.exit(1)
                
                print(f"   ✅ Registered to PKA Server")
        except Exception as e:
            print(f"   ❌ [ERROR] Cannot connect to PKA: {e}")
            sys.exit(1)

    def get_public_key(self, target_username):
        print(f"\n[STEP 4] Fetching public key for '{target_username}' from PKA...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.pka_host, self.pka_port))
            
            request = {
                "type": "get_public_key",
                "username": target_username
            }
            
            sock.send(json.dumps(request).encode('utf-8'))
            response = sock.recv(1024).decode('utf-8')
            
            response_data = json.loads(response)
            
            if 'error' in response_data:
                print(f"   ❌ [ERROR] {response_data['error']}")
                raise Exception(response_data['error'])
            
            print(f"   ✅ Public key retrieved: (e={response_data['e']}, n={response_data['n']})")
            return response_data

    def establish_secure_session(self, target_username, host='localhost', port=6000):
        print("\n" + "="*70)
        print(f"ESTABLISHING SECURE SESSION WITH {target_username}")
        print("="*70)
        
        # Generate DES key
        print("\n[STEP 3] Generating DES secret key...")
        des_key = "0000000000000ABC"
        print(f"   DES Key: {des_key}")
        
        # Get target's public key
        target_public_key = self.get_public_key(target_username)
        
        # Encrypt DES key with target's public key
        print(f"\n[STEP 5] Encrypting DES key with {target_username}'s public key...")
        encrypted_des_key = rsa.encrypt(des_key.encode(), target_public_key)
        print(f"   Encrypted DES Key: {encrypted_des_key}")
        
        # Connect to server
        print(f"\n[STEP 6] Connecting to server at {host}:{port}...")
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client_socket.connect((host, port))
            print(f"   ✅ Connected to {host}:{port}")
        except Exception as e:
            print(f"   ❌ [ERROR] Cannot connect to server: {e}")
            return
        
        # Send encrypted DES key
        print(f"\n[STEP 7] Sending encrypted DES key to {target_username}...")
        payload = json.dumps({
            "sender": self.username,
            "encrypted_des_key": str(encrypted_des_key)
        })
        client_socket.send(payload.encode())
        print(f"   ✅ DES key sent")
        
        # Generate DES round keys
        rkb, rk = des.generate_keys(des_key)
        
        print("\n" + "="*70)
        print(f"✅ SECURE SESSION ESTABLISHED with {target_username}")
        print(f"   Encryption: DES with shared key")
        print("="*70)
        print("\n[INFO] Chat session started. Type your messages below.")
        print("       Type 'exit' to quit.\n")
        
        # Chat loop
        while True:
            try:
                # Send message
                message = input(f"[{self.username}] Message: ").strip()
                
                if message.lower() == 'exit':
                    print("\n[INFO] Closing connection...")
                    break
                
                if not message:
                    continue
                
                # Encrypt message
                encrypted_msg = des.encrypt(message, rkb, rk, is_ascii=True)
                
                print(f"   [{self.username}] Plaintext  : {message}")
                print(f"   [{self.username}] Encrypted  : {encrypted_msg[:50]}...")
                
                client_socket.send(encrypted_msg.encode())
                print("   ✅ Message sent")
                
                # Receive response
                print(f"\n   ⏳ Waiting for reply from {target_username}...\n")
                encrypted_response = client_socket.recv(1024).decode()
                
                if not encrypted_response:
                    print(f"\n[INFO] {target_username} disconnected.")
                    break
                
                response = des.decrypt(encrypted_response, rkb, rk, is_ascii=True)
                
                print("-" * 70)
                print(f"📨 [{target_username}] Encrypted : {encrypted_response[:50]}...")
                print(f"   [{target_username}] Decrypted : {response}")
                print("-" * 70 + "\n")
                
            except Exception as e:
                print(f"\n❌ [ERROR] Communication error: {e}")
                break
        
        client_socket.close()
        print("\n[INFO] Session closed.")

if __name__ == "__main__":
    print("\n" + "="*70)
    print("SETUP SECURE CHAT CLIENT")
    print("="*70)
    
    username = input("Enter your username: ").strip()
    
    # Get PKA server IP
    pka_host = input("Enter PKA Server IP (default: localhost): ").strip()
    if not pka_host:
        pka_host = 'localhost'
    
    client = SecureClient(username, pka_host=pka_host)
    
    print("\n" + "="*70)
    print("CONNECTION SETUP")
    print("="*70)
    
    target = input("Enter destination username: ").strip()
    server_host = input("Enter server IP (default: localhost): ").strip()
    if not server_host:
        server_host = 'localhost'
    
    client.establish_secure_session(target, host=server_host)