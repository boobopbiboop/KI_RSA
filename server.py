import socket
import des
import json
import rsa
import sys

class SecureServer:
    def __init__(self, username, private_key, public_key, pka_host='localhost', pka_port=5000, host='0.0.0.0', port=6000):
        self.username = username
        self.private_key = private_key
        self.public_key = public_key
        self.pka_host = pka_host
        self.pka_port = pka_port
        self.host = host
        self.port = port

        self.des_key = None
        self.rk = None
        
        print("\n" + "="*70)
        print("SECURE CHAT SERVER - RSA + DES ENCRYPTION")
        print("="*70)
        print(f"Username    : {self.username}")
        print(f"Public Key  : (e={public_key['e']}, n={public_key['n']})")
        print(f"Private Key : (d={private_key['d']}, n={private_key['n']})")
        print("="*70)

        self.register_to_pka()

    def register_to_pka(self):
        print(f"\n[STEP 1] Registering to PKA Server at {self.pka_host}:{self.pka_port}...")
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
                    print(f"❌ [ERROR] PKA Registration failed: {response_data['error']}")
                    sys.exit(1)
                
                print(f"✅ [SUCCESS] Registered to PKA Server")
        except Exception as e:
            print(f"❌ [ERROR] Cannot connect to PKA: {e}")
            sys.exit(1)

    def get_public_key(self, username):
        print(f"\n[INFO] Fetching public key for '{username}' from PKA...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((self.pka_host, self.pka_port))
            
            request = {
                "type": "get_public_key",
                "username": username
            }
            
            sock.send(json.dumps(request).encode('utf-8'))
            response = sock.recv(1024).decode('utf-8')
            response_data = json.loads(response)
            
            if 'error' in response_data:
                print(f"❌ [ERROR] {response_data['error']}")
                raise Exception(response_data['error'])
            
            print(f"✅ [SUCCESS] Public key retrieved: (e={response_data['e']}, n={response_data['n']})")
            return response_data

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(1)
        
        # Get actual IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        
        print("\n" + "="*70)
        print("[STEP 2] Starting Chat Server...")
        print("="*70)
        print(f"Server IP   : {local_ip}")
        print(f"Port        : {self.port}")
        print(f"Status      : Listening")
        print("="*70)
        print("\n[INFO] Waiting for client connection...\n")

        try:
            conn, addr = server_socket.accept()
            
            print("="*70)
            print(f"🔗 [CONNECTION] Client connected from {addr[0]}:{addr[1]}")
            print("="*70)

            # Receive encrypted DES key
            print("\n[STEP 3] Receiving encrypted DES key...")
            payload = conn.recv(1024).decode()
            payload_data = json.loads(payload)
            
            sender = payload_data['sender']
            encrypted_des_key = int(payload_data['encrypted_des_key'])
            
            print(f"   Sender            : {sender}")
            print(f"   Encrypted DES Key : {encrypted_des_key}")

            # Get sender's public key (for verification)
            target_public_key = self.get_public_key(sender)

            # Decrypt DES key using private key
            print(f"\n[STEP 4] Decrypting DES key with private key...")
            self.des_key = rsa.decrypt(encrypted_des_key, self.private_key)
            print(f"   ✅ DES Key (decrypted): {self.des_key}")

            # Generate DES round keys
            self.rkb, self.rk = des.generate_keys(self.des_key)

            print("\n" + "="*70)
            print(f"✅ SECURE SESSION ESTABLISHED with {sender}")
            print(f"   Encryption: DES with shared key")
            print("="*70)
            print("\n[INFO] Chat session started. Type your messages below.\n")

            self.handle_communication(conn, sender)

        except Exception as e:
            print(f"\n❌ [ERROR] {e}")
            import traceback
            traceback.print_exc()
        finally:
            conn.close()
            server_socket.close()
            print("\n[INFO] Server closed.")

    def handle_communication(self, conn, sender):
        while True:
            try:
                # Receive encrypted message
                encrypted_msg = conn.recv(1024).decode()
                if not encrypted_msg:
                    print(f"\n[INFO] {sender} disconnected.")
                    break
                
                # Decrypt message
                decrypted_msg = des.decrypt(encrypted_msg, self.rkb, self.rk, is_ascii=True)
                
                print("-" * 70)
                print(f"📨 [{sender}] Encrypted : {encrypted_msg[:50]}...")
                print(f"   [{sender}] Decrypted : {decrypted_msg}")
                print("-" * 70)

                # Reply
                reply = input(f"\n[{self.username}] Reply: ").strip()
                
                if not reply:
                    continue
                
                # Encrypt reply
                encrypted_reply = des.encrypt(reply, self.rkb, self.rk, is_ascii=True)
                
                print(f"   [{self.username}] Plaintext  : {reply}")
                print(f"   [{self.username}] Encrypted  : {encrypted_reply[:50]}...")
                
                conn.send(encrypted_reply.encode())
                print("   ✅ Message sent\n")
                
            except Exception as e:
                print(f"\n❌ [ERROR] Communication error: {e}")
                break

if __name__ == "__main__":
    print("\n" + "="*70)
    print("SETUP SECURE CHAT SERVER")
    print("="*70)
    
    username = input("Enter server username: ").strip()
    
    # RSA Key Generation
    print("\n[INFO] Generating RSA keypair...")
    p, q = 97, 89
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    e = rsa.generate_e(phi_n)
    d = rsa.mod_inverse(e, phi_n)
    
    private_key = {"d": d, "n": n}
    public_key = {"e": e, "n": n}
    
    print(f"✅ RSA keys generated")
    
    # Get PKA server IP
    pka_host = input("\nEnter PKA Server IP (default: localhost): ").strip()
    if not pka_host:
        pka_host = 'localhost'
    
    server = SecureServer(username, private_key, public_key, pka_host=pka_host)
    server.start_server()