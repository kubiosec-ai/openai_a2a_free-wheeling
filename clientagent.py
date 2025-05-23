import socket
import base64
import json
import openai
import os
import argparse
import requests
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend

openai.api_key = os.getenv("OPENAI_API_KEY")

def create_key_pair():
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_key = priv_key.public_key()
    return priv_key, pub_key

def serialize_public_key(pub_key):
    return base64.b64encode(
        pub_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    ).decode("utf-8")

def sign_message(priv_key, message: bytes):
    return base64.b64encode(
        priv_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    ).decode("utf-8")

def verify_signature(pub_key, message: bytes, signature: str):
    try:
        pub_key.verify(
            base64.b64decode(signature),
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def load_private_key(key_path):
    
    with open(key_path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

def load_certificate(cert_path):
    
    with open(cert_path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

def load_ca_cert(ca_path):
    
    with open(ca_path, 'rb') as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())

class SecureAgent:
    def __init__(self, name, system_prompt, debug_mode="true"):
        
        self.name = name
        self.system_prompt = system_prompt
        if name == "Alice":
            self.priv_key = load_private_key("certs/alice.key.pem")  
            if debug_mode == "untrusted":
                self.cert = load_certificate("certs/alice_self_signed.cert.pem") 
            else:
                self.cert = load_certificate("certs/alice.cert.pem")    
        elif name == "Bob":
            self.priv_key = load_private_key("certs/bob.key.pem")   
            self.cert = load_certificate("certs/bob.cert.pem")     
        else:
            raise ValueError("Unknown agent name")
        self.cert_str = base64.b64encode(self.cert.public_bytes(serialization.Encoding.PEM)).decode("utf-8")
        self.debug_mode = debug_mode

    def generate_question(self):
        response = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": "Generate a question for my conversation."}
            ]
        )
        return response.choices[0].message.content

    def send_message(self, message, recipient_name, connection, use_web=False):
        
        msg_bytes = message.encode('utf-8')
        signature = sign_message(self.priv_key, msg_bytes)
        if self.debug_mode == "invalid":
            tampered_message = message + "_tampered"  
            msg_obj = {
                'from': self.name,
                'from_cert': self.cert_str,
                'to': recipient_name,
                'content': tampered_message,
                'signature': signature
            }
        else:
            msg_obj = {
                'from': self.name,
                'from_cert': self.cert_str,
                'to': recipient_name,
                'content': message,
                'signature': signature
            }
        if use_web:
            response = requests.post(f"http://{connection}/send", json=msg_obj)
            if response.status_code != 200:
                raise ValueError("Failed to send message via HTTP")
        else:
            connection.sendall(json.dumps(msg_obj).encode('utf-8'))

    def receive_message(self, connection, use_web=False):
        
        if use_web:
            response = requests.get(f"http://{connection}/receive")
            if response.status_code != 200:
                raise ValueError("Failed to receive message via HTTP")
            msg_obj = response.json()
        else:
            data = connection.recv(8192)
            msg_obj = json.loads(data)
        ca_cert = load_ca_cert("certs/ca.cert.pem")  
        sender_cert = x509.load_pem_x509_certificate(base64.b64decode(msg_obj['from_cert']), default_backend())
        # Verify sender's cert is signed by CA
        ca_pub_key = ca_cert.public_key()
        try:
            ca_pub_key.verify(
                sender_cert.signature,
                sender_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                sender_cert.signature_hash_algorithm,
            )
        except Exception:
            print(f"DEBUG: Invalid certificate signature for {msg_obj['from']}")
            raise ValueError("Invalid certificate!")
        sender_pub_key = sender_cert.public_key()
        msg_bytes = msg_obj['content'].encode('utf-8')
        is_valid = verify_signature(sender_pub_key, msg_bytes, msg_obj['signature'])
        if not is_valid:
            print(f"DEBUG: Invalid signature detected for message from {msg_obj['from']}")
            raise ValueError("Invalid signature!")
        print(f"{self.name} received message from {msg_obj['from']}: {msg_obj['content']}")
        return msg_obj

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", default="true", choices=["true", "untrusted", "invalid"], help="Set to 'untrusted' to use a self-signed cert, 'invalid' to tamper with the signature, or 'true' for normal operation.")
    parser.add_argument("--web", action="store_true", help="Use HTTP for communication instead of TCP.")
    parser.add_argument("--prompt", type=str, default=None, help="Specify a question to send instead of generating one with OpenAI.")
    args = parser.parse_args()
    print(f"DEBUG MODE: {args.debug}")

    agent_a = SecureAgent("Alice", "You are a helpful research agent.", args.debug)
    HOST, PORT = '127.0.0.1', 9999

    if args.web:
        connection = f"{HOST}:{PORT}"
        print("Client/Agent Alice using HTTP for communication.")
    else:
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.connect((HOST, PORT))
        print("Client/Agent Alice connected to server via TCP.")

    try:
        # Alice uses provided prompt, stdin, or generates a question dynamically
        if args.prompt is not None:
            question = args.prompt
        elif not sys.stdin.isatty():
            question = sys.stdin.read()
            if question is not None:
                question = question.strip()
        else:
            question = agent_a.generate_question()
        if not question:
            print("Error: No prompt provided via --prompt, stdin, or OpenAI.")
            sys.exit(1)
        agent_a.send_message(question, "Bob", connection, use_web=args.web)
        print("Alice sent message to Bob. Waiting for reply...")

        # Alice receives Bob's reply (which could be faked, depending on Bob's debug mode)
        msg_obj = agent_a.receive_message(connection, use_web=args.web)

        print("Alice verified Bob's signature and received his reply!")
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        if not args.web:
            connection.close()
