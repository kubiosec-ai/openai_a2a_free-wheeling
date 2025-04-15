import socket
import base64
import json
import openai
import os
import argparse
import threading
import flask
from flask import request, jsonify
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import logging  

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
            if debug_mode == "fake":
                self.cert = load_certificate("certs/alice_self_signed.cert.pem")  # Use self-signed for debug
            else:
                self.cert = load_certificate("certs/alice.cert.pem")    
        elif name == "Bob":
            self.priv_key = load_private_key("certs/bob.key.pem")   
            self.cert = load_certificate("certs/bob.cert.pem")     
        else:
            raise ValueError("Unknown agent name")
        self.cert_str = base64.b64encode(self.cert.public_bytes(serialization.Encoding.PEM)).decode("utf-8")
        self.debug_mode = debug_mode
        # Set up logging
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')  

    def send_message(self, message, recipient_name, connection):
        
        msg_bytes = message.encode('utf-8')
        signature = sign_message(self.priv_key, msg_bytes)
        if self.debug_mode == "fake":
            signature = "invalid_signature"  # Corrupt it deliberately
        msg_obj = {
            'from': self.name,
            'from_cert': self.cert_str,
            'to': recipient_name,
            'content': message,
            'signature': signature
        }
        
        if self.debug_mode == "invalid":
            # Intentionally corrupt the payload after signing (e.g., flip a char in content)
            msg_obj['content'] = message + "!" if not message.endswith("!") else message[:-1]
        connection.sendall(json.dumps(msg_obj).encode('utf-8'))

    def receive_message(self, connection):
        
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
            logging.error("untrusted certificate detected from %s", msg_obj.get('from', 'unknown'))  
            raise ValueError("Invalid certificate!")
        sender_pub_key = sender_cert.public_key()
        msg_bytes = msg_obj['content'].encode('utf-8')
        is_valid = verify_signature(sender_pub_key, msg_bytes, msg_obj['signature'])
        if not is_valid:
            logging.error("invalid signature detected from %s", msg_obj.get('from', 'unknown'))  
            raise ValueError("Invalid signature!")
        logging.info("%s received message from %s: %s", self.name, msg_obj['from'], msg_obj['content'])  
        return msg_obj

    def respond_using_openai(self, prompt):
        chat_completion = openai.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": prompt},
            ]
        )
        return chat_completion.choices[0].message.content

def handle_client(conn, addr, agent_b):
    with conn:
        print(f"Connected by {addr}")
        try:
            msg_obj = agent_b.receive_message(conn)
            response_b = agent_b.respond_using_openai(msg_obj['content'])
            agent_b.send_message(response_b, msg_obj['from'], conn)
            print("Bob sent response back to Alice!")
        except Exception as e:
            print(f"Server error: {e}")

def run_flask_server(agent_b, host, port):
    
    app = flask.Flask(__name__)
    app.config["JSONIFY_PRETTYPRINT_REGULAR"] = False
    state = {"last_msg": None, "last_response": None}

    @app.route("/send", methods=["POST"])
    def receive_message():
        msg_obj = request.get_json()
        try:
            ca_cert = load_ca_cert("certs/ca.cert.pem")
            sender_cert = x509.load_pem_x509_certificate(base64.b64decode(msg_obj['from_cert']), default_backend())
            ca_pub_key = ca_cert.public_key()
            try:
                ca_pub_key.verify(
                    sender_cert.signature,
                    sender_cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    sender_cert.signature_hash_algorithm,
                )
            except Exception:
                logging.error("untrusted certificate detected from %s (HTTP)", msg_obj.get('from', 'unknown'))  
                return jsonify({"error": "Invalid certificate!"}), 400
            sender_pub_key = sender_cert.public_key()
            msg_bytes = msg_obj['content'].encode('utf-8')
            is_valid = verify_signature(sender_pub_key, msg_bytes, msg_obj['signature'])
            if not is_valid:
                logging.error("invalid signature detected from %s (HTTP)", msg_obj.get('from', 'unknown'))  
                return jsonify({"error": "Invalid signature!"}), 400
            logging.info("Bob received message from %s: %s", msg_obj['from'], msg_obj['content'])  
            state["last_msg"] = msg_obj
            # Generate response
            response_b = agent_b.respond_using_openai(msg_obj['content'])
            # Prepare response
            msg_bytes = response_b.encode('utf-8')
            signature = sign_message(agent_b.priv_key, msg_bytes)
            if agent_b.debug_mode == "fake":
                signature = "invalid_signature"
            response_obj = {
                'from': agent_b.name,
                'from_cert': agent_b.cert_str,
                'to': msg_obj['from'],
                'content': response_b,
                'signature': signature
            }
            state["last_response"] = response_obj
            return jsonify(response_obj)
        except Exception as e:
            logging.error("Server error: %s", str(e))  
            return jsonify({"error": str(e)}), 400

    @app.route("/receive", methods=["GET"])
    def get_last_response():
        if state["last_response"]:
            return jsonify(state["last_response"])
        else:
            return jsonify({"error": "No response yet"}), 404

    app.run(host=host, port=port)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", default="true", choices=["true", "fake", "invalid"], help="Set to 'fake' to send a fake signature on reply.")
    parser.add_argument("--web", action="store_true", help="Use HTTP for communication instead of TCP.")
    args = parser.parse_args()
    print(f"DEBUG MODE: {args.debug}")

    agent_b = SecureAgent("Bob", "You are an assistant AI specializing in metaphors.", args.debug)

    HOST, PORT = '127.0.0.1', 9999
    if args.web:
        print("Server/Agent Bob using HTTP for communication.")
        run_flask_server(agent_b, HOST, PORT)
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, PORT))
            s.listen()
            print("Server/Agent Bob is listening on port 9999...")
            while True:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=handle_client, args=(conn, addr, agent_b), daemon=True)
                client_thread.start()
