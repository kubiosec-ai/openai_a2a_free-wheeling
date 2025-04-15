import socket
import base64
import json
import openai
import os
import argparse
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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

class SecureAgent:
    def __init__(self, name, system_prompt, debug_mode="true"):
        self.name = name
        self.system_prompt = system_prompt
        self.priv_key, self.pub_key = create_key_pair()
        self.pub_key_str = serialize_public_key(self.pub_key)
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

    def send_message(self, message, recipient_name, connection):
        msg_bytes = message.encode('utf-8')
        signature = sign_message(self.priv_key, msg_bytes)
        if self.debug_mode == "fake":
            signature = "invalid_signature"  # Corrupt it deliberately
        msg_obj = {
            'from': self.name,
            'from_pub_key': self.pub_key_str,
            'to': recipient_name,
            'content': message,
            'signature': signature
        }
        connection.sendall(json.dumps(msg_obj).encode('utf-8'))

    def receive_message(self, connection):
        data = connection.recv(8192)
        msg_obj = json.loads(data)
        sender_pub_key = serialization.load_pem_public_key(base64.b64decode(msg_obj['from_pub_key']))
        msg_bytes = msg_obj['content'].encode('utf-8')
        is_valid = verify_signature(sender_pub_key, msg_bytes, msg_obj['signature'])
        if not is_valid:
            print(f"DEBUG: Invalid signature detected for message from {msg_obj['from']}")
            raise ValueError("Invalid signature!")
        print(f"{self.name} received message from {msg_obj['from']}: {msg_obj['content']}")
        return msg_obj

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", default="true", choices=["true", "fake"], help="Set to 'fake' to send a fake signature on outgoing message.")
    args = parser.parse_args()
    print(f"DEBUG MODE: {args.debug}")

    agent_a = SecureAgent("Alice", "You are a helpful research agent.", args.debug)
    HOST, PORT = '127.0.0.1', 9999

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("Client/Agent Alice connected to server.")
        try:
            # Alice generates a question dynamically
            question = agent_a.generate_question()
            agent_a.send_message(question, "Bob", s)
            print("Alice sent message to Bob. Waiting for reply...")

            # Alice receives Bob's reply (which could be faked, depending on Bob's debug mode)
            msg_obj = agent_a.receive_message(s)

            print("Alice verified Bob's signature and received his reply!")
        except Exception as e:
            print(f"Client error: {e}")