# Secure Messaging Agent

This project implements a secure messaging agent using public key cryptography. The main component is the `SecureAgent` class, which facilitates secure communication between agents by signing and verifying messages.

## Features

- **Public Key Cryptography**: Utilizes RSA for secure message signing and verification.  
- **Debug Modes**: Supports different modes for testing, including a mode that sends a fake signature.  
- **Socket and HTTP Communication**: Supports both TCP socket and HTTP (web) message exchange.  

## Setup and Installation

1. **Clone the repository:**
   ```sh
   git clone <repository-url>
   cd openai_a2a_free-wheeling
   ```

2. **Install the required dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

3. **Set up your OpenAI API key in your environment:**
   ```sh
   export OPENAI_API_KEY='your-api-key'
   ```

4. **Generate certificates (if not already present):**
   ```sh
   ./gen_certs.sh
   ```

## Usage

### TCP Socket Mode (default)

Start the server (Bob):
```sh
python serveragent.py
```

Start the client (Alice):
```sh
python clientagent.py
```

### HTTP (Web) Mode

Start the server (Bob) in web mode:
```sh
python serveragent.py --web
```

Start the client (Alice) in web mode:
```sh
python clientagent.py --web
```

### Debug/Fake Signature Mode

You can use the `--debug fake` flag to test signature verification failures:
```sh
python clientagent.py --debug fake
```

## Application Concept and Security Model

This application demonstrates secure, authenticated message exchange between two agents (Alice and Bob) using public key cryptography and X.509 certificates.  

- **Certificate Authority (CA):** A CA certificate is used to sign agent certificates. Both Alice and Bob trust the CA.  
- **Agent Certificates:** Each agent (Alice, Bob) has a private key and a certificate signed by the CA.  
- **Message Signing:** When sending a message, the sender signs the message content with their private key and attaches their certificate.  
- **Verification:** The receiver verifies the sender's certificate using the CA, then verifies the message signature using the sender's public key from the certificate.  
- **Tamper-Proof:** As long as the CA certificate is trusted and private keys are secure, the system is tamper-proof and authenticates both sender and message integrity.  

### Communication Modes

- **TCP Socket:** By default, messages are exchanged as JSON blobs over a TCP connection.  
- **HTTP (Web):** If `--web` is specified, the server runs a Flask HTTP server and the client uses HTTP POST/GET to exchange messages.  

### Message Flow

1. The client (Alice) generates a question and sends it to the server (Bob), signing the message and attaching her certificate.  
2. The server (Bob) verifies Alice's certificate and signature, generates a response, signs it, and sends it back with his certificate.  
3. The client (Alice) verifies Bob's certificate and signature upon receiving the reply.  

## Contributing

Feel free to submit issues or pull requests for improvements or bug fixes.  