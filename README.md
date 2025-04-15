# Secure Messaging Agent

This project implements a secure messaging agent using public key cryptography. The main component is the `SecureAgent` class, which facilitates secure communication between agents by signing and verifying messages.

## Features

- **Public Key Cryptography**: Utilizes RSA for secure message signing and verification.
- **Debug Modes**: Supports different modes for testing, including a mode that sends a fake signature.
- **Socket Communication**: Connects to a server for sending and receiving messages.

## Setup

1. Clone the repository:
   ```
   git clone <repository-url>
   cd testing
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up your OpenAI API key in your environment:
   ```
   export OPENAI_API_KEY='your-api-key'
   ```

## Usage

To run the agent, execute the following command:
```
python clientagent.py --debug true
```
or to test with a fake signature:
```
python clientagent.py --debug fake
```

## Contributing

Feel free to submit issues or pull requests for improvements or bug fixes.