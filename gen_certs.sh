set -e

CERTS_DIR=./certs
mkdir -p "$CERTS_DIR"

# 1. Create CA key and certificate
openssl genrsa -out "$CERTS_DIR/ca.key.pem" 4096
openssl req -x509 -new -nodes -key "$CERTS_DIR/ca.key.pem" -sha256 -days 3650 \
  -subj "/O=radarhack.com/OU=agents/CN=RadarHack CA" \
  -out "$CERTS_DIR/ca.cert.pem"

# 2. Generate key and CSR for Bob
openssl genrsa -out "$CERTS_DIR/bob.key.pem" 2048
openssl req -new -key "$CERTS_DIR/bob.key.pem" -subj "/O=radarhack.com/OU=agents/CN=Bob" -out "$CERTS_DIR/bob.csr.pem"

# 3. Sign Bob's certificate
openssl x509 -req -in "$CERTS_DIR/bob.csr.pem" -CA "$CERTS_DIR/ca.cert.pem" -CAkey "$CERTS_DIR/ca.key.pem" -CAcreateserial \
  -out "$CERTS_DIR/bob.cert.pem" -days 365 -sha256

# 4. Generate key and CSR for Alice
openssl genrsa -out "$CERTS_DIR/alice.key.pem" 2048
openssl req -new -key "$CERTS_DIR/alice.key.pem" -subj "/O=radarhack.com/OU=agents/CN=Alice" -out "$CERTS_DIR/alice.csr.pem"

# 5. Sign Alice's certificate
openssl x509 -req -in "$CERTS_DIR/alice.csr.pem" -CA "$CERTS_DIR/ca.cert.pem" -CAkey "$CERTS_DIR/ca.key.pem" -CAcreateserial \
  -out "$CERTS_DIR/alice.cert.pem" -days 365 -sha256

# 6. Generate a self-signed certificate for Alice (for testing/debugging purposes)
openssl req -x509 -new -nodes -key "$CERTS_DIR/alice.key.pem" -sha256 -days 365 \
  -subj "/O=radarhack.com/OU=agents/CN=Alice Self-Signed" \
  -out "$CERTS_DIR/alice_self_signed.cert.pem"

echo "Self-signed certificate for Alice generated: alice_self_signed.cert.pem" 

echo "Certificates generated in $CERTS_DIR: ca.cert.pem, bob.cert.pem, alice.cert.pem"
