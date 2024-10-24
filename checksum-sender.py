import socket
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA keys
def generate_keys():
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

# One's complement function for checksum
def ones_complement(decimal_value, bit_size):
    max_value = (2**bit_size) - 1
    return max_value - decimal_value

# Handle wrapping for checksum calculation
def handle_wrapping(sum_value, bit_size):
    carry = sum_value >> bit_size
    wrapped_sum = sum_value & ((1 << bit_size) - 1)
    wrapped_sum += carry
    if wrapped_sum >= (1 << bit_size):
        wrapped_sum = handle_wrapping(wrapped_sum, bit_size)
    return wrapped_sum

# Calculate checksum
def calculate_checksum(data, bit_size):
    total_sum = sum(ord(char) for char in data)
    wrapped_sum = handle_wrapping(total_sum, bit_size)
    checksum = ones_complement(wrapped_sum, bit_size)
    return checksum

# Encrypt data using public key
def encrypt_data(public_key, data, checksum):
    cipher = PKCS1_OAEP.new(public_key)
    message = f"{data}:{checksum}"
    encrypted_data = cipher.encrypt(message.encode())
    return encrypted_data

# Sender function
def sender():
    host = 'localhost'
    port = 12345
    
    # Generate RSA keys
    private_key, public_key = generate_keys()

    # Connect to the receiver
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        
        # Sample data
        data = "NSCOM3"
        
        # Calculate checksum
        checksum = calculate_checksum(data, 8)

        # Encrypt data and checksum
        encrypted_data = encrypt_data(public_key, data, checksum)

        # Serialize data and send it to the receiver
        # For testing, send the private key along (not secure, but for demo)
        packet = pickle.dumps((encrypted_data, private_key.export_key()))
        s.sendall(packet)
        print(f"Sent encrypted data: {encrypted_data}")

if __name__ == "__main__":
    sender()
