import socket
import pickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

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

# Decrypt data using private key
def decrypt_data(private_key, encrypted_data):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_data = cipher.decrypt(encrypted_data).decode()
    data, checksum = decrypted_data.split(":")
    return data, int(checksum)

# Receiver function
def receiver():
    host = 'localhost'
    port = 12345
    
    # Create socket and listen for incoming connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print("Waiting for sender...")

        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            # Receive encrypted data and private key
            data = conn.recv(4096)
            if data:
                encrypted_data, private_key_data = pickle.loads(data)
                private_key = RSA.import_key(private_key_data)
                print(f"Received encrypted data: {encrypted_data}")
                
                # Decrypt the data
                decrypted_data, received_checksum = decrypt_data(private_key, encrypted_data)
                print(f"Decrypted Data: {decrypted_data}")
                print(f"Received Checksum: {received_checksum}")

                # Verify checksum
                calculated_checksum = calculate_checksum(decrypted_data, 8)
                if calculated_checksum == received_checksum:
                    print("Checksum verified, data is intact.")
                else:
                    print("Checksum mismatch, data is corrupted.")

if __name__ == "__main__":
    receiver()
