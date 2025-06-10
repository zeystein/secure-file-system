import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding, rsa
from scapy.all import sniff, IP
import hashlib

# Anahtar çifti üret (ilk seferde)
def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    with open("server_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key

# IP paketleri dinle
def capture_ip_packets(expected_size):
    received_payloads = []

    def pkt_handler(pkt):
        if IP in pkt and bytes(pkt[IP].payload).startswith(b"MYFILE"):
            raw_data = bytes(pkt[IP].payload)[6:]  # "MYFILE" imzasını çıkar
            received_payloads.append(raw_data)

    sniff(prn=pkt_handler, timeout=10)
    return b"".join(received_payloads)

# Sunucu başlat
def start_server():
    HOST = "0.0.0.0"
    PORT = 5001

    private_key = generate_keys()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    print("[*] Listening on 0.0.0.0:5001")

    conn, addr = server.accept()
    print("[*] Client connected.")

    encrypted_key = conn.recv(256)
    received_hash = conn.recv(32)
    file_size = int.from_bytes(conn.recv(4), 'big')
    conn.close()

    print("[*] Listening for IP packets...")
    encrypted_data = capture_ip_packets(file_size)
    print(f"[i] Expected {file_size} bytes, captured {len(encrypted_data)} bytes")

    if len(encrypted_data) < file_size:
        print("[!] Incomplete data received. Aborting.")
        return

    aes_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    digest = hashlib.sha256(data).digest()
    if digest == received_hash:
        print("[+] File received and verified successfully.")
        with open("received_file.txt", "wb") as f:
            f.write(data)
    else:
        print("[!] File integrity verification failed.")

if __name__ == "__main__":
    start_server()
