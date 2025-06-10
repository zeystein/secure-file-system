import socket
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from scapy.all import IP, send
import hashlib

# AES anahtarı üret
aes_key = os.urandom(32)
iv = os.urandom(16)

# Sunucu bilgileri
server_ip = "192.168.1.97"  # Buraya kendi IP adresini yaz
server_port = 5001

# Dosya oku ve AES ile şifreleimport socket # Ağ bağlantıları için socket modülü
import os # İşletim sistemi fonksiyonları, özellikle rastgele veri üretimi için
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # Şifreleme algoritmaları ve modları
from cryptography.hazmat.backends import default_backend # Kriptografik işlemler için varsayılan arka uç
from cryptography.hazmat.primitives import padding, hashes, serialization # Dolgu (padding), hash fonksiyonları ve anahtar serileştirme
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding # Asimetrik şifreleme dolgusu
from cryptography.hazmat.primitives.asymmetric import rsa # RSA anahtar çifti oluşturma (bu projede kullanılmıyor, server tarafında üretiliyor)
from scapy.all import IP, send # Düşük seviye IP paketleri oluşturma ve gönderme
import hashlib # SHA-256 hash fonksiyonu için

# AES anahtarı üretimi: 32 bayt (256 bit) uzunluğunda rastgele bir anahtar
aes_key = os.urandom(32)
# AES CBC modu için başlatma vektörü (IV) üretimi: 16 bayt (128 bit) uzunluğunda
iv = os.urandom(16)

# Sunucu bilgileri
server_ip = "192.168.1.97"  # Sunucunun IP adresi buraya yazılmalı
server_port = 5001 # Sunucunun TCP dinleme portu

# testfile.txt dosyasını binary (ikili) modda oku
with open("testfile.txt", "rb") as f:
    data = f.read()

# AES şifreleme için PKCS7 dolgu nesnesi oluştur
padder = padding.PKCS7(128).padder() # 128 bit blok boyutu için PKCS7
# Veriye dolgu uygula
padded_data = padder.update(data) + padder.finalize()

# AES-256-CBC algoritması ve üretilen anahtar/IV ile şifreleyici nesnesi oluştur
cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
# Veriyi şifrele
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

# Orijinal dosyanın SHA-256 hash değerini hesapla
digest = hashlib.sha256(data).digest()

# server_public.pem dosyasından RSA açık anahtarını yükle
with open("server_public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

# AES anahtarını RSA açık anahtarı ile OAEP dolgu kullanarak şifrele
encrypted_aes_key = public_key.encrypt(
    aes_key, # Şifrelenecek AES anahtarı
    asym_padding.OAEP( # OAEP dolgu şeması
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), # MGF1 maske oluşturma fonksiyonu SHA256 ile
        algorithm=hashes.SHA256(), # OAEP için hash algoritması
        label=None # İsteğe bağlı etiket
    )
)

# TCP soket oluştur ve sunucuya bağlan
tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sock.connect((server_ip, server_port))
# Şifreli AES anahtarını gönder
tcp_sock.sendall(encrypted_aes_key)
# Dosyanın hash değerini gönder
tcp_sock.sendall(digest)
# Şifreli verinin boyutunu 4 baytlık big-endian formatında gönder
tcp_sock.sendall(len(encrypted_data).to_bytes(4, 'big'))
# TCP bağlantısını kapat
tcp_sock.close()

# IP üzerinden şifreli veriyi parçalar halinde gönder (raw socket ile)
fragment_size = 512 # Her IP paketinin taşıyacağı veri boyutu
for i in range(0, len(encrypted_data), fragment_size):
    fragment = encrypted_data[i:i + fragment_size] # Veriyi parçalara ayır
    payload = b"MYFILE" + fragment # Her parçanın başına "MYFILE" imzası ekle
    # IP paketi oluştur: Hedef IP, TTL 64, Don't Fragment bayrağı ayarlı
    packet = IP(dst=server_ip, ttl=64, flags='DF') / payload
    # Paketi belirtilen ağ arayüzü (iface="en0") üzerinden gönder, verbose=False ile çıktıları gizle
    send(packet, iface="en0", verbose=False)

print("[+] Dosya, TTL/flags ayarlı raw IP paketleri kullanılarak gönderildi.")
with open("testfile.txt", "rb") as f:
    data = f.read()

padder = padding.PKCS7(128).padder()
padded_data = padder.update(data) + padder.finalize()

cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

# SHA-256 hash
digest = hashlib.sha256(data).digest()

# RSA public key al
with open("server_public.pem", "rb") as f:
    public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

# AES anahtarını RSA ile şifrele
encrypted_aes_key = public_key.encrypt(
    aes_key,
    asym_padding.OAEP(
        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# TCP ile anahtar + hash + boyut gönder
tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sock.connect((server_ip, server_port))
tcp_sock.sendall(encrypted_aes_key)
tcp_sock.sendall(digest)
tcp_sock.sendall(len(encrypted_data).to_bytes(4, 'big'))
tcp_sock.close()

# IP üzerinden şifreli veriyi gönder (raw socket ile)
fragment_size = 512
for i in range(0, len(encrypted_data), fragment_size):
    fragment = encrypted_data[i:i + fragment_size]
    payload = b"MYFILE" + fragment
    packet = IP(dst=server_ip, ttl=64, flags='DF') / payload
    send(packet, iface="en0", verbose=False)

print("[+] File sent using raw IP packets with TTL/flags.")
