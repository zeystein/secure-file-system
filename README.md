# Advanced Secure File Transfer System

## Overview

This project implements a secure and high-performance file transfer system, applying network security and performance principles. It features advanced encryption algorithms (AES and RSA), data integrity verification (SHA-256), low-level IP packet processing using Scapy, and extensive network performance analysis with Wireshark, iPerf3, and ping tools.

## Features

### 1. File Transfer System

* **Control Channel (TCP)**: Reliable TCP connection for AES key distribution, encrypted data length transfer, and hash verification.
* **Data Channel (Raw IP)**: Encrypted data sent in fragments as custom IP packets using Scapy (with custom headers like TTL and Flags).

### 2. Security Mechanisms

* **Asymmetric Encryption (RSA-2048)**: Secure RSA-2048 key-pair generation for securely transferring AES session keys.
* **Symmetric Encryption (AES-256-CBC)**: Secure file content encryption with AES-256-CBC.
* **Data Integrity (SHA-256)**: Verification of file integrity using SHA-256 hashing.

### 3. Low-Level IP Header Processing

* **Scapy Integration**: Manual adjustment and management of IP headers, including TTL, Flags (DF bit), and checksums.
* **Fragmentation & Reassembly**: Data fragmentation based on a defined `fragment_size` and reassembly on the server.

### 4. Network Performance Analysis

* **Latency (RTT)**: Round Trip Time measured using `ping`; reporting average RTT and packet loss.
* **Bandwidth Analysis**: Tested bandwidth using `iPerf3` under localhost and Wi-Fi conditions, including network conditions simulation via MacOS Network Link Conditioner.
* **Packet Analysis (Wireshark)**: IP packets captured and verified for encryption effectiveness.

## Installation

### Dependencies

* Python 3.x
* Cryptography: `pip install cryptography`
* Scapy: `pip install scapy`
* hashlib (built-in)
* iPerf3 (network performance analysis)
* Wireshark (packet analysis)
* ping utility
* Optional for MacOS: Network Link Conditioner

### Project Structure

```
.
├── client.py
├── server.py
├── testfile.txt
├── server_public.pem (auto-generated)
└── received_file.txt (created upon successful transfer)
```

## Setup and Execution

1. **Install Required Libraries**:

```sh
pip install cryptography scapy
```

2. **Prepare Test File (`testfile.txt`)**:

```
Bu bir test dosyasidir.
Proje icin ornek veri icerir.
```

3. **Start the Server**:

```sh
python server.py
```

*Note*: The server generates `server_public.pem` upon the first execution.

4. **Configure Client (`client.py`)**:
   Update `server_ip` variable:

```python
server_ip = "192.168.1.97"  # Replace with server IP
```

5. **Run Client**:

```sh
python client.py
```

## Usage Flow

* Client encrypts `testfile.txt`, computes hash, and sends RSA-encrypted AES keys via TCP.
* Client transmits encrypted data using Scapy-generated IP packets.
* Server receives keys and metadata via TCP, decrypts AES keys, captures IP packets, decrypts data, verifies hash, and saves to `received_file.txt`.

## Limitations and Future Enhancements

* **MacOS Loopback Issues**: IP packet capture issues on loopback; use physical network recommended.
* **Testing Environment**: Currently untested with Ethernet and VPN environments.
* **MITM Tests**: Planned but not executed practically.
* **Future Plans**: GUI development and TCP/UDP hybrid transfers.

## Screenshots and Files

Refer to detailed screenshots and files in the project report.

* **Experimental Screenshots**:

  * iPerf3 tests (Wi-Fi, localhost)
  * Ping RTT tests
  * Wireshark packet capture analysis

* **Generated Files**:

  * `testfile.txt`: Original data
  * `server_public.pem`: RSA public key
  * `received_file.txt`: Verified and successfully received file

## References

* [Scapy Documentation](https://scapy.net/)
* [Python Cryptography Documentation](https://cryptography.io/)
* [iPerf3 Documentation](https://iperf.fr/)
* [Wireshark Documentation](https://wireshark.org/)
* [Apple Developer Documentation (Network Link Conditioner)](https://developer.apple.com/)

## Author

**Zeynep Sude Güneş**
22360859055
Computer Engineering - 3rd Year
Bursa Technical University, Faculty of Engineering and Natural Sciences
