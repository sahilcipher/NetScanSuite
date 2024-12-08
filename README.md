# NetScanSuite

NetScanSuite is a powerful and easy-to-use network scanning tool designed to help users:
1. Perform ARP scans to discover devices in a network.
2. Conduct TCP scans to identify open ports on a specific host.

[+] Features
-   ARP Scanning  : Quickly find devices on your network with their IP and MAC addresses.
-   TCP Scanning  : Identify open ports on a target host using SYN packets.
-   Command-line Interface  : Simple and intuitive commands for performing scans.

[+] Requirements
-   Python  : Version 3.x
-   Scapy  : Install using `pip install scapy`

[+] Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/[YourUsername]/NetScanSuite.git
   ```
2. Navigate to the project directory:
   ```bash
   cd NetScanSuite
   ```
3. Install the required library:
   ```bash
   pip install scapy
   ```

[+] Usage

#[+] ARP Scan
Discover devices in a network by performing an ARP scan.
```bash
python3 network_scanner.py ARP <IP or Range>
```
Examples:
- Scan a single IP:
  ```bash
  python3 network_scanner.py ARP 192.168.1.1
  ```
- Scan a range of IPs:
  ```bash
  python3 network_scanner.py ARP 192.168.1.1/24
  ```

#[+] TCP Scan
Identify open ports on a target host using a TCP scan.
```bash
python3 network_scanner.py TCP <IP> <ports...> [--range]
```
Examples:
- Scan specific ports:
  ```bash
  python3 network_scanner.py TCP 192.168.1.1 22 80 443
  ```
- Scan a range of ports:
  ```bash
  python3 network_scanner.py TCP 192.168.1.1 20 80 --range
  ```

[+] Example Output

#[+] ARP Scan
```bash
Discovered Devices:
IP: 192.168.1.1, MAC: c4:93:d9:8b:3e:5a
IP: 192.168.1.2, MAC: 98:5f:d3:6c:4a:12
```

#[+] TCP Scan
```bash
Open Ports:
Port 22 is open.
Port 80 is open.
Port 443 is open.
```

[+] Contributing
Contributions are welcome! Feel free to fork this repository and submit pull requests to add new features or improve the tool.

[+] License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

[+] Acknowledgments
Developed by Parmar Sahil.

