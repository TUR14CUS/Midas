# MidasV1

## Overview

**MidasV1** is a Python script designed for network manipulation using ARP spoofing and packet sniffing techniques. It can be utilized for educational purposes to understand network vulnerabilities and security measures. Please be aware of the ethical and legal implications of using this script and ensure that you have appropriate authorization before deploying it on any network.

## Features

- **Network Scanning**: The script utilizes ARP requests to scan and identify devices on a specified target IP or IP range.

- **ARP Spoofing**: MidasV1 performs ARP spoofing attacks by manipulating ARP tables, redirecting traffic through the attacker's machine.

- **Packet Sniffing**: The script captures and analyzes network traffic, specifically focusing on HTTP requests. It identifies URLs being accessed and potential username/password combinations transmitted over the network.

- **Automatic ARP Table Restoration**: In case of an interruption or when the user interrupts the script execution, it automatically restores ARP tables to their original state.

## Prerequisites

Before using MidasV1, ensure you have the necessary dependencies installed:

```bash
pip install scapy
```

## Usage

1. Clone the repository:

```bash
git clone https://github.com/TUR14CUS/MidasV1.git
cd MidasV1
```

2. Run the script with the desired command-line arguments:

```bash
python midasV1.py -t [TARGET_IP] -g [GATEWAY_IP]
```

- `-t` or `--target`: Specify the target IP or IP range.
- `-g` or `--gateway`: Specify the gateway IP.

**Example:**

```bash
python midasV1.py -t 192.168.1.10 -g 192.168.1.1
```

## Disclaimer

This script is provided for educational purposes only. Unauthorized use of this script on networks without explicit permission may violate privacy and legal regulations. The author is not responsible for any misuse of the script.

## Author

- **TUR14CUS** - [GitHub](https://github.com/TUR14CUS)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
