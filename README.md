# Network Packet Analyzer

## Overview
This project is a Python-based Network Packet Analyzer designed to capture, inspect, and analyze network traffic in real time. The application processes packet-level data to monitor network activity, identify protocols, and assist in debugging and traffic analysis tasks commonly used in networking and system-level environments.

The project demonstrates practical understanding of packet inspection, protocol analysis, and network monitoring concepts using Python.

---

## Key Features
- Real-Time Packet Capture
- Network Traffic Monitoring
- Protocol Identification
- Packet Inspection and Analysis
- TCP/IP Packet Processing
- Lightweight Python-Based Architecture
- PCAP File Support
- Modular Analyzer Design
- Debugging and Traffic Visualization

---

## Technologies Used
- Python
- Scapy
- Socket Programming
- Networking Protocols
- PCAP Analysis

---

## Project Architecture

```text
network-packet-analyzer/
│
├── sample_data/
│   └── sample.pcap
│
├── analyzer.py
├── sniffer.py
├── utils.py
├── app.py
├── requirements.txt
└── README.md
```

---

## Core Components

### Packet Sniffer
Captures live network packets from the selected network interface for real-time analysis.

### Packet Analyzer
Processes captured packets and extracts protocol-level information including source, destination, and packet type.

### Utility Module
Provides helper functions for packet formatting, filtering, and data handling.

### PCAP Support
Allows analysis of stored packet capture files for offline traffic inspection.

---

## Supported Protocols
- TCP
- UDP
- HTTP
- DNS
- ICMP
- IP

---

## Functional Workflow
1. Capture network packets
2. Identify packet protocols
3. Extract packet metadata
4. Analyze source and destination information
5. Display traffic insights
6. Monitor packet activity in real time

---

## Applications
- Network Monitoring
- Packet Inspection
- Traffic Analysis
- Protocol Debugging
- Cybersecurity Learning
- System-Level Network Analysis

---

## Installation

### Clone Repository
```bash
git clone https://github.com/your-username/network-packet-analyzer.git
```

### Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Running the Project

### Start Packet Analyzer
```bash
python app.py
```

### Run Packet Sniffer
```bash
python sniffer.py
```

---

## Expected Output
- Live packet capture logs
- Protocol identification
- Source and destination details
- Packet statistics
- Network traffic insights

---

## Future Enhancements
- GUI-Based Traffic Dashboard
- Advanced Packet Filtering
- Intrusion Detection Features
- Network Traffic Visualization
- Multi-Interface Monitoring
- Packet Export Functionality

---

## Learning Outcomes
- Understanding of Networking Protocols
- Hands-on Packet Analysis
- Real-Time Traffic Monitoring
- Python-Based Network Programming
- System-Level Debugging Concepts
- Traffic Inspection Techniques

---

## Author
Byreddy Sai Reddy

Electronics and Communication Engineering  
Semiconductor and Embedded Systems Enthusiast
