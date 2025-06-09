# CodeAlpha-task1
# Basic Network Sniffer in Python

A minimal and elegant command-line Python tool to capture and analyze network traffic.  
This project helps you understand how data flows on a network and how network packets are structured.

---

## Overview

This sniffer captures Ethernet frames and parses IPv4 packets along with TCP and UDP headers.  
It provides clear, detailed console output about source and destination addresses, protocols, ports, flags, and packet sizes.

The project is designed as a learning tool for educational purposes and requires administrative privileges to run.

---

## Features

- Raw packet capture on Ethernet interfaces  
- Parsing and display of Ethernet, IPv4, TCP, and UDP headers  
- Human-readable output with timestamps and detailed packet info  
- Simple, dependency-free Python script  
- Clean and well-documented code for easy understanding and extension  

---

## Getting Started

### Prerequisites

- Python 3.6 or higher  
- Linux environment (tested on Ubuntu). Windows support requires adjustments and is not officially supported.  
- Run the script with root or administrator privileges to access raw sockets  

### Running the Sniffer

```bash
sudo python3 network_sniffer.py
