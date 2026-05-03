# Port Scan Detector

A simple, real-time Network Intrusion Detection System (NIDS) built with Python and Scapy.
This project helps detect suspicious port scanning activity on a network and is designed to be easy to understand and use.

---

## What This Project Does

This tool monitors live network traffic and looks for patterns that may indicate a port scan.
For example:

* One machine trying many ports in a short time
* Ports being scanned in sequence
* Repeated connection attempts from the same source

When such behavior is detected, it raises an alert and logs the activity.

---

## Features

* Real-time packet sniffing
* Detects common scan types:

  * TCP SYN (half-open) scans
  * Sequential port scans
  * Rapid multi-port probing
* Logs suspicious activity
* Lightweight and beginner-friendly

---

## Project Structure

```bash
port-scan-detector/
│── port_scan_detector.py
│── requirements.txt
│── logs/
│── Guide.txt
│── README.md
│── LICENSE
```

---

## Setup

Clone the repository:

```bash
git clone https://github.com/KKU89/port-scan-detector.git
cd port-scan-detector
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## Usage

Run the script with administrator/root privileges:

```bash
sudo python port_scan_detector.py
```

---

## How It Works

The script captures packets using Scapy and analyzes traffic patterns.
It tracks connection attempts from each IP and checks for unusual behavior such as scanning multiple ports quickly or in sequence.

If suspicious activity is found, it generates an alert and stores the details in log files.

---

## Example Output

```text
[ALERT] Possible port scan detected
Source IP: 192.168.1.10
Ports scanned: 20, 21, 22, 23, 25
Scan type: Sequential TCP SYN Scan
```

---

## Configuration

You can adjust detection settings inside:

```
port_scan_detector.py
```

This includes:

* Scan detection thresholds
* Time windows
* Logging behavior

---

## Logs

All alerts are saved in the `logs/` folder for later review.

---

## Use Cases

* Learning cybersecurity basics.
* Understanding network scanning behavior.
* Small lab or personal network monitoring.
* Detecting suspicious pot scanning activities in local networks.

---

## Disclaimer

This project is for educational and ethical use only.
Only run it on systems or networks where you have permission.
This tool should be used only for authorized security testing purposes.


---

## Contributing

Contributions are welcome. You can improve detection logic, optimize performance, or enhance documentation.

---

## License

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy of this software...

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.


---

## Author

ADITYA UPMANYU <Team Leader > 


