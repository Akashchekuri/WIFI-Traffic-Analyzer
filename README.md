# Wi-Fi Traffic & Protocol Analyzer

A Python-based network traffic analysis application that extracts packet information from PCAP/PCAPNG files, identifies communication protocols, and displays basic network diagnostic indicators through an interactive dashboard.

## Project Overview

The Wi-Fi Traffic & Protocol Analyzer helps examine captured network traffic and understand communication patterns.

It uses Wireshark's command-line utility, TShark, to extract packet information and Python libraries to process and visualize the results.

## Features

- Upload PCAP and PCAPNG capture files.
- Extract packet information using TShark.
- Identify observed protocol stacks.
- Calculate total packets, data volume, and average packet size.
- Analyze source and destination IP addresses.
- Detect TCP reset packets and TCP retransmissions.
- Summarize DNS requests and responses.
- Filter packet details by protocol.
- Download analyzed packet data as CSV.
- Interactive dashboard with charts and tables.

## Technologies Used

- Python
- Wireshark / TShark
- Pandas
- Streamlit
- Plotly
- CSV

## Project Structure

```text
WiFi-Traffic-Analyzer/
│
├── data/
│   ├── captures/
│   └── processed/
│
├── src/
│   ├── capture.py
│   ├── analyzer.py
│   └── diagnostics.py
│
├── dashboard.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Installation

### 1. Install Python

Install Python on your computer.

### 2. Install Wireshark

Install Wireshark with TShark and Npcap.

### 3. Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

### 4. Open the Project Folder

```bash
cd WiFi-Traffic-Analyzer
```

### 5. Install Dependencies

```bash
pip install -r requirements.txt
```

### 6. Configure TShark

Make sure TShark is installed and update its executable path in `src/capture.py` if your installation uses a different location.

## Run the Application

```bash
python -m streamlit run dashboard.py
```

The application will open in your browser.

## How to Use

1. Open the dashboard.
2. Upload a PCAP or PCAPNG file.
3. Click **Analyze Network Traffic**.
4. View network overview statistics.
5. Examine protocol distribution and IP addresses.
6. Review network diagnostic indicators.
7. Filter packet details by protocol.
8. Download the analyzed packet data as CSV.

## Diagnostic Indicators

The application checks for:

- TCP connection reset packets.
- TCP retransmission indicators.
- DNS requests and responses.

These indicators help identify patterns that may deserve further investigation. They do not independently confirm a network fault.

## Important Note

This project analyzes packet captures from networks you own or are authorized to inspect.

Encrypted application traffic, such as TLS, is not decrypted by this application. Analysis is based on the packet fields extracted by TShark.

## Author

B.Tech Data Science Student

Interested in Computer Networking, Wireless Technologies,