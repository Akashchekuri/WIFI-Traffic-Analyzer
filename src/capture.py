import subprocess
from pathlib import Path


TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"


def extract_packets(pcap_file, output_csv):

    pcap_file = Path(pcap_file)
    output_csv = Path(output_csv)

    if not pcap_file.exists():
        raise FileNotFoundError(f"Capture file not found: {pcap_file}")

    fields = [
        "frame.number",
        "frame.time",
        "frame.protocols",
        "frame.len",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
"udp.dstport",
"tcp.flags.reset",
"tcp.analysis.retransmission",
"dns.id",
"dns.flags.response",
"dns.qry.name"
    ]

    command = [
        TSHARK_PATH,
        "-r", str(pcap_file),
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=,",
        "-E", "quote=d"
    ]

    for field in fields:
        command.extend(["-e", field])

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    with open(output_csv, "w", encoding="utf-8", newline="") as file:
        subprocess.run(
            command,
            stdout=file,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )

    return output_csv