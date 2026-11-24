import pandas as pd


def generate_diagnostics(df):

    findings = []

    # Check TCP resets
    if "tcp.flags.reset" in df.columns:

        resets = (
            df["tcp.flags.reset"].astype(str).str.strip() == "1"
        ).sum()

        if resets > 0:
            findings.append({
                "Issue": "TCP Connection Resets",
                "Count": int(resets),
                "Status": "Warning",
                "Details": "TCP reset packets were detected."
            })

    # Check TCP retransmissions
    if "tcp.analysis.retransmission" in df.columns:

        retransmissions = (
            df["tcp.analysis.retransmission"]
            .astype(str)
            .str.strip()
            .eq("1")
        ).sum()

        if retransmissions > 0:
            findings.append({
                "Issue": "TCP Retransmissions",
                "Count": int(retransmissions),
                "Status": "Warning",
                "Details": "TCP retransmission packets were detected."
            })

    # Check DNS activity
    if (
        "dns.id" in df.columns
        and "dns.flags.response" in df.columns
    ):

        valid_dns = (
            df["dns.id"].astype(str).str.strip()
            .ne("Unknown")
            & df["dns.id"].astype(str).str.strip().ne("")
        )

        dns_requests = (
            valid_dns
            & (df["dns.flags.response"].astype(str).str.strip() == "0")
        ).sum()

        dns_responses = (
            valid_dns
            & (df["dns.flags.response"].astype(str).str.strip() == "1")
        ).sum()

        findings.append({
            "Issue": "DNS Activity",
            "Count": int(dns_requests + dns_responses),
            "Status": "Info",
            "Details": (
                f"DNS requests: {dns_requests}, "
                f"DNS responses: {dns_responses}"
            )
        })

    # Default result
    if not findings:
        findings.append({
            "Issue": "No Major Indicators",
            "Count": 0,
            "Status": "Good",
            "Details": "No matching diagnostic indicators were found."
        })

    return findings