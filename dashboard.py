
import streamlit as st
import pandas as pd
import plotly.express as px

from pathlib import Path
from src.capture import extract_packets
from src.analyzer import analyze_packets
from src.diagnostics import generate_diagnostics


# Project paths
BASE_DIR = Path(__file__).resolve().parent

DEFAULT_PCAP = BASE_DIR / "data" / "captures" / "first_capture.pcapng"
CSV_FILE = BASE_DIR / "data" / "processed" / "packets.csv"


# Page configuration
st.set_page_config(
    page_title="Wi-Fi Traffic Analyzer",
    page_icon="📡",
    layout="wide"
)


# Sidebar
st.sidebar.title("📡 Traffic Analyzer")
st.sidebar.markdown("---")

st.sidebar.subheader("About Project")
st.sidebar.write(
    "A network traffic analysis tool that extracts "
    "packet information and identifies communication patterns."
)

st.sidebar.markdown("---")
st.sidebar.subheader("Technologies")

st.sidebar.write(
    "• Python\n"
    "• Wireshark / TShark\n"
    "• Pandas\n"
    "• Streamlit\n"
    "• Plotly"
)

st.sidebar.markdown("---")

st.sidebar.info(
    "Upload a PCAP or PCAPNG file to analyse network traffic."
)


# Main title
st.title("📡 Wi-Fi Traffic & Protocol Analyzer")

st.write(
    "Analyze captured network packets, identify protocols "
    "and examine basic network diagnostic indicators."
)

st.divider()


# Packet capture analysis
st.subheader("Packet Capture Analysis")

uploaded_file = st.file_uploader(
    "Upload a network capture file",
    type=["pcap", "pcapng"]
)

if uploaded_file is not None:
    pcap_file = (
        BASE_DIR / "data" / "captures" /
        Path(uploaded_file.name).name
    )

    pcap_file.parent.mkdir(parents=True, exist_ok=True)
    pcap_file.write_bytes(uploaded_file.getvalue())

else:
    pcap_file = DEFAULT_PCAP


# Analyze button
if st.button("Analyze Network Traffic"):

    if not pcap_file.exists():
        st.error("Packet capture file not found.")
        st.stop()

    try:
        with st.spinner("Extracting packets..."):
            extract_packets(pcap_file, CSV_FILE)

        st.success("Packet extraction completed!")

    except Exception as e:
        st.error(f"Analysis failed: {e}")
        st.stop()


# Load analysis results
if CSV_FILE.exists():

    try:
        results = analyze_packets(CSV_FILE)

        df = results["data"]

        # Ensure Main Protocol exists
        if "Main Protocol" not in df.columns:

            if "frame.protocols" in df.columns:
                df["Main Protocol"] = (
                    df["frame.protocols"]
                    .fillna("Unknown")
                    .astype(str)
                    .str.split(":")
                    .str[-1]
                    .str.upper()
                )
            else:
                df["Main Protocol"] = "UNKNOWN"


        # Network overview
        st.divider()
        st.subheader("Network Overview")

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total Packets",
            f"{results['total_packets']:,}"
        )

        col2.metric(
            "Total Data",
            f"{results['total_data'] / 1024:.2f} KB"
        )

        col3.metric(
            "Average Packet Size",
            f"{results['average_size']:.2f} Bytes"
        )


        # Protocol distribution
        st.divider()
        st.subheader("Protocol Distribution")

        protocol_data = results["protocol_counts"]

        fig = px.bar(
            protocol_data.head(10),
            x="Protocol",
            y="Packets",
            title="Top 10 Observed Protocol Stacks"
        )

        st.plotly_chart(fig, use_container_width=True)


        # IP analysis
        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Top Source IP Addresses")
            st.dataframe(
                results["source_counts"].head(10),
                use_container_width=True
            )

        with col2:
            st.subheader("Top Destination IP Addresses")
            st.dataframe(
                results["destination_counts"].head(10),
                use_container_width=True
            )


        # Network diagnostics
        st.divider()
        st.subheader("Network Diagnostics")

        findings = generate_diagnostics(df)

        st.dataframe(
            pd.DataFrame(findings),
            use_container_width=True
        )


        # Packet details
        st.divider()
        st.subheader("Packet Details")

        protocol_options = ["All"] + sorted(
            df["Main Protocol"].dropna().unique().tolist()
        )

        selected_protocol = st.selectbox(
            "Filter packets by protocol",
            protocol_options
        )

        if selected_protocol == "All":
            filtered_df = df
        else:
            filtered_df = df[
                df["Main Protocol"] == selected_protocol
            ]

        st.dataframe(
            filtered_df.head(100),
            use_container_width=True
        )

        st.caption(
            f"Showing {min(len(filtered_df), 100)} of "
            f"{len(filtered_df)} matching packets."
        )


        # Download packet data
        st.download_button(
            label="Download Packet Data (CSV)",
            data=df.to_csv(index=False),
            file_name="network_packet_analysis.csv",
            mime="text/csv"
        )


    except Exception as e:
        st.error(f"Could not load analysis results: {e}")

else:
    st.info("Click 'Analyze Network Traffic' to begin.")
