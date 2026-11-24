
import pandas as pd


def analyze_packets(csv_file):

    df = pd.read_csv(csv_file)

    # Clean column names
    df.columns = df.columns.str.strip()

    # Replace missing values
    df = df.fillna("Unknown")

    # Convert packet size to numeric
    df["frame.len"] = pd.to_numeric(
        df["frame.len"], errors="coerce"
    ).fillna(0)

    # Basic statistics
    total_packets = len(df)
    total_data = df["frame.len"].sum()
    average_size = df["frame.len"].mean()

    # Extract the main protocol
    if "frame.protocols" in df.columns:

        df["Main Protocol"] = (
            df["frame.protocols"]
            .astype(str)
            .str.split(":")
            .str[-1]
            .str.upper()
        )

    else:
        df["Main Protocol"] = "UNKNOWN"

    # Protocol distribution
    protocol_counts = (
        df["Main Protocol"]
        .value_counts()
        .reset_index()
    )

    protocol_counts.columns = ["Protocol", "Packets"]

    # Source IP distribution
    source_counts = (
        df["ip.src"]
        .replace("Unknown", pd.NA)
        .dropna()
        .value_counts()
        .reset_index()
    )

    source_counts.columns = ["Source IP", "Packets"]

    # Destination IP distribution
    destination_counts = (
        df["ip.dst"]
        .replace("Unknown", pd.NA)
        .dropna()
        .value_counts()
        .reset_index()
    )

    destination_counts.columns = ["Destination IP", "Packets"]

    return {
        "data": df,
        "total_packets": total_packets,
        "total_data": total_data,
        "average_size": average_size,
        "protocol_counts": protocol_counts,
        "source_counts": source_counts,
        "destination_counts": destination_counts
    }
