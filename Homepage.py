import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from db_connection import get_db
from db_utils import fetch_intrusion_logs

st.set_page_config(
    page_title="Network Intrusion Insights",
    page_icon="🛡️",
    layout="wide"
)

st.title("Network Intrusion Insight")

# Function to test MongoDB connection
def test_mongo_connection():
    try:
        # Check the connection
        db = get_db()
        db.command("ping")
        st.write("✅ Successfully connected to MongoDB!")
        return True, db.list_collection_names()
    except Exception as e:
        st.write("❌ Failed to connect to MongoDB:", e)

# Test the MongoDB connection
connection_status, connection_info = test_mongo_connection()

# Show connection status
if connection_status:
    st.success(f"Connected to MongoDB. Collections: {connection_info}")
else:
    st.error(f"Failed to connect to MongoDB. Error: {connection_info}")

# Fetch data
data = fetch_intrusion_logs()

db = get_db()
collection = db["intrusion-logs"]

# Fetch some quick stats
total_entries = collection.count_documents({})
unique_protocols = len(collection.distinct("network_activity.protocol"))

col1, col2 = st.columns(2)
# Display key metrics
col1.metric("Total Intrusion Logs", total_entries)
col2.metric("Unique Protocols Detected", unique_protocols)


with st.expander("Raw Data"):
    st.write(data)

