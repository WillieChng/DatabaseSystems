import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from db_connection import get_db
from db_utils import fetch_cyber_detection
from pymongo import MongoClient

st.set_page_config(
    page_title="Network Intrusion Insights",
    page_icon="🛡️",
    layout="wide"
)

st.title("Network Intrusion Insight 🔍")

# Function to test MongoDB connection
def test_mongo_connection(connection_string, db_name):
    try:
        # Check the connection
        client = MongoClient(connection_string)
        db = client[db_name]
        db.command("ping")
        if "localhost" in connection_string:
            connection_type = "local"
        else:
            connection_type = "cloud"
        st.write(f"✅ Successfully connected to {connection_type} MongoDB at {connection_string}!")
        return True, db_name, db.list_collection_names()
    except Exception as e:
        st.write(f"❌ Failed to connect to MongoDB at {connection_string}:", e)
        return False, None, None

# Test the MongoDB connection
connection_string = "mongodb+srv://mongoadmin:J3ENeAyxqKSx8gNz@cyberintrusion.xnava.mongodb.net/"
db_name = "cyber_detection"
connection_status, db_name, collection_info = test_mongo_connection(connection_string, db_name)

# Show connection status
if connection_status:
    st.success(f"Connected to MongoDB. Database: {db_name}. Collections: {collection_info}")
else:
    st.error(f"Failed to connect to MongoDB.")

# Fetch data
data = fetch_cyber_detection()

db = get_db()
collection = db["intrusion_logs"]

# Fetch some quick stats
total_entries = collection.count_documents({})
unique_protocols = len(collection.distinct("network_activity.protocol"))

# Display Key Stats
col1, col2 = st.columns(2)
col1.metric("📄 Total Intrusion Logs", f"{total_entries:,}")
col2.metric("🔗 Unique Protocols Detected", unique_protocols)

# Add Refresh Button
if st.button("🔄 Refresh Data"):
    data = fetch_cyber_detection()
    st.rerun()

# Collapsible Raw Data Preview
with st.expander("📊 View Raw Data"):
    st.dataframe(pd.DataFrame(data).head(10))