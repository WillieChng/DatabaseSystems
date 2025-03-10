import datetime
import random

import altair as alt
import numpy as np
import pandas as pd
import streamlit as st

from db_connection import get_db

st.set_page_config(
    page_title="Multipage App", 
    page_icon="🎫"
)

st.title("HomePage")
st.sidebar.success("Select page")

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

# Get the database connection.
db = get_db()
collection = db["tickets"]

