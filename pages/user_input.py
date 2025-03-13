import streamlit as st
from db_connection import get_db
from datetime import datetime

# Connect to MongoDB
db = get_db()
collection = db["intrusion-logs"]

st.header("Intrusion Detection")

col1, col2 = st.columns(2)

# User Inputs
with col1:
    protocol_type = st.selectbox("Protocol Type", ["TCP", "UDP", "ICMP"])
    network_packet_size = st.number_input("Network Packet Size", min_value=0)
    session_duration = st.number_input("Session Duration (seconds)", min_value=0.0)
    login_attempts = st.number_input("Login Attempts", min_value=0)
    failed_logins = st.number_input("Failed Logins", min_value=0)
    
with col2:
    unusual_time_access = st.selectbox("Unusual Time Access", [0, 1])
    ip_reputation_score = st.number_input("IP Reputation Score", min_value=0.0, max_value=1.0)
    encryption_used = st.selectbox("Encryption Used", ["DES", "AES", "None"])
    browser_type = st.selectbox("Browser Type", ["Chrome", "Firefox", "Edge", "Safari", "Other"])

# Process query only when "Submit" is clicked
if st.button("Submit"):
    # Create a document based on user inputs
    document = {
        # "session_id": session_id, prob not needed since its randomly generated, but could be useful for tracking
        "network_activity": {
            "protocol": protocol_type,
            "packet_size": network_packet_size,
            "duration": session_duration
        },
        "authentication": {
            "login_attempts": login_attempts,
            "failed_logins": failed_logins,
            "unusual_time_access": unusual_time_access
        },
        "security_metrics": {
            "ip_reputation_score": ip_reputation_score,
            "encryption_used": encryption_used,
            "attack_detected": None  # This will be predicted
        },
        "browser": browser_type
    }

    # Here you would call your prediction model to predict if an intrusion is detected
    # For example:
    # prediction = predict_intrusion(document)
    # st.write(f"Intrusion Detected: {prediction}")

    st.write("User input document:", document)