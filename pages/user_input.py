import streamlit as st
from db_connection import get_db
from datetime import datetime

# Connect to MongoDB
db = get_db()
collection = db["intrusion-logs"]

st.set_page_config(
    page_icon="🛡️",
    layout="wide"
)
st.header("Intrusion Detection")

# Load external CSS
def load_css(css_file):
    with open(css_file) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

load_css("styles.css")

col1, col2 = st.columns(2)

# User Inputs
with col1:
    st.markdown('Protocol Type <span class="tooltip">❓<span class="tooltiptext">Use netstat -an (Windows) or ss -tulnp (Linux/Mac) in the terminal to check active connections.</span></span>', unsafe_allow_html=True)
    protocol_type = st.selectbox("", ["TCP", "UDP", "ICMP"], label_visibility="collapsed")
    st.markdown('Network Packet Size <span class="tooltip">❓<span class="tooltiptext">Open browser developer tools (F12 > Network tab) and check the request/response size in the headers.</span></span>', unsafe_allow_html=True)
    network_packet_size = st.number_input("Network Packet Size", min_value=0, label_visibility="collapsed")
    st.markdown('Session Duration (seconds) <span class="tooltip">❓<span class="tooltiptext">Visit a secure website (https://), click the padlock in the address bar, and check connection details for TLS/SSL encryption.</span></span>', unsafe_allow_html=True)
    session_duration = st.number_input("Session Duration (seconds)", min_value=0.0, label_visibility="collapsed")
    st.markdown('Login Attempts <span class="tooltip">❓<span class="tooltiptext">Check system logs (Event Viewer on Windows or /var/log/auth.log on Linux) for login entries.</span></span>', unsafe_allow_html=True)
    login_attempts = st.number_input("Login Attempts", min_value=0, label_visibility="collapsed")
    st.markdown('Failed Logins <span class="tooltip">❓<span class="tooltiptext">Filter system logs for unsuccessful login attempts.</span></span>', unsafe_allow_html=True)
    failed_logins = st.number_input("Failed Logins", min_value=0, label_visibility="collapsed")
    
with col2:
    st.markdown('Unusual Time Access <span class="tooltip">❓<span class="tooltiptext">Compare login timestamps with normal working hours in system logs.</span></span>', unsafe_allow_html=True)
    unusual_time_access = st.selectbox("Unusual Time Access", [0, 1], label_visibility="collapsed")
    st.markdown('Unusual Time Access <span class="tooltip">❓<span class="tooltiptext">Use AbuseIPDB or IPVoid to check if an IP is flagged as risky.</span></span>', unsafe_allow_html=True)
    ip_reputation_score = st.number_input("IP Reputation Score", min_value=0.0, max_value=1.0, label_visibility="collapsed")
    st.markdown('Encryption Used <span class="tooltip">❓<span class="tooltiptext"> Visit a secure website (https://), click the padlock in the address bar, and check connection details for TLS/SSL encryption.</span></span>', unsafe_allow_html=True)
    encryption_used = st.selectbox("Encryption Used", ["DES", "AES", "None"], label_visibility="collapsed")
    st.markdown('Browser Type <span class="tooltip">❓<span class="tooltiptext">Open browser developer tools (F12) and check the User-Agent string.l working hours in system logs.</span></span>', unsafe_allow_html=True)
    browser_type = st.selectbox("Browser Type", ["Chrome", "Firefox", "Edge", "Safari", "Other"], label_visibility="collapsed")

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