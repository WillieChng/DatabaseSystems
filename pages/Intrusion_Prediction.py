import streamlit as st
from model.prediction import PredictionModel
from db_connection import get_db
from datetime import datetime

# Connect to MongoDB
db = get_db()
collection = db["user_incoming_input"]

anomaly_dict = {
    "IRS" : "Low IP Reputation Score",
    "UTA" : "Unusual Time Access",
    "LA" : "Unusual Login Attempts",
    "FL" : "Failed Logins",
    "SD" : "Long Session Duration",
    "NPS" : "Large Network Packet Size",
    "EU" : "Weak Encryption",
    "PT" : "Uncommon Protocol"
}

st.set_page_config(
    page_title="Intrusion Prediction",
    page_icon="🛡️",
    layout="wide"
)
st.header("Intrusion Prediction 🚨")

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
    unusual_time_options = {True: 1, False: 0}
    unusual_time_display = st.selectbox("Unusual Time Access", 
                                    options=list(unusual_time_options.keys()),
                                    format_func=lambda x: "True" if x else "False", 
                                    label_visibility="collapsed")
    unusual_time_access = unusual_time_options[unusual_time_display]
    st.markdown('IP Reputation Score <span class="tooltip">❓<span class="tooltiptext">Use AbuseIPDB or IPVoid to check if an IP is flagged as risky.</span></span>', unsafe_allow_html=True)
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
    
    # Store input in MongoDB
    collection.insert_one(document)

    # Create a placeholder for the spinner
    spinner_placeholder = st.empty()
    
    # Show loading indicator before prediction
    with spinner_placeholder.container():
        with st.spinner("Predicting..."):
            # Run your prediction model (only once)
            prediction = PredictionModel(db, "intrusion_logs")
            probability, detected_anomaly = prediction.predict(document)
            # Add a small delay so the spinner is visible
            import time
            time.sleep(1)

    # Clear the spinner after prediction completes
    spinner_placeholder.empty()
    
    # Create a placeholder for the final result display 
    result_placeholder = st.empty()

    # Display detected anomalies with sequential animation
    if detected_anomaly:
        # Create placeholders for each anomaly
        anomaly_placeholders = []
        for _ in detected_anomaly:
            anomaly_placeholders.append(st.empty())
        
        # Use custom HTML and CSS for animated display
        st.markdown("""
        <style>
        @keyframes fadeIn {
            0% { opacity: 0; transform: translateY(20px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        .anomaly-alert {
            padding: 10px 15px;
            background-color: #ff4d4d;
            color: white;
            border-radius: 5px;
            margin-bottom: 8px;
            animation: fadeIn 0.5s ease-out forwards;
        }
        .anomaly-alert-fadeout {
            padding: 10px 15px;
            background-color: #ff4d4d;
            color: white;
            border-radius: 5px;
            margin-bottom: 8px;
            animation: fadeOut 0.5s ease-in forwards;
        }
        </style>
        """, unsafe_allow_html=True)
        
        # Display each anomaly with a delay
        import time
        
        for i, anomaly_code in enumerate(detected_anomaly):
            # Get the full description from the dictionary
            anomaly_description = anomaly_dict[anomaly_code]
            
            # Display with animation
            anomaly_placeholders[i].markdown(
                f"""
                <div class="anomaly-alert">
                    <strong>{anomaly_description}</strong>: <strong>Detected</strong>
                </div>
                """, 
                unsafe_allow_html=True
            )
            
            # Add a short delay between each anomaly appearing
            time.sleep(0.7)

            # Replace with fadeout version
            anomaly_placeholders[i].markdown(
                f"""
                <div class="anomaly-alert-fadeout">
                    <strong>{anomaly_description}</strong>: <strong>Detected</strong>
                </div>
                """, 
                unsafe_allow_html=True
            )
            
            # Wait for fade-out animation
            time.sleep(0.7)
            
            # Clear the placeholder
            anomaly_placeholders[i].empty()

    with result_placeholder:
        probability_percentage = probability * 100
        # Show prediction result
        st.subheader("Prediction Result")

        # Show risk level based on probability with percentage
        if probability > 0.7:
            st.error(f"⚠️ HIGH RISK: Potential intrusion detected! (Score: {probability_percentage:.1f}%)")
        elif probability > 0.4:
            st.warning(f"⚠️ MEDIUM RISK: Some suspicious indicators detected (Score: {probability_percentage:.1f}%)")
        else:
            st.success(f"✅ LOW RISK: No significant threat detected (Score: {probability_percentage:.1f}%)")

    # Add collapsible section for user input details
    with st.expander("Show Input Details", expanded=False):
        # Format the document for better display
        st.subheader("Network Activity")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Protocol", document["network_activity"]["protocol"])
        with col2:
            st.metric("Packet Size", f"{document['network_activity']['packet_size']} bytes")
        with col3:
            st.metric("Session Duration", f"{document['network_activity']['duration']} sec")

        st.subheader("Authentication")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Login Attempts", document["authentication"]["login_attempts"])
        with col2:
            st.metric("Failed Logins", document["authentication"]["failed_logins"])
        with col3:
            unusual = "Yes" if document["authentication"]["unusual_time_access"] == 1 else "No"
            st.metric("Unusual Time Access", unusual)

        st.subheader("Security")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("IP Reputation Score", f"{document['security_metrics']['ip_reputation_score']:.2f}")
        with col2:
            st.metric("Encryption", document["security_metrics"]["encryption_used"])
        with col3:
            st.metric("Browser", document["browser"])
        