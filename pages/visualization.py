import streamlit as st
import pandas as pd
import altair as alt
import plotly.express as px
from db_connection import get_db
import matplotlib.pyplot as plt
import seaborn as sns  # Import Seaborn for advanced plotting

st.title("Data visualization")

# Get the database connection
db = get_db()
collection = db["intrusion-logs"]

# Fetch data from MongoDB because there's nested JSON structures
data = list(collection.find({}, {"_id": 0}))
with st.expander("Raw Data"):
    st.write(data)

# Flatten nested data  
df = pd.json_normalize(data)
st.write("Flattened Data:", df.head())

# Display charts in two columns
col1, col2 = st.columns(2)

# Packet Size per Session [Bar Chart]
with col1:
    fig = px.bar(df, x="session_id", y="network_activity.packet_size", 
                 title="Packet Size per Session",
                 labels={"network_activity.packet_size": "Packet Size", "session_id": "Session ID"})
    st.plotly_chart(fig)

# Session Duration [Line Chart]
with col2:
    fig = px.line(df, x="session_id", y="network_activity.duration",
                  title="Session Duration",
                  labels={"network_activity.duration": "Duration", "session_id": "Session ID"})
    st.plotly_chart(fig)

# Count the occurrences of each protocol
protocol_counts = df['network_activity.protocol'].value_counts().reset_index()
protocol_counts.columns = ['protocol', 'count']

# Count the occurrences of each encryption method
encryption_counts = df['security_metrics.encryption_used'].value_counts().reset_index()
encryption_counts.columns = ['encryption_used', 'count']

# Protocol Distribution [Pie Chart]
with col1:
    fig = px.pie(protocol_counts, names="protocol", values="count", 
                 title="Protocol Distribution")
    st.plotly_chart(fig)

# Encryption Method Distribution [Pie Chart]
with col2:
    fig = px.pie(encryption_counts, names="encryption_used", values="count", 
                 title="Encryption Method Distribution")
    st.plotly_chart(fig)


# Correlation Matrix [Heatmap] - Full Width
# Select only numeric columns
numeric_df = df.select_dtypes(include=['float64', 'int64'])

# Compute correlation matrix on numeric data only
corr = numeric_df.corr()

# Plot correlation matrix
fig, ax = plt.subplots()
sns.heatmap(corr, annot=True, fmt=".2f", cmap="coolwarm", ax=ax)
st.pyplot(fig)


