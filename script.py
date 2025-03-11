import pandas as pd
import json
from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["cybersecurity_db"]  # Database name
collection = db["intrusion_logs"]  # Collection name

# Load the dataset
file_path = "cybersecurity_intrusion_data.csv"
df = pd.read_csv(file_path)
print(df.head(1))

#Transform relational schema into a document-based format
def transform_data(row):
    return {
        "session_id": row["session_id"],
        "network_activity": {
            "protocol": row["protocol_type"],
            "packet_size": row["network_packet_size"],
            "duration": row["session_duration"]
        },
        "authentication": {
            "login_attempts": row["login_attempts"],
            "failed_logins": row["failed_logins"],
            "unusual_time_access": row["unusual_time_access"]
        },
        "security_metrics": {
            "ip_reputation_score": row["ip_reputation_score"],
            "encryption_used": row["encryption_used"],
            "attack_detected": row["attack_detected"]
        },
        "browser": row["browser_type"]
    }

# Convert DataFrame rows to JSON-like documents
documents = df.apply(transform_data, axis=1).tolist()
print(f"Transformed {len(documents)} records into document format")
print("Sample transformed document:", documents[0])

# # Insert data into MongoDB
# collection.insert_many(documents)
# print("Data inserted successfully!")

# # Perform basic analysis
# print("Total number of logs:", collection.count_documents({}))

# # Count attacks detected
# attack_counts = collection.aggregate([
#     {"$group": {"_id": "$security_metrics.attack_detected", "count": {"$sum": 1}}},
#     {"$sort": {"count": -1}}
# ])
# print("Attack detection summary:")
# for attack in attack_counts:
#     print("Detected:" if attack["_id"] == 1 else "Not Detected:", attack["count"])
