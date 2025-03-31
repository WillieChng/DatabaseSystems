from model.prediction import PredictionModel
from db_connection import get_db


prediction = PredictionModel(get_db(), "intrusion_logs")

prediction.mongoConnect()

sample_data = {
            "session_id": "abc123",
            "network_activity": {
                "protocol": "TCP",
                "packet_size": 1024,
                "duration": 120
            },
            "authentication": {
                "login_attempts": 5,
                "failed_logins": 3,
                "unusual_time_access": 1
            },
            "security_metrics": {
                "ip_reputation_score": 0.2,
                "encryption_used": "None",
                "attack_detected": 1
            },
            "browser": "Chrome"
        }

probability, detected_anomaly = prediction.predict(sample_data)
print(f"Probability of Anomaly: {probability}")
print(f"Detected Anomaly: {detected_anomaly}")
#print(len(prediction.get_data(sample_data)))
