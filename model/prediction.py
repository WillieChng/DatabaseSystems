import pymongo
from math import ceil
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

class PredictionModel:
    def __init__(self, db, db_collection):
        self.db = db
        self.collection = self.db[f"{db_collection}"]
        self.weights = {
            "protocol": 0.05,
            "packet_size": 0.10,
            "duration": 0.10,
            "login_attempts": 0.15,
            "failed_logins": 0.15,
            "unusual_time_access": 0.15, #flag
            "ip_reputation_score": 0.25,
            "encryption_used": 0.05
        }

    def mongoConnect(self):
        try:
            self.db.command("ping")
            print("Atlas Cloud Connected Successfully")
        except ConnectionFailure as e:
            print(f"Atlas Connection Failed: {e}")    
    
    def get_avg(self):
        def get_data():
            return self.collection.find({
                "security_metrics.attack_detected": 1  # Only look at confirmed attacks
            })
        
        def dict_gen(dict, input, none_handler):
            if input == None:
                input = none_handler
            if input in dict:
                dict[f"{input}"] += 1
            else:
                dict[f"{input}"] = 0

        confirmed_attacks = get_data()
        
        count = 0
        sum_packet_size = 0
        sum_duration = 0
        sum_login_attempts = 0
        sum_failed_logins = 0
        sum_ip_score = 0
        encryption_dict = {}
        protocol_dict = {}

        for attack in confirmed_attacks:
            count += 1
            sum_packet_size += attack["network_activity"]["packet_size"]
            sum_duration += attack["network_activity"]["duration"]
            sum_login_attempts += attack["authentication"]["login_attempts"]
            sum_failed_logins += attack["authentication"]["failed_logins"]
            sum_ip_score += attack["security_metrics"]["ip_reputation_score"]
            encryption = attack["security_metrics"]["encryption_used"]
            protocol = attack["network_activity"]["protocol"]
            dict_gen(encryption_dict, encryption, "No Encryption")
            dict_gen(protocol_dict, protocol, "No protocol")


        avg_packet_size = ceil(sum_packet_size / count)
        avg_duration = ceil(sum_duration / count)
        avg_login_attempts = ceil(sum_login_attempts / count)
        avg_failed_logins = ceil(sum_failed_logins / count)
        avg_ip_score = ceil((sum_ip_score / count) * 10) / 10.0
        common_enc = max(encryption_dict, key=encryption_dict.get)
        common_pro = max(protocol_dict, key=protocol_dict.get)

        #test result
        print(f"\n----- Analysis of {count} attack records -----")
        print(f"Sum packet size: {sum_packet_size:.2f} bytes")
        print(f"Sum duration: {sum_duration:.2f} seconds")
        print(f"Sum login attempts: {sum_login_attempts:.2f}")
        print(f"Sum failed logins: {sum_failed_logins:.2f}")
        print(f"Sum IP reputation score: {sum_ip_score:.2f}")
        print("Encryption types distribution:")
        for enc_type, enc_count in encryption_dict.items():
            print(f"  - {enc_type}: {enc_count}")

        print("\nProtocol types distribution:")
        for protocol_type, protocol_count in protocol_dict.items():
            print(f"  - {protocol_type}: {protocol_count}")

        print(f"\n----- Analysis of {count} attack records (AVERAGE) -----")
        print(f"Average packet size: {avg_packet_size:.2f} bytes")
        print(f"Average duration: {avg_duration:.2f} seconds")
        print(f"Average login attempts: {avg_login_attempts:.2f}")
        print(f"Average failed logins: {avg_failed_logins:.2f}")
        print(f"Average IP reputation score: {avg_ip_score:.2f}")
        print("Encryption types distribution:")
        for enc_type, enc_count in encryption_dict.items():
            print(f"  - {enc_type}: {enc_count}")

        print("\nProtocol types distribution:")
        for protocol_type, protocol_count in protocol_dict.items():
            print(f"  - {protocol_type}: {protocol_count}")

        return {
            "common_enc" : common_enc,
            "common_pro" : common_pro,
            "avg_packet_size" : avg_packet_size,
            "avg_duration" : avg_duration,
            "avg_login_attempts" : avg_login_attempts,
            "avg_failed_logins" : avg_failed_logins,
            "avg_ip_score" : avg_ip_score
        }
        

    def predict(self, user_input):
        average_stats = self.get_avg()
        for key, value in average_stats.items():
            print(f"{key}: {value}")

        probability = 0.0
        detected_anomaly = []

        # calculate in priority order
        # 1. IP reputation score
        if user_input["security_metrics"]["ip_reputation_score"] <= average_stats["avg_ip_score"]:
            detected_anomaly.append("IRS")
            probability += self.weights["ip_reputation_score"]

        # 2. Unusual time access
        if user_input["authentication"]["unusual_time_access"] == 1:
            detected_anomaly.append("UTA")
            probability += self.weights["unusual_time_access"]

        # 3. Login attempts
        if user_input["authentication"]["login_attempts"] >= average_stats["avg_login_attempts"]:
            detected_anomaly.append("LA")
            probability += self.weights["login_attempts"]

        # 4. Failed logins
        if user_input["authentication"]["failed_logins"] >= average_stats["avg_failed_logins"]:
            detected_anomaly.append("FL")
            probability += self.weights["failed_logins"]

        # 5. Session duration
        if user_input["network_activity"]["duration"] >= average_stats["avg_duration"]:
            detected_anomaly.append("SD")
            probability += self.weights["duration"]

        # 6. Network packet size
        if user_input["network_activity"]["packet_size"] >= average_stats["avg_packet_size"]:
            detected_anomaly.append("NPS")
            probability += self.weights["packet_size"]

        # 7. Encryption used
        if user_input["security_metrics"]["encryption_used"] != average_stats["common_enc"]:
            detected_anomaly.append("EU")
            probability += self.weights["encryption_used"]

        # 8. Protocol type
        if user_input["network_activity"]["protocol"] != average_stats["common_pro"]:
            detected_anomaly.append("PT")
            probability += self.weights["protocol"]

        return probability, detected_anomaly

        