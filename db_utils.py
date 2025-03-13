from db_connection import get_db

def fetch_cyber_detection():
    db = get_db()
    collection = db["intrusion_logs"]
    data = list(collection.find({}, {"_id": 0})) 
    return data
