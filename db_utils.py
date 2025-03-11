from db_connection import get_db

def fetch_intrusion_logs():
    db = get_db()
    collection = db["intrusion-logs"]
    data = list(collection.find({}, {"_id": 0})) 
    return data
