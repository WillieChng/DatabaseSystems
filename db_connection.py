from pymongo import MongoClient

def get_db():
    client = MongoClient("mongodb+srv://mongoadmin:J3ENeAyxqKSx8gNz@cyberintrusion.xnava.mongodb.net/")
    db = client["cyber_detection"]
    return db
