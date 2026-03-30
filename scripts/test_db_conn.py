import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

def test_connection():
    uri = os.getenv("MONGO_URI")
    db_name = os.getenv("MONGO_DB_NAME", "mini_soc")
    
    print(f"Connecting to MongoDB...")
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        # The ismaster command is cheap and does not require auth.
        client.admin.command('ismaster')
        print("✅ MongoDB Connection Successful!")
        
        db = client[db_name]
        print(f"Connected to database: {db_name}")
        
        # Test write
        test_col = db['connection_test']
        test_col.insert_one({"test": "success", "timestamp": "now"})
        print("✅ Write Test Successful!")
        
        # Test read
        doc = test_col.find_one({"test": "success"})
        if doc:
            print("✅ Read Test Successful!")
        
        # Clean up
        test_col.delete_many({"test": "success"})
        
    except Exception as e:
        print(f"❌ Connection Failed: {e}")

if __name__ == "__main__":
    test_connection()
