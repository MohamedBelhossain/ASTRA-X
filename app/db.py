import os
from dotenv import load_dotenv
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

if os.getenv("RUNNING_IN_DOCKER", "").lower() not in {"1", "true", "yes", "on"}:
    load_dotenv()

uri = os.getenv("MONGO_URI")

client = MongoClient(uri, server_api=ServerApi('1'))

try:
    client.admin.command('ping')
    print("Connected!")
except Exception as e:
    print(e)
