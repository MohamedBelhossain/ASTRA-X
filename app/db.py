import logging
import os
from dotenv import load_dotenv
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

if os.getenv("RUNNING_IN_DOCKER", "").lower() not in {"1", "true", "yes", "on"}:
    load_dotenv()

uri = os.getenv("MONGO_URI")
logger = logging.getLogger("webvulnscan.db")

client = MongoClient(uri, server_api=ServerApi('1'))

try:
    client.admin.command('ping')
    logger.debug("MongoDB connection verified.")
except Exception as e:
    logger.error("MongoDB connection failed: %s", e)
