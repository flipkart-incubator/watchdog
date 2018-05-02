from pymongo import MongoClient
import os

def mongo_client(client=None):
    if not client:
        client = MongoClient('mongodb://127.0.0.1:27017')

    return client



