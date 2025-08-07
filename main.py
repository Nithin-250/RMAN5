from fastapi import FastAPI, Request
from pydantic import BaseModel
from fastapi.encoders import jsonable_encoder
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime
from geopy.distance import geodesic
import os
import numpy as np

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("MONGO_DB_NAME")
COLLECTION_NAME = os.getenv("MONGO_COLLECTION_NAME")

client = MongoClient(MONGO_URI)
db = client[DB_NAME]
collection = db[COLLECTION_NAME]
blacklist_collection = db["blacklist"]

app = FastAPI()

location_lookup = {
    "Chennai": (13.0827, 80.2707),
    "Mumbai": (19.0760, 72.8777),
    "Delhi": (28.6139, 77.2090),
    "Bangalore": (12.9716, 77.5946),
}

# Track accepted last known location per card
last_known_location = {}

# Sample blacklisted IPs
BLACKLISTED_IPS = {
    "203.0.113.5",
    "198.51.100.10",
    "45.33.32.156"
}

# Sample blacklisted accounts for startup
startup_blacklisted_accounts = ["9876543210", "1111222233"]
for acc in startup_blacklisted_accounts:
    if not blacklist_collection.find_one({"type": "account", "value": acc}):
        blacklist_collection.insert_one({
            "type": "account",
            "value": acc,
            "reason": ["Predefined blacklist"],
            "timestamp": datetime.now()
        })

class Transaction(BaseModel):
    transaction_id: str
    timestamp: str  # Format: "2025-08-07 16:55:00"
    amount: float
    location: str
    card_type: str
    currency: str
    recipient_account_number: str
    sender_account_number: str


def detect_behavioral_anomaly(past_txns, current_amount, window_size=5, z_thresh=2.5):
    amounts = [txn["amount"] for txn in past_txns][-window_size:]
    if len(amounts) < 2:
        return False
    mean = np.mean(amounts)
    std = np.std(amounts)
    z_score = abs((current_amount - mean) / std) if std != 0 else 0
    return z_score > z_thresh


def detect_geo_drift(card_type, current_location, max_km=500):
    if current_location not in location_lookup:
        return False

    current_coords = location_lookup[current_location]
    last_location = last_known_location.get(card_type)

    if not last_location or last_location not in location_lookup:
        return False

    last_coords = location_lookup[last_location]
    distance = geodesic(last_coords, current_coords).km
    return distance > max_km


def get_client_ip(request: Request):
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host


@app.post("/check_fraud")
async def check_fraud(txn: Transaction, request: Request):
    now = datetime.strptime(txn.timestamp, "%Y-%m-%d %H:%M:%S")
    reasons = []
    is_fraud = False

    client_ip = get_client_ip(request)

    # Check if IP is blacklisted
    if client_ip in BLACKLISTED_IPS:
        reasons.append(f"Blacklisted IP Address: {client_ip}")
        is_fraud = True

    # Check if recipient account is blacklisted
    if blacklist_collection.find_one({"type": "account", "value": txn.recipient_account_number}):
        reasons.append(f"Blacklisted Recipient Account: {txn.recipient_account_number}")
        is_fraud = True

    # Check if sender account is blacklisted
    if blacklist_collection.find_one({"type": "account", "value": txn.sender_account_number}):
        reasons.append(f"Blacklisted Sender Account: {txn.sender_account_number}")
        is_fraud = True

    # Odd hour transaction check (12 AM to 4 AM)
    if 0 <= now.hour < 4:
        reasons.append("Transaction During Odd Hours (12 AM - 4 AM)")
        is_fraud = True

    # Get past transactions for the card
    past_txns = list(collection.find({"card_type": txn.card_type}).sort("timestamp", 1))

    # Behavioral anomaly detection
    if detect_behavioral_anomaly(past_txns, txn.amount):
        reasons.append("Abnormal Amount (Behavioral)")
        is_fraud = True

    # Geo drift detection
    if detect_geo_drift(txn.card_type, txn.location):
        reasons.append("Geo Drift Detected")
        is_fraud = True

    # If not fraud, update last known location
    if not is_fraud:
        last_known_location[txn.card_type] = txn.location

    # Store transaction
    collection.insert_one({
        "transaction_id": txn.transaction_id,
        "timestamp": now,
        "amount": txn.amount,
        "location": txn.location,
        "card_type": txn.card_type,
        "currency": txn.currency,
        "recipient_account": txn.recipient_account_number,
        "sender_account": txn.sender_account_number,
        "client_ip": client_ip,
        "is_fraud": bool(is_fraud),
        "fraud_reason": reasons,
    })

    # If fraud, blacklist recipient or sender account
    if is_fraud:
        for account in [txn.recipient_account_number, txn.sender_account_number]:
            if not blacklist_collection.find_one({"type": "account", "value": account}):
                blacklist_collection.insert_one({
                    "type": "account",
                    "value": account,
                    "reason": reasons,
                    "timestamp": now
                })

    return {"fraud": is_fraud, "reasons": reasons}


@app.get("/transactions")
def get_all_transactions():
    transactions = list(collection.find({}, {"_id": 0}))
    return jsonable_encoder(transactions)


@app.get("/blacklist")
def get_blacklist():
    entries = list(blacklist_collection.find({}, {"_id": 0}))
    return jsonable_encoder(entries)
