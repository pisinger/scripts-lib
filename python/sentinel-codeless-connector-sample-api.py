import azure.functions as func
import socket
import json
import time
import urllib.request
import random
from datetime import datetime, timedelta

# Sample data for random generation
protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS']
client_names = ['server-01', 'Server-22', 'Laptop-17', 'Client-99', 'Node-03', 'DC-01']
regions = ['EMEA', 'APAC', 'NA', 'LATAM', 'ANZ']
ports = [22, 80, 443, 8080, 3306, 5432, 6379]

# Define allowed API keys
ALLOWED_API_KEYS = {
    "xxxxxx", 
    "xxxxxx"
}

def is_authorized(req: func.HttpRequest):
    api_key = req.headers.get("x-api-key")
    return api_key in ALLOWED_API_KEYS

def generate_random_ip():
    return '.'.join(str(random.randint(1, 254)) for _ in range(4))

def generate_event():
    timestamp = (datetime.utcnow() - timedelta(seconds=random.randint(0, 10))).isoformat() + 'Z'
    return {
        "Timestamp": timestamp,
        "SourceIp": generate_random_ip(),
        "DestIp": generate_random_ip(),
        "Protocol": random.choice(protocols),
        "Ports": random.choice(ports),
        "ClientName": random.choice(client_names),
        "Region": random.choice(regions)
    }

def get_siem_events():
    batch_size = 10  # Number of events per call
    events = [generate_event() for _ in range(batch_size)]    
    return json.dumps(events, indent=2)

def main(req: func.HttpRequest) -> func.HttpResponse:
    if not is_authorized(req):
        print("non-Authorized request received")
        return func.HttpResponse(
            json.dumps({"error": "Forbidden: Invalid or missing API key."}),
            status_code=403,
            headers={"Content-Type": "application/json"}
        )
    else:
        print("Authorized request received")
        return func.HttpResponse(
            get_siem_events(),
            status_code=200,
            headers={"Content-Type": "application/json"}
        )