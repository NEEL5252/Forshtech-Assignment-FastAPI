from .celery_worker import celery_app
import requests, os, json, hashlib, sys
import pandas as pd
from datetime import datetime
from dotenv import load_dotenv
from sqlalchemy.orm import Session
from virustotal_fastapi.models import VirusTotalReport
from virustotal_fastapi.database import get_db
from icecream import ic

load_dotenv()

API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")

HEADERS = {
    "accept": "application/json",
    "x-apikey": API_KEY
}


@celery_app.task
def refresh_virus_total_data():
    sys.stdout.write("Starting VirusTotal Data Refresh Task...\n")

    # Create DB session manually (Celery runs outside FastAPI app context)
    db = next(get_db())

    reports = db.query(VirusTotalReport).all()
    df = pd.DataFrame([r.__dict__ for r in reports])
    df['cache_key'] = "vt_" + df['endpoint_type'] + "_" + df['endpoint_value']

    for _, row in df.iterrows():
        endpoint_type = row['endpoint_type']
        endpoint_value = row['endpoint_value']

        if endpoint_type == "files":
            url = f"{BASE_URL}/files/{endpoint_value}"
        else:
            url = f"{BASE_URL}/{endpoint_type}/{endpoint_value}"

        resp = requests.get(url, headers=HEADERS)
        if resp.status_code == 200:
            data = resp.json()
            report = db.query(VirusTotalReport).get(row['id'])
            report.full_data = data
            report.last_updated_at = datetime.utcnow()
            db.add(report)
            db.commit()
        else:
            sys.stdout.write(f"Error refreshing {endpoint_type}/{endpoint_value}\n")

    db.close()
    sys.stdout.write("Data refresh completed.\n")
    return "VirusTotal Data Refreshed Successfully"
