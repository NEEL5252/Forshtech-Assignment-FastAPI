import httpx, hashlib, asyncio, json, os
from redis.asyncio import from_url
from .models import VirusTotalReport
from sqlalchemy.orm import Session
from icecream import ic
from .database import get_db
from fastapi import Depends
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")

HEADERS = {"accept": "application/json", "x-apikey": API_KEY}
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/1")

redis = from_url(REDIS_URL, decode_responses=True)

async def compute_file_hash(file_path:str) -> str:
    """Compute SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# async def fetch_virustotal_report(endpoint_type:str, endpoint_value:str,db:Session = Depends(get_db), file:str = None) -> dict:
#     if file is None:
#         url = f"{BASE_URL}/{endpoint_type}/{endpoint_value}"
#     else:
#         endpoint_value = compute_file_hash(file)
#         url = f"{BASE_URL}/files"

#     cache_key = f"vt_{endpoint_type}_{endpoint_value}"
#     cached = await redis.get(cache_key)
#     if cached:
#         return json.loads(cached), False
    
#     report = db.query(VirusTotalReport).filter_by(endpoint_value=endpoint_value).first()
#     if report:
#         await redis.set(cache_key, json.dumps(report.data), ex=86400)
#         return report.data, False
    
#     async with httpx.AsyncClient() as client:
#         if endpoint_type == "files" and file is not None:
#             with open(file, "rb") as f:
#                 files = {"file": (os.path.basename(file), f)}
#                 response = await client.post(url, headers=HEADERS, files=files)

#             analysis_link = response.get("data", {}).get("links", {}).get("self", "") 

#             await asyncio.sleep(15)  # Wait for analysis to complete
#             report = await client.get(analysis_link, headers=HEADERS)
#             data = report.json()
#         else:
#             report = await client.get(url, headers=HEADERS)
#             data = report.json()

#     vt_report = VirusTotalReport(
#         endpoint_type=endpoint_type,
#         endpoint_value=endpoint_value,
#         data=data
#     )
#     db.add(vt_report)
#     db.commit()
#     db.refresh(vt_report)

#     await redis.set(cache_key, json.dumps(data), ex=86400)
#     return data, True



async def fetch_virustotal_report_without_redis(endpoint_type: str, endpoint_value: str, db:Session = Depends(get_db), file:str = None):
    if file is not None:
        endpoint_value = compute_file_hash(file)
        url = f"{BASE_URL}/files"
    else:
        url = f"{BASE_URL}/{endpoint_type}/{endpoint_value}"

    # Check if report exists in database and is still valid
    report = (
        db.query(VirusTotalReport)
        .filter_by(endpoint_value=endpoint_value)
        .first()
    )

    if report:
        # Check if cache expired
        if report.expires_at and report.expires_at > datetime.utcnow():
            # Cache still valid → return cached data
            return json.loads(report.data), False
        else:
            # Expired → delete old cache
            db.delete(report)
            db.commit()

    # Fetch fresh data from VirusTotal
    async with httpx.AsyncClient() as client:
        if endpoint_type == "files" and file is not None:
            # Upload file and get analysis link
            with open(file, "rb") as f:
                files = {"file": (os.path.basename(file), f)}
                upload_response = await client.post(
                    url,
                    headers=HEADERS,
                    files=files
                )
                upload_data = upload_response.json()
                analysis_link = upload_data.get("data", {}).get("links", {}).get("self")

            # Wait for VirusTotal to complete analysis
            await asyncio.sleep(15)

            # Fetch analysis report
            report_response = await client.get(analysis_link, headers=HEADERS)
            ic(report_response)

            data = report_response.json()
        else:
            # Domain / IP / URL analysis
            response = await client.get(url, headers=HEADERS)
            data = response.json()

    # Store the new report in the database (24h expiry)
    new_report = VirusTotalReport(
        endpoint_type=endpoint_type,
        endpoint_value=endpoint_value,
        data=json.dumps(data),  # store JSON as text
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(hours=24)
    )

    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    return data, True
