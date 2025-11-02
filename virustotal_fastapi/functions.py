import httpx, hashlib, asyncio, json, os, shutil
from redis.asyncio import from_url
from .models import VirusTotalReport
from sqlalchemy.orm import Session
from icecream import ic
from .database import get_db
from fastapi import Depends, UploadFile
from datetime import datetime, timedelta
from dotenv import load_dotenv
from typing import Union
load_dotenv()

API_KEY = os.getenv("API_KEY")
BASE_URL = os.getenv("BASE_URL")

UPLOAD_DIR = "uploads/"

HEADERS = {"accept": "application/json", "x-apikey": API_KEY}
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/1")

redis = from_url(REDIS_URL, decode_responses=True)

async def save_file(uploaded_file: UploadFile) -> str:
    """Save uploaded file to disk and return its full path."""
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    # Create a unique name for each upload
    filename = f"{datetime.utcnow().timestamp()}_{uploaded_file.filename}"
    file_path = os.path.join(UPLOAD_DIR, filename)

    with open(file_path, "wb") as f:
        shutil.copyfileobj(uploaded_file.file, f)

    uploaded_file.file.seek(0)  # Reset pointer for re-use if needed
    return file_path 

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



async def fetch_virustotal_report_without_redis(
    endpoint_type: str,
    endpoint_value: str,
    db: Session = Depends(get_db),
    file: UploadFile = None,
    file_path: str = None,
):
    if not file:
        url = f"{BASE_URL}/{endpoint_type}/{endpoint_value}"
    else:
        # endpoint_value = await compute_file_hash(file_path)
        url = f"{BASE_URL}/files"

    # Check cached report
    report = db.query(VirusTotalReport).filter_by(endpoint_value=endpoint_value).first()
    if report and report.expires_at > datetime.utcnow():
        return json.loads(report.data), False
    elif report:
        db.delete(report)
        db.commit()

    # Fetch from VirusTotal
    async with httpx.AsyncClient() as client:
        if endpoint_type == "files" and file is not None:
            file_path = await save_file(file)
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                upload_response = await client.post(url, headers=HEADERS, files=files)
                upload_data = upload_response.json()
                analysis_link = upload_data.get("data", {}).get("links", {}).get("self")

            await asyncio.sleep(15)
            report_response = await client.get(analysis_link, headers=HEADERS)
            data = report_response.json()
        else:
            response = await client.get(url, headers=HEADERS)
            data = response.json()

    # Save in DB
    new_report = VirusTotalReport(
        endpoint_type=endpoint_type,
        endpoint_value=endpoint_value,
        data=json.dumps(data),
        file_path=file_path,
        created_at=datetime.utcnow(),
        expires_at=datetime.utcnow() + timedelta(hours=24)
    )
    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    return data, True