import json, os, shutil, tempfile
from fastapi import FastAPI, Depends, UploadFile, File, HTTPException, Body, Form, Request
from sqlalchemy.orm import Session
from dotenv import load_dotenv
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from .database import Base, engine, get_db
from .schemas import FetchRequest
from icecream import ic
from .functions import fetch_virustotal_report, compute_file_hash
load_dotenv()


app = FastAPI(title="VirusTotal Data Pipeline (FastAPI)")
Base.metadata.create_all(bind=engine)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


@app.post("/get_virustotal_report/")
# @limiter.limit("5/minute")
async def get_virustotal_report(
    request: Request,
    db: Session = Depends(get_db)
):
    if request.headers.get("content-type", "").startswith("application/json"):
        body = await request.body()
        body = json.loads(body)
    else:
        body = await request.form()
        body = dict(body)
    endpoint_type = body.get("endpoint_type")
    endpoint_value = body.get("endpoint_value")
    file: UploadFile = body.get("file")
    if endpoint_type == "files" and file:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            shutil.copyfileobj(file.file, tmp)
            tmp_path = tmp.name
        endpoint_value = await compute_file_hash(tmp_path)
    elif not endpoint_value:
        raise HTTPException(status_code=400, detail="endpoint_value is required")

    data, fetched = await fetch_virustotal_report(endpoint_type, endpoint_value, db)
    return {"source": "VirusTotal API" if fetched else "Cache/DB", "data": data}

@app.get("/{endpoint_type}/{endpoint_value}/refresh/")
# @limiter.limit("3/minute")
async def refresh_data(endpoint_type: str, endpoint_value: str, db: Session = Depends(get_db)):
    data, _ = await fetch_virustotal_report(endpoint_type, endpoint_value, db)
    return {"refreshed": True, "data": data}

@app.post("/{endpoint_type}/refresh/")
# @limiter.limit("3/minute")
async def refresh_file(endpoint_type: str,  request:Request, db: Session = Depends(get_db)):
    form = await request.form()
    file: UploadFile = form.get("file")
    
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name
    endpoint_value = await compute_file_hash(tmp_path)
    data, _ = await fetch_virustotal_report(endpoint_type, endpoint_value, db)
    return {"refreshed": True, "data": data}