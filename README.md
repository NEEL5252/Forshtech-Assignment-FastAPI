# 🧠 VirusTotal FastAPI Assignment

This project is a **FastAPI-based microservice** that integrates with the **VirusTotal API** to fetch, store, and cache reports for domains, IPs, and files.  
It demonstrates how to build a performant, scalable API service using FastAPI — with and without **Redis caching**.

---

## 🚀 1. Features & Functionalities Implemented

### 🧩 Core Functionalities

#### 1. FastAPI Framework
Used to build asynchronous REST APIs with automatic validation, dependency injection, and OpenAPI documentation.

```python
from fastapi import FastAPI, Request, Depends
app = FastAPI(title="VirusTotal FastAPI")
```

---

#### 2. Redis as Cache (Optional)
Used for caching frequently accessed VirusTotal API responses.

```python
from redis import Redis
redis_client = Redis.from_url(REDIS_URL)
```

✅ Significantly improves performance  
✅ Reduces redundant VirusTotal API calls  
✅ Supports TTL (time-based expiration)

---

#### 3. Database Integration
Used **SQLAlchemy ORM** for persistence of VirusTotal reports.

```python
from sqlalchemy import Column, String, JSON
class VirusTotalReport(Base):
    __tablename__ = "virustotal_reports"
    endpoint_type = Column(String)
    endpoint_value = Column(String, primary_key=True)
    report = Column(JSON)
```

If Redis is unavailable, the application still caches and retrieves data using this database layer.

---

#### 4. Rate Limiting
(Optional) Can be added using libraries such as `slowapi`:

```python
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)
```

Prevents overuse of local and VirusTotal APIs.

---

#### 5. Two Main APIs

1️⃣ **Fetch API** – `/get_virustotal_report/`  
Fetches and caches data for domains, IPs, and files.

2️⃣ **Refresh API** – `/refresh_virustotal_report/`  
Re-fetches and updates the stored data manually.

---

#### 6. Cache Key Strategy
Cache data is stored with the following key format:
```
vt_{endpoint_type}_{endpoint_value}
```

Example:  
```
vt_domain_google.com  
vt_ip_8.8.8.8  
vt_file_abcd1234ef...
```

---

## 🧠 2. API Endpoints & Logic

### 1️⃣ Fetch Data Endpoint

**URL:**  
```
POST /get_virustotal_report/
```

**Request:**
```json
{
  "endpoint_type": "domain",
  "endpoint_value": "google.com"
}
```

**Logic Flow:**

1. **Check Redis Cache**  
   - If found → return cached result immediately.

2. **Check Database**  
   - If not in cache → query SQLAlchemy DB.

3. **Fetch from VirusTotal API**  
   - If not found in DB → call VirusTotal API, store in DB and Redis, and return response.

4. **File Handling Logic**
   - When a file is uploaded, compute its hash and send it to VirusTotal for analysis.
   - If an analysis ID is returned, poll the analysis endpoint to retrieve the final report.

---

### Example Flow Diagram

```
Client → /get_virustotal_report/
       → Check Redis cache
          → If found → return cached
          → Else check database
               → If found → cache & return
               → Else → fetch from VirusTotal
                     → save to DB + Redis
                     → return report
```

---

### 2️⃣ Refresh Endpoint

**URL:**  
```
POST /refresh_virustotal_report/
```

**Purpose:**  
Re-fetches data from VirusTotal and updates local cache & DB.

**Why separate?**  
- Files need hashing and async processing.  
- Domains/IPs are direct identifiers.

---

## ⚙️ Caching Modes

### 🧱 Without Redis
- Only SQLAlchemy (DB) used for caching.
- Slower but persistent.
- Best for small deployments.

### ⚡ With Redis
- Hybrid caching using both Redis + DB.
- Fastest performance.
- Redis stores in-memory cache with TTL.

---

## 🧪 Example Response

```json
{
  "endpoint_type": "domains",
  "endpoint_value": "google.com",
  "report": {...},
  "cached": true
}
```

---

## 🛠️ Setup & Installation

### 1️⃣ Clone the Project
```bash
git clone https://github.com/NEEL5252/Forshtech-Assignment-FastAPI
cd virustotal-fastapi
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

### 3️⃣ Environment Variables
Create `.env` file:
```
VT_API_KEY=your_virustotal_api_key
DATABASE_URL=sqlite:///./vt_reports.db
REDIS_URL=redis://localhost:6379/0
```

### 4️⃣ Run Server
```bash
uvicorn main:app --reload
```

Server available at:  
👉 http://127.0.0.1:8000/docs

---

## 🧰 Tech Stack

| Component | Technology |
|------------|-------------|
| API Framework | FastAPI |
| ORM | SQLAlchemy |
| Database | SQLite / PostgreSQL |
| Caching | Redis (optional) |
| Validation | Pydantic |
| Web Server | Uvicorn |
| External API | VirusTotal API v3 |

---

----------
## 👏 Summary

| Feature | Without Redis | With Redis |
|----------|----------------|-------------|
| **Speed** | Medium | ⚡ Fast |
| **Persistence** | ✅ Yes | ✅ Optional |
| **Complexity** | Low | Moderate |
| **Scalability** | Limited | Excellent |
