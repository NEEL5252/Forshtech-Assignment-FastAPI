from celery import Celery
from celery.schedules import crontab
import os
from dotenv import load_dotenv
load_dotenv()

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

celery_app = Celery(
    "worker",
    broker=CELERY_BROKER_URL,
    backend=CELERY_RESULT_BACKEND
)

celery_app.autodiscover_tasks(["virustotal_fastapi.background"])
celery_app.conf.beat_schedule = {
    "refresh-every-6-hours": {
        "task": "virustotal_fastapi.background.tasks.refresh_virus_total_data",
        "schedule": crontab(minute="*"),  # 6 hours in seconds
    },
}

celery_app.conf.timezone = "UTC"
celery_app.conf.task_routes = {"virustotal_fastapi.background.tasks.*": {"queue": "virustotal_queue"}}
