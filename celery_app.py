from celery import Celery
from config import Config

def make_celery(app_name=__name__):
    return Celery(app_name, broker=os.getenv('CELERY_BROKER_URL','redis://localhost:6379/0'),
                 backend=os.getenv('CELERY_RESULT_BACKEND','redis://localhost:6379/0'))

celery = make_celery()
