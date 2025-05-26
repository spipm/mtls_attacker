from datetime import timedelta, datetime, UTC
import time


def timestamp():
  return int(time.time())
  
def utcnow():
  return datetime.now(UTC)

def utc_formatted():
  return utcnow().strftime('%y-%m-%d %H:%M:%S')

def cert_date_yesterday():
  return utcnow() - timedelta(days=1)

def cert_date_add_year():
  return utcnow() + timedelta(days=365)








