from fastapi import FastAPI
import json

app = FastAPI()

LOG_FILE = "data/logs/events.json"


def read_logs():
    logs = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                logs.append(json.loads(line))
    except:
        pass
    return logs


@app.get("/")
def root():
    return {"message": "NetSentinel API running"}


@app.get("/alerts")
def get_alerts():
    return read_logs()


@app.get("/blocked")
def get_blocked():
    logs = read_logs()
    blocked = [log for log in logs if log["action"] == "Blocked"]
    return blocked