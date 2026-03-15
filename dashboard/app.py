import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from flask import Flask, render_template
import json
from intelligence.ip_info import get_ip_info
from collections import Counter
app = Flask(__name__)

@app.route("/")
def home():

    alerts = []

    try:
        with open("logs/alerts.log") as f:
            for line in f:
                alerts.append(json.loads(line))
    except:
        pass

    for alert in alerts:
        info = get_ip_info(alert["attacker_ip"])
        alert["country"] = info["country"]

    hours = []
    for alert in alerts:
        hour = alert["time"][11:13]
        hours.append(hour)

    hour_counts = Counter(hours)

    labels = list(hour_counts.keys())
    values = list(hour_counts.values())

    count = len(alerts)

    if count < 5:
        threat = "LOW"
    elif count < 15:
        threat = "MEDIUM"
    else:
        threat = "CRITICAL"

    return render_template(
        "dashboard.html",
        alerts=alerts[::-1],
        count=count,
        threat=threat,
        labels=labels,
        values=values
    )

app.run(host="0.0.0.0", port=5000)
