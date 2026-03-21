from flask import Flask, render_template
import json
import requests
from collections import Counter

app = Flask(__name__)


# ---------- IP INTELLIGENCE ----------
def get_ip_info(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}")
        data = r.json()

        return {
            "country": data.get("country", "Unknown")
        }
    except:
        return {"country": "Unknown"}


# ---------- MAIN ROUTE ----------
@app.route("/")
def home():
    alerts = []

    # Read alerts log
    try:
        with open("logs/alerts.log") as f:
            for line in f:
                alerts.append(json.loads(line))
    except:
        pass

    # Add country info
    for alert in alerts:
        info = get_ip_info(alert["attacker_ip"])
        alert["country"] = info["country"]

    # ---------- COUNTRY DATA ----------
    countries = []
    for alert in alerts:
        country = alert.get("country", "Unknown")
        countries.append(country)

    country_counts = Counter(countries)
    country_labels = list(country_counts.keys())
    country_values = list(country_counts.values())

    # ---------- TIME DATA ----------
    hours = []
    for alert in alerts:
        hour = alert["time"][11:13]
        hours.append(hour)

    hour_counts = Counter(hours)
    labels = list(hour_counts.keys())
    values = list(hour_counts.values())

    # ---------- TOP ATTACKER IPS ----------
    ip_list = []
    for alert in alerts:
        ip_list.append(alert["attacker_ip"])

    ip_counts = Counter(ip_list)
    top_ips = ip_counts.most_common(5)

    # ---------- THREAT LEVEL ----------
    count = len(alerts)

    if count < 5:
        threat = "LOW"
    elif count < 15:
        threat = "MEDIUM"
    else:
        threat = "CRITICAL"

    # ---------- FINAL OUTPUT ----------
    return render_template(
        "dashboard.html",
        alerts=alerts[::-1],
        count=count,
        threat=threat,
        labels=labels,
        values=values,
        country_labels=country_labels,
        country_values=country_values,
        top_ips=top_ips
    )


# ---------- RUN APP ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
