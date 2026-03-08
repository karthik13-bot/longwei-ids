from flask import Flask
import json

app = Flask(__name__)

LOG_FILE = "logs/alerts.log"

@app.route("/")
def index():
    attacks = []

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                attacks.append(json.loads(line))
    except:
        pass

    total_attacks = len(attacks)
    unique_ips = len(set(a["attacker_ip"] for a in attacks))

    return {
        "total_attacks": total_attacks,
        "unique_attackers": unique_ips,
        "attacks": attacks
    }

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
