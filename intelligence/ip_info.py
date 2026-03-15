import requests

def get_ip_info(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}")
        data = r.json()

        return {
            "country": data.get("country", "Unknown")
        }

    except:
        return {"country": "Unknown"}
