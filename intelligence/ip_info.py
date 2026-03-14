import requests

def get_ip_info(ip):
    try:
        url = f"http://ip-api.com/json/{ip}"
        r = requests.get(url, timeout=3)
        data = r.json()

        return {
            "country": data.get("country", "Unknown"),
            "city": data.get("city", "Unknown"),
            "isp": data.get("isp", "Unknown")
        }
    except:
        return {
            "country": "Unknown",
            "city": "Unknown",
            "isp": "Unknown"
        }
