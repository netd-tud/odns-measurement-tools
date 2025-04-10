import requests
from keys import shodan_api_key

ips = ["8.8.8.8"]

for ip in ips:
    url = f"https://api.shodan.io/shodan/host/{ip}?key={shodan_api_key}"
    resp = requests.get(url)
    print(resp.content)