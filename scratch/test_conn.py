import httpx
import sys

url = "https://5uc6g0vjt8ax2yyl1kcdvq.c0.asia-southeast1.gcp.weaviate.cloud"
try:
    print(f"Attempting to connect to {url}...")
    response = httpx.get(url, timeout=10.0, follow_redirects=True)
    print(f"Final URL: {response.url}")
    print(f"Status Code: {response.status_code}")
except Exception as e:
    print(f"Connection failed: {e}")
    sys.exit(1)
