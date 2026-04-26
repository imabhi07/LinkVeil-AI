import requests

def test_analytics():
    url = "http://localhost:8000/api/v1/analytics/"
    try:
        response = requests.get(url)
        print(f"Status: {response.status_code}")
        if response.status_code == 200:
            print("Analytics Data:")
            print(response.json())
        else:
            print(f"Error: {response.text}")
    except Exception as e:
        print(f"Failed to connect to backend: {e}")

if __name__ == "__main__":
    test_analytics()
