import requests

url = "http://127.0.0.1:5500/add_admin"
payload = {
    "name": "test@gmail.com",
    "email": "test@gmail.com",
    "password": "test@gmail.com"
}
headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}

response = requests.post(url, data=payload, headers=headers)

# Check response
print("Status Code:", response.status_code)
print("Response Body:", response.text)
