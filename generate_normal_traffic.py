import requests
import time
import random

def send_requests():
    while True:
        response = requests.get('http://localhost:1337')
        time.sleep(5)  # Wait for 5 seconds before the next request

if __name__ == '__main__':
    send_requests()
