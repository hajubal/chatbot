import requests


payload = {
        "model": "llama3.1",
        "messages": [{"role": "user", "content": "hi?"}],
        "stream": True
    }

response = requests.post("http://localhost:11434/api/chat", json=payload)

print(response.status_code)
