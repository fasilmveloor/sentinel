FROM python:3.11-slim

WORKDIR /app

COPY vulnerable_api.py .
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["python", "vulnerable_api.py"]
