FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY replay.py ./replay.py
COPY scenarios ./scenarios

# NEW: include Bot-IoT-derived cases
COPY data ./data

CMD ["python", "replay.py"]