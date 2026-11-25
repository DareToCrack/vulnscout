# VulnScout runs locally or in Docker. Nmap cannot run on serverless
# platforms (Vercel, Lambda, etc.) — this image is the deployment.
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Data directory for the SQLite scan history
RUN mkdir -p /app/data
VOLUME /app/data

ENV PORT=5000 HOST=0.0.0.0
EXPOSE 5000

CMD ["python", "run.py"]
