FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        nmap \
        libpango-1.0-0 \
        libpangoft2-1.0-0 \
        libgdk-pixbuf-2.0-0 \
        libffi-dev \
        shared-mime-info \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

# MONGO_URI and SECRET_KEY should be passed as environment variables at runtime
# e.g.: docker run -e MONGO_URI="mongodb://mongo:27017/webvuln" -e SECRET_KEY="..." ...

CMD ["python", "-m", "app.app"]
