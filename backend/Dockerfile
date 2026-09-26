FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY backend/requirements.txt ./requirements.txt

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir -r requirements.txt

RUN git clone --depth 1 \
    https://github.com/danielmiessler/SecLists.git \
    /opt/seclists

COPY backend/app ./app
COPY frontend ./frontend

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]