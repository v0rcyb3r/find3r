FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FIND3R_HOME=/data/find3r

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    dnsutils \
    git \
    libpq-dev \
    nmap \
    whois \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY neesha ./neesha

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir . && \
    pip install --no-cache-dir holehe socialscan h8mail toutatis sherlock-project || true

RUN mkdir -p /data/find3r

EXPOSE 8765

CMD ["sh", "-c", "find3r init && find3r serve --host 0.0.0.0 --port 8765"]
