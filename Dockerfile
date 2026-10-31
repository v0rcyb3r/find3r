FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY neesha ./neesha

RUN pip install --no-cache-dir .

ENTRYPOINT ["neesha"]
