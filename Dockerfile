FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system utilities: nmap, curl, gcc, libpq for postgres, whois, dnsutils
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    gcc \
    libpq-dev \
    dnsutils \
    whois \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy platform source code
COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
