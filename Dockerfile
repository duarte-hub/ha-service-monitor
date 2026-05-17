FROM projectdiscovery/nuclei:latest AS nuclei

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap iputils-ping snmp \
    && rm -rf /var/lib/apt/lists/*

# Copy Nuclei binary from official image
COPY --from=nuclei /usr/local/bin/nuclei /usr/local/bin/nuclei

# Pre-download templates so scans work immediately at runtime
RUN nuclei -update-templates

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/

EXPOSE 9099

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import requests; r=requests.get('http://localhost:9099/api/health', timeout=5); exit(0 if r.status_code in (200,503) else 1)"

CMD ["python", "app.py"]
