FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap iputils-ping snmp curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei vulnerability scanner
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
        amd64) NA="amd64" ;; \
        arm64) NA="arm64" ;; \
        armhf) NA="armhf" ;; \
        *)     NA="amd64" ;; \
    esac && \
    curl -sL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_${NA}.zip" \
         -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /tmp/nuclei_bin/ && \
    mv /tmp/nuclei_bin/nuclei /usr/local/bin/nuclei && \
    rm -rf /tmp/nuclei.zip /tmp/nuclei_bin && \
    nuclei -update-templates

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY app.py .
COPY templates/ templates/

EXPOSE 9099

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD python -c "import requests; r=requests.get('http://localhost:9099/api/health', timeout=5); exit(0 if r.status_code in (200,503) else 1)"

CMD ["python", "app.py"]
