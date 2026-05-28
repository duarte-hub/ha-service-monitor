FROM python:3.12-slim
WORKDIR /app

# ── System deps + APT security tools ────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan hydra john sqlmap ncrack dnsenum gobuster ffuf \
    perl git curl wget unzip ca-certificates jq \
    && rm -rf /var/lib/apt/lists/*

# ── nikto (Perl, clone from GitHub) ─────────────────────────────────────────
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && chmod +x /opt/nikto/program/nikto.pl

# ── ProjectDiscovery tools (pinned) ─────────────────────────────────────────
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v3.3.9/nuclei_3.3.9_linux_amd64.zip \
    -o /tmp/nuclei.zip && unzip -qo /tmp/nuclei.zip nuclei -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip

RUN curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    -o /tmp/subfinder.zip && unzip -qo /tmp/subfinder.zip subfinder -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/subfinder && rm /tmp/subfinder.zip

RUN curl -sL https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_amd64.zip \
    -o /tmp/httpx.zip && unzip -qo /tmp/httpx.zip httpx -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/httpx && rm /tmp/httpx.zip

RUN curl -sL https://github.com/projectdiscovery/katana/releases/download/v1.1.2/katana_1.1.2_linux_amd64.zip \
    -o /tmp/katana.zip && unzip -qo /tmp/katana.zip katana -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/katana && rm /tmp/katana.zip

RUN curl -sL https://github.com/projectdiscovery/naabu/releases/download/v2.3.1/naabu_2.3.1_linux_amd64.zip \
    -o /tmp/naabu.zip && unzip -qo /tmp/naabu.zip naabu -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/naabu && rm /tmp/naabu.zip

# ── feroxbuster ──────────────────────────────────────────────────────────────
RUN curl -sL https://github.com/epi052/feroxbuster/releases/download/v2.13.1/x86_64-linux-feroxbuster.zip \
    -o /tmp/ferox.zip \
    && unzip -qo /tmp/ferox.zip feroxbuster -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/feroxbuster && rm /tmp/ferox.zip \
    || echo "WARNING: feroxbuster skipped"

# ── amass ────────────────────────────────────────────────────────────────────
RUN curl -sL https://github.com/owasp-amass/amass/releases/download/v5.1.1/amass_linux_amd64.tar.gz \
    -o /tmp/amass.tar.gz \
    && tar -xzf /tmp/amass.tar.gz -C /tmp/ \
    && mv /tmp/amass_linux_amd64/amass /usr/local/bin/amass \
    && chmod +x /usr/local/bin/amass \
    && rm -rf /tmp/amass.tar.gz /tmp/amass_linux_amd64/ \
    || echo "WARNING: amass skipped"

# ── Python tools via pip ─────────────────────────────────────────────────────
RUN pip install --no-cache-dir wafw00f
RUN pip install --no-cache-dir wfuzz || true
RUN pip install --no-cache-dir theHarvester || true

# ── Python server requirements ───────────────────────────────────────────────
COPY requirements_minimal.txt .
RUN pip install --no-cache-dir -r requirements_minimal.txt

COPY . .

EXPOSE 8888
ENV HEXSTRIKE_PORT=8888
CMD ["python3", "-u", "hexstrike_server.py"]
