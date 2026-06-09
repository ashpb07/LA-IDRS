# docker/Dockerfile
FROM ubuntu:22.04

LABEL maintainer="NetSentinel LA-IDRS"
LABEL description="Lightweight Autonomous Intrusion Detection and Response System"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# ── System deps ────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    gcc \
    make \
    libpcap-dev \
    libpcap0.8 \
    iptables \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ──────────────────────────────────────────────────────
WORKDIR /app

# ── Python deps ────────────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# ── Copy source ────────────────────────────────────────────────────────────
COPY . .

# ── Build C packet engine ──────────────────────────────────────────────────
RUN cd packet_engine && make

# ── Permissions ────────────────────────────────────────────────────────────
RUN chmod +x scripts/run.sh scripts/cleanup.sh scripts/setup.sh \
             response_engine/firewall/iptables.sh

# ── Data directories ───────────────────────────────────────────────────────
RUN mkdir -p data/logs data/db/reports data/db/graphs data/runtime

# ── Expose API port ────────────────────────────────────────────────────────
EXPOSE 8000

# ── Entry point ────────────────────────────────────────────────────────────
CMD ["python3", "main.py"]
