# Build RL red-team agent for IDS evasion (Snort 2.9 + Suricata 7.0.3)
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:$PATH"

# System dependencies: Snort 2.9, Suricata 7.0.3, Python 3.11, build tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3.11 python3.11-venv python3.11-dev \
    build-essential git curl wget \
    libpcap-dev libdumbnet-dev libdaq-dev zlib1g-dev \
    snort suricata \
    tcpdump libnetfilter-queue-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy project files (exclude .venv via .dockerignore)
COPY environment.yml ./
COPY ai_agent/ ./ai_agent/
COPY snort_validation/ ./snort_validation/
COPY controls/ ./controls/
COPY tests/ ./tests/
COPY data/ ./data/
COPY rulesets/ ./rulesets/
COPY models/ ./models/
COPY README.md README.vi.md ./

# Create venv and install dependencies
RUN python3.11 -m venv .venv && \
    .venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel && \
    .venv/bin/pip install --no-cache-dir \
        torch==2.0.1 --index-url https://download.pytorch.org/whl/cpu && \
    .venv/bin/pip install --no-cache-dir \
        stable-baselines3==2.0.0 \
        scapy==2.5.0 \
        pandas==2.0.3 \
        numpy==1.24.3 \
        gymnasium==0.28.1 \
        sb3-contrib==2.0.0

# Snort 2.9 config validation
RUN snort -V

# Suricata 7.0.3 config validation
RUN suricata --build-info

# Default: run tests
CMD [".venv/bin/pytest", "tests/", "-v", "--tb=short"]
