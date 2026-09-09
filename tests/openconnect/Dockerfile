FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends ocserv openssl iproute2 dnsmasq \
    && rm -rf /var/lib/apt/lists/*
COPY server.py /server.py
CMD ["python", "/server.py"]
