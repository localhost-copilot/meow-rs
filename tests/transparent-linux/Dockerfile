FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 nftables iproute2 procps ca-certificates && rm -rf /var/lib/apt/lists/*
COPY check.py /check.py
ENTRYPOINT ["python3", "/check.py"]
