FROM debian:bookworm-slim

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        tcpdump python3 && \
    rm -rf /var/lib/apt/lists/*

COPY monitor_entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
