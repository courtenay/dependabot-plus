FROM node:20-bookworm-slim

RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        inotify-tools python3 procps tcpdump && \
    rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /sandbox

ENTRYPOINT ["/entrypoint.sh"]
